# `permissions_check` 故障压缩诊断与接口契约建议

适用对象：本仓库 `src/keycloak/keycloak_uma.py` 中的
`KeycloakUMA.permissions_check`（同步）与 `KeycloakUMA.a_permissions_check`（异步）。
所有结论均由 `diagnose_permissions_check.py` 用传输替身真实执行得到，未假设所有
HTTP 错误同源；运行环境 `requests 2.34.2` / `httpx 0.28.1` / Python 3.12。

## 1. 两条路径的实际代码结构

同步 `permissions_check`（`src/keycloak/keycloak_uma.py:422`）与异步
`a_permissions_check`（`src/keycloak/keycloak_uma.py:915`）结构完全对称：

1. 组装 `response_mode=decision` 的表单；若 `payload["permission"]` 为空字符串，
   **在任何网络调用之前直接 `return True`**（`:455` 与 `:948`）。
2. 每次调用都 `new` 一个 `ConnectionManager`（`:464` / `:957`），同步路径随方法结束
   被 GC，异步路径创建的 `httpx.AsyncClient` 未显式 `aclose()`，存在连接资源滞留。
3. `raw_post` / `a_raw_post` 把底层 `requests`/`httpx` 的所有异常（含超时、连接拒绝）
   统一包装成 `KeycloakConnectionError`（`connection.py:375`、`connection.py:502`）。
4. 随后 `raise_error_from_response`（`exceptions.py:148`）按状态码决定返回 JSON 或抛异常：
   - 200/201/204：返回 `response.json()`；JSON 解析失败时返回原始 `bytes`。
   - 401：强制改抛 `KeycloakAuthenticationError`（`exceptions.py:200`）。
   - 其它非预期状态码：抛传入的 `KeycloakPostError`，并带 `response_code`。
5. 调用点只 `except KeycloakPostError: return False`（`:476` / `:972`）。
6. 200 响应再做 `isinstance(data, dict)` 检查，非 dict 抛 `TypeError`；dict 则
   `return data.get("result", False)`（`:481`-`:488` / `:977`-`:984`）。

关键继承关系（脚本实测）：
`KeycloakAuthenticationError` **不是** `KeycloakPostError` 的子类，
`KeycloakConnectionError` 也不是。因此第 5 步的 `except` 抓不到这两类异常。

## 2. 实测行为矩阵（同步与异步结果一致）

| 传输替身场景 | 库的实际结果 | 状态码是否保留 | 调用方看到的语义 |
|---|---|---|---|
| 200 + `{"result": false}` | `return False` | 是（200） | 授权服务器明确拒绝（可信 deny） |
| 200 + `{"result": true}` | `return True` | 是（200） | 明确允许 |
| 401 | 抛 `KeycloakAuthenticationError` | 是（401） | 令牌问题，需重新认证 |
| 403 | `return False` | **否，被吞** | 被误并入“无权限” |
| 429 | `return False` | **否，被吞** | 限流，本应重试，却变拒绝 |
| 500 | `return False` | **否，被吞** | 服务故障，本应重试/告警，却变拒绝 |
| 200 + 坏 JSON | 抛 `TypeError` | 否 | 协议违规，调用方常未捕获 |
| 200 + JSON 数组（非对象） | 抛 `TypeError` | 否 | 协议违规 |
| 200 + 对象但无 `result` 字段 | `return False` | 语义丢失 | 缺字段被默认成拒绝 |
| `requests.ReadTimeout`（同步超时） | 抛 `KeycloakConnectionError` | 否 | 可重试故障 |
| `httpx.ReadTimeout`（异步超时） | 抛 `KeycloakConnectionError` | 否 | 可重试故障 |
| 连接拒绝 | 抛 `KeycloakConnectionError` | 否 | 可重试故障 |

补充（POST 之前的路径，脚本同样实测）：

- **空权限集合短路**：传入空 iterable 时，即使传输替身被配置成必定超时，
  `post 调用次数=0`，方法直接返回 `True`。该短路本身不掩盖 POST 错误（因为根本不发
  请求），但它是一条 **fail-open** 路径：上游若因 bug 拼出空权限集合，会在无任何
  授权校验的情况下放行。建议对“空集合”显式记录日志/指标，不要静默。
- **well-known 不可达**：在首次访问 `uma_well_known` 时抛底层连接异常，POST 不会发出，
  `post 调用次数=0`。
- **`connection.base_url is None`**：抛 `AttributeError`（`:458` / `:951`），同样在 POST 前。

## 3. 被压缩掉的状态（问题本质）

布尔接口把至少三类语义不同的情况折叠成同一个 `False`：

1. **可信否定裁决**：200 + `result=false`，以及协议层面的 403。
2. **临时性基础设施故障**：429、5xx —— 被 `except KeycloakPostError: return False` 吞掉，
   身份服务故障因此被后端当成“用户没有权限”。
3. **响应契约违规**：200 但缺 `result` 字段 —— 被 `dict.get("result", False)` 默认成拒绝。

而 401、超时/连接错误、坏 JSON 又以不同异常类型冒出，调用方仅靠 `True/False` 无法统一
处理，且不同后端容易只写 `if not permitted: 拒绝页面`，于是把重试类/告警类故障全部
误判为授权拒绝。

## 4. 建议的接口契约

### 4.1 三值（实为五态）决策模型

不再返回裸布尔，返回结构化 `PermissionDecision`（参考实现见
`contract_reference.py`）：

| 决策码 | 触发条件（实测可得） | 调用方处置 |
|---|---|---|
| `allow` | 200 + `result=true` | 放行 |
| `deny` | 200 + `result=false`；HTTP 403 | 进入拒绝页面 |
| `retryable` | 超时/连接拒绝（`KeycloakConnectionError`）；HTTP 429/500/502/503/504 | 有限次指数退避重试；持续失败告警并 fail-closed |
| `authn_error` | HTTP 401（`KeycloakAuthenticationError`） | 刷新令牌/重新登录，不展示“无权限” |
| `indeterminate` | 200 坏 JSON、非对象响应、缺 `result`、未分类错误码 | 告警并保留原始响应；默认 fail-closed，禁止静默当 deny |

路由原则：**只有授权服务器给出的明确否定（`result=false` / 403）才能进拒绝页面**；
传输与 5xx/429 进入重试；401 进入重新认证；协议畸形进入告警。任何非 `allow` 决策在
无法进一步处理时都应 fail-closed（拒绝访问），但要带上区分度，不得与可信 deny 混为一谈。

### 4.2 库层面的建议改造（供上游参考）

- 新增 `permissions_check_strict` / `a_permissions_check_strict`：删除
  `except KeycloakPostError: return False`，让带 `response_code` 的异常透出；
  对 200 缺 `result` 字段抛专门的契约异常而非默认 `False`。
- 严格版返回 `PermissionDecision`，或抛出分类异常（`PermissionDenied`、
  `PermissionServiceUnavailable`、`PermissionAuthenticationRequired`、
  `PermissionResponseInvalid`）。
- 异步路径对方法内新建的 `ConnectionManager` 调用 `aclose()`，避免 `httpx` 客户端滞留。
- 空权限短路保留，但改为可观测（debug 日志/指标），并在文档中标注其 fail-open 语义。

## 5. 与现有布尔接口的兼容方案

分三步，可在不改库源码的前提下先落地（`contract_reference.PermissionChecker`）：

1. **适配层包装（立即可用，向后兼容）**：业务侧统一改调 `PermissionChecker.check` /
   `a_check`，内部仍调用现有布尔方法。它能正确区分 401（异常）、超时/连接（异常）、
   200 坏 JSON（`TypeError`）。
2. **承认布尔接口的盲区**：在适配层下，403/429/500 因库已吞掉状态码，**无法**与可信
   `result=false` 区分，只能一并归为 `deny`。要消除该盲区，需第 4.2 节的严格版接口；
   脚本的“严格版对比”演示了同一 429/500 响应在不吞异常后可正确归入 `retryable`。
3. **布尔兼容出口**：`PermissionDecision.allowed` 保留布尔语义（仅 `allow` 为 `True`），
   老代码可先用 `decision.allowed` 平替；新增代码按 `decision.code` 分流。库若新增严格
   方法，旧 `permissions_check` 保留不破坏，内部可委托严格方法并维持原异常吞没行为，
   通过弃用警告引导迁移。

最小迁移示例：

```python
from diagnostics.contract_reference import PermissionChecker, DecisionCode

decision = PermissionChecker().check(uma, token, permissions)
if decision.code is DecisionCode.ALLOW:
    ...                       # 放行
elif decision.code is DecisionCode.DENY:
    show_forbidden_page()     # 仅可信否定才到这里
elif decision.code is DecisionCode.AUTHN_ERROR:
    reauthenticate()          # 401：重新登录
elif decision.code is DecisionCode.RETRYABLE:
    response = retry_with_backoff()  # 429/5xx/超时
else:  # INDETERMINATE
    alert_and_fail_closed()   # 协议畸形：告警，不放行也不冒充 deny
```

## 6. 复现方式

```bash
.venv/bin/python diagnostics/diagnose_permissions_check.py \
    --json "$TMPDIR/perm_report.json"
```

- 无需真实 Keycloak：传输替身顶替了 `keycloak_uma.ConnectionManager`。
- 退出码 `0` 表示实测结果与脚本内置基线（baseline 提交 `22191f8`）一致；
  升级依赖后若出现 `DRIFT`（退出码 `1`），说明库行为变化，需重新核对本契约。
- 同步、异步在全部 12 个场景下结果一致；空权限短路、well-known 故障、`base_url=None`
  另有独立检查项。
