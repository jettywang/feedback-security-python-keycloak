# Keycloak offline token 接入与失效观察实验

面向 Python 后台作业（worker / cron / 批处理）的 Keycloak `offline_access`
接入方案，以及一套**无需运行 Keycloak、无需监听 TCP 端口**的最小状态实验。
假服务端是 Keycloak 已文档化行为的模型，配合确定性时钟与真实的
`python-keycloak` 客户端，量化每种令牌校验策略在撤销后的观察窗口。

## 运行

```bash
.venv/bin/python -m pytest experiments/offline_token -q       # 断言版（9 个用例）
.venv/bin/python experiments/offline_token/run_experiments.py # 可读时序打印版
```

依赖仅 `requests`、`jwcrypto`、`freezegun`、`pytest`，均已在仓库 venv 中。

## 文件

| 文件 | 职责 |
| --- | --- |
| `fake_keycloak.py` | `FakeRealm` 状态机：RSA 签名、在线/离线会话、刷新轮转与复用检测、登出/撤销、禁用用户、introspect/userinfo |
| `fake_transport.py` | 挂载到 `requests.Session` 的内存传输适配器，走 SDK 完整请求/异常路径，不绑定端口 |
| `job_token_manager.py` | 作业侧参考实现：一次性授权、0600 令牌保险库、主动轮转、失效分级处理、登出 |
| `run_experiments.py` | 确定性时钟下的六组场景，打印每种策略的接受/拒绝时序 |
| `test_offline_token.py` | 同样行为的 pytest 断言 |

## 概念区分：四类“会话/校验”的观察范围

1. **在线会话（online session）**：`scope=openid`。SSO 会话随浏览器登出/超时结束；
   refresh token 寿命短（实验取 300s）。用户关掉网页后，在线 SSO 会话即终止。
2. **离线会话（offline session）**：`scope=openid offline_access`。Keycloak 独立保存一条
   offline session，不依赖浏览器 SSO；refresh token 寿命由
   `Offline Session Idle/Max` 控制（实验取 3600s，生产常以天计）。**这才是作业要用的形态。**
3. **访问令牌本地验签**：`KeycloakOpenID.decode_token(validate=True)`。只做 JWKS 签名校验
   与时间声明（`exp`，SDK 默认 `leeway=60`）。除取 JWKS 外不发起服务端调用，
   因而**看不到会话撤销、登出、用户禁用**。
4. **服务端内省**：`introspect()`（RFC 7662）或带 bearer 调受保护端点 `userinfo()`。
   每次都向授权服务器查询实时状态，能立即反映撤销/禁用，但每次校验都有一次网络往返，
   且要求客户端是 confidential（带 secret）。

> 关键结论：**SDK 不会在未请求服务端的情况下“立即知道”撤销。**
> 本地验签对撤销天然无感，只有 introspect / userinfo / refresh 这类服务端调用才能发现。

## 实验得到的撤销可用窗口（access TTL=60s，leeway=60s）

在 t0 发放令牌并随即登出/撤销后，对**同一张已发放 access token** 的观察结果：

| 策略 | t0+0 | t0+59 | t0+61（过 exp，未过 leeway） | t0+121（过 exp+leeway） | 每次网络往返 |
| --- | --- | --- | --- | --- | --- |
| 本地 `decode_token` | 接受 | 接受 | **仍接受** | 拒绝 `JWTExpired` | 0（仅取 JWKS） |
| 服务端 `introspect` | `active=false` | false | false | false | 1 |
| 受保护端点 `userinfo` | 401 | 401 | 401 | 401 | 1 |
| `refresh_token` 授权 | 400 invalid_grant | 400 | 400 | 400 | 1 |

撤销上界（最坏情况下旧 access token 还能被本地验签接受多久）：

- 本地验签：`access_token 寿命 + 验签 leeway`，实验为 **60 + 60 = 120s**，与是否撤销无关，
  只看 `exp` 和时钟。生产上界 = 配置的 Access Token Lifetime + 客户端 leeway。
- 服务端内省 / 受保护端点 / 刷新：**接近 0**（下一次服务端调用即被拒），实际延迟取决于
  调用频率与网络，不依赖令牌寿命。

管理员禁用用户的结论与登出一致：本地验签在令牌自然到期前持续放行；任何服务端路径立即拒绝。

## 三种服务端感知路径的差异

- `refresh_token`：成功即证明 offline session 仍存活，并顺带**轮转**出一对新令牌。
  作业的主路径就是“按需刷新”，所以撤销通常在下次刷新时自然暴露，无需额外内省。
- `introspect`：只查询不轮转，适合在不能/不应刷新时检查某张令牌。
- 受保护端点（如 `userinfo` 或资源网关）：由资源侧基于实时状态返回 401。
  资源网关若只做本地验签，同样存在上面的 120s 窗口；要即时生效需网关启用内省或撤销同步。

## 刷新轮转与复用检测

Keycloak 默认开启 refresh token 轮转：每次刷新旧 refresh token 作废、发放新值。
实验场景 5 验证：重放已轮转的旧 refresh token 会触发整段会话撤销，连刚签发的新
refresh token 也一并失效。因此**每个作业实例只能串行持有并使用最新 refresh token，
绝不能多副本并发刷新同一 offline token**。

## 作业重启、刷新失败、禁用用户的状态处理

- **重启**：作业只持久化 offline refresh token（见 `OfflineTokenStore`，权限 0600、原子替换）。
  重启后从保险库加载，access token 过期就用 refresh token 换新，无需用户在场。
- **刷新返回 400 `invalid_grant`**（会话撤销、用户禁用、令牌过期、复用被踢）：
  这是**确定性失效**，清除本地令牌并进入“需重新授权”状态，停止重试，告警并走重新发放流程。
- **网络异常 / 5xx**（SDK 包装为 `KeycloakConnectionError`，对应 `ConnectionError`）：
  这是**临时性故障**，**保留**保险库中的 offline token，本次作业失败、退避后重试，
  不得清除令牌。实验场景 6 覆盖该区分。
- **管理员禁用用户**：下一次刷新即收到 400，按确定性失效处理；在那之前，
  仍在有效期内的 access token 对纯本地验签的组件继续有效（见上界）。

## 必须由部署/Realm 配置保证的条件

1. 作业客户端为 **confidential**，妥善保管 client secret；introspect 仅对 confidential 开放。
2. Realm/客户端启用并授予 `offline_access` scope，且该 scope 出现在授权请求里
   （`KeycloakOpenID.token(..., scope="openid offline_access")`）。
3. 规划 `Offline Session Idle`（空闲超时）与 `Offline Session Max`（绝对上限）：
   作业刷新间隔必须显著小于 Idle，否则 offline session 会在两次运行间过期；
   到达 Max 后无论如何都需用户重新同意。
4. 缩短 Access Token Lifetimes 以压低本地验签的撤销窗口；明确并统一各服务的 leeway。
5. 资源网关要即时撤销：启用内省/撤销同步（如 admin events、Back-Channel Logout），
   不要只依赖本地 JWT 验签。
6. refresh token 持久化按凭证级保护（0600/密钥管理），单实例独占、原子写、避免并发刷新。
7. 时钟同步（NTP）：本地 `exp` 判定完全依赖本机墙钟，时钟漂移会放大或缩短窗口。
8. 若需要“撤销后秒级生效”，安全关键动作必须走服务端内省或资源侧实时校验，
   不能只靠 `decode_token`。

## 推荐的失效处理策略（默认）

- 作业主循环：用 access token 调资源；临近过期（提前 skew，如 30s）主动用 offline
  refresh token 轮转，而不是等 401。
- 400 `invalid_grant` → 清令牌、停止、告警、重新授权；连接错误 → 保留令牌、退避重试。
- 高敏感操作前按需补一次 `introspect`，把撤销窗口从“令牌寿命级”压缩到“单次调用级”。
- 普通内部调用可接受 `Access TTL + leeway` 的撤销上界，换取零额外往返；按数据敏感度选择。
