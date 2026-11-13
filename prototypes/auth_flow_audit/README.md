# Keycloak 认证流离线审查原型

在变更认证流之前，静态回答一个问题：**当前导出的配置里，是否存在只用密码就能完成登录的分支？**

原型只读取导出文件，不连接、不修改任何 Keycloak 服务器；它是对登录集成测试的补充，而不是替代。

## 组成

- `collect_export.py` — 基于 python-keycloak 的只读采集器。只调用
  `KeycloakAdmin.get_authentication_flows()` 与
  `KeycloakAdmin.get_authentication_flow_executions()`（均为 GET），
  递归展开子流程，产出导出包 JSON。
- `auth_flow_audit.py` — 离线分析器 + CLI。读取导出包，重建子流程层级与
  执行顺序，枚举所有成功登录路径并给出结论。
- `fixtures/` — 三个最小配置：必经 MFA、可绕行 MFA、依赖未知自定义条件。
- `tests/` — pytest 测试（不依赖服务器）。

## 用法

```sh
# 1. 从服务器导出（只读）
python collect_export.py --server-url https://sso.example.com \
    --realm myrealm --username auditor --output flow-export.json

# 2. 离线审查
python auth_flow_audit.py flow-export.json --flow browser
```

## 语义规则

- 按 `(level, index)` 恢复执行顺序；`authenticationFlow` 执行项递归展开子流程，
  引用成环直接报错。
- `REQUIRED` 全部必经；连续 `ALTERNATIVE` 兄弟构成一个选择点；
  `DISABLED` 剪枝；无法识别的 requirement 告警并按 DISABLED 处理。
- `CONDITIONAL` 子流程：内置条件（`conditional-user-configured` 等）给出
  具名运行时依赖；**自定义/未知执行器产生 UNKNOWN 分支**——"条件成立"与
  "条件不成立"两条路径都枚举，绝不假定恒真或恒假。
- 结论绑定 **snapshot id**（flows + executions 规范化 JSON 的 SHA-256），
  `export_meta`（realm 名、导出时间）不参与哈希；realm 名仅作展示，
  不是配置版本的稳定标识。

## 结论等级

- `MFA_ENFORCED` — 所有枚举路径都包含第二因子或强无密码认证器。
- `MFA_BYPASSABLE` — 存在仅密码路径，且其依赖均为可命名的运行时条件。
- `UNKNOWN_DEPENDENT` — 仅密码路径只在未知自定义条件的某个取值下成立，
  需要人工审查该执行器。

## 已知限制

- 条件求值是静态的：即使内置条件也按运行时依赖处理（两个分支都枚举）。
- `identity-provider-redirector` 等外部委托不按因子分类；外部 IdP 的
  认证强度不在本工具视野内。
- 自定义认证器的因子类别默认归为 `other`，需要时可在
  `auth_flow_audit.py` 的注册表中补充。
- 静态分析不能证明运行时行为；变更前后仍应在测试环境做真实登录验证。
