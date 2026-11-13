# permissions_check 故障诊断产物

无需真实 Keycloak，全部通过传输替身（transport double）驱动。

## 文件

- `diagnose_permissions_check.py` — 可重复执行的诊断脚本，覆盖同步/异步两条路径、
  12 个传输场景、空权限短路与 POST 前故障，并内置基线漂移检测。
- `contract_reference.py` — 建议契约的参考实现：五态 `PermissionDecision` 与
  `PermissionChecker` 适配层（含布尔兼容出口 `allowed` 与严格版 `check_strict`）。
- `PERMISSION_CHECK_CONTRACT.md` — 实测行为矩阵、状态压缩分析、接口契约建议与
  布尔接口兼容/迁移方案。

## 运行

```bash
.venv/bin/python diagnostics/diagnose_permissions_check.py --json report.json
```

退出码 `0` = 实测与基线一致；`1` = 库行为漂移，需重新核对契约。
