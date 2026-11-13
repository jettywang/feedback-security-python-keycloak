#!/usr/bin/env python3
"""
python-keycloak ``KeycloakUMA.permissions_check`` / ``a_permissions_check``
故障压缩诊断脚本（可重复执行，无需真实 Keycloak）。

做法：
1. 用传输替身（transport double）顶替 ``keycloak_uma.ConnectionManager``，
   分别让 token 端点返回可信 result=false、401、403、429、500、坏 JSON、
   非对象 JSON，或直接抛出超时/连接异常。
2. 真实执行同步与异步两条路径，只记录 *实际* 返回值或异常（含状态码），
   不预设所有 HTTP 错误同源。
3. 额外验证空权限集合的短路行为，以及 well-known 拉取失败、base_url 缺失等
   发生在 POST 之前的故障。
4. 同时演示一个可立即采用的三值分类适配层（见本目录
   PERMISSION_CHECK_CONTRACT.md 与 contract_reference.py）。

用法：
    .venv/bin/python diagnostics/diagnose_permissions_check.py
    .venv/bin/python diagnostics/diagnose_permissions_check.py --json report.json

退出码：0 = 实测结果与本脚本内置的“当前行为基线”一致；
        1 = 库行为发生漂移（升级后需要重新核对契约）。
"""

from __future__ import annotations

import argparse
import asyncio
import json
import sys
from dataclasses import dataclass
from pathlib import Path
from typing import Any

# 确保优先使用仓库内 src/ 的包，而不是环境里其它安装版本
ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))

import httpx  # noqa: E402
import requests  # noqa: E402

from keycloak import keycloak_uma as uma_module  # noqa: E402
from keycloak.exceptions import (  # noqa: E402
    KeycloakAuthenticationError,
    KeycloakConnectionError,
    KeycloakError,
    KeycloakPostError,
)
from keycloak.keycloak_uma import KeycloakUMA  # noqa: E402
from keycloak.uma_permissions import UMAPermission  # noqa: E402

from contract_reference import DecisionCode, PermissionChecker, PermissionDecision  # noqa: E402

TOKEN_ENDPOINT = "https://idp.example.test/realms/diag/protocol/openid-connect/token"
WELL_KNOWN = {"token_endpoint": TOKEN_ENDPOINT}


# --------------------------------------------------------------------------- #
# 传输替身
# --------------------------------------------------------------------------- #
class FakeResponse:
    """同时满足 requests.Response 与 httpx.Response 在本调用链中用到的接口。"""

    def __init__(
        self,
        status_code: int,
        json_body: Any = None,
        content: bytes = b"",
        malformed: bool = False,
    ) -> None:
        self.status_code = status_code
        self._json_body = json_body
        self._malformed = malformed
        if malformed:
            self.content = b"<<not-a-json-body>>"
        else:
            self.content = content or (
                json.dumps(json_body).encode() if json_body is not None else b""
            )

    def json(self) -> Any:
        if self._malformed:
            raise json.JSONDecodeError("malformed transport double response", "", 0)
        return self._json_body


@dataclass
class Behavior:
    """一次传输替身被调用时应表现出的行为。"""

    kind: str  # "response" 或 "raise"
    response: FakeResponse | None = None
    underlying_error: Exception | None = None


class StubConnectionManager:
    """
    镜像真实 ``ConnectionManager`` 的关键行为：
    - 构造参数与真实类一致（permissions_check 内部按关键字传入）；
    - ``raw_post`` / ``a_raw_post`` 捕获底层异常并统一包装成
      ``KeycloakConnectionError``，与 connection.py 的 except Exception 一致；
    - 记录调用次数，用于判断是否发生短路。
    """

    def __init__(self, behavior_holder: "BehaviorHolder", **kwargs: Any) -> None:
        self.behavior_holder = behavior_holder
        self.config = kwargs
        self.headers: dict[str, str] = {}
        self.post_calls: list[tuple[str, Any]] = []

    def add_param_headers(self, key: str, value: str) -> None:
        self.headers[key] = value

    def _deliver(self, path: str, data: Any) -> FakeResponse:
        self.post_calls.append((path, data))
        self.behavior_holder.call_count += 1
        behavior = self.behavior_holder.behavior
        if behavior.kind == "raise":
            assert behavior.underlying_error is not None
            raise behavior.underlying_error
        assert behavior.response is not None
        return behavior.response

    def raw_post(self, path: str, data: Any = None, **kwargs: Any) -> FakeResponse:
        try:
            return self._deliver(path, data)
        except Exception as exc:  # 与 connection.py raw_post 完全一致的包装
            raise KeycloakConnectionError("Can't connect to server") from exc

    async def a_raw_post(self, path: str, data: Any = None, **kwargs: Any) -> FakeResponse:
        try:
            return self._deliver(path, data)
        except Exception as exc:  # 与 connection.py a_raw_post 完全一致的包装
            raise KeycloakConnectionError("Can't connect to server") from exc

    # 以下两个方法仅在 well-known 未缓存时才会走到
    def raw_get(self, path: str, **kwargs: Any) -> FakeResponse:
        return self.behavior_holder.well_known_response

    async def a_raw_get(self, path: str, **kwargs: Any) -> FakeResponse:
        return self.behavior_holder.well_known_response


@dataclass
class BehaviorHolder:
    behavior: Behavior
    well_known_response: FakeResponse | None = None
    call_count: int = 0

    def factory(self, **kwargs: Any) -> StubConnectionManager:
        return StubConnectionManager(self, **kwargs)


class FakeOpenIDConnection:
    """permissions_check 只读取连接对象上的若干配置属性。"""

    def __init__(
        self,
        well_known: dict | None,
        well_known_behavior: Behavior | None = None,
        base_url: str | None = "https://idp.example.test",
    ) -> None:
        self.base_url = base_url
        self.client_id = "diag-client"
        self.realm_name = "diag"
        self.timeout = 5
        self.verify = True
        self.proxies = None
        self.cert = None
        self.max_retries = 1
        self.pool_maxsize = None
        self._well_known = well_known
        self._well_known_behavior = well_known_behavior
        self.well_known_fetch_count = 0

    def _fetch_well_known(self) -> FakeResponse:
        self.well_known_fetch_count += 1
        behavior = self._well_known_behavior
        if behavior is not None and behavior.kind == "raise":
            assert behavior.underlying_error is not None
            raise behavior.underlying_error
        return FakeResponse(200, json_body=WELL_KNOWN)

    def raw_get(self, path: str, **kwargs: Any) -> FakeResponse:
        return self._fetch_well_known()

    async def a_raw_get(self, path: str, **kwargs: Any) -> FakeResponse:
        return self._fetch_well_known()


# --------------------------------------------------------------------------- #
# 观测工具
# --------------------------------------------------------------------------- #
@dataclass
class Observation:
    path: str
    outcome: str  # "return" | "raise"
    value: Any = None
    error_type: str | None = None
    status_code: int | None = None
    transport_called: bool = False
    well_known_fetched: bool = False

    def summary(self) -> str:
        if self.outcome == "return":
            return f"return {self.value!r}"
        return f"raise {self.error_type}(code={self.status_code})"


def build_uma(holder: BehaviorHolder, connection: FakeOpenIDConnection) -> KeycloakUMA:
    uma = KeycloakUMA(connection=connection)
    if connection._well_known is not None:
        uma._well_known = connection._well_known
    return uma


def observe_sync(holder: BehaviorHolder, connection: FakeOpenIDConnection,
                 permissions: list[UMAPermission]) -> Observation:
    uma = build_uma(holder, connection)
    try:
        value = uma.permissions_check("user-token", permissions)
        return Observation("sync", "return", value=value,
                          transport_called=holder.call_count > 0,
                          well_known_fetched=connection.well_known_fetch_count > 0)
    except BaseException as exc:  # 诊断需要捕获一切，包括 TypeError
        return Observation(
            "sync", "raise",
            error_type=type(exc).__name__,
            status_code=getattr(exc, "response_code", None),
            transport_called=holder.call_count > 0,
            well_known_fetched=connection.well_known_fetch_count > 0,
        )


async def _observe_async(holder: BehaviorHolder, connection: FakeOpenIDConnection,
                         permissions: list[UMAPermission]) -> Observation:
    uma = build_uma(holder, connection)
    try:
        value = await uma.a_permissions_check("user-token", permissions)
        return Observation("async", "return", value=value,
                           transport_called=holder.call_count > 0,
                           well_known_fetched=connection.well_known_fetch_count > 0)
    except BaseException as exc:
        return Observation(
            "async", "raise",
            error_type=type(exc).__name__,
            status_code=getattr(exc, "response_code", None),
            transport_called=holder.call_count > 0,
            well_known_fetched=connection.well_known_fetch_count > 0,
        )


def observe_async(holder: BehaviorHolder, connection: FakeOpenIDConnection,
                  permissions: list[UMAPermission]) -> Observation:
    return asyncio.run(_observe_async(holder, connection, permissions))


# --------------------------------------------------------------------------- #
# 场景定义
# --------------------------------------------------------------------------- #
PERMS = [UMAPermission(resource="document", scope="read")]


def scenarios() -> dict[str, Behavior]:
    return {
        "authoritative result=false": Behavior(
            "response", FakeResponse(200, json_body={"result": False})),
        "authoritative result=true (sanity)": Behavior(
            "response", FakeResponse(200, json_body={"result": True})),
        "HTTP 401 unauthorized": Behavior(
            "response", FakeResponse(401, json_body={"message": "unauthorized"})),
        "HTTP 403 forbidden": Behavior(
            "response", FakeResponse(403, json_body={"error": "access_denied"})),
        "HTTP 429 rate limited": Behavior(
            "response", FakeResponse(429, json_body={"error": "too many requests"})),
        "HTTP 500 server error": Behavior(
            "response", FakeResponse(500, json_body={"errorMessage": "boom"})),
        "HTTP 200 malformed JSON": Behavior(
            "response", FakeResponse(200, malformed=True)),
        "HTTP 200 JSON but not an object (list)": Behavior(
            "response", FakeResponse(200, json_body=["unexpected", "shape"])),
        "HTTP 200 object missing result claim": Behavior(
            "response", FakeResponse(200, json_body={"something": "else"})),
        "sync timeout (requests.ReadTimeout)": Behavior(
            "raise", underlying_error=requests.exceptions.ReadTimeout("read timed out")),
        "async timeout (httpx.ReadTimeout)": Behavior(
            "raise", underlying_error=httpx.ReadTimeout("read timed out")),
        "connection refused": Behavior(
            "raise", underlying_error=httpx.ConnectError("[Errno 61] connection refused")),
    }


# 脚本编写时（baseline 提交 22191f8）实测到的库行为，用于升级后检测漂移
BASELINE: dict[str, tuple[str, Any, str | None, int | None]] = {
    # 场景: (outcome, value 或 None, error_type 或 None, status_code 或 None)
    "authoritative result=false": ("return", False, None, None),
    "authoritative result=true (sanity)": ("return", True, None, None),
    "HTTP 401 unauthorized": ("raise", None, "KeycloakAuthenticationError", 401),
    "HTTP 403 forbidden": ("return", False, None, None),
    "HTTP 429 rate limited": ("return", False, None, None),
    "HTTP 500 server error": ("return", False, None, None),
    "HTTP 200 malformed JSON": ("raise", None, "TypeError", None),
    "HTTP 200 JSON but not an object (list)": ("raise", None, "TypeError", None),
    "HTTP 200 object missing result claim": ("return", False, None, None),
    "sync timeout (requests.ReadTimeout)": (
        "raise", None, "KeycloakConnectionError", None),
    "async timeout (httpx.ReadTimeout)": (
        "raise", None, "KeycloakConnectionError", None),
    "connection refused": ("raise", None, "KeycloakConnectionError", None),
}


def run_scenario(name: str, behavior: Behavior) -> tuple[Observation, Observation,
                                                         PermissionDecision, PermissionDecision]:
    # 同步与异步各用独立的 holder/连接，互不污染
    sync_holder = BehaviorHolder(behavior)
    async_holder = BehaviorHolder(behavior)
    original = uma_module.ConnectionManager
    uma_module.ConnectionManager = sync_holder.factory  # type: ignore[assignment]
    try:
        sync_conn = FakeOpenIDConnection(dict(WELL_KNOWN))
        sync_obs = observe_sync(sync_holder, sync_conn, PERMS)
    finally:
        uma_module.ConnectionManager = original

    uma_module.ConnectionManager = async_holder.factory  # type: ignore[assignment]
    try:
        async_conn = FakeOpenIDConnection(dict(WELL_KNOWN))
        async_obs = observe_async(async_holder, async_conn, PERMS)
    finally:
        uma_module.ConnectionManager = original

    checker = PermissionChecker()
    sync_decision = checker.classify_observation(sync_obs)
    async_decision = checker.classify_observation(async_obs)
    return sync_obs, async_obs, sync_decision, async_decision


def run_empty_permission_short_circuit() -> dict[str, Any]:
    """空权限集合：即使传输层被设计成超时，也应在发请求前短路。"""
    timeout_behavior = Behavior("raise",
                                underlying_error=requests.exceptions.ReadTimeout("x"))
    results: dict[str, Any] = {}

    holder = BehaviorHolder(timeout_behavior)
    original = uma_module.ConnectionManager
    uma_module.ConnectionManager = holder.factory  # type: ignore[assignment]
    try:
        conn = FakeOpenIDConnection(dict(WELL_KNOWN))
        obs = observe_sync(holder, conn, [])
    finally:
        uma_module.ConnectionManager = original
    results["sync"] = {
        "observation": obs.summary(),
        "transport_post_calls": holder.call_count,
        "short_circuited": holder.call_count == 0,
    }

    holder = BehaviorHolder(timeout_behavior)
    uma_module.ConnectionManager = holder.factory  # type: ignore[assignment]
    try:
        conn = FakeOpenIDConnection(dict(WELL_KNOWN))
        obs = observe_async(holder, conn, [])
    finally:
        uma_module.ConnectionManager = original
    results["async"] = {
        "observation": obs.summary(),
        "transport_post_calls": holder.call_count,
        "short_circuited": holder.call_count == 0,
    }
    return results


def run_pre_post_failures() -> list[dict[str, Any]]:
    """POST 之前就失败的路径：well-known 拉取失败、base_url 缺失。"""
    findings: list[dict[str, Any]] = []

    wk_behavior = Behavior("raise", underlying_error=httpx.ConnectError("well known down"))
    holder = BehaviorHolder(wk_behavior)
    original = uma_module.ConnectionManager
    uma_module.ConnectionManager = holder.factory  # type: ignore[assignment]
    try:
        conn = FakeOpenIDConnection(well_known=None, well_known_behavior=wk_behavior)
        sync_obs = observe_sync(holder, conn, PERMS)
        conn2 = FakeOpenIDConnection(well_known=None, well_known_behavior=wk_behavior)
        async_obs = observe_async(holder, conn2, PERMS)
    finally:
        uma_module.ConnectionManager = original
    findings.append({
        "scenario": "well-known endpoint unreachable",
        "sync": sync_obs.summary(),
        "async": async_obs.summary(),
        "transport_post_calls": holder.call_count,
    })

    holder = BehaviorHolder(Behavior("response", FakeResponse(200, {"result": True})))
    uma_module.ConnectionManager = holder.factory  # type: ignore[assignment]
    try:
        conn = FakeOpenIDConnection(well_known=dict(WELL_KNOWN), base_url=None)
        sync_obs = observe_sync(holder, conn, PERMS)
        async_obs = observe_async(holder, conn, PERMS)
    finally:
        uma_module.ConnectionManager = original
    findings.append({
        "scenario": "connection.base_url is None",
        "sync": sync_obs.summary(),
        "async": async_obs.summary(),
        "transport_post_calls": holder.call_count,
    })
    return findings


def run_strict_comparison() -> list[dict[str, Any]]:
    """
    对比演示：同一条 403/429/500 响应，在“严格版”接口（不吞 KeycloakPostError）下
    可以恢复真实状态码并做正确分类，而当前布尔接口只能给出无法区分的 False。
    严格版通过运行时包装实现，不修改库源码。
    """
    from keycloak.exceptions import raise_error_from_response

    def permissions_check_strict(uma: KeycloakUMA, token: str,
                                 permissions: list[UMAPermission]) -> bool:
        payload = {
            "grant_type": "urn:ietf:params:oauth:grant-type:uma-ticket",
            "permission": ",".join(str(p) for p in permissions),
            "response_mode": "decision",
            "audience": uma.connection.client_id,
        }
        connection = uma_module.ConnectionManager(
            base_url=uma.connection.base_url,
            timeout=uma.connection.timeout,
            verify=uma.connection.verify,
            proxies=uma.connection.proxies,
            cert=uma.connection.cert,
            max_retries=uma.connection.max_retries,
            pool_maxsize=uma.connection.pool_maxsize,
        )
        connection.add_param_headers("Authorization", "Bearer " + token)
        connection.add_param_headers("Content-Type", "application/x-www-form-urlencoded")
        data_raw = connection.raw_post(uma.uma_well_known["token_endpoint"], data=payload)
        data = raise_error_from_response(data_raw, KeycloakPostError)  # 不吞异常
        if not isinstance(data, dict):
            msg = ("Unexpected response type. Expected 'dict', received "
                   f"'{type(data)}', value '{data}'.")
            raise TypeError(msg)
        return data.get("result", False)

    class StrictUMA:
        """把严格版函数挂成 PermissionChecker.check_strict 期望的方法名。"""

        def __init__(self, uma: KeycloakUMA) -> None:
            self._uma = uma

        def permissions_check_strict(self, token: str,
                                     permissions: list[UMAPermission]) -> bool:
            return permissions_check_strict(self._uma, token, permissions)

    checker = PermissionChecker()
    rows: list[dict[str, Any]] = []
    for name in ("HTTP 403 forbidden", "HTTP 429 rate limited", "HTTP 500 server error",
                 "HTTP 401 unauthorized"):
        behavior = scenarios()[name]
        holder = BehaviorHolder(behavior)
        original = uma_module.ConnectionManager
        uma_module.ConnectionManager = holder.factory  # type: ignore[assignment]
        try:
            uma = build_uma(holder, FakeOpenIDConnection(dict(WELL_KNOWN)))
            decision = checker.check_strict(StrictUMA(uma), "user-token", PERMS)
            strict_observation = (
                "return bool" if decision.code is DecisionCode.ALLOW
                or decision.code is DecisionCode.DENY and decision.status_code == 200
                else f"raise (status_code={decision.status_code})")
        finally:
            uma_module.ConnectionManager = original

        rows.append({
            "scenario": name,
            "current_bool_api": (
                "raise KeycloakAuthenticationError（401 未被吞，但与 deny 语义仍不同）"
                if name == "HTTP 401 unauthorized"
                else "return False（HTTP 状态码被吞，无法与可信 deny 区分）"),
            "strict_adapted_decision": decision.as_dict(),
            "strict_observation": strict_observation,
        })
    return rows


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--json", dest="json_path", default=None,
                        help="将完整诊断结果写入指定 JSON 文件")
    args = parser.parse_args()

    print("=" * 96)
    print("python-keycloak permissions_check 故障压缩诊断（同步 vs 异步，实测结果）")
    print("=" * 96)

    drift = False
    report: dict[str, Any] = {
        "package": "python-keycloak (src/keycloak)",
        "requests_version": requests.__version__,
        "httpx_version": httpx.__version__,
        "exception_hierarchy": {
            "KeycloakAuthenticationError is KeycloakPostError subclass":
                issubclass(KeycloakAuthenticationError, KeycloakPostError),
            "KeycloakAuthenticationError is KeycloakError subclass":
                issubclass(KeycloakAuthenticationError, KeycloakError),
            "KeycloakConnectionError is KeycloakPostError subclass":
                issubclass(KeycloakConnectionError, KeycloakPostError),
        },
        "scenarios": [],
    }

    header = f"{'scenario':<42}{'sync actual':<46}{'async actual':<46}{'verdict'}"
    print(header)
    print("-" * 96)

    for name, behavior in scenarios().items():
        sync_obs, async_obs, sync_dec, async_dec = run_scenario(name, behavior)
        baseline = BASELINE[name]
        sync_match = (sync_obs.outcome, sync_obs.value, sync_obs.error_type,
                      sync_obs.status_code) == baseline
        async_match = (async_obs.outcome, async_obs.value, async_obs.error_type,
                       async_obs.status_code) == baseline
        verdict = "MATCH" if sync_match and async_match else "DRIFT"
        drift = drift or not (sync_match and async_match)

        print(f"{name:<42}{sync_obs.summary():<46}{async_obs.summary():<46}{verdict}")
        report["scenarios"].append({
            "scenario": name,
            "sync": _obs_dict(sync_obs, sync_dec),
            "async": _obs_dict(async_obs, async_dec),
            "baseline": {
                "outcome": baseline[0], "value": baseline[1],
                "error_type": baseline[2], "status_code": baseline[3],
            },
            "verdict": verdict,
        })

    print("-" * 96)
    print("\n[空权限集合短路检查]（传输替身被配置为必定超时）")
    empty = run_empty_permission_short_circuit()
    report["empty_permission_short_circuit"] = empty
    for path, data in empty.items():
        print(f"  {path:<6} {data['observation']:<30} post调用次数={data['transport_post_calls']}"
              f"  短路={data['short_circuited']}")

    print("\n[POST 之前的故障路径]")
    pre_post = run_pre_post_failures()
    report["pre_post_failures"] = pre_post
    for item in pre_post:
        print(f"  {item['scenario']:<34} sync={item['sync']:<40} async={item['async']}"
              f"  post调用次数={item['transport_post_calls']}")

    print("\n[三值适配层 PermissionChecker 分类结果]")
    for item in report["scenarios"]:
        print(f"  {item['scenario']:<42} -> {item['sync']['adapted_decision']}")

    print("\n[严格版接口对比：恢复被吞掉的 HTTP 状态码]")
    strict_rows = run_strict_comparison()
    report["strict_api_comparison"] = strict_rows
    for row in strict_rows:
        print(f"  {row['scenario']:<28} 现状: {row['current_bool_api']}")
        print(f"  {'':<28} 严格: {row['strict_observation']} "
              f"-> {row['strict_adapted_decision']['code']} "
              f"({row['strict_adapted_decision']['handling']})")

    if args.json_path:
        Path(args.json_path).write_text(json.dumps(report, ensure_ascii=False, indent=2),
                                        encoding="utf-8")
        print(f"\n完整 JSON 报告已写入: {args.json_path}")

    print("\n结论：DRIFT 表示库的实际行为与基线不同，需重新评估契约；"
          "所有 MATCH 仅代表复现了当前行为，不代表该行为合理。")
    return 1 if drift else 0


def _obs_dict(obs: Observation, decision: PermissionDecision) -> dict[str, Any]:
    return {
        "outcome": obs.outcome,
        "return_value": obs.value if obs.outcome == "return" else None,
        "error_type": obs.error_type,
        "status_code": obs.status_code,
        "transport_called": obs.transport_called,
        "well_known_fetched": obs.well_known_fetched,
        "adapted_decision": decision.as_dict(),
    }


if __name__ == "__main__":
    raise SystemExit(main())
