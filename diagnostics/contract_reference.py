"""
permissions_check 建议接口契约的参考实现（适配层，不修改 python-keycloak 源码）。

核心问题：库的布尔接口把多种语义不同的失败折叠成 ``False``：
- 授权服务器明确拒绝（可信 deny）；
- 403/429/500 等 HTTP 错误（被 ``except KeycloakPostError: return False`` 吞掉）；
- 响应缺 ``result`` 字段（``dict.get("result", False)`` 的默认值）。
而 401、传输超时、坏 JSON 又以异常形式冒出，调用方同样无法只凭布尔值区分。

本适配层把结果显式拆成三类决策，调用方据此决定“拒绝页面 / 重试 / 告警”，
同时保留与旧布尔接口完全兼容的降级方式。
"""

from __future__ import annotations

from dataclasses import dataclass
from enum import Enum
from typing import TYPE_CHECKING, Any

from keycloak.exceptions import (
    KeycloakAuthenticationError,
    KeycloakConnectionError,
    KeycloakError,
)

if TYPE_CHECKING:
    from keycloak.uma_permissions import UMAPermission

    from diagnose_permissions_check import Observation


class DecisionCode(str, Enum):
    """授权决策的三值分类。"""

    ALLOW = "allow"              # 授权服务器明确允许（result=true）
    DENY = "deny"                # 授权服务器明确拒绝（可信 result=false / 403）
    RETRYABLE = "retryable"      # 身份服务暂不可用：超时、429、5xx、连接故障
    AUTHN_ERROR = "authn_error"  # 401：令牌无效/过期，需重新登录而非当成无权限
    INDETERMINATE = "indeterminate"  # 响应畸形/协议违规，无法判定，需告警


# 各决策对应的处置策略
HANDLING = {
    DecisionCode.ALLOW: "放行",
    DecisionCode.DENY: "进入拒绝页面（403 视为授权服务器的明确否定裁决）",
    DecisionCode.RETRYABLE: "有限次退避重试；持续失败则告警并按 fail-closed 处理",
    DecisionCode.AUTHN_ERROR: "触发重新认证（刷新令牌/重新登录），不要展示无权限",
    DecisionCode.INDETERMINATE: "告警并保留原始响应；默认 fail-closed，禁止当成 deny 静默",
}

# 建议重试的 HTTP 状态码
RETRYABLE_STATUS = {425, 429, 500, 502, 503, 504}


@dataclass(frozen=True)
class PermissionDecision:
    """结构化授权决策，携带足够的可观测信息。"""

    code: DecisionCode
    status_code: int | None = None
    detail: str = ""
    raw_error: str | None = None

    @property
    def allowed(self) -> bool:
        """与旧布尔接口兼容：只有明确 ALLOW 才为 True。"""
        return self.code is DecisionCode.ALLOW

    def as_dict(self) -> dict[str, Any]:
        return {
            "code": self.code.value,
            "handling": HANDLING[self.code],
            "status_code": self.status_code,
            "detail": self.detail,
        }


class PermissionChecker:
    """对 ``KeycloakUMA.permissions_check`` / ``a_permissions_check`` 的安全封装。"""

    def check(self, uma: Any, token: str, permissions: "Iterable[UMAPermission]",
              **extra_payload: Any) -> PermissionDecision:
        """同步封装：把库的布尔/异常结果翻译成三值决策。"""
        try:
            allowed = uma.permissions_check(token, permissions, **extra_payload)
        except KeycloakAuthenticationError as exc:
            return PermissionDecision(
                DecisionCode.AUTHN_ERROR, exc.response_code,
                "令牌未被授权服务器接受（401）", type(exc).__name__)
        except KeycloakConnectionError as exc:
            # requests/httpx 的超时、连接拒绝都被连接层包成此异常
            return PermissionDecision(
                DecisionCode.RETRYABLE, getattr(exc, "response_code", None),
                "传输层故障（超时/连接拒绝/DNS 等），可重试", type(exc).__name__)
        except KeycloakError as exc:
            code = exc.response_code
            if code in RETRYABLE_STATUS:
                return PermissionDecision(
                    DecisionCode.RETRYABLE, code,
                    f"授权服务器临时错误 HTTP {code}", type(exc).__name__)
            if code == 403:
                return PermissionDecision(
                    DecisionCode.DENY, code, "授权服务器明确拒绝（403）",
                    type(exc).__name__)
            return PermissionDecision(
                DecisionCode.INDETERMINATE, code,
                f"未分类的 Keycloak 错误 HTTP {code}", type(exc).__name__)
        except TypeError as exc:
            # 库对 200 + 坏 JSON / 非对象响应抛 TypeError
            return PermissionDecision(
                DecisionCode.INDETERMINATE, None,
                f"响应体无法解析为授权决策对象: {exc}", type(exc).__name__)

        return PermissionDecision(
            DecisionCode.ALLOW if allowed else DecisionCode.DENY,
            200, "授权服务器在 HTTP 200 中给出 result 裁决")

    async def a_check(self, uma: Any, token: str,
                      permissions: "Iterable[UMAPermission]",
                      **extra_payload: Any) -> PermissionDecision:
        """异步封装，分类规则与同步完全一致。"""
        try:
            allowed = await uma.a_permissions_check(token, permissions, **extra_payload)
        except KeycloakAuthenticationError as exc:
            return PermissionDecision(
                DecisionCode.AUTHN_ERROR, exc.response_code,
                "令牌未被授权服务器接受（401）", type(exc).__name__)
        except KeycloakConnectionError as exc:
            return PermissionDecision(
                DecisionCode.RETRYABLE, getattr(exc, "response_code", None),
                "传输层故障（超时/连接拒绝/DNS 等），可重试", type(exc).__name__)
        except KeycloakError as exc:
            code = exc.response_code
            if code in RETRYABLE_STATUS:
                return PermissionDecision(
                    DecisionCode.RETRYABLE, code,
                    f"授权服务器临时错误 HTTP {code}", type(exc).__name__)
            if code == 403:
                return PermissionDecision(
                    DecisionCode.DENY, code, "授权服务器明确拒绝（403）",
                    type(exc).__name__)
            return PermissionDecision(
                DecisionCode.INDETERMINATE, code,
                f"未分类的 Keycloak 错误 HTTP {code}", type(exc).__name__)
        except TypeError as exc:
            return PermissionDecision(
                DecisionCode.INDETERMINATE, None,
                f"响应体无法解析为授权决策对象: {exc}", type(exc).__name__)

        return PermissionDecision(
            DecisionCode.ALLOW if allowed else DecisionCode.DENY,
            200, "授权服务器在 HTTP 200 中给出 result 裁决")

    def check_strict(self, raising_uma: Any, token: str,
                     permissions: "Iterable[UMAPermission]",
                     **extra_payload: Any) -> PermissionDecision:
        """
        面向建议的“严格版”库接口：该接口不再吞掉 KeycloakPostError，
        让 403/429/5xx 的真实状态码透出，适配层据此做状态感知分类。

        ``raising_uma`` 可以是升级后提供 ``permissions_check_strict`` 的库对象，
        也可以是临时 monkeypatch、去掉 ``except KeycloakPostError`` 的等价实现。
        """
        try:
            allowed = raising_uma.permissions_check_strict(
                token, permissions, **extra_payload)
        except TypeError as exc:
            return PermissionDecision(
                DecisionCode.INDETERMINATE, None,
                f"响应体无法解析为授权决策对象: {exc}", type(exc).__name__)
        except KeycloakAuthenticationError as exc:
            return PermissionDecision(
                DecisionCode.AUTHN_ERROR, exc.response_code,
                "令牌未被授权服务器接受（401）", type(exc).__name__)
        except KeycloakConnectionError as exc:
            return PermissionDecision(
                DecisionCode.RETRYABLE, getattr(exc, "response_code", None),
                "传输层故障（超时/连接拒绝/DNS 等），可重试", type(exc).__name__)
        except KeycloakError as exc:
            code = exc.response_code
            if code in RETRYABLE_STATUS:
                return PermissionDecision(
                    DecisionCode.RETRYABLE, code,
                    f"授权服务器临时错误 HTTP {code}", type(exc).__name__)
            if code == 403:
                return PermissionDecision(
                    DecisionCode.DENY, code, "授权服务器明确拒绝（403）",
                    type(exc).__name__)
            return PermissionDecision(
                DecisionCode.INDETERMINATE, code,
                f"未分类的 Keycloak 错误 HTTP {code}", type(exc).__name__)

        return PermissionDecision(
            DecisionCode.ALLOW if allowed else DecisionCode.DENY,
            200, "授权服务器在 HTTP 200 中给出 result 裁决")

    # ---- 仅供诊断脚本使用：直接对 Observation 分类 ----
    def classify_observation(self, obs: "Observation") -> PermissionDecision:
        if obs.outcome == "return":
            if obs.value is True:
                return PermissionDecision(DecisionCode.ALLOW, 200,
                                          "result=true（明确允许）")
            return PermissionDecision(DecisionCode.DENY, 200,
                                      "库返回 False；注意可能是被压缩的错误")
        if obs.error_type == "KeycloakAuthenticationError":
            return PermissionDecision(DecisionCode.AUTHN_ERROR, obs.status_code,
                                      "401 需重新认证")
        if obs.error_type == "KeycloakConnectionError":
            return PermissionDecision(DecisionCode.RETRYABLE, obs.status_code,
                                      "传输/超时故障，可重试")
        if obs.error_type == "TypeError":
            return PermissionDecision(
                DecisionCode.INDETERMINATE, obs.status_code,
                "200 响应不是合法决策对象，协议违规需告警")
        return PermissionDecision(
            DecisionCode.INDETERMINATE, obs.status_code,
            f"未预期异常 {obs.error_type}，需告警")
