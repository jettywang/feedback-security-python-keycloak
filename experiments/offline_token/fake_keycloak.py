"""A minimal, scriptable Keycloak-compatible OIDC provider.

It implements only the endpoints that python-keycloak's token / refresh /
logout / introspect / certs / userinfo paths call.  All state lives in a
FakeRealm so tests can deterministically reproduce revoke, logout and
admin-disable scenarios without running a real Keycloak server.

This is a *model* of Keycloak's documented behaviour, not Keycloak itself:
the goal is to make the observation window of each token validation strategy
measurable and reproducible.
"""

from __future__ import annotations

import json
import time
from typing import Any

from jwcrypto import jwk, jwt

REALM = "demo"
CLIENT_ID = "job-client"
CLIENT_SECRET = "job-secret"
ISSUER = f"http://fake-keycloak/realms/{REALM}"


def _b64_thumbprint(key: jwk.JWK) -> str:
    return key.thumbprint().decode() if isinstance(key.thumbprint(), bytes) else key.thumbprint()


class FakeRealm:
    """In-memory state machine modelling online/offline sessions and tokens."""

    def __init__(
        self,
        access_lifetime: int = 60,
        online_refresh_lifetime: int = 300,
        offline_refresh_lifetime: int = 3600,
        clock: "Clock | None" = None,
    ) -> None:
        self.signing_key = jwk.JWK.generate(kty="RSA", size=2048)
        self.kid = _b64_thumbprint(self.signing_key)
        self.access_lifetime = access_lifetime
        self.online_refresh_lifetime = online_refresh_lifetime
        self.offline_refresh_lifetime = offline_refresh_lifetime
        self.clock = clock or SystemClock()

        # username -> enabled
        self.users: dict[str, bool] = {"alice": True}
        # session_id -> session record
        self.sessions: dict[str, dict[str, Any]] = {}
        # every issued access/refresh token jti -> revocation record
        self.issued: dict[str, dict[str, Any]] = {}
        # refresh-token jti already rotated (reuse detection)
        self.rotated_refresh: set[str] = set()
        # token jti explicitly revoked (admin revoke / logout)
        self.revoked: set[str] = set()
        self.event_log: list[dict[str, Any]] = []
        self._seq = 0

    # ------------------------------------------------------------------ utils
    def _now(self) -> int:
        return int(self.clock.time())

    def _next_id(self) -> str:
        self._seq += 1
        return f"id-{self._seq}"

    def public_jwks(self) -> dict[str, Any]:
        jwk_dict = self.signing_key.export_public(as_dict=True)
        jwk_dict["kid"] = self.kid
        jwk_dict["alg"] = "RS256"
        jwk_dict["use"] = "sig"
        return {"keys": [jwk_dict]}

    def _sign(self, claims: dict[str, Any]) -> str:
        header = {"alg": "RS256", "kid": self.kid, "typ": "JWT"}
        token = jwt.JWT(header=header, claims=claims)
        token.make_signed_token(self.signing_key)
        return token.serialize()

    def _mint_access_token(self, session: dict[str, Any]) -> str:
        now = self._now()
        jti = self._next_id()
        claims = {
            "iss": ISSUER,
            "sub": session["user"],
            "aud": ["account", CLIENT_ID],
            "iat": now,
            "nbf": 0,
            "exp": now + self.access_lifetime,
            "jti": jti,
            "typ": "Bearer",
            "azp": CLIENT_ID,
            "sid": session["id"],
            "scope": session["scope"],
        }
        token = self._sign(claims)
        self.issued[jti] = {
            "kind": "access",
            "session": session["id"],
            "user": session["user"],
            "exp": claims["exp"],
            "token": token,
        }
        return token

    def _mint_refresh_token(self, session: dict[str, Any]) -> str:
        now = self._now()
        jti = self._next_id()
        lifetime = (
            self.offline_refresh_lifetime
            if session["offline"]
            else self.online_refresh_lifetime
        )
        claims = {
            "iss": ISSUER,
            "sub": session["user"],
            "aud": [CLIENT_ID],
            "iat": now,
            "nbf": 0,
            "exp": now + lifetime,
            "jti": jti,
            "typ": "RefreshToken",
            "azp": CLIENT_ID,
            "sid": session["id"],
            "scope": session["scope"],
            "offline_access": session["offline"],
        }
        token = self._sign(claims)
        self.issued[jti] = {
            "kind": "refresh",
            "session": session["id"],
            "user": session["user"],
            "exp": claims["exp"],
            "token": token,
            "offline": session["offline"],
        }
        return token

    def _token_response(self, session: dict[str, Any]) -> dict[str, Any]:
        now = self._now()
        access = self._mint_access_token(session)
        refresh = self._mint_refresh_token(session)
        session["last_seen"] = now
        return {
            "access_token": access,
            "refresh_token": refresh,
            "token_type": "Bearer",
            "expires_in": self.access_lifetime,
            "refresh_expires_in": (
                self.offline_refresh_lifetime
                if session["offline"]
                else self.online_refresh_lifetime
            ),
            "scope": session["scope"],
            "not-before-policy": 0,
            "session_state": session["id"],
        }

    # ------------------------------------------------------------- public API
    def issue(self, username: str, scope: str) -> dict[str, Any]:
        if not self.users.get(username):
            raise TokenEndpointError(401, "invalid_grant", "Account disabled or not found")
        offline = "offline_access" in scope.split()
        session_id = self._next_id()
        session = {
            "id": session_id,
            "user": username,
            "offline": offline,
            "scope": scope,
            "created": self._now(),
            "last_seen": self._now(),
            "logged_out": False,
        }
        self.sessions[session_id] = session
        self.event_log.append({"event": "issue", "session": session_id, "offline": offline})
        return self._token_response(session)

    def refresh(self, refresh_token: str) -> dict[str, Any]:
        claims = self._decode_unverified(refresh_token)
        jti, sid, user = claims["jti"], claims["sid"], claims["sub"]
        now = self._now()

        if jti in self.rotated_refresh:
            # Refresh-token reuse / revocation: Keycloak revokes the whole session.
            self._revoke_session(sid, reason="reused-refresh-token")
            raise TokenEndpointError(400, "invalid_grant", "Session not active")
        if jti in self.revoked or claims["exp"] <= now:
            raise TokenEndpointError(400, "invalid_grant", "Refresh token expired")
        session = self.sessions.get(sid)
        if session is None or session["logged_out"]:
            raise TokenEndpointError(400, "invalid_grant", "Session not active")
        if not self.users.get(user, False):
            raise TokenEndpointError(400, "invalid_grant", "User is disabled")

        # Rotation: old refresh token becomes unusable, a new one is issued.
        self.rotated_refresh.add(jti)
        self.event_log.append({"event": "refresh", "session": sid, "rotated": jti})
        return self._token_response(session)

    def logout(self, refresh_token: str) -> None:
        claims = self._decode_unverified(refresh_token)
        sid, jti = claims["sid"], claims["jti"]
        self._revoke_session(sid, reason="logout")
        self.revoked.add(jti)
        self.event_log.append({"event": "logout", "session": sid})

    def introspect(self, token: str) -> dict[str, Any]:
        try:
            claims = self._decode_verified(token)
        except Exception:
            return {"active": False}
        now = self._now()
        jti, sid, user = claims["jti"], claims["sid"], claims["sub"]
        active = (
            claims["exp"] > now
            and jti not in self.revoked
            and (session := self.sessions.get(sid)) is not None
            and not session["logged_out"]
            and self.users.get(user, False)
        )
        if not active:
            return {"active": False}
        return {
            "active": True,
            "sub": user,
            "client_id": CLIENT_ID,
            "username": user,
            "scope": claims.get("scope"),
            "iss": ISSUER,
            "jti": jti,
            "sid": sid,
            "exp": claims["exp"],
            "iat": claims["iat"],
            "token_type": "Bearer",
        }

    def userinfo(self, token: str) -> dict[str, Any]:
        info = self.introspect(token)
        if not info["active"]:
            raise TokenEndpointError(401, "invalid_token", "Token is not active")
        return {"sub": info["sub"], "preferred_username": info["username"]}

    # ------------------------------------------------- orchestration / control
    def admin_disable_user(self, username: str) -> None:
        self.users[username] = False
        # Disabling a user invalidates their sessions on the server side.
        for sid, session in self.sessions.items():
            if session["user"] == username:
                session["logged_out"] = True
        self.event_log.append({"event": "admin_disable", "user": username})

    def revoke_session(self, sid: str) -> None:
        self._revoke_session(sid, reason="admin-revoke")

    def list_sessions(self, user: str) -> list[str]:
        return [sid for sid, s in self.sessions.items() if s["user"] == user]

    def _revoke_session(self, sid: str, reason: str) -> None:
        session = self.sessions.get(sid)
        if session:
            session["logged_out"] = True
        for jti, record in self.issued.items():
            if record["session"] == sid:
                self.revoked.add(jti)
        self.event_log.append({"event": "revoke", "session": sid, "reason": reason})

    # ------------------------------------------------------------- jwt helpers
    def _decode_unverified(self, token: str) -> dict[str, Any]:
        # The provider signed this token itself; read claims without re-verifying.
        import base64

        segment = token.split(".")[1]
        padded = segment + "=" * (-len(segment) % 4)
        return json.loads(base64.urlsafe_b64decode(padded))

    def _decode_verified(self, token: str) -> dict[str, Any]:
        key = jwk.JWK(**self.public_jwks()["keys"][0])
        verified = jwt.JWT(jwt=token)
        verified.leeway = 0
        verified.validate(key)
        return json.loads(verified.claims)


class Clock:
    def time(self) -> float:  # pragma: no cover - interface
        raise NotImplementedError


class SystemClock(Clock):
    def time(self) -> float:
        return time.time()


class ManualClock(Clock):
    """Deterministic clock shared by realm and freezegun-style tests."""

    def __init__(self, start: float) -> None:
        self.offset = start

    def advance(self, seconds: int) -> None:
        self.offset += seconds

    def time(self) -> float:
        return self.offset


class TokenEndpointError(Exception):
    def __init__(self, status: int, error: str, description: str) -> None:
        super().__init__(description)
        self.status = status
        self.body = {"error": error, "error_description": description}
