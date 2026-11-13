"""In-process HTTP transport for the fake Keycloak provider.

Mounting this adapter on the SDK's requests.Session routes every call through
the same request/response/error code path as a real network call, without
binding a TCP port (which the sandbox forbids).  It also records every request
so observation windows and server round-trips are measurable.
"""

from __future__ import annotations

import io
import urllib.parse
from typing import Any

import requests
from requests.adapters import BaseAdapter
from requests.models import PreparedRequest, Response

from fake_keycloak import REALM, TokenEndpointError


class FakeKeycloakTransport(BaseAdapter):
    def __init__(self, realm: "FakeRealm", host: str = "fake-keycloak.test") -> None:
        super().__init__()
        self.realm = realm
        self.host = host
        self.prefix = f"http://{host}/realms/{REALM}"
        self.requests: list[dict[str, Any]] = []
        self._fallback: BaseAdapter | None = None

    # ---------------------------------------------------------------- routing
    def send(self, request: PreparedRequest, timeout=None, **kwargs: Any) -> Response:
        parsed = urllib.parse.urlparse(request.url)
        if parsed.netloc != self.host:
            # Let any non-faked request fall through to the default adapter.
            return self._fallback.send(request, timeout=timeout, **kwargs)
        path = parsed.path
        form = self._form(request)
        self.requests.append({"method": request.method, "path": path, "form_keys": sorted(form)})

        try:
            status, payload = self._route(request.method, path, form, request.headers)
        except TokenEndpointError as exc:
            status, payload = exc.status, exc.body

        return self._build_response(status, payload, request.url)

    def _route(self, method: str, path: str, form: dict[str, str], headers) -> tuple[int, Any]:
        if method == "GET":
            if path.endswith("/.well-known/openid-configuration"):
                base = self.prefix
                return 200, {
                    "issuer": base,
                    "jwks_uri": f"{base}/protocol/openid-connect/certs",
                    "token_endpoint": f"{base}/protocol/openid-connect/token",
                    "introspection_endpoint": f"{base}/protocol/openid-connect/token/introspect",
                    "userinfo_endpoint": f"{base}/protocol/openid-connect/userinfo",
                    "end_session_endpoint": f"{base}/protocol/openid-connect/logout",
                }
            if path.endswith("/protocol/openid-connect/certs"):
                return 200, self.realm.public_jwks()
            if path.endswith("/protocol/openid-connect/userinfo"):
                token = self._bearer(headers)
                if token is None:
                    raise TokenEndpointError(401, "invalid_token", "missing bearer")
                return 200, self.realm.userinfo(token)
            return 404, {"error": "not found"}

        if method == "POST":
            if path.endswith("/protocol/openid-connect/token"):
                grant = form.get("grant_type")
                if grant == "password":
                    return 200, self.realm.issue(form["username"], form.get("scope", "openid"))
                if grant == "refresh_token":
                    return 200, self.realm.refresh(form["refresh_token"])
                raise TokenEndpointError(400, "unsupported_grant_type", str(grant))
            if path.endswith("/protocol/openid-connect/logout"):
                self.realm.logout(form["refresh_token"])
                return 204, {}
            if path.endswith("/token/introspect"):
                return 200, self.realm.introspect(form["token"])
            return 404, {"error": "not found"}

        return 405, {"error": "method not allowed"}

    # ----------------------------------------------------------------- helpers
    @staticmethod
    def _form(request: PreparedRequest) -> dict[str, str]:
        body = request.body
        if body is None:
            return {}
        if isinstance(body, bytes):
            body = body.decode("utf-8")
        return {k: v[0] for k, v in urllib.parse.parse_qs(body).items()}

    @staticmethod
    def _bearer(headers) -> str | None:
        header = headers.get("Authorization", "")
        return header[len("Bearer "):] if header.startswith("Bearer ") else None

    @staticmethod
    def _build_response(status: int, payload: Any, url: str) -> Response:
        import json

        response = Response()
        response.status_code = status
        if status == 204:
            response.raw = io.BytesIO(b"")
            response.headers["Content-Type"] = "application/json"
        else:
            body = json.dumps(payload).encode("utf-8")
            response.raw = io.BytesIO(body)
            response.headers["Content-Type"] = "application/json"
            response.headers["Content-Length"] = str(len(body))
        response.url = url
        response.encoding = "utf-8"
        return response

    def close(self) -> None:
        return None


def mount(session: requests.Session, transport: FakeKeycloakTransport) -> FakeKeycloakTransport:
    # requests picks adapters by the longest scheme/host prefix, so mount on the
    # scheme and keep a fallback for any non-faked host.
    transport._fallback = session.get_adapter(f"http://{transport.host}/")
    session.mount("http://", transport)
    return transport
