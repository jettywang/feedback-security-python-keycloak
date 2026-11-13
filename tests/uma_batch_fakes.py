#
# The MIT License (MIT)
#
# Copyright (C) 2017 Marcos Pereira <marcospereira.mpj@gmail.com>
#
# Permission is hereby granted, free of charge, to any person obtaining a copy of
# this software and associated documentation files (the "Software"), to deal in
# the Software without restriction, including without limitation the rights to
# use, copy, modify, merge, publish, distribute, sublicense, and/or sell copies of
# the Software, and to permit persons to whom the Software is furnished to do so,
# subject to the following conditions:
#
# The above copyright notice and this permission notice shall be included in all
# copies or substantial portions of the Software.
#
# THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
# IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY, FITNESS
# FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR
# COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER
# IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN
# CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.

"""In-memory Keycloak double used by the UMA batch tests and the demo script."""
# ruff: noqa: ANN101, ANN401, ARG002

from __future__ import annotations

import json
from dataclasses import dataclass, field
from typing import Any

_BASE = "https://keycloak.example/realms/demo/protocol/openid-connect"
WELL_KNOWN = {
    "permission_endpoint": f"{_BASE}/authz/permission",
    "token_endpoint": f"{_BASE}/token",
    "resource_registration_endpoint": (
        "https://keycloak.example/realms/demo/authz/resource-server/resource"
    ),
    "policy_endpoint": "https://keycloak.example/realms/demo/authz/resource-server/policy",
}

# Authorization policy of the fake server:
# resource -> (granted scopes, grant the whole resource without scopes?)
GRANT_POLICY: dict[str, tuple[set[str], bool]] = {
    "reporting-api": ({"read", "export"}, False),
    "billing-api": (set(), True),
}
# A resource the server may return that no caller ever requested.
UNREQUESTED_GRANT = {"rsid": "ghost-resource", "rsname": "ghost-resource", "scopes": ["read"]}


@dataclass
class FakeResponse:
    """Minimal response object understood by raise_error_from_response."""

    status_code: int
    payload: Any

    def json(self) -> Any:
        """
        Return the decoded payload.

        :returns: The JSON payload.
        :rtype: Any
        """
        return self.payload

    @property
    def content(self) -> bytes:
        """
        Return the raw response body.

        :returns: JSON encoded payload.
        :rtype: bytes
        """
        return json.dumps(self.payload).encode()


@dataclass
class FakeKeycloakServer:
    """
    Stateful in-memory double of the Keycloak UMA endpoints.

    Every HTTP call is recorded so tests can assert the real request count.
    """

    call_log: list[dict[str, Any]] = field(default_factory=list)
    ticket_payloads: dict[str, list[dict[str, Any]]] = field(default_factory=dict)
    status_code: int = 200
    omit_ticket: bool = False

    @property
    def request_count(self) -> int:
        """
        Count every HTTP call performed against the double.

        :returns: Total number of requests.
        :rtype: int
        """
        return len(self.call_log)

    @property
    def authorization_request_count(self) -> int:
        """
        Count authorization POST calls only (excluding well-known discovery).

        :returns: Number of POST calls hitting the permission/token endpoints.
        :rtype: int
        """
        return sum(
            1
            for call in self.call_log
            if call["method"] == "POST"
            and (
                call["path"] == WELL_KNOWN["permission_endpoint"]
                or call["path"].endswith("/protocol/openid-connect/token")
            )
        )

    def _record(self, method: str, path: str, payload: Any) -> str | None:
        self.call_log.append({"method": method, "path": path, "payload": payload})
        if method == "POST" and path == WELL_KNOWN["permission_endpoint"]:
            ticket = f"TICKET-{len(self.call_log)}"
            self.ticket_payloads[ticket] = json.loads(payload)
            return ticket
        return None

    def _grant_for_ticket(self, ticket_items: list[dict[str, Any]]) -> list[dict[str, Any]]:
        grants: list[dict[str, Any]] = []
        for item in ticket_items:
            resource = item["resource_id"]
            scopes, resource_level = GRANT_POLICY[resource]
            requested = set(item.get("resource_scopes", ()))
            if item.get("resource_scopes"):
                allowed = sorted(requested & scopes)
                if allowed:
                    grants.append({"rsid": resource, "rsname": resource, "scopes": allowed})
            elif resource_level:
                grants.append({"rsid": resource, "rsname": resource, "scopes": []})
        grants.append(dict(UNREQUESTED_GRANT))
        return grants

    def handle(self, method: str, path: str, data: Any) -> FakeResponse:
        """
        Dispatch one HTTP call to the matching fake endpoint.

        :param method: HTTP method.
        :type method: str
        :param path: Requested path/URL.
        :type path: str
        :param data: Request payload (JSON string or form dict).
        :type data: Any
        :returns: A fake response.
        :rtype: FakeResponse
        """
        ticket = self._record(method, path, data)

        if path.endswith("/uma2-configuration"):
            return FakeResponse(self.status_code, dict(WELL_KNOWN))

        if path == WELL_KNOWN["permission_endpoint"]:
            items = json.loads(data)
            grants = self._grant_for_ticket(items)
            body: dict[str, Any] = {"authorization_permissions": grants}
            if not self.omit_ticket:
                body["ticket"] = ticket
            return FakeResponse(self.status_code, body)

        if path.endswith("/protocol/openid-connect/token"):
            form = data if isinstance(data, dict) else {}
            if "ticket" in form:
                grants = self._grant_for_ticket(self.ticket_payloads[form["ticket"]])
                return FakeResponse(
                    self.status_code,
                    {"access_token": "fake-rpt", "authorization_permissions": grants},
                )

            # response_mode=permissions token call with permission strings.
            permissions = form.get("permission", [])
            grants = self._grants_from_permission_strings(permissions)
            return FakeResponse(self.status_code, grants)

        return FakeResponse(404, {"message": f"Unknown path {path}"})

    def _grants_from_permission_strings(self, permissions: list[str]) -> list[dict[str, Any]]:
        by_resource: dict[str, set[str]] = {}
        resource_level: set[str] = set()
        for permission in permissions:
            resource, sep, scope = permission.partition("#")
            if sep:
                by_resource.setdefault(resource, set()).add(scope)
            else:
                resource_level.add(resource)

        grants: list[dict[str, Any]] = []
        for resource, requested in by_resource.items():
            scopes, _ = GRANT_POLICY[resource]
            allowed = sorted(requested & scopes)
            if allowed:
                grants.append({"rsid": resource, "rsname": resource, "scopes": allowed})
        for resource in resource_level:
            _, whole_resource = GRANT_POLICY[resource]
            if whole_resource:
                grants.append({"rsid": resource, "rsname": resource, "scopes": []})
        grants.append(dict(UNREQUESTED_GRANT))
        return grants


class FakeConnection:
    """
    Connection double exposing the surface used by KeycloakUMA/KeycloakOpenID.

    Both the requests-style and httpx-style entry points delegate to the same
    in-memory server so sync and async code paths observe identical behavior.
    """

    def __init__(
        self,
        server: FakeKeycloakServer,
        realm_name: str = "demo",
        client_id: str = "demo-client",
        base_url: str = "https://keycloak.example",
    ) -> None:
        """
        Init method.

        :param server: In-memory server double.
        :type server: FakeKeycloakServer
        :param realm_name: Realm name.
        :type realm_name: str
        :param client_id: Client id.
        :type client_id: str
        :param base_url: Base URL.
        :type base_url: str
        """
        self.server = server
        self.realm_name = realm_name
        self.client_id = client_id
        self.base_url = base_url
        self.timeout = 60
        self.verify = True
        self.proxies = None
        self.cert = None
        self.max_retries = 1
        self.pool_maxsize = None
        self.headers: dict[str, str] = {}

    def add_param_headers(self, key: str, value: str) -> None:
        """
        Add a header.

        :param key: Header name.
        :type key: str
        :param value: Header value.
        :type value: str
        """
        self.headers[key] = value

    def del_param_headers(self, key: str) -> None:
        """
        Remove a header.

        :param key: Header name.
        :type key: str
        """
        self.headers.pop(key, None)

    def raw_get(self, path: str, **kwargs: Any) -> FakeResponse:
        """
        Fake synchronous GET.

        :param path: Request path.
        :type path: str
        :param kwargs: Ignored query parameters.
        :type kwargs: Any
        :returns: Fake response.
        :rtype: FakeResponse
        """
        return self.server.handle("GET", path, None)

    def raw_post(self, path: str, data: Any, **kwargs: Any) -> FakeResponse:
        """
        Fake synchronous POST.

        :param path: Request path.
        :type path: str
        :param data: Payload.
        :type data: Any
        :param kwargs: Ignored parameters.
        :type kwargs: Any
        :returns: Fake response.
        :rtype: FakeResponse
        """
        return self.server.handle("POST", path, data)

    async def a_raw_get(self, path: str, **kwargs: Any) -> FakeResponse:
        """
        Fake asynchronous GET.

        :param path: Request path.
        :type path: str
        :param kwargs: Ignored query parameters.
        :type kwargs: Any
        :returns: Fake response.
        :rtype: FakeResponse
        """
        return self.server.handle("GET", path, None)

    async def a_raw_post(self, path: str, data: Any, **kwargs: Any) -> FakeResponse:
        """
        Fake asynchronous POST.

        :param path: Request path.
        :type path: str
        :param data: Payload.
        :type data: Any
        :param kwargs: Ignored parameters.
        :type kwargs: Any
        :returns: Fake response.
        :rtype: FakeResponse
        """
        return self.server.handle("POST", path, data)
