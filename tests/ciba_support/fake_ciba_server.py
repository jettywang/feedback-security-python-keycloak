"""
In-process fake of the Keycloak CIBA endpoints.

The sandbox used by this project forbids binding local TCP ports, so the fake
identity provider is implemented as a :class:`requests.adapters.BaseAdapter`
mounted on the client session. Requests still flow through the real
``requests`` / :class:`~keycloak.connection.ConnectionManager` stack and return
genuine :class:`requests.Response` objects; only the network hop is replaced.

The fake models the two endpoints used by CIBA ping mode:

* ``POST .../ext/ciba/auth``  - backchannel authentication request;
* ``POST .../token``          - CIBA token exchange.

It never sends a notification itself. The test or demo calls
:meth:`FakeCibaServer.send_ping` to emulate the provider calling the client
notification endpoint, which keeps the credential and ordering fully
controllable.
"""

from __future__ import annotations

import json as json_lib
import threading
import uuid
from datetime import datetime, timezone
from typing import TYPE_CHECKING, Any
from urllib.parse import parse_qsl

from keycloak.keycloak_openid import KeycloakOpenID
from requests.adapters import BaseAdapter
from requests.models import PreparedRequest, Response

if TYPE_CHECKING:
    from keycloak.connection import ConnectionManager

CIBA_PATH = "/protocol/openid-connect/ext/ciba/auth"
TOKEN_PATH = "/protocol/openid-connect/token"  # noqa: S105


class FakeCibaServer(BaseAdapter):
    """
    Stateful, thread-safe fake Keycloak CIBA provider.

    :param realm_name: Realm served by the fake provider
    :type realm_name: str
    :param client_id: Client accepted by the fake provider
    :type client_id: str
    :param client_secret: Client secret required on every call
    :type client_secret: str
    :param notification_credential: Bearer credential used for ping callbacks
    :type notification_credential: str
    :param base_url: Base URL the adapter is mounted on
    :type base_url: str
    """

    def __init__(
        self,
        realm_name: str,
        client_id: str,
        client_secret: str = "demo-secret",  # noqa: S107
        notification_credential: str = "demo-ping-secret",
        base_url: str = "https://fake-keycloak.local/",
    ) -> None:
        """
        Initialise the fake provider and its pending request store.

        :param realm_name: Realm served by the fake provider
        :type realm_name: str
        :param client_id: Client accepted by the fake provider
        :type client_id: str
        :param client_secret: Client secret required on every call
        :type client_secret: str
        :param notification_credential: Bearer credential used for ping callbacks
        :type notification_credential: str
        :param base_url: Base URL the adapter is mounted on
        :type base_url: str
        """
        self.realm_name = realm_name
        self.client_id = client_id
        self.client_secret = client_secret
        self.notification_credential = notification_credential
        self.base_url = base_url
        self._lock = threading.Lock()
        self._requests: dict[str, dict[str, Any]] = {}
        self.token_exchanges: list[dict[str, Any]] = []
        self.backchannel_calls: list[dict[str, Any]] = []
        self.last_request: PreparedRequest | None = None

    def mount_on(self, connection: ConnectionManager) -> None:
        """
        Replace the HTTP transport of a connection with this fake.

        :param connection: Connection manager used by a KeycloakOpenID client
        :type connection: ConnectionManager
        """
        connection._s.mount(self.base_url, self)

    def build_client(self, **kwargs: Any) -> KeycloakOpenID:  # noqa: ANN401
        """
        Create a KeycloakOpenID client wired to this fake provider.

        :param kwargs: Extra KeycloakOpenID constructor arguments
        :type kwargs: dict
        :returns: Configured OpenID client
        :rtype: KeycloakOpenID
        """
        client = KeycloakOpenID(
            server_url=self.base_url,
            realm_name=self.realm_name,
            client_id=self.client_id,
            client_secret_key=self.client_secret,
            **kwargs,
        )
        self.mount_on(client.connection)
        return client

    def _response(
        self,
        status_code: int,
        payload: dict[str, Any] | list[Any] | str,
        request: PreparedRequest,
    ) -> Response:
        response = Response()
        response.status_code = status_code
        if isinstance(payload, (dict, list)):
            body = json_lib.dumps(payload).encode("utf-8")
            response.headers["Content-Type"] = "application/json"
        else:
            body = str(payload).encode("utf-8")
        response._content = body
        response.request = request
        response.url = request.url
        response.headers["Date"] = datetime.now(tz=timezone.utc).isoformat()
        response.encoding = "utf-8"
        return response

    @staticmethod
    def _form_data(request: PreparedRequest) -> dict[str, str]:
        if isinstance(request.body, bytes):
            body = request.body.decode("utf-8")
        else:
            body = request.body or ""
        return dict(parse_qsl(body, keep_blank_values=True))

    def send(  # type: ignore[override]
        self,
        request: PreparedRequest,
        stream: bool = False,  # noqa: ARG002
        timeout: float | tuple[float, float] | None = None,  # noqa: ARG002
        verify: bool | str = True,  # noqa: ARG002
        cert: bytes | str | tuple | None = None,  # noqa: ARG002
        proxies: dict | None = None,  # noqa: ARG002
    ) -> Response:
        """
        Dispatch a fake request to the CIBA backchannel or token endpoint.

        :param request: Outgoing prepared request
        :type request: PreparedRequest
        :param stream: Ignored stream flag from requests
        :type stream: bool
        :param timeout: Ignored timeout from requests
        :type timeout: float
        :param verify: Ignored verify flag from requests
        :type verify: bool
        :param cert: Ignored cert from requests
        :type cert: bytes
        :param proxies: Ignored proxies from requests
        :type proxies: dict
        :returns: A fabricated response
        :rtype: Response
        """
        path = request.path_url.split("?")[0]
        self.last_request = request
        with self._lock:
            if path.endswith(CIBA_PATH):
                return self._handle_backchannel(request)
            if path.endswith(TOKEN_PATH):
                return self._handle_token(request)
        return self._response(404, {"message": f"Unknown path '{path}'"}, request)

    def close(self) -> None:
        """No resources to release; present for the BaseAdapter contract."""

    def _handle_backchannel(self, request: PreparedRequest) -> Response:
        data = self._form_data(request)
        self.backchannel_calls.append(dict(data))
        if data.get("client_id") != self.client_id:
            return self._response(400, {"error": "unauthorized_client"}, request)
        if data.get("client_secret") != self.client_secret:
            return self._response(401, {"error": "invalid_client"}, request)
        if not any(data.get(hint) for hint in ("login_hint", "login_hint_token", "id_token_hint")):
            return self._response(400, {"error": "invalid_request"}, request)

        auth_req_id = str(uuid.uuid4())
        self._requests[auth_req_id] = {
            "status": "pending",
            "data": data,
            "error": None,
            "exchanged": False,
            "delay_exchanges": 0,
        }
        return self._response(
            200,
            {
                "auth_req_id": auth_req_id,
                "expires_in": int(data.get("requested_expiry", 120)),
                "interval": 2,
            },
            request,
        )

    def _handle_token(self, request: PreparedRequest) -> Response:
        data = self._form_data(request)
        self.token_exchanges.append(dict(data))
        auth_req_id = data.get("auth_req_id", "")
        record = self._requests.get(auth_req_id)
        if record is None:
            return self._response(400, {"error": "invalid_grant"}, request)

        if record["delay_exchanges"] > 0:
            record["delay_exchanges"] -= 1
            return self._response(400, {"error": "authorization_pending"}, request)

        status = record["status"]
        if status == "pending":
            return self._response(400, {"error": "authorization_pending"}, request)
        if status == "denied":
            record["exchanged"] = True
            return self._response(400, {"error": "access_denied"}, request)
        if status == "expired":
            record["exchanged"] = True
            return self._response(400, {"error": "expired_token"}, request)

        record["exchanged"] = True
        return self._response(
            200,
            {
                "access_token": f"access-{auth_req_id}",
                "refresh_token": f"refresh-{auth_req_id}",
                "token_type": "Bearer",
                "expires_in": 300,
                "scope": record["data"].get("scope", "openid"),
            },
            request,
        )

    # -- provider-side controls used by tests and the demo -----------------

    def send_ping(self, auth_req_id: str) -> dict[str, str]:
        """
        Emulate the provider calling the client notification endpoint.

        :param auth_req_id: Request to send the ping for
        :type auth_req_id: str
        :returns: Notification body that the client endpoint would receive
        :rtype: dict[str, str]
        """
        return {
            "auth_req_id": auth_req_id,
            "credential": self.notification_credential,
        }

    def set_outcome(
        self,
        auth_req_id: str,
        status: str,
        *,
        delay_exchanges: int = 0,
    ) -> None:
        """
        Set the user's decision for a pending backchannel request.

        :param auth_req_id: Request to update
        :type auth_req_id: str
        :param status: One of pending, approved, denied, expired
        :type status: str
        :param delay_exchanges: Number of token polls that must still answer
            ``authorization_pending``
        :type delay_exchanges: int
        """
        with self._lock:
            record = self._requests[auth_req_id]
            record["status"] = status
            record["delay_exchanges"] = delay_exchanges

    def pending_requests(self) -> list[str]:
        """
        List the auth_req_id values known to the fake provider.

        :returns: Known authentication request ids
        :rtype: list[str]
        """
        with self._lock:
            return list(self._requests)
