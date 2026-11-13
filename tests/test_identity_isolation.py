"""Tests for identity and header isolation between interleaved requests."""

from __future__ import annotations

import asyncio
import json
from typing import Any
from urllib.parse import parse_qs

import httpx
import pytest
import requests
from keycloak import KeycloakAdmin, KeycloakOpenID
from keycloak.connection import ConnectionManager
from keycloak.exceptions import KeycloakConnectionError

RPT_TOKEN_TYPE = "requesting_party_token"
CLIENT_AUTH = "Bearer client-credential"


class AsyncBarrier:
    """Barrier releasing all waiting coroutines once enough have arrived."""

    def __init__(self, parties: int) -> None:
        """
        Init method.

        :param parties: Number of coroutines that must arrive.
        :type parties: int
        """
        self._parties = parties
        self._arrived = 0
        self._event = asyncio.Event()

    async def wait(self) -> None:
        """Wait until every party has reached the barrier."""
        self._arrived += 1
        if self._arrived >= self._parties:
            self._event.set()
        await self._event.wait()


class RecordingAsyncTransport(httpx.AsyncBaseTransport):
    """Transport recording each request's headers/body and simulating failures."""

    def __init__(self, barrier: AsyncBarrier | None = None) -> None:
        """
        Init method.

        :param barrier: Optional barrier every request waits at.
        :type barrier: AsyncBarrier | None
        """
        self.requests: list[dict[str, Any]] = []
        self.barrier = barrier
        self.fail_tokens: set[str] = set()
        self.block = False
        self.entered = asyncio.Event()
        self.release = asyncio.Event()
        self.release.set()

    async def handle_async_request(self, request: httpx.Request) -> httpx.Response:
        """Record the request, synchronise at the barrier, then respond."""
        headers = dict(request.headers)
        body = request.content.decode() if request.content else ""
        self.requests.append(
            {"method": request.method, "url": str(request.url), "headers": headers, "body": body}
        )
        self.entered.set()
        if self.block:
            await self.release.wait()
        if self.barrier is not None:
            await self.barrier.wait()

        token = parse_qs(body).get("token", [""])[0]
        if token in self.fail_tokens:
            msg = f"transport failure for {token}"
            raise httpx.ConnectError(msg)

        bearer = headers.get("authorization")
        if "introspect" in request.url.path:
            return httpx.Response(200, json={"active": True, "identity": bearer})
        return httpx.Response(200, json={"issuer": "http://test.test", "identity": bearer})


class RecordingSession:
    """requests.Session double recording headers and payloads per request."""

    def __init__(self) -> None:
        """Init method."""
        self.requests: list[dict[str, Any]] = []
        self.fail = False

    def close(self) -> None:
        """Match requests.Session's interface used by ConnectionManager.__del__."""

    def _respond(
        self,
        method: str,
        url: str,
        headers: dict | None,
        data: Any = None,  # noqa: ANN401
    ) -> requests.Response:
        self.requests.append(
            {"method": method, "url": url, "headers": dict(headers or {}), "data": data}
        )
        if self.fail:
            msg = "transport failure"
            raise requests.exceptions.ConnectionError(msg)
        response = requests.Response()
        response.status_code = 200
        response.headers["Content-Type"] = "application/json"
        bearer = (headers or {}).get("Authorization")
        response._content = json.dumps({"active": True, "identity": bearer}).encode()
        return response

    def get(self, url: str, **kwargs: Any) -> requests.Response:  # noqa: ANN401
        """Record a GET request."""
        return self._respond("GET", url, kwargs.get("headers"))

    def post(self, url: str, **kwargs: Any) -> requests.Response:  # noqa: ANN401
        """Record a POST request."""
        return self._respond("POST", url, kwargs.get("headers"), kwargs.get("data"))

    def put(self, url: str, **kwargs: Any) -> requests.Response:  # noqa: ANN401
        """Record a PUT request."""
        return self._respond("PUT", url, kwargs.get("headers"), kwargs.get("data"))

    def delete(self, url: str, **kwargs: Any) -> requests.Response:  # noqa: ANN401
        """Record a DELETE request."""
        return self._respond("DELETE", url, kwargs.get("headers"), kwargs.get("data"))


def make_oid(custom_headers: dict | None = None) -> KeycloakOpenID:
    """Create a KeycloakOpenID client without performing any network calls."""
    return KeycloakOpenID(
        server_url="http://test.test",
        realm_name="test-realm",
        client_id="test-client",
        custom_headers=custom_headers,
    )


def install_async_transport(
    oid: KeycloakOpenID,
    transport: RecordingAsyncTransport,
) -> httpx.AsyncClient:
    """Replace the client's async transport with the recording one."""
    client = httpx.AsyncClient(transport=transport)
    oid.connection.async_s = client  # type: ignore[assignment]
    return client


def rpt_introspect(oid: KeycloakOpenID, access: str, rpt: str) -> dict[str, Any]:
    """Await an async RPT introspection for the given access token."""
    return oid.a_introspect(token=access, rpt=rpt, token_type_hint=RPT_TOKEN_TYPE)


def parsed(record: dict[str, Any]) -> dict[str, list[str]]:
    """Parse the recorded form body of a request."""
    return parse_qs(record["body"])


def header_values(record: dict[str, Any], name: str) -> list[str]:
    """Return all header values whose name matches case-insensitively."""
    return [v for k, v in record["headers"].items() if k.lower() == name.lower()]


@pytest.mark.asyncio
async def test_interleaved_identities_keep_their_own_headers() -> None:
    """Two users' RPT introspections, a plain introspection and a raw request interleave."""
    oid = make_oid({"Authorization": CLIENT_AUTH, "X-Custom": "shared"})
    connection = oid.connection
    barrier = AsyncBarrier(4)
    transport = RecordingAsyncTransport(barrier)
    client = install_async_transport(oid, transport)

    alice_access = "alice-access"
    bob_access = "bob-access"
    alice_rpt = "alice-rpt"
    bob_rpt = "bob-rpt"

    alice, bob, plain, raw = await asyncio.wait_for(
        asyncio.gather(
            rpt_introspect(oid, alice_access, alice_rpt),
            rpt_introspect(oid, bob_access, bob_rpt),
            oid.a_introspect(token=alice_access),
            oid.a_well_known(),
        ),
        timeout=5,
    )
    await client.aclose()

    introspect_calls = [r for r in transport.requests if "introspect" in r["url"]]
    raw_calls = [r for r in transport.requests if "well-known" in r["url"]]
    assert len(introspect_calls) == 3
    assert len(raw_calls) == 1

    expected_rpt_bearer = {alice_rpt: f"Bearer {alice_access}", bob_rpt: f"Bearer {bob_access}"}
    for call in introspect_calls:
        values = header_values(call, "authorization")
        assert len(values) == 1, call
        fields = parsed(call)
        hint = fields.get("token_type_hint", [""])[0]
        token = fields["token"][0]
        if hint == RPT_TOKEN_TYPE:
            assert values[0] == expected_rpt_bearer[token]
        else:
            assert token == alice_access
            assert values[0] == CLIENT_AUTH
        assert call["headers"].get("x-custom") == "shared"

    raw_call = raw_calls[0]
    assert header_values(raw_call, "authorization") == [CLIENT_AUTH]
    assert raw_call["headers"].get("x-custom") == "shared"

    # Each caller only observes data derived from its own identity.
    assert alice == {"active": True, "identity": f"Bearer {alice_access}"}
    assert bob == {"active": True, "identity": f"Bearer {bob_access}"}
    assert plain == {"active": True, "identity": CLIENT_AUTH}
    assert raw == {"issuer": "http://test.test", "identity": CLIENT_AUTH}

    assert connection.headers["Authorization"] == CLIENT_AUTH
    assert connection.headers["X-Custom"] == "shared"


@pytest.mark.asyncio
async def test_concurrent_transport_failure_is_confined_to_one_user() -> None:
    """One user's transport error must not leak identity into the other user's call."""
    oid = make_oid({"X-Custom": "shared"})
    connection = oid.connection
    barrier = AsyncBarrier(2)
    transport = RecordingAsyncTransport(barrier)
    transport.fail_tokens.add("alice-rpt")
    client = install_async_transport(oid, transport)

    alice = asyncio.create_task(rpt_introspect(oid, "alice-access", "alice-rpt"))
    bob = asyncio.create_task(rpt_introspect(oid, "bob-access", "bob-rpt"))

    bob_result = await asyncio.wait_for(bob, timeout=5)
    with pytest.raises(KeycloakConnectionError):
        await alice

    assert bob_result == {"active": True, "identity": "Bearer bob-access"}
    assert "Authorization" not in connection.headers

    transport.fail_tokens.clear()
    recovery = await oid.a_well_known()
    await client.aclose()

    last = transport.requests[-1]
    assert header_values(last, "authorization") == []
    assert last["headers"].get("x-custom") == "shared"
    assert recovery["identity"] is None
    assert "Authorization" not in connection.headers


@pytest.mark.asyncio
async def test_failed_rpt_introspection_keeps_original_custom_bearer() -> None:
    """Connection-level credentials survive a failed per-user introspection."""
    oid = make_oid({"Authorization": CLIENT_AUTH, "X-Custom": "shared"})
    connection = oid.connection
    transport = RecordingAsyncTransport()
    transport.fail_tokens.add("alice-rpt")
    client = install_async_transport(oid, transport)

    with pytest.raises(KeycloakConnectionError):
        await rpt_introspect(oid, "alice-access", "alice-rpt")

    assert connection.headers["Authorization"] == CLIENT_AUTH

    normal = await oid.a_introspect(token="alice-access")
    recovery = await oid.a_well_known()
    await client.aclose()

    introspect_call = transport.requests[-2]
    assert header_values(introspect_call, "authorization") == [CLIENT_AUTH]
    assert normal["identity"] == CLIENT_AUTH
    assert header_values(transport.requests[-1], "authorization") == [CLIENT_AUTH]
    assert recovery["identity"] == CLIENT_AUTH
    assert connection.headers["Authorization"] == CLIENT_AUTH


@pytest.mark.asyncio
async def test_cancelled_rpt_introspection_does_not_leak_identity() -> None:
    """Cancelling a coroutine mid-transport must not change later identities."""
    oid = make_oid({"X-Custom": "shared"})
    connection = oid.connection
    transport = RecordingAsyncTransport()
    transport.block = True
    transport.release.clear()
    client = install_async_transport(oid, transport)

    task = asyncio.create_task(rpt_introspect(oid, "alice-access", "alice-rpt"))
    await transport.entered.wait()
    task.cancel()
    with pytest.raises(asyncio.CancelledError):
        await task

    assert "Authorization" not in connection.headers

    transport.block = False
    transport.release.set()
    recovery = await oid.a_well_known()
    await client.aclose()

    last = transport.requests[-1]
    assert header_values(last, "authorization") == []
    assert last["headers"].get("x-custom") == "shared"
    assert recovery["identity"] is None
    assert "Authorization" not in connection.headers


def test_sync_rpt_introspection_is_isolated_and_restores_identity() -> None:
    """Sync RPT introspection uses its own bearer, then restores shared credentials."""
    oid = make_oid({"Authorization": CLIENT_AUTH, "X-Custom": "shared"})
    connection = oid.connection
    session = RecordingSession()
    connection._s = session  # type: ignore[assignment]

    result = oid.introspect(token="alice-access", rpt="alice-rpt", token_type_hint=RPT_TOKEN_TYPE)
    call = session.requests[-1]
    assert call["headers"]["Authorization"] == "Bearer alice-access"
    assert call["headers"]["X-Custom"] == "shared"
    assert call["data"]["token"] == "alice-rpt"
    assert result["identity"] == "Bearer alice-access"
    assert connection.headers["Authorization"] == CLIENT_AUTH

    session.fail = True
    with pytest.raises(KeycloakConnectionError):
        oid.introspect(token="bob-access", rpt="bob-rpt", token_type_hint=RPT_TOKEN_TYPE)
    session.fail = False

    assert connection.headers["Authorization"] == CLIENT_AUTH

    plain = oid.introspect(token="alice-access")
    assert plain["identity"] == CLIENT_AUTH
    assert session.requests[-1]["headers"]["Authorization"] == CLIENT_AUTH
    assert connection.headers["Authorization"] == CLIENT_AUTH


def test_sync_rpt_introspection_without_base_credentials() -> None:
    """A connection with no base Authorization sends user and no-auth headers correctly."""
    oid = make_oid({"X-Custom": "shared"})
    connection = oid.connection
    session = RecordingSession()
    connection._s = session  # type: ignore[assignment]

    result = oid.introspect(token="alice-access", rpt="alice-rpt", token_type_hint=RPT_TOKEN_TYPE)
    assert session.requests[-1]["headers"]["Authorization"] == "Bearer alice-access"
    assert result["identity"] == "Bearer alice-access"
    assert "Authorization" not in connection.headers

    plain = oid.introspect(token="alice-access")
    assert "Authorization" not in session.requests[-1]["headers"]
    assert plain["identity"] is None
    assert "Authorization" not in connection.headers


def test_headers_snapshot_is_isolated_from_callers() -> None:
    """Passing a header dict does not let later mutation change the connection."""
    source = {"X-Custom": "shared"}
    connection = ConnectionManager(base_url="http://test.test", headers=source)
    source["Authorization"] = "Bearer attacker"
    assert "Authorization" not in connection.headers

    merged = connection._request_headers({"authorization": "Bearer per-request"})
    assert merged["authorization"] == "Bearer per-request"
    assert "Authorization" not in connection.headers


def test_admin_certificate_upload_keeps_connection_identity() -> None:
    """Multipart upload overrides Content-Type per request without touching identity."""
    connection = ConnectionManager(
        base_url="http://test.test", headers={"Authorization": CLIENT_AUTH}
    )
    connection.realm_name = "test-realm"  # type: ignore[attr-defined]
    session = RecordingSession()
    connection._s = session  # type: ignore[assignment]

    admin = KeycloakAdmin.__new__(KeycloakAdmin)
    admin._connection = connection  # type: ignore[attr-defined]

    result = admin.upload_certificate(client_id="client-id", certcont="PEM")
    call = session.requests[-1]
    assert call["headers"]["Authorization"] == CLIENT_AUTH
    assert call["headers"]["Content-Type"].startswith("multipart/form-data")
    assert connection.headers == {"Authorization": CLIENT_AUTH}
    assert result == {"active": True, "identity": CLIENT_AUTH}


def test_request_headers_override_is_case_insensitive() -> None:
    """Per-request overrides replace any casing variant of the same header."""
    connection = ConnectionManager(
        base_url="http://test.test",
        headers={"Authorization": CLIENT_AUTH, "X-Custom": "shared"},
    )
    merged = connection._request_headers({"authorization": "Bearer user"})
    assert merged["authorization"] == "Bearer user"
    matching = [k for k in merged if k.lower() == "authorization"]
    assert matching == ["authorization"]
    assert connection.headers["Authorization"] == CLIENT_AUTH
