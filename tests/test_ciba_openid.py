"""Tests for the low-level CIBA methods on KeycloakOpenID."""

from __future__ import annotations

from unittest import mock

import pytest
from keycloak import KeycloakPostError

from tests.ciba_support.fake_ciba_server import CIBA_PATH, FakeCibaServer

REALM = "openid-realm"
CLIENT = "openid-client"


@pytest.fixture()
def server() -> FakeCibaServer:
    """
    Build a fake provider for the OpenID client tests.

    :returns: Fake CIBA server
    :rtype: FakeCibaServer
    """
    return FakeCibaServer(realm_name=REALM, client_id=CLIENT)


def test_ciba_returns_auth_req_id(server: FakeCibaServer) -> None:
    """The backchannel call returns the CIBA response envelope."""
    client = server.build_client()

    response = client.ciba(login_hint="alice", binding_message="hello")

    assert set(response) == {"auth_req_id", "expires_in", "interval"}
    assert response["expires_in"] == 120
    posted = server.backchannel_calls[0]
    assert posted["login_hint"] == "alice"
    assert posted["binding_message"] == "hello"
    assert server.token_exchanges == []


def test_ciba_posts_to_the_backchannel_endpoint(server: FakeCibaServer) -> None:
    """The request targets the realm's CIBA backchannel URL."""
    client = server.build_client()

    client.ciba(login_hint="alice")

    assert server.last_request is not None
    assert CIBA_PATH in server.last_request.path_url


def test_ciba_sends_requested_expiry_and_secret(server: FakeCibaServer) -> None:
    """Optional parameters and the client secret reach the provider."""
    client = server.build_client()

    response = client.ciba(login_hint="alice", requested_expiry=30)

    assert response["expires_in"] == 30
    assert server.backchannel_calls[0]["requested_expiry"] == "30"
    assert server.backchannel_calls[0]["client_secret"] == "demo-secret"  # noqa: S105


def test_ciba_requires_a_user_hint(server: FakeCibaServer) -> None:
    """CIBA must identify the user through one of the three hints."""
    client = server.build_client()

    with pytest.raises(ValueError, match="login_hint"):
        client.ciba()


def test_ciba_propagates_provider_error(server: FakeCibaServer) -> None:
    """An invalid client id surfaces as a Keycloak POST error."""
    client = server.build_client()
    client.client_id = "wrong-client"

    with pytest.raises(KeycloakPostError):
        client.ciba(login_hint="alice")


def test_ciba_token_exchange_grant_type(server: FakeCibaServer) -> None:
    """The token exchange uses the CIBA grant type and auth_req_id."""
    client = server.build_client()
    initiated = client.ciba(login_hint="alice")
    server.set_outcome(initiated["auth_req_id"], "approved")

    token = client.token(
        grant_type="urn:ietf:params:oauth:grant-type:ciba",
        auth_req_id=initiated["auth_req_id"],
    )

    assert token["access_token"] == f"access-{initiated['auth_req_id']}"
    exchange = server.token_exchanges[0]
    assert exchange["grant_type"] == "urn:ietf:params:oauth:grant-type:ciba"
    assert exchange["auth_req_id"] == initiated["auth_req_id"]


@pytest.mark.asyncio()
async def test_a_ciba_builds_ciba_payload(server: FakeCibaServer) -> None:
    """The asynchronous method issues a CIBA backchannel request."""
    client = server.build_client()
    fake_response = mock.Mock()
    fake_response.status_code = 200
    fake_response.json.return_value = {
        "auth_req_id": "async-req",
        "expires_in": 120,
        "interval": 2,
    }

    with mock.patch.object(
        client.connection,
        "a_raw_post",
        new=mock.AsyncMock(return_value=fake_response),
    ) as post:
        response = await client.a_ciba(login_hint="alice", binding_message="async-hello")

    assert response["auth_req_id"] == "async-req"
    _, kwargs = post.call_args
    payload = kwargs["data"]
    assert payload["login_hint"] == "alice"
    assert payload["binding_message"] == "async-hello"
    assert CIBA_PATH in post.call_args[0][0]


@pytest.mark.asyncio()
async def test_a_ciba_requires_a_user_hint(server: FakeCibaServer) -> None:
    """The asynchronous method enforces the same user hint validation."""
    client = server.build_client()

    with pytest.raises(ValueError, match="login_hint"):
        await client.a_ciba()
