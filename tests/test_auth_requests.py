"""Tests for the shared authorization request descriptions."""

from __future__ import annotations

import asyncio
import dataclasses
from types import MappingProxyType
from unittest import mock
from urllib.parse import parse_qsl

import httpx
import pytest
import requests

from keycloak import KeycloakOpenID
from keycloak._auth_requests import (
    build_exchange_token_request,
    build_introspection_request,
    build_refresh_token_request,
    build_token_request,
)
from keycloak.exceptions import KeycloakAuthenticationError, KeycloakRPTNotFound


TOKEN_URL = "realms/realm/protocol/openid-connect/token"
INTROSPECT_URL = "realms/realm/protocol/openid-connect/token/introspect"


class FormRecorder:
    """Record the exact form body produced by each transport."""

    def __init__(self) -> None:
        self.requests: list[tuple[str, str, dict, str]] = []

    def sync_post(self, path, data=None, headers=None, **kwargs):
        prepared = requests.Request(
            "POST", "http://kc.test/" + path, data=data, headers=headers or {}
        ).prepare()
        self.requests.append((path, _body_text(prepared.body), _headers(prepared.headers), "sync"))
        return mock.Mock(status_code=200, json=lambda: {"active": True}, content=b"{}")

    async def async_post(self, path, data=None, headers=None, **kwargs):
        request = httpx.Request(
            "POST", "http://kc.test/" + path, data=data, headers=headers or {}
        )
        self.requests.append((path, _body_text(request.content), _headers(request.headers), "async"))
        return httpx.Response(200, json={"active": True}, content=b"{}")


def make_client() -> tuple[KeycloakOpenID, FormRecorder]:
    oid = KeycloakOpenID(
        server_url="http://kc.test",
        realm_name="realm",
        client_id="client",
        client_secret_key="secret",
    )
    recorder = FormRecorder()
    oid.connection.raw_post = recorder.sync_post
    oid.connection.a_raw_post = recorder.async_post
    return oid, recorder


def _body_text(body: bytes | str) -> str:
    return body if isinstance(body, str) else body.decode()


def _headers(headers: dict) -> dict:
    return {key.lower(): value for key, value in headers.items()}


def _form(body: bytes | str) -> dict:
    return dict(parse_qsl(_body_text(body)))


def test_token_descriptions_match_with_none_values():
    """None-valued token fields are omitted identically by both description builders."""
    request = build_token_request(
        realm_name="realm",
        client_id="client",
        client_secret="secret",
        username="alice",
        password=None,
        grant_type="password",
        code=None,
        redirect_uri=None,
        totp=None,
        scope="openid",
        code_verifier=None,
        extra={"custom": "value"},
    )
    assert request.path == TOKEN_URL
    assert request.form == {
        "username": "alice",
        "client_id": "client",
        "grant_type": "password",
        "scope": "openid",
        "custom": "value",
        "client_secret": "secret",
    }
    assert request.content_type == "application/x-www-form-urlencoded"
    assert not request.bearer_auth


def test_exchange_description_omits_absent_optional_fields():
    """Optional exchange fields that are absent must not appear as blank values."""
    request = build_exchange_token_request(
        realm_name="realm",
        client_id="client",
        client_secret="secret",
        token="subject",
        audience=None,
        subject=None,
        subject_token_type=None,
        subject_issuer=None,
        requested_issuer=None,
        requested_token_type="urn:ietf:params:oauth:token-type:refresh_token",
        scope="openid",
    )
    assert request.path == TOKEN_URL
    assert request.form == {
        "grant_type": "urn:ietf:params:oauth:grant-type:token-exchange",
        "client_id": "client",
        "subject_token": "subject",
        "requested_token_type": "urn:ietf:params:oauth:token-type:refresh_token",
        "scope": "openid",
        "client_secret": "secret",
    }


def test_introspection_rpt_keeps_user_token_out_of_description():
    """The RPT flow must reference the RPT in the form and the user token as bearer."""
    request = build_introspection_request(
        realm_name="realm",
        client_id="client",
        client_secret="secret",
        token="user-token",
        rpt="rpt-token",
        token_type_hint="requesting_party_token",  # noqa: S106
    )
    assert request.path == INTROSPECT_URL
    assert request.form == {
        "client_id": "client",
        "token": "rpt-token",
        "token_type_hint": "requesting_party_token",  # noqa: S105
        "client_secret": "secret",
    }
    assert request.bearer_auth


def test_introspection_without_rpt_raises_before_io():
    """Missing RPT is a ValueError-like Keycloak error, not a network call."""
    with pytest.raises(KeycloakRPTNotFound):
        build_introspection_request(
            realm_name="realm",
            client_id="client",
            client_secret=None,
            token="user-token",
            rpt=None,
            token_type_hint="requesting_party_token",  # noqa: S106
        )


@pytest.mark.parametrize(
    ("call_sync", "call_async", "method"),
    [
        (
            lambda oid: oid.token(
                username="alice",
                password="pw",
                totp=123456,
                scope="openid email",
                code_verifier="verifier",
                extra_param="foo",
            ),
            lambda oid: oid.a_token(
                username="alice",
                password="pw",
                totp=123456,
                scope="openid email",
                code_verifier="verifier",
                extra_param="foo",
            ),
            "token",
        ),
        (
            lambda oid: oid.token(username="alice", password=None, code=None),
            lambda oid: oid.a_token(username="alice", password=None, code=None),
            "token-none",
        ),
        (
            lambda oid: oid.refresh_token("refresh-value"),
            lambda oid: oid.a_refresh_token("refresh-value"),
            "refresh_token",
        ),
        (
            lambda oid: oid.exchange_token("subject", audience="aud", subject="sub"),
            lambda oid: oid.a_exchange_token("subject", audience="aud", subject="sub"),
            "exchange_token",
        ),
        (
            lambda oid: oid.introspect("user-token"),
            lambda oid: oid.a_introspect("user-token"),
            "introspect",
        ),
        (
            lambda oid: oid.introspect(
                "user-token", rpt="rpt-token", token_type_hint="requesting_party_token"
            ),
            lambda oid: oid.a_introspect(
                "user-token", rpt="rpt-token", token_type_hint="requesting_party_token"
            ),
            "introspect-rpt",
        ),
    ],
)
def test_sync_and_async_emit_identical_requests(call_sync, call_async, method):
    """Both transports must send the same path, form bytes, and auth placement."""
    sync_client, sync_recorder = make_client()
    call_sync(sync_client)
    async_client, async_recorder = make_client()
    asyncio.run(call_async(async_client))

    sync_send = sync_recorder.requests[0]
    async_send = async_recorder.requests[0]
    assert sync_send[0] == async_send[0]
    assert sync_send[1] == async_send[1]
    assert sync_send[2].get("content-type") == async_send[2].get("content-type")
    assert sync_send[2].get("authorization") == async_send[2].get("authorization")
    if method == "introspect-rpt":
        assert sync_send[2]["authorization"] == "Bearer user-token"
    else:
        assert "authorization" not in sync_send[2]


def test_sync_and_async_error_types_match():
    """A rejected request surfaces the same exception class on both transports."""
    def rejected_sync(path, data=None, headers=None, **kwargs):
        return mock.Mock(status_code=401, json=lambda: {"message": "denied"}, content=b"{}")

    async def rejected_async(path, data=None, headers=None, **kwargs):
        return httpx.Response(401, json={"message": "denied"}, content=b"{}")

    sync_client, _ = make_client()
    sync_client.connection.raw_post = rejected_sync
    async_client, _ = make_client()
    async_client.connection.a_raw_post = rejected_async

    with pytest.raises(KeycloakAuthenticationError):
        sync_client.token(username="alice", password="pw")
    with pytest.raises(KeycloakAuthenticationError):
        asyncio.run(async_client.a_token(username="alice", password="pw"))


def test_interleaved_users_do_not_share_request_state():
    """Interleaved requests for different users must not leak headers or form data."""
    client, recorder = make_client()

    with mock.patch.object(
        client.connection,
        "async_s",
        mock.Mock(
            request=mock.AsyncMock(
                side_effect=lambda **kwargs: (
                    recorder.requests.append(
                        (
                            kwargs["url"].split("/realms/", 1)[1],
                            httpx.Request(
                                "POST",
                                "http://kc.test",
                                data=kwargs["data"],
                                headers=kwargs["headers"],
                            ).content,
                            _headers(kwargs["headers"]),
                            "async",
                        )
                    )
                    or httpx.Response(200, json={"active": True}, content=b"{}")
                )
            )
        ),
    ):
        async def user_a():
            return await client.a_introspect(
                "token-a", rpt="rpt-a", token_type_hint="requesting_party_token"
            )

        async def user_b():
            return await client.a_token(username="bob", password="pw")

        async def run():
            await asyncio.gather(user_a(), user_b())

        asyncio.run(run())

    first, second = recorder.requests
    assert _form(first[1])["token"] == "rpt-a"
    assert first[2]["authorization"] == "Bearer token-a"
    assert _form(second[1])["username"] == "bob"
    assert "authorization" not in second[2]

    assert client.connection.headers == {}


def test_sequential_user_requests_leave_connection_headers_untouched():
    """Sequential RPT and non-RPT requests must not accumulate connection headers."""
    client, recorder = make_client()
    client.introspect("token-a", rpt="rpt-a", token_type_hint="requesting_party_token")  # noqa: S106
    client.token(username="bob", password="pw")
    client.introspect("token-c", rpt="rpt-c", token_type_hint="requesting_party_token")  # noqa: S106

    assert client.connection.headers == {}
    assert recorder.requests[0][2]["authorization"] == "Bearer token-a"
    assert "authorization" not in recorder.requests[1][2]
    assert recorder.requests[2][2]["authorization"] == "Bearer token-c"


def test_description_is_immutable():
    """Callers cannot mutate a description's form mapping."""
    request = build_refresh_token_request(
        realm_name="realm",
        client_id="client",
        client_secret=None,
        refresh_token="value",
        grant_type="refresh_token",
    )
    assert isinstance(request.form, MappingProxyType)
    with pytest.raises(dataclasses.FrozenInstanceError):
        request.path = "other"
    with pytest.raises(TypeError):
        request.form["token"] = "other"
