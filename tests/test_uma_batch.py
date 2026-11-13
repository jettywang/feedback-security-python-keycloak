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

"""Tests for batched UMA permission processing."""

from __future__ import annotations

import json

import pytest
from keycloak import KeycloakOpenID, KeycloakUMA, UMARequestStatus
from keycloak.exceptions import KeycloakPostError
from keycloak.uma_batch import (
    build_permission_strings,
    build_ticket_payload,
    evaluate_uma_batch,
    merge_uma_requests,
    normalize_uma_requests,
)
from keycloak.uma_permissions import Resource, Scope

from tests.uma_batch_fakes import WELL_KNOWN, FakeConnection, FakeKeycloakServer

CALLER_REQUESTS = [
    {"resource": "reporting-api", "resource_id": "reporting-api", "scopes": ["read", "write"]},
    {"resource": "reporting-api", "resource_id": "reporting-api", "scopes": ["read", "export"]},
    {"resource": "billing-api", "resource_id": "billing-api"},
]


def _openid(server: FakeKeycloakServer) -> KeycloakOpenID:
    client = KeycloakOpenID(
        server_url="https://keycloak.example",
        realm_name="demo",
        client_id="demo-client",
    )
    client.connection = FakeConnection(server)
    return client


def _uma(server: FakeKeycloakServer) -> KeycloakUMA:
    return KeycloakUMA(FakeConnection(server))


def test_normalize_empty_inputs() -> None:
    """Empty and null inputs normalize to an empty tuple."""
    assert normalize_uma_requests(None) == ()
    assert normalize_uma_requests([]) == ()
    assert normalize_uma_requests(()) == ()
    assert normalize_uma_requests(set()) == ()


def test_normalize_supported_shapes() -> None:
    """All accepted input shapes normalize with preserved order."""
    requests = normalize_uma_requests(
        [
            "reporting-api#read",
            ("reporting-api", "write"),
            ("reporting-api", ["export", "read"]),
            {"resource": "billing-api", "resource_id": "bid", "scopes": None},
            Resource("plain-resource"),
            Resource("combined")(Scope("delete")),
        ]
    )

    assert requests[0].resource == "reporting-api"
    assert requests[0].scopes == ("read",)
    assert requests[1].scopes == ("write",)
    assert requests[2].scopes == ("export", "read")
    assert requests[3].is_resource_level
    assert requests[3].resource_id == "bid"
    assert requests[4].is_resource_level
    assert requests[5].scopes == ("delete",)
    assert [req.index for req in requests] == list(range(6))


def test_normalize_requires_resource() -> None:
    """Requests without a resource name are rejected."""
    with pytest.raises(ValueError, match="has no resource"):
        normalize_uma_requests([{"resource": "", "scopes": ["read"]}])


def test_duplicates_merge_but_keep_member_indices() -> None:
    """Duplicate requests merge while keeping every index."""
    requests = normalize_uma_requests(["r#a", "r#a", {"resource": "r", "scopes": ["a", "b"]}])
    entries = merge_uma_requests(requests)

    assert len(entries) == 1
    assert entries[0].scopes == ("a", "b")
    assert entries[0].member_indices == (0, 1, 2)
    assert build_permission_strings(entries) == ["r#a", "r#b"]


def test_resource_level_request_is_never_merged_with_scopes() -> None:
    """Resource-level and scope-level requests stay separate."""
    requests = normalize_uma_requests(
        [
            {"resource": "r", "scopes": ["a"]},
            {"resource": "r"},
            {"resource": "r", "scopes": ["b"]},
        ]
    )
    entries = merge_uma_requests(requests)

    assert len(entries) == 2
    scope_entry = next(entry for entry in entries if not entry.is_resource_level)
    resource_entry = next(entry for entry in entries if entry.is_resource_level)
    assert scope_entry.scopes == ("a", "b")
    assert scope_entry.member_indices == (0, 2)
    assert resource_entry.member_indices == (1,)
    assert build_ticket_payload(entries) == [
        {"resource_id": "r", "resource_scopes": ["a", "b"]},
        {"resource_id": "r"},
    ]


def test_evaluate_partial_grant_and_mapping_back() -> None:
    """Partial grants map back to each merged member request."""
    requests = normalize_uma_requests(
        [
            {"resource": "r", "scopes": ["a", "b"]},
            {"resource": "r", "scopes": ["a", "c"]},
        ]
    )
    entries = merge_uma_requests(requests)
    granted = [{"rsid": "r", "rsname": "r", "scopes": ["a"]}]

    result = evaluate_uma_batch(requests, entries, granted)

    assert result.results[0].status is UMARequestStatus.PARTIAL
    assert result.results[0].granted_scopes == frozenset({"a"})
    assert result.results[0].missing_scopes == frozenset({"b"})
    assert result.results[1].status is UMARequestStatus.PARTIAL
    assert result.results[1].missing_scopes == frozenset({"c"})


def test_resource_level_grant_does_not_satisfy_scope_request() -> None:
    """Whole-resource grants do not satisfy scope requests."""
    requests = normalize_uma_requests([{"resource": "r", "scopes": ["a"]}])
    entries = merge_uma_requests(requests)
    granted = [{"rsid": "r", "rsname": "r", "scopes": []}]

    result = evaluate_uma_batch(requests, entries, granted)

    assert result.results[0].status is UMARequestStatus.DENIED
    assert result.results[0].missing_scopes == frozenset({"a"})


def test_scope_grant_does_not_satisfy_resource_level_request() -> None:
    """Scope grants do not satisfy resource-level requests."""
    requests = normalize_uma_requests([{"resource": "r"}])
    entries = merge_uma_requests(requests)
    granted = [{"rsid": "r", "rsname": "r", "scopes": ["a", "b"]}]

    result = evaluate_uma_batch(requests, entries, granted)

    assert result.results[0].status is UMARequestStatus.DENIED
    assert result.results[0].missing_scopes is None


def test_unrequested_resources_and_scopes_are_extra() -> None:
    """Unrequested grants are reported as extra permissions."""
    requests = normalize_uma_requests(
        [
            {"resource": "r", "scopes": ["a"]},
            {"resource": "other"},
        ]
    )
    entries = merge_uma_requests(requests)
    granted = [
        {"rsid": "r", "rsname": "r", "scopes": ["a", "bonus"]},
        {"rsid": "other", "rsname": "other", "scopes": []},
        {"rsid": "ghost", "rsname": "ghost", "scopes": ["read"]},
    ]

    result = evaluate_uma_batch(requests, entries, granted)

    assert result.results[0].status is UMARequestStatus.GRANTED
    assert result.results[1].status is UMARequestStatus.GRANTED
    extra = {(item["resource"], tuple(item["scopes"])) for item in result.extra_permissions}
    assert ("r", ("bonus",)) in extra
    assert ("ghost", ("read",)) in extra


def test_sync_token_style_batch() -> None:
    """Sync token-endpoint batch maps results in one POST."""
    server = FakeKeycloakServer()
    client = _openid(server)

    result = client.permissions_batch("user-token", CALLER_REQUESTS)

    assert server.authorization_request_count == 1
    assert result.network_requests == 1
    assert [entry.resource for entry in result.entries] == ["reporting-api", "billing-api"]
    assert [item.status for item in result.results] == [
        UMARequestStatus.PARTIAL,
        UMARequestStatus.GRANTED,
        UMARequestStatus.GRANTED,
    ]
    assert result.results[0].missing_scopes == frozenset({"write"})
    assert result.extra_permissions

    token_call = next(
        call for call in server.call_log if call["path"].endswith("/protocol/openid-connect/token")
    )
    assert token_call["payload"]["permission"] == [
        "reporting-api#read",
        "reporting-api#write",
        "reporting-api#export",
        "billing-api",
    ]


def test_sync_token_style_empty_input_makes_no_request() -> None:
    """Sync token-endpoint empty input skips the network."""
    server = FakeKeycloakServer()
    client = _openid(server)

    result = client.permissions_batch("user-token", [])

    assert result.results == []
    assert result.network_requests == 0
    assert server.request_count == 0


@pytest.mark.asyncio()
async def test_async_token_style_batch() -> None:
    """Async token-endpoint batch maps results in one POST."""
    server = FakeKeycloakServer()
    client = _openid(server)

    result = await client.a_permissions_batch("user-token", CALLER_REQUESTS)

    assert server.authorization_request_count == 1
    assert result.results[0].status is UMARequestStatus.PARTIAL
    assert result.results[2].status is UMARequestStatus.GRANTED


@pytest.mark.asyncio()
async def test_async_token_style_empty_input_makes_no_request() -> None:
    """Async token-endpoint empty input skips the network."""
    server = FakeKeycloakServer()
    client = _openid(server)

    result = await client.a_permissions_batch("user-token", None)

    assert result.network_requests == 0
    assert server.request_count == 0


def test_sync_ticket_style_batch() -> None:
    """Sync ticket batch uses two POSTs and maps every request."""
    server = FakeKeycloakServer()
    uma = _uma(server)

    result = uma.permissions_batch(CALLER_REQUESTS)

    assert server.authorization_request_count == 2
    assert result.network_requests == 2
    assert result.ticket is not None
    assert [item.status for item in result.results] == [
        UMARequestStatus.PARTIAL,
        UMARequestStatus.GRANTED,
        UMARequestStatus.GRANTED,
    ]

    permission_call = next(
        call for call in server.call_log if call["path"] == WELL_KNOWN["permission_endpoint"]
    )
    assert json.loads(permission_call["payload"]) == [
        {"resource_id": "reporting-api", "resource_scopes": ["read", "write", "export"]},
        {"resource_id": "billing-api"},
    ]
    token_call = next(
        call for call in server.call_log if call["path"].endswith("/protocol/openid-connect/token")
    )
    assert token_call["payload"]["ticket"] == result.ticket


def test_sync_ticket_only_batch() -> None:
    """Ticket-only batch performs a single permission POST."""
    server = FakeKeycloakServer()
    uma = _uma(server)

    result = uma.permission_ticket_batch(CALLER_REQUESTS)

    assert server.authorization_request_count == 1
    assert result.network_requests == 1
    assert result.ticket is not None
    assert result.results == []
    assert len(result.entries) == 2


def test_sync_ticket_style_empty_input_makes_no_request() -> None:
    """Sync ticket batch empty input skips the network."""
    server = FakeKeycloakServer()
    uma = _uma(server)

    result = uma.permissions_batch([])

    assert result.network_requests == 0
    assert result.results == []
    assert server.request_count == 0


@pytest.mark.asyncio()
async def test_async_ticket_style_batch() -> None:
    """Async ticket batch uses two POSTs and maps every request."""
    server = FakeKeycloakServer()
    uma = _uma(server)

    result = await uma.a_permissions_batch(CALLER_REQUESTS)

    assert server.authorization_request_count == 2
    assert result.results[0].missing_scopes == frozenset({"write"})
    assert result.results[1].status is UMARequestStatus.GRANTED
    assert result.results[2].status is UMARequestStatus.GRANTED


@pytest.mark.asyncio()
async def test_async_ticket_style_empty_input_makes_no_request() -> None:
    """Async ticket batch empty input skips the network."""
    server = FakeKeycloakServer()
    uma = _uma(server)

    result = await uma.a_permissions_batch(())

    assert result.network_requests == 0
    assert server.request_count == 0


def test_missing_ticket_raises() -> None:
    """A permission response without a ticket is reported explicitly."""
    server = FakeKeycloakServer(omit_ticket=True)
    uma = _uma(server)

    with pytest.raises(KeycloakPostError, match="did not contain a ticket"):
        uma.permissions_batch(CALLER_REQUESTS)


@pytest.mark.asyncio()
async def test_async_missing_ticket_raises() -> None:
    """The async path also rejects a permission response without a ticket."""
    server = FakeKeycloakServer(omit_ticket=True)
    uma = _uma(server)

    with pytest.raises(KeycloakPostError, match="did not contain a ticket"):
        await uma.a_permissions_batch(CALLER_REQUESTS)
