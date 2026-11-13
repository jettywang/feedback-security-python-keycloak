#!/usr/bin/env python3
"""
In-memory demo of batched UMA permission requests in python-keycloak.

Three caller requests are merged into two resource tickets. Overlapping scopes
on the same resource are combined, the resource-level request stays separate,
and only part of the requested scopes is granted. The fake Keycloak server
also returns a resource nobody requested, which must be surfaced as an extra
permission rather than satisfying an original request.

Run it with the repository virtualenv::

    .venv/bin/python examples/uma_batch_demo.py
"""
# ruff: noqa: T201, E402, S101, PLR2004

from __future__ import annotations

import asyncio
import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "tests"))

from keycloak import KeycloakOpenID, KeycloakUMA, UMARequestStatus
from uma_batch_fakes import FakeConnection, FakeKeycloakServer

# Three caller requests: two scope-level requests on the same resource plus a
# resource-level request on a different resource.
CALLER_REQUESTS = [
    {"resource": "reporting-api", "resource_id": "reporting-api", "scopes": ["read", "write"]},
    {"resource": "reporting-api", "resource_id": "reporting-api", "scopes": ["read", "export"]},
    {"resource": "billing-api", "resource_id": "billing-api"},
]


def print_result(label: str, result: object, server: FakeKeycloakServer) -> None:
    """
    Pretty-print a batch result and the observed network traffic.

    :param label: Section title.
    :type label: str
    :param result: The batch result returned by the client.
    :type result: UMABatchResult
    :param server: The fake server holding the call log.
    :type server: FakeKeycloakServer
    """
    print(f"\n=== {label} ===")
    print("merged ticket payload:")
    for entry in result.entries:
        kind = "resource-level" if entry.is_resource_level else f"scopes={list(entry.scopes)}"
        print(f"  - {entry.resource} ({kind}) <- requests {list(entry.member_indices)}")

    print("per-request outcomes:")
    for item in result.results:
        req = item.request
        asked = "whole resource" if req.is_resource_level else ",".join(req.scopes)
        line = f"  #{req.index} {req.resource} [{asked}] -> {item.status.value}"
        if not req.is_resource_level:
            line += (
                f" | granted={sorted(item.granted_scopes)}"
                f" missing={sorted(item.missing_scopes)}"
            )
        print(line)

    print("extra permissions (never requested):")
    for extra in result.extra_permissions:
        print(f"  - {extra['resource']} scopes={extra['scopes']}")

    print(f"client-reported authorization requests: {result.network_requests}")
    print(f"real authorization POSTs observed: {server.authorization_request_count}")
    print(f"total HTTP calls (including discovery): {server.request_count}")
    for call in server.call_log:
        print(f"  {call['method']} {call['path'].split('/realms/')[-1]} :: {call['payload']}")


def run_sync() -> None:
    """Run both API styles through the synchronous clients."""
    server = FakeKeycloakServer()
    connection = FakeConnection(server)

    # Style 1: permission-ticket endpoint + ticket exchange (KeycloakUMA).
    uma = KeycloakUMA(connection)  # type: ignore[arg-type]
    ticket_result = uma.permissions_batch(CALLER_REQUESTS)
    print_result("sync style 1: permission ticket + exchange", ticket_result, server)
    assert server.authorization_request_count == 2  # ticket POST + token exchange POST
    assert ticket_result.results[0].status is UMARequestStatus.PARTIAL
    assert ticket_result.results[1].status is UMARequestStatus.GRANTED
    assert ticket_result.results[2].status is UMARequestStatus.GRANTED
    assert ticket_result.extra_permissions

    # Style 2: token endpoint response_mode=permissions (KeycloakOpenID).
    server2 = FakeKeycloakServer()
    openid = KeycloakOpenID(
        server_url="https://keycloak.example",
        realm_name="demo",
        client_id="demo-client",
    )
    openid.connection = FakeConnection(server2)  # type: ignore[assignment]
    token_result = openid.permissions_batch("user-token", CALLER_REQUESTS)
    print_result("sync style 2: token endpoint permissions", token_result, server2)
    assert server2.authorization_request_count == 1  # one token POST for the batch
    assert [item.status for item in token_result.results] == [
        UMARequestStatus.PARTIAL,
        UMARequestStatus.GRANTED,
        UMARequestStatus.GRANTED,
    ]
    assert token_result.extra_permissions

    # Empty input short-circuits without touching the network.
    empty_result = openid.permissions_batch("user-token", [])
    assert empty_result.network_requests == 0
    assert server2.authorization_request_count == 1
    print("\nempty input -> 0 network requests, 0 results: OK")


async def run_async() -> None:
    """Run both API styles through the asynchronous clients."""
    server = FakeKeycloakServer()
    connection = FakeConnection(server)
    uma = KeycloakUMA(connection)  # type: ignore[arg-type]
    ticket_result = await uma.a_permissions_batch(CALLER_REQUESTS)
    print_result("async style 1: permission ticket + exchange", ticket_result, server)
    assert server.authorization_request_count == 2

    server2 = FakeKeycloakServer()
    openid = KeycloakOpenID(
        server_url="https://keycloak.example",
        realm_name="demo",
        client_id="demo-client",
    )
    openid.connection = FakeConnection(server2)  # type: ignore[assignment]
    token_result = await openid.a_permissions_batch("user-token", CALLER_REQUESTS)
    print_result("async style 2: token endpoint permissions", token_result, server2)
    assert server2.authorization_request_count == 1

    empty_result = await openid.a_permissions_batch("user-token", None)
    assert empty_result.network_requests == 0
    print("\nasync empty input -> 0 network requests: OK")


if __name__ == "__main__":
    run_sync()
    asyncio.run(run_async())
    print("\nraw JSON view of one result:")
    demo_server = FakeKeycloakServer()
    demo_conn = FakeConnection(demo_server)
    demo = KeycloakUMA(demo_conn)  # type: ignore[arg-type]
    outcome = demo.permissions_batch(CALLER_REQUESTS)
    print(
        json.dumps(
            [
                {
                    "index": item.request.index,
                    "resource": item.request.resource,
                    "status": item.status.value,
                    "missing": sorted(item.missing_scopes or []),
                }
                for item in outcome.results
            ],
            indent=2,
        )
    )
