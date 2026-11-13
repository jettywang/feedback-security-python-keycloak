#!/usr/bin/env python3
"""Demonstrate rsid/rsname disambiguation in ``has_uma_access`` offline."""

# Two resources are created whose display names cross the other resource's id:
#
#     resource Alpha: rsid="id-alpha", rsname="id-beta"
#     resource Beta:  rsid="id-beta",  rsname="id-alpha"
#
# The authenticated user is granted *only* resource Alpha. The token endpoint is mocked so
# the demo runs fully offline, but it exercises the real ``KeycloakOpenID.has_uma_access``
# code path (synchronous and asynchronous) shared with production use.
#
# Run it with:
#
#     python bin/demo_uma_strict_id_mode.py

from __future__ import annotations

import asyncio

from keycloak import KeycloakOpenID
from keycloak.uma_permissions import AuthStatus, IdentityType, PermissionRequest

# The permission ticket response Keycloak would return for a user that only owns Alpha.
GRANTED_ALPHA = [{"rsid": "id-alpha", "rsname": "id-beta", "scopes": []}]


def build_client() -> KeycloakOpenID:
    """Build a client and replace the network call with the canned server response."""
    client = KeycloakOpenID(
        server_url="http://localhost:8080/",
        realm_name="demo",
        client_id="demo-client",
    )

    def _uma_permissions(_token: str, _permissions: object) -> list:
        return GRANTED_ALPHA

    async def _a_uma_permissions(_token: str, _permissions: object) -> list:
        return GRANTED_ALPHA

    client.uma_permissions = _uma_permissions  # type: ignore[method-assign]
    client.a_uma_permissions = _a_uma_permissions  # type: ignore[method-assign]
    return client


def heading(text: str) -> None:
    """Print a section heading."""
    print(f"\n=== {text} ===")


def show(label: str, status: AuthStatus) -> None:
    """Print an authorization result and the identity of any missing permission."""
    missing = status.missing_permissions
    identities = sorted(item.identity_type.value for item in missing)
    print(
        f"{label:38} authorized={status.is_authorized!s:<5} "
        f"missing={ {str(item) for item in missing} } identity={identities}",
    )


def main() -> None:
    """Run the compatibility-vs-strict comparison."""
    client = build_client()

    heading("Resources (name/id cross)")
    print("Alpha -> rsid='id-alpha', rsname='id-beta'   (granted to the user)")
    print("Beta  -> rsid='id-beta',  rsname='id-alpha'  (NOT granted)")

    heading("Request access to the value 'id-beta'")
    # Compatibility mode: a plain string is interpreted as a resource *name*. Alpha's
    # rsname is 'id-beta', so the request succeeds even though 'id-beta' is also Beta's id.
    compat = client.has_uma_access("token", "id-beta")
    show("compat mode, plain string (rsname)", compat)

    # Strict id mode: every requested value is interpreted as an rsid. Alpha's rsid is
    # 'id-alpha', so a display-name collision can never grant access to resource Beta.
    strict = client.has_uma_access("token", "id-beta", strict_id_mode=True)
    show("strict id mode (rsid only)", strict)

    heading("Explicit identity still works in compatibility mode")
    by_id = client.has_uma_access(
        "token",
        [PermissionRequest(resource="id-alpha", identity_type=IdentityType.RSID)],
    )
    show("explicit rsid request for Alpha", by_id)

    heading("Async client gives identical results")
    async_compat, async_strict = asyncio.run(_async_checks(client))
    show("async compat mode", async_compat)
    show("async strict id mode", async_strict)

    heading("Conclusion")
    print("In strict id mode any display-name collision is rejected: Beta stays inaccessible.")


async def _async_checks(client: KeycloakOpenID) -> tuple:
    """Run the same two requests through the asynchronous client."""
    compat = await client.a_has_uma_access("token", "id-beta")
    strict = await client.a_has_uma_access("token", "id-beta", strict_id_mode=True)
    return compat, strict


if __name__ == "__main__":
    main()
