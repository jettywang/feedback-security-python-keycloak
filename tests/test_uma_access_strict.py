"""
Unit tests for has_uma_access strict rsid/rsname handling.

These tests mock the token-endpoint call (``uma_permissions`` /
``a_uma_permissions``) so the authorization logic can be exercised without a running
Keycloak server. Synchronous and asynchronous clients must produce identical results.
"""

from collections.abc import Callable

import pytest
from keycloak import KeycloakOpenID
from keycloak.exceptions import KeycloakAuthenticationError, KeycloakPostError
from keycloak.uma_permissions import IdentityType, PermissionRequest


def _make_client() -> KeycloakOpenID:
    """Build a client whose network layer is never touched by these tests."""
    return KeycloakOpenID(
        server_url="http://localhost:8080/",
        realm_name="master",
        client_id="client",
    )


# Two resources whose display names cross the other resource's id.
ALPHA_GRANT = {"rsid": "id-alpha", "rsname": "id-beta", "scopes": []}
BETA_GRANT = {"rsid": "id-beta", "rsname": "id-alpha", "scopes": []}


def _fake_uma_permissions(token: str, permissions: object) -> list:
    """Stand-in synchronous token-endpoint response for the granted Alpha resource."""
    return [ALPHA_GRANT]


@pytest.fixture()
def grant(monkeypatch: pytest.MonkeyPatch) -> Callable[[object], KeycloakOpenID]:
    """Return a helper that wires a synchronous permission response into a client."""
    oid = _make_client()

    def _configure(response: object) -> KeycloakOpenID:
        def _fake_uma_permissions(token: str, permissions: object) -> list:
            if isinstance(response, Exception):
                raise response
            return response  # type: ignore[return-value]

        monkeypatch.setattr(oid, "uma_permissions", _fake_uma_permissions)
        return oid

    return _configure


def test_compat_mode_name_collision_grants_access(
    grant: Callable[[object], KeycloakOpenID],
) -> None:
    """Compatibility mode matches a name request against rsname, even if it equals an rsid."""
    status = grant([ALPHA_GRANT]).has_uma_access("token", "id-beta")
    assert status.is_logged_in is True
    assert status.is_authorized is True
    assert status.missing_permissions == set()


def test_strict_mode_name_collision_does_not_grant(
    grant: Callable[[object], KeycloakOpenID],
) -> None:
    """Strict id mode compares against rsid only, so the crossed name cannot grant access."""
    status = grant([ALPHA_GRANT]).has_uma_access("token", "id-beta", strict_id_mode=True)
    assert status.is_authorized is False
    missing = status.missing_permissions
    assert {str(item) for item in missing} == {"id-beta"}
    assert next(iter(missing)).identity_type is IdentityType.RSID


def test_strict_mode_grants_real_rsid(grant: Callable[[object], KeycloakOpenID]) -> None:
    """Strict id mode still grants when the requested value is the actual rsid."""
    status = grant([ALPHA_GRANT]).has_uma_access("token", "id-alpha", strict_id_mode=True)
    assert status.is_authorized is True
    assert status.missing_permissions == set()


def test_explicit_rsid_request_uses_rsid_in_compat_mode(
    grant: Callable[[object], KeycloakOpenID],
) -> None:
    """An explicitly labeled rsid request matches rsid even in compatibility mode."""
    request = PermissionRequest(resource="id-alpha", identity_type=IdentityType.RSID)
    status = grant([ALPHA_GRANT]).has_uma_access("token", [request])
    assert status.is_authorized is True


def test_resource_level_and_scoped_do_not_overwrite(
    grant: Callable[[object], KeycloakOpenID],
) -> None:
    """Resource-level and scoped permissions never satisfy each other."""
    response = [{"rsid": "id-alpha", "rsname": "alpha", "scopes": ["read"]}]
    status = grant(response).has_uma_access("token", ["alpha", "alpha#read", "alpha#delete"])
    assert status.is_authorized is False
    assert {str(item) for item in status.missing_permissions} == {"alpha", "alpha#delete"}


def test_missing_identity_type_is_preserved(
    grant: Callable[[object], KeycloakOpenID],
) -> None:
    """Missing permissions retain the rsname/rsid identity of the original request."""
    request = PermissionRequest(resource="id-beta", identity_type=IdentityType.RSID)
    status = grant([ALPHA_GRANT]).has_uma_access("token", [request])
    missing = status.missing_permissions
    assert len(missing) == 1
    assert next(iter(missing)).identity_type is IdentityType.RSID


def test_incomplete_server_response_is_denied_safely(
    grant: Callable[[object], KeycloakOpenID],
) -> None:
    """Malformed server entries never raise and never satisfy a request."""
    status = grant([None, "no-dict", {}, {"rsname": ""}]).has_uma_access("token", "alpha")
    assert status.is_authorized is False
    assert {str(item) for item in status.missing_permissions} == {"alpha"}


def test_duplicate_requests_collapse(grant: Callable[[object], KeycloakOpenID]) -> None:
    """Repeated identical requests are de-duplicated and reported once."""
    status = grant([BETA_GRANT]).has_uma_access(
        "token",
        ["id-alpha", "id-alpha"],
        strict_id_mode=True,
    )
    assert {str(item) for item in status.missing_permissions} == {"id-alpha"}


def test_forbidden_returns_unauthorized_status(
    grant: Callable[[object], KeycloakOpenID],
) -> None:
    """A 403 response marks the user logged in but not authorized and keeps the request."""
    error = KeycloakPostError("forbidden", response_code=403)
    status = grant(error).has_uma_access("token", "alpha", strict_id_mode=True)
    assert status.is_logged_in is True
    assert status.is_authorized is False
    assert {str(item) for item in status.missing_permissions} == {"alpha"}
    assert next(iter(status.missing_permissions)).identity_type is IdentityType.RSID


def test_unauthorized_returns_not_logged_in(
    grant: Callable[[object], KeycloakOpenID],
) -> None:
    """A 401 response marks the user as not logged in."""
    error = KeycloakAuthenticationError("unauthorized", response_code=401)
    status = grant(error).has_uma_access("token", "alpha")
    assert status.is_logged_in is False
    assert status.is_authorized is False
    assert {str(item) for item in status.missing_permissions} == {"alpha"}


def test_other_error_is_raised(grant: Callable[[object], KeycloakOpenID]) -> None:
    """Unexpected transport errors propagate instead of being swallowed."""
    error = KeycloakPostError("boom", response_code=500)
    with pytest.raises(KeycloakPostError):
        grant(error).has_uma_access("token", "alpha")


@pytest.mark.asyncio()
async def test_async_matches_sync_for_crossed_resources(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """The asynchronous client returns the same strict/compat decisions as the sync one."""
    sync_client = _make_client()
    async_client = _make_client()

    async def _fake_a_uma_permissions(token: str, permissions: object) -> list:
        return [ALPHA_GRANT]

    monkeypatch.setattr(
        sync_client,
        "uma_permissions",
        _fake_uma_permissions,
    )
    monkeypatch.setattr(async_client, "a_uma_permissions", _fake_a_uma_permissions)

    for strict_id_mode in (False, True):
        sync_status = sync_client.has_uma_access(
            "token",
            "id-beta",
            strict_id_mode=strict_id_mode,
        )
        async_status = await async_client.a_has_uma_access(
            "token",
            "id-beta",
            strict_id_mode=strict_id_mode,
        )
        assert sync_status.is_authorized == async_status.is_authorized
        assert {str(item) for item in sync_status.missing_permissions} == {
            str(item) for item in async_status.missing_permissions
        }


@pytest.mark.asyncio()
async def test_async_strict_mode_preserves_identity(monkeypatch: pytest.MonkeyPatch) -> None:
    """The async path also keeps the rsid identity of a denied strict request."""
    async_client = _make_client()

    async def _fake_a_uma_permissions(token: str, permissions: object) -> list:
        return [ALPHA_GRANT]

    monkeypatch.setattr(async_client, "a_uma_permissions", _fake_a_uma_permissions)
    status = await async_client.a_has_uma_access("token", "id-beta", strict_id_mode=True)
    assert status.is_authorized is False
    assert next(iter(status.missing_permissions)).identity_type is IdentityType.RSID


@pytest.mark.asyncio()
async def test_async_forbidden_and_unauthorized(monkeypatch: pytest.MonkeyPatch) -> None:
    """The async path maps 403/401 to the same statuses as the synchronous client."""
    async_client = _make_client()
    forbidden_error = KeycloakPostError("forbidden", response_code=403)

    async def _raise_forbidden(token: str, permissions: object) -> list:
        raise forbidden_error

    monkeypatch.setattr(async_client, "a_uma_permissions", _raise_forbidden)
    forbidden = await async_client.a_has_uma_access("token", "alpha")
    assert forbidden.is_logged_in is True
    assert forbidden.is_authorized is False
    assert {str(item) for item in forbidden.missing_permissions} == {"alpha"}

    unauthorized_error = KeycloakAuthenticationError("unauthorized", response_code=401)

    async def _raise_unauthorized(token: str, permissions: object) -> list:
        raise unauthorized_error

    monkeypatch.setattr(async_client, "a_uma_permissions", _raise_unauthorized)
    unauthorized = await async_client.a_has_uma_access("token", "alpha")
    assert unauthorized.is_logged_in is False
    assert unauthorized.is_authorized is False
