#
# Copyright (C) 2017 Marcos Pereira <marcospereira.mpj@gmail.com>
#
# This program is free software: you can redistribute it and/or modify
# it under the terms of the GNU Lesser General Public License as published by
# the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU Lesser General Public License for more details.
#
# You should have received a copy of the GNU Lesser General Public License
# along with this program.  If not, see <http://www.gnu.org/licenses/>.

"""Test uma permissions."""

import re

import pytest
from keycloak.exceptions import KeycloakPermissionFormatError
from keycloak.uma_permissions import (
    AuthStatus,
    IdentityType,
    PermissionRequest,
    Resource,
    Scope,
    UMAPermission,
    build_permission_param,
    evaluate_uma_access,
    parse_permission_requests,
)


def test_uma_permission_obj() -> None:
    """Test generic UMA permission."""
    p1 = UMAPermission(permission=Resource("Resource"))
    assert p1.resource == "Resource"
    assert p1.scope == ""
    assert repr(p1) == "Resource"
    assert str(p1) == "Resource"

    p2 = UMAPermission(permission=Scope("Scope"))
    assert p2.resource == ""
    assert p2.scope == "Scope"
    assert repr(p2) == "#Scope"
    assert str(p2) == "#Scope"
    assert {p1, p1} != {p2, p2}


def test_resource_with_scope_obj() -> None:
    """Test resource with scope."""
    r = Resource("Resource1")
    s = Scope("Scope1")
    assert r(s) == "Resource1#Scope1"


def test_scope_with_resource_obj() -> None:
    """Test scope with resource."""
    r = Resource("Resource1")
    s = Scope("Scope1")
    assert s(r) == "Resource1#Scope1"


def test_resource_scope_str() -> None:
    """Test resource scope as string."""
    r = Resource("Resource1")
    s = "Scope1"
    assert r(scope=s) == "Resource1#Scope1"


def test_scope_resource_str() -> None:
    """Test scope resource as string."""
    r = "Resource1"
    s = Scope("Scope1")
    assert s(resource=r) == "Resource1#Scope1"


def test_build_permission_none() -> None:
    """Test build permission param with None."""
    assert build_permission_param(None) == set()


def test_build_permission_empty_str() -> None:
    """Test build permission param with an empty string."""
    assert build_permission_param("") == set()


def test_build_permission_empty_list() -> None:
    """Test build permission param with an empty list."""
    assert build_permission_param([]) == set()


def test_build_permission_empty_tuple() -> None:
    """Test build permission param with an empty tuple."""
    assert build_permission_param(()) == set()


def test_build_permission_empty_set() -> None:
    """Test build permission param with an empty set."""
    assert build_permission_param(set()) == set()


def test_build_permission_empty_dict() -> None:
    """Test build permission param with an empty dict."""
    assert build_permission_param({}) == set()


def test_build_permission_str() -> None:
    """Test build permission param as string."""
    assert build_permission_param("resource1") == {"resource1"}


def test_build_permission_list_str() -> None:
    """Test build permission param with list of strings."""
    assert build_permission_param(["res1#scope1", "res1#scope2"]) == {"res1#scope1", "res1#scope2"}


def test_build_permission_tuple_str() -> None:
    """Test build permission param with tuple of strings."""
    assert build_permission_param(("res1#scope1", "res1#scope2")) == {"res1#scope1", "res1#scope2"}


def test_build_permission_set_str() -> None:
    """Test build permission param with set of strings."""
    assert build_permission_param({"res1#scope1", "res1#scope2"}) == {"res1#scope1", "res1#scope2"}


def test_build_permission_tuple_dict_str_str() -> None:
    """Test build permission param with dictionary."""
    assert build_permission_param({"res1": "scope1"}) == {"res1#scope1"}


def test_build_permission_tuple_dict_str_list_str() -> None:
    """Test build permission param with dictionary of list."""
    assert build_permission_param({"res1": ["scope1", "scope2"]}) == {"res1#scope1", "res1#scope2"}


def test_build_permission_tuple_dict_str_list_str2() -> None:
    """Test build permission param with mutliple-keyed dictionary."""
    assert build_permission_param(
        {"res1": ["scope1", "scope2"], "res2": ["scope2", "scope3"]},
    ) == {"res1#scope1", "res1#scope2", "res2#scope2", "res2#scope3"}


def test_build_permission_uma() -> None:
    """Test build permission param with UMA."""
    assert build_permission_param(Resource("res1")(Scope("scope1"))) == {"res1#scope1"}


def test_build_permission_uma_list() -> None:
    """Test build permission param with list of UMAs."""
    assert build_permission_param(
        [Resource("res1")(Scope("scope1")), Resource("res1")(Scope("scope2"))],
    ) == {"res1#scope1", "res1#scope2"}


def test_build_permission_misbuilt_dict_str_list_list_str() -> None:
    """Test bad build of permission param from dictionary."""
    with pytest.raises(KeycloakPermissionFormatError) as err:
        build_permission_param({"res1": [["scope1", "scope2"]]})
    assert err.match(re.escape("misbuilt permission {'res1': [['scope1', 'scope2']]}"))


def test_build_permission_misbuilt_dict_non_iterable() -> None:
    """Test bad build of permission param from non-iterable."""
    with pytest.raises(KeycloakPermissionFormatError) as err:
        build_permission_param({"res1": 5})
    assert err.match(re.escape("misbuilt permission {'res1': 5}"))


def test_auth_status_bool() -> None:
    """Test bool method of AuthStatus."""
    assert not bool(AuthStatus(is_logged_in=True, is_authorized=False, missing_permissions=""))
    assert bool(AuthStatus(is_logged_in=True, is_authorized=True, missing_permissions=""))


def test_build_permission_without_scopes() -> None:
    """Test build permission param with scopes."""
    assert build_permission_param(permissions={"Resource": None}) == {"Resource"}


def test_permission_request_identity_and_text() -> None:
    """Test typed permission requests keep the wire text and the identity type."""
    by_name = PermissionRequest.from_string("Resource#read", IdentityType.RSNAME)
    assert by_name.resource == "Resource"
    assert by_name.scope == "read"
    assert str(by_name) == "Resource#read"
    assert by_name.identity_type is IdentityType.RSNAME

    by_id = PermissionRequest(resource="abc-123", identity_type=IdentityType.RSID)
    assert by_id.scope == ""
    assert str(by_id) == "abc-123"
    assert by_id.identity_type is IdentityType.RSID

    # repr stays string-compatible, including inside containers
    assert repr(by_name) == "'Resource#read'"
    assert str({by_id}) == "{'abc-123'}"

    # equality/hashing follow the textual representation
    assert by_name == "Resource#read"
    assert {by_name} == {"Resource#read"}


def test_parse_permission_requests_default_identity() -> None:
    """Test parsing assigns the requested default identity to untyped inputs."""
    parsed = parse_permission_requests(
        ["res#read", "res2", Resource("res3")(Scope("write"))],
        IdentityType.RSID,
    )
    assert {str(item) for item in parsed} == {"res#read", "res2", "res3#write"}
    assert all(item.identity_type is IdentityType.RSID for item in parsed)


def test_parse_permission_requests_keeps_explicit_identity() -> None:
    """Test parsing preserves the identity of an explicit typed request."""
    explicit = PermissionRequest(resource="res", identity_type=IdentityType.RSID)
    parsed = parse_permission_requests([explicit, "res#scope"], IdentityType.RSNAME)
    by_identity = {item.resource + "#" + item.scope: item.identity_type for item in parsed}
    assert by_identity["res#"] is IdentityType.RSID
    assert by_identity["res#scope"] is IdentityType.RSNAME


def test_parse_permission_requests_dict() -> None:
    """Test parsing dictionary inputs labels every generated scope."""
    parsed = parse_permission_requests(
        {"res": ["read", "write"], "other": None},
        IdentityType.RSID,
    )
    assert {str(item) for item in parsed} == {"res#read", "res#write", "other"}
    assert all(item.identity_type is IdentityType.RSID for item in parsed)


def test_parse_permission_requests_dedup_is_deterministic() -> None:
    """Test repeated textual permissions collapse to a single request."""
    parsed = parse_permission_requests(
        ["res#read", "res#read", PermissionRequest.from_string("res#read", IdentityType.RSID)],
        IdentityType.RSNAME,
    )
    assert len(parsed) == 1
    assert next(iter(parsed)).identity_type is IdentityType.RSNAME


def test_parse_permission_requests_misbuilt() -> None:
    """Test parsing rejects the same malformed inputs as build_permission_param."""
    with pytest.raises(KeycloakPermissionFormatError):
        parse_permission_requests({"res": 5}, IdentityType.RSID)
    with pytest.raises(KeycloakPermissionFormatError):
        parse_permission_requests([1], IdentityType.RSID)


def test_evaluate_empty_request_is_authorized() -> None:
    """Test that no requested permission means nothing is missing."""
    assert evaluate_uma_access(set(), [{"rsid": "r", "rsname": "n"}]) == set()


def test_evaluate_resource_level_grant() -> None:
    """Test a grant without scopes satisfies only the resource-level request."""
    requested = parse_permission_requests(["Resource", "Resource#read"], IdentityType.RSNAME)
    granted = [{"rsid": "id", "rsname": "Resource", "scopes": []}]
    missing = evaluate_uma_access(requested, granted)
    assert {str(item) for item in missing} == {"Resource#read"}


def test_evaluate_scoped_grant_does_not_satisfy_resource_level() -> None:
    """Test a scoped grant cannot satisfy a resource-level request."""
    requested = parse_permission_requests(["Resource"], IdentityType.RSNAME)
    granted = [{"rsid": "id", "rsname": "Resource", "scopes": ["read"]}]
    missing = evaluate_uma_access(requested, granted)
    assert {str(item) for item in missing} == {"Resource"}


def test_evaluate_scope_match_and_mismatch() -> None:
    """Test only the exact granted scope satisfies a scoped request."""
    requested = parse_permission_requests(
        ["Resource#read", "Resource#delete"],
        IdentityType.RSNAME,
    )
    granted = [{"rsid": "id", "rsname": "Resource", "scopes": ["read"]}]
    missing = evaluate_uma_access(requested, granted)
    assert {str(item) for item in missing} == {"Resource#delete"}


def test_evaluate_missing_rsname_uses_rsid_identity() -> None:
    """Test an rsid-labeled request matches rsid even when rsname is absent."""
    requested = parse_permission_requests(
        [PermissionRequest(resource="id-1", identity_type=IdentityType.RSID)],
        IdentityType.RSNAME,
    )
    granted = [{"rsid": "id-1"}]  # incomplete response: no rsname, no scopes
    missing = evaluate_uma_access(requested, granted)
    assert missing == set()


def test_evaluate_rsname_request_ignores_rsid_collision() -> None:
    """Test an rsname-labeled request is not satisfied through the rsid field."""
    requested = parse_permission_requests(["shared-value"], IdentityType.RSNAME)
    granted = [{"rsid": "shared-value", "rsname": "something-else"}]
    missing = evaluate_uma_access(requested, granted)
    assert {str(item) for item in missing} == {"shared-value"}


def test_evaluate_strict_id_mode_ignores_display_name() -> None:
    """Test strict id mode compares against rsid only."""
    requested = parse_permission_requests(["id-1"], IdentityType.RSID)
    granted = [{"rsid": "id-1", "rsname": "id-1", "scopes": []}]
    assert evaluate_uma_access(requested, granted, strict_id_mode=True) == set()

    other = parse_permission_requests(["Display Name"], IdentityType.RSID)
    name_only_grant = [{"rsid": "id-9", "rsname": "Display Name", "scopes": []}]
    missing = evaluate_uma_access(other, name_only_grant, strict_id_mode=True)
    assert {str(item) for item in missing} == {"Display Name"}


def test_evaluate_duplicate_grants_are_idempotent() -> None:
    """Test repeated grant entries do not change the result."""
    requested = parse_permission_requests(["Resource#read"], IdentityType.RSNAME)
    grant = {"rsid": "id", "rsname": "Resource", "scopes": ["read"]}
    assert evaluate_uma_access(requested, [grant, grant, dict(grant)]) == set()


def test_evaluate_incomplete_server_response_is_safe() -> None:
    """Test malformed grant entries can never satisfy a request and never raise."""
    requested = parse_permission_requests(["Resource"], IdentityType.RSNAME)
    granted = [
        None,
        "not-a-dict",
        {},
        {"rsname": ""},
        {"rsid": "id-1", "rsname": "", "scopes": None},
    ]
    missing = evaluate_uma_access(requested, granted)
    assert {str(item) for item in missing} == {"Resource"}


def test_evaluate_does_not_mutate_requested() -> None:
    """Test the input set and the identity types of missing items are preserved."""
    requested = parse_permission_requests(["Resource#read"], IdentityType.RSID)
    snapshot = set(requested)
    evaluate_uma_access(requested, [{"rsid": "other", "rsname": "Resource"}])
    assert requested == snapshot
    missing = evaluate_uma_access(
        requested,
        [{"rsid": "other", "rsname": "Resource"}],
    )
    assert next(iter(missing)).identity_type is IdentityType.RSID


def test_evaluate_name_id_crossed_resources() -> None:
    """Test the canonical crossed name/id scenario in both modes."""
    # Two resources whose display names cross the other's id:
    #   Alpha: rsid="id-alpha", rsname="id-beta"  (Alpha's name equals Beta's id)
    #   Beta:  rsid="id-beta",  rsname="id-alpha"
    # The user is only granted Alpha.
    granted = [{"rsid": "id-alpha", "rsname": "id-beta", "scopes": []}]

    # Compatibility mode: requesting by the display name "id-beta" matches Alpha's rsname.
    compat_request = parse_permission_requests(["id-beta"], IdentityType.RSNAME)
    assert evaluate_uma_access(compat_request, granted, strict_id_mode=False) == set()

    # Strict id mode: "id-beta" is treated as an rsid; Alpha's rsid is "id-alpha",
    # so the display-name collision must not grant access to resource Beta.
    strict_request = parse_permission_requests(["id-beta"], IdentityType.RSID)
    strict_missing = evaluate_uma_access(strict_request, granted, strict_id_mode=True)
    assert {str(item) for item in strict_missing} == {"id-beta"}
    assert next(iter(strict_missing)).identity_type is IdentityType.RSID
