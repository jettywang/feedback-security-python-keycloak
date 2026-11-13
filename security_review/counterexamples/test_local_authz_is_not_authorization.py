"""
Executable counterexamples: python-keycloak's local Authorization parser
is a display helper, not an authorization decision point.

Each test needs no Keycloak server: token introspection is stubbed at
``KeycloakOpenID._token_info`` and configs are loaded from
``security_review/counterexamples/configs``.

Run with:
    .venv/bin/python -m pytest -q -o addopts= security_review/counterexamples/
"""

from __future__ import annotations

import json
import pathlib

import pytest

from keycloak import KeycloakOpenID
from keycloak.exceptions import KeycloakAuthorizationConfigError

CONFIG_DIR = pathlib.Path(__file__).parent / "configs"


def make_client(config_name: str, roles: list[str], client_id: str = "app") -> KeycloakOpenID:
    """Build an offline client with a loaded local authorization config."""
    oid = KeycloakOpenID(
        server_url="http://127.0.0.1:1",
        realm_name="demo",
        client_id=client_id,
    )
    oid.load_authorization_config(str(CONFIG_DIR / config_name))
    oid._token_info = lambda token, method, **kwargs: {  # noqa: ARG005
        "active": True,
        "resource_access": {client_id: {"roles": roles}},
    }
    return oid


def permission_names(oid: KeycloakOpenID) -> list[str]:
    """Return local permission names for a token, as get_permissions would report them."""
    result = oid.get_permissions("ignored-token")
    return sorted(str(p) for p in (result or []))


def test_decision_strategy_is_ignored_unanymous_vs_affirmative() -> None:
    """Same role membership, opposite server verdicts, identical local output."""
    unanymous = make_client("01_unanymous_required_roles.json", ["alice"])
    affirmative = make_client("02_affirmative_required_roles.json", ["alice"])

    # Server truth: UNANIMOUS over required alice+bob DENIES (bob missing);
    # AFFIRMATIVE over the same roles GRANTS. Local output cannot tell them apart.
    assert permission_names(unanymous) == permission_names(affirmative) == ["Permission: read-doc (resource)"]


def test_role_required_flag_is_ignored() -> None:
    """A required role the user lacks is treated exactly like an optional role."""
    unanymous = make_client("01_unanymous_required_roles.json", ["alice"])
    assert permission_names(unanymous) == ["Permission: read-doc (resource)"]

    # Only alice is present, so the required bob is missing: server DENIES.
    # Local code reports the permission anyway because it only checks membership.
    assert unanymous.authorization.policies["engineers"].roles[1].required is True


def test_negative_logic_inverts_without_local_effect() -> None:
    """NEGATIVE logic is parsed but never applied; both users get the same answer."""
    has_role = make_client("03_negative_logic.json", ["alice"])
    lacks_role = make_client("03_negative_logic.json", ["bob"])

    # Server: NEGATIVE + alice-present => DENY; NEGATIVE + alice-absent => GRANT.
    # Local: membership-only -> alice granted, bob denied. Exactly inverted.
    assert permission_names(has_role) == ["Permission: read-doc (resource)"]
    assert permission_names(lacks_role) == []


def test_unmodeled_group_policy_silently_dropped_from_permission() -> None:
    """A permission bound to role+group is treated as role-only when the group is unmodeled."""
    oid = make_client("04_role_and_group_to_same_permission.json", ["alice"])
    # Server: UNANIMOUS over (role alice AND group g-engineering). The user is not in
    # the group, so the server DENIES. Local parser never models type=group, so the
    # permission binds only to alice-role and is reported as granted. This is a
    # silent widening: a composite rule became a single-clause rule.
    assert permission_names(oid) == ["Permission: read-doc (resource)"]
    assert "eng-group" not in oid.authorization.policies


def test_scope_and_resource_permissions_are_not_differentiated() -> None:
    """get_permissions returns resource and scope grants with no resource/scope matching."""
    oid = make_client("05_scope_and_resource_same_policy.json", ["alice"])
    # The client never asks for a resource or scope. Local code returns both grants,
    # so a caller that only needs doc-1 read also appears to hold an any-scope grant.
    assert permission_names(oid) == [
        "Permission: doc-2-any-scope (scope)",
        "Permission: write-doc-1 (resource)",
    ]


def test_policy_declared_after_permission_is_silently_dropped() -> None:
    """Load order changes meaning: applyPolicies only binds to already-loaded policies."""
    oid = make_client("06_permission_before_policy.json", ["alice"])
    # Server resolves applyPolicies by name regardless of declaration order; it GRANTS.
    # Local parser drops the binding because alice-role is not yet in self.policies,
    # so it DENIES here (fail-closed for this order). A permission declared before a
    # policy that is later replaced has the mirror-image misbinding (fail-open).
    assert permission_names(oid) == []
    assert [str(p) for p in oid.get_policies("ignored-token") or []] == ["Policy: alice-role (role)"]


def test_reload_never_clears_previous_policies() -> None:
    """Two load_authorization_config calls accumulate; stale grants stay visible."""
    oid = make_client("01_unanymous_required_roles.json", ["alice"])
    assert permission_names(oid) == ["Permission: read-doc (resource)"]

    oid.load_authorization_config(str(CONFIG_DIR / "03_negative_logic.json"))
    # The second config has no read-doc permission and a NEGATIVE policy, yet the
    # first config's read-doc grant is still returned because load_config only adds.
    # It is returned twice: a second Permission object with the same name is appended.
    assert permission_names(oid) == [
        "Permission: read-doc (resource)",
        "Permission: read-doc (resource)",
    ]


def test_duplicate_policy_name_last_declaration_wins() -> None:
    """A repeated policy name replaces the earlier object (silent last-wins)."""
    with open(CONFIG_DIR / "01_unanymous_required_roles.json") as fp:
        raw = json.load(fp)
    original = raw["policies"][0]
    replacement = json.loads(json.dumps(original))
    replacement["config"]["roles"] = json.dumps([{"id": "app/bob", "required": True}])
    raw["policies"].append(replacement)

    oid = KeycloakOpenID(server_url="http://127.0.0.1:1", realm_name="demo", client_id="app")
    oid.authorization.load_config(raw)
    oid._token_info = lambda token, method, **kwargs: {  # noqa: ARG005
        "active": True,
        "resource_access": {"app": {"roles": ["alice"]}},
    }
    # The duplicate replaced the alice entry, so alice no longer matches even though
    # the permission still names the same policy.
    assert [str(p) for p in oid.get_policies("t") or []] == []
    assert "engineers" in oid.authorization.policies


def test_missing_resource_access_returns_none_not_denied() -> None:
    """No client roles yields None (indistinguishable from "not configured")."""
    oid = KeycloakOpenID(server_url="http://127.0.0.1:1", realm_name="demo", client_id="app")
    oid.load_authorization_config(str(CONFIG_DIR / "01_unanymous_required_roles.json"))
    oid._token_info = lambda token, method, **kwargs: {  # noqa: ARG005
        "active": True,
        "resource_access": {},
    }
    # Callers must treat None as deny; the API advertises "no roles" the same way it
    # advertises "no config" (the latter is an exception, the former is None).
    assert oid.get_permissions("ignored-token") is None
    assert oid.get_policies("ignored-token") is None


def test_load_config_ignores_enforcement_mode() -> None:
    """policyEnforcementMode / allowRemoteResourceManagement are never read."""
    with open(CONFIG_DIR / "01_unanymous_required_roles.json") as fp:
        raw = json.load(fp)
    raw["policyEnforcementMode"] = "DISABLED"

    oid = KeycloakOpenID(server_url="http://127.0.0.1:1", realm_name="demo", client_id="app")
    oid.authorization.load_config(raw)
    oid._token_info = lambda token, method, **kwargs: {  # noqa: ARG005
        "active": True,
        "resource_access": {"app": {"roles": ["bob"]}},
    }
    # A DISABLED server bypass is not representable: the loader stores only the policy
    # list, so the local result is the same as under ENFORCING. Bob alone still matches
    # by membership even though the server (UNANIMOUS over required alice+bob) denies.
    assert oid.authorization.policies
    assert permission_names(oid) == ["Permission: read-doc (resource)"]


def test_scope_permission_without_apply_policies_is_silently_ignored() -> None:
    """Scope permission missing applyPolicies is skipped; resource permission raises KeyError."""
    data = {
        "policies": [
            {
                "name": "role-p",
                "type": "role",
                "logic": "POSITIVE",
                "decisionStrategy": "UNANIMOUS",
                "config": {"roles": json.dumps([{"id": "app/alice", "required": False}])},
            },
            {
                "name": "scope-p",
                "type": "scope",
                "logic": "POSITIVE",
                "decisionStrategy": "UNANIMOUS",
                "config": {"scopes": "[]"},
            },
        ],
        "scopes": [],
    }
    oid = KeycloakOpenID(server_url="http://127.0.0.1:1", realm_name="demo", client_id="app")
    oid.authorization.load_config(data)
    # The scope permission is neither registered nor rejected: a config that the
    # server would reject or evaluate is silently dropped locally.
    assert "scope-p" not in oid.authorization.policies
    assert oid.authorization.policies["role-p"].permissions == []


def test_malformed_local_config_is_not_a_denial_object() -> None:
    """Structural errors raise Python exceptions, not an authorization denial."""
    oid = KeycloakOpenID(server_url="http://127.0.0.1:1", realm_name="demo", client_id="app")
    with pytest.raises(KeyError):
        # No "policies" key: the parser raises KeyError, not a denial object.
        oid.authorization.load_config({"scopes": []})
    with pytest.raises(KeyError):
        # A role policy missing logic/decisionStrategy is a structural KeyError.
        oid.authorization.load_config({"policies": [{"name": "P", "type": "role"}]})
