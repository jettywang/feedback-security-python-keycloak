import copy
import json
import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from auth_flow_audit import (  # noqa: E402
    AuditError,
    audit,
    build_tree,
    load_bundle,
    snapshot_id,
)

FIXTURES = Path(__file__).resolve().parent.parent / "fixtures"


def load_fixture(name):
    return load_bundle(str(FIXTURES / name))


def test_mandatory_mfa_is_enforced():
    result = audit(load_fixture("mandatory_mfa.json"))
    assert result["verdict"] == "MFA_ENFORCED"
    assert len(result["analysed"]) == 1
    path = result["analysed"][0]["path"]
    assert path.steps == ["auth-username-password-form", "auth-otp-form"]
    assert not result["analysed"][0]["password_only"]


def test_disabled_executions_are_pruned():
    result = audit(load_fixture("mandatory_mfa.json"))
    steps = [s for a in result["analysed"] for s in a["path"].steps]
    assert "auth-spnego" not in steps


def test_bypassable_mfa_has_password_only_path():
    result = audit(load_fixture("bypassable_mfa.json"))
    assert result["verdict"] == "MFA_BYPASSABLE"
    password_only = [a for a in result["analysed"] if a["password_only"]]
    assert len(password_only) == 1
    path = password_only[0]["path"]
    assert path.steps == ["auth-username-password-form"]
    assert len(path.conditions) == 1
    condition = path.conditions[0]
    assert condition.provider_id == "conditional-user-configured"
    assert condition.assumed is False
    assert condition.certainty == "known-runtime"


def test_unknown_condition_produces_unknown_branches():
    result = audit(load_fixture("unknown_condition.json"))
    assert result["verdict"] == "UNKNOWN_DEPENDENT"
    # both outcomes of the unknown condition are enumerated, neither assumed
    assert len(result["analysed"]) == 2
    password_only = [a for a in result["analysed"] if a["password_only"]]
    assert len(password_only) == 1
    unknowns = password_only[0]["unknown_conditions"]
    assert len(unknowns) == 1
    assert unknowns[0].provider_id == "com.acme.conditional-risk-engine"
    assert unknowns[0].certainty == "unknown"


def test_snapshot_binds_to_content_not_realm():
    bundle = load_fixture("bypassable_mfa.json")
    original = snapshot_id(bundle)
    renamed = copy.deepcopy(bundle)
    renamed["export_meta"]["realm"] = "some-other-realm"
    renamed["export_meta"]["exported_at"] = "2030-01-01T00:00:00+00:00"
    assert snapshot_id(renamed) == original
    changed = copy.deepcopy(bundle)
    changed["executions"]["browser"][0]["requirement"] = "REQUIRED"
    assert snapshot_id(changed) != original


def test_snapshots_differ_between_fixtures():
    ids = {
        snapshot_id(load_fixture(name))
        for name in ("mandatory_mfa.json", "bypassable_mfa.json", "unknown_condition.json")
    }
    assert len(ids) == 3


def test_execution_order_follows_level_and_index():
    bundle = load_fixture("mandatory_mfa.json")
    shuffled = copy.deepcopy(bundle)
    shuffled["executions"]["browser"] = list(reversed(shuffled["executions"]["browser"]))
    tree_original = build_tree(bundle, "browser")
    tree_shuffled = build_tree(shuffled, "browser")
    assert [c.node_id for c in tree_original.children] == [
        c.node_id for c in tree_shuffled.children
    ]


def test_cycle_in_subflows_is_rejected():
    bundle = load_fixture("mandatory_mfa.json")
    bundle["executions"]["browser-forms"].append(
        {
            "id": "e9",
            "requirement": "REQUIRED",
            "displayName": "loop",
            "alias": "browser",
            "authenticationFlow": True,
            "level": 0,
            "index": 1,
        }
    )
    with pytest.raises(AuditError, match="cycle"):
        build_tree(bundle, "browser")


def test_missing_flow_executions_is_rejected():
    bundle = load_fixture("mandatory_mfa.json")
    del bundle["executions"]["browser-forms"]
    with pytest.raises(AuditError, match="no executions exported"):
        build_tree(bundle, "browser")


def test_unrecognised_requirement_warns_and_is_pruned():
    bundle = load_fixture("mandatory_mfa.json")
    bundle["executions"]["browser"][1]["requirement"] = "SOMEDAY"
    result = audit(bundle)
    assert result["verdict"] == "MFA_BYPASSABLE"
    assert any("SOMEDAY" in w for w in result["warnings"])
    steps = [s for a in result["analysed"] for s in a["path"].steps]
    assert "auth-otp-form" not in steps


def test_conditional_flow_without_condition_is_unknown():
    bundle = load_fixture("bypassable_mfa.json")
    bundle["executions"]["browser-conditional-otp"] = [
        e
        for e in bundle["executions"]["browser-conditional-otp"]
        if e["providerId"] != "conditional-user-configured"
    ]
    result = audit(bundle)
    assert result["verdict"] == "UNKNOWN_DEPENDENT"


def test_report_mentions_snapshot_and_scope():
    from auth_flow_audit import render_report

    result = audit(load_fixture("unknown_condition.json"))
    report = render_report(result)
    assert result["snapshot_id"] in report
    assert "not the realm name" in report
    assert "does not replace login integration tests" in report
    assert "UNKNOWN" in report


def test_bundle_requires_keys(tmp_path):
    bad = tmp_path / "bad.json"
    bad.write_text(json.dumps({"flows": []}))
    with pytest.raises(AuditError, match="export_meta"):
        load_bundle(str(bad))
