"""Offline audit of exported Keycloak authentication flows.

Reads a static export bundle (AuthenticationFlowRepresentation list plus
AuthenticationExecutionInfoRepresentation lists, as returned by
``KeycloakAdmin.get_authentication_flows`` and
``KeycloakAdmin.get_authentication_flow_executions``) and enumerates every
successful login path, so reviewers can tell whether a password-only branch
exists before changing the configuration.

The tool never talks to a Keycloak server. All conclusions are bound to a
content hash of the exported configuration (the snapshot id), not to the
realm name, which is not a stable identifier of a configuration revision.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import sys
from dataclasses import dataclass, field
from pathlib import Path

REQUIREMENTS = ("REQUIRED", "ALTERNATIVE", "DISABLED", "CONDITIONAL")

# Built-in conditional executors whose runtime meaning we can name. Even for
# these, the outcome depends on runtime state, so both branches are
# enumerated; the difference vs. custom executors is that the dependency is
# labelled instead of "unknown".
KNOWN_CONDITIONS = {
    "conditional-user-configured": "user has the required authenticator configured",
    "conditional-user-role": "user has the configured realm/client role",
    "conditional-user-attribute": "user attribute matches the configured rule",
    "conditional-sub-flow-executed": "referenced sub-flow already executed successfully",
}

# Well-known built-in authenticators, grouped by the factor they provide.
PASSWORD_PROVIDERS = {"auth-password-form", "auth-username-password-form"}
SECOND_FACTOR_PROVIDERS = {
    "auth-otp-form",
    "auth-webauthn-form",
    "auth-recovery-authn-code-form",
}
STRONG_PASSWORDLESS_PROVIDERS = {"auth-webauthn-passwordless-form"}
KNOWN_OTHER_PROVIDERS = {
    "auth-cookie",
    "auth-spnego",
    "identity-provider-redirector",
    "auth-username-form",
    "auth-x509-client-username-form",
    "auth-x509-client-username-form",
    "direct-grant-validate-username",
    "direct-grant-validate-password",
    "direct-grant-validate-otp",
}
KNOWN_AUTHENTICATORS = (
    PASSWORD_PROVIDERS
    | SECOND_FACTOR_PROVIDERS
    | STRONG_PASSWORDLESS_PROVIDERS
    | KNOWN_OTHER_PROVIDERS
)


class AuditError(Exception):
    """Raised for malformed exports or unsupported structures."""


@dataclass
class Condition:
    """A runtime predicate a path depends on."""

    provider_id: str
    description: str
    assumed: bool
    certainty: str  # "known-runtime" | "unknown"

    def render(self) -> str:
        value = "true" if self.assumed else "false"
        tag = "UNKNOWN" if self.certainty == "unknown" else "runtime"
        return f"{self.description} = {value} [{tag}: {self.provider_id}]"


@dataclass
class Path:
    """One successful login path: ordered authenticators plus conditions."""

    steps: list = field(default_factory=list)
    conditions: list = field(default_factory=list)

    def merged(self, other: "Path") -> "Path":
        return Path(self.steps + other.steps, self.conditions + other.conditions)


@dataclass
class Node:
    """An execution or (sub-)flow in the rebuilt hierarchy."""

    node_id: str
    label: str
    requirement: str
    provider_id: str | None = None
    is_flow: bool = False
    flow_alias: str | None = None
    children: list = field(default_factory=list)


def load_bundle(path: str) -> dict:
    with open(path, encoding="utf-8") as handle:
        bundle = json.load(handle)
    for key in ("export_meta", "flows", "executions"):
        if key not in bundle:
            raise AuditError(f"export bundle is missing '{key}'")
    return bundle


def snapshot_id(bundle: dict) -> str:
    """Content hash of the configuration payload only.

    export_meta (realm name, timestamps, tool version) is deliberately
    excluded: the snapshot identifies the configuration, not the realm.
    """
    payload = {"flows": bundle["flows"], "executions": bundle["executions"]}
    canonical = json.dumps(payload, sort_keys=True, separators=(",", ":"))
    return hashlib.sha256(canonical.encode("utf-8")).hexdigest()


def build_tree(bundle: dict, flow_alias: str) -> Node:
    """Rebuild the sub-flow hierarchy and execution order for one flow."""
    flows_by_alias = {f.get("alias"): f for f in bundle["flows"]}
    executions = bundle["executions"]
    warnings: list[str] = []

    def build(alias: str, stack: tuple) -> Node:
        if alias in stack:
            raise AuditError(f"cycle detected in sub-flow references: {' -> '.join(stack + (alias,))}")
        if alias not in executions:
            raise AuditError(f"no executions exported for flow alias '{alias}'")
        flow_repr = flows_by_alias.get(alias, {})
        node = Node(
            node_id=flow_repr.get("id", alias),
            label=alias,
            requirement="REQUIRED",
            is_flow=True,
            flow_alias=alias,
        )
        ordered = sorted(
            executions[alias],
            key=lambda e: (e.get("level", 0), e.get("index", 0), e.get("priority", 0)),
        )
        for exc in ordered:
            requirement = exc.get("requirement", "")
            if requirement not in REQUIREMENTS:
                warnings.append(
                    f"flow '{alias}': execution '{exc.get('displayName')}' has "
                    f"unrecognised requirement '{requirement}'; treated as DISABLED"
                )
                requirement = "DISABLED"
            child = Node(
                node_id=exc.get("id", "?"),
                label=exc.get("displayName") or exc.get("providerId") or "?",
                requirement=requirement,
                provider_id=exc.get("providerId"),
                is_flow=bool(exc.get("authenticationFlow")),
                flow_alias=exc.get("alias") or exc.get("flowAlias"),
            )
            if child.is_flow:
                if not child.flow_alias:
                    raise AuditError(
                        f"flow '{alias}': sub-flow execution '{child.label}' has no alias"
                    )
                child.children = build(child.flow_alias, stack + (alias,)).children
                child.label = child.flow_alias
            node.children.append(child)
        return node

    tree = build(flow_alias, ())
    tree._warnings = warnings  # noqa: SLF001 - attached for the report
    return tree


def _is_condition(execution: Node) -> bool:
    """Heuristic: inside a CONDITIONAL sub-flow, anything that is not a known
    authenticator is treated as a condition. Unknown providers therefore
    become unknown conditions instead of being silently ignored."""
    if execution.is_flow:
        return False
    provider = execution.provider_id or ""
    if provider in KNOWN_CONDITIONS:
        return True
    return provider not in KNOWN_AUTHENTICATORS


def _condition_for(execution: Node) -> Condition:
    provider = execution.provider_id or "<none>"
    if provider in KNOWN_CONDITIONS:
        return Condition(provider, KNOWN_CONDITIONS[provider], True, "known-runtime")
    return Condition(
        provider,
        f"custom condition '{provider}' (semantics not known to this tool)",
        True,
        "unknown",
    )


def enumerate_paths(node: Node) -> list[Path]:
    """Enumerate all successful login paths through a flow tree.

    Ternary condition handling: known conditions enumerate both outcomes with
    a named dependency; unknown custom conditions also enumerate both
    outcomes but flag the dependency as unknown. Nothing is assumed to be
    always-true or always-false.
    """
    if not node.is_flow:
        return [Path(steps=[node.provider_id or node.label])]

    if node.requirement == "CONDITIONAL":
        conditions = [c for c in node.children if _is_condition(c)]
        body = [c for c in node.children if not _is_condition(c)]
        conditions = [_condition_for(c) for c in conditions]
        if not conditions:
            conditions = [
                Condition(
                    "<none>",
                    f"CONDITIONAL sub-flow '{node.label}' has no recognisable "
                    "condition execution",
                    True,
                    "unknown",
                )
            ]
        taken: list[Path] = []
        for path in _enumerate_sequence(body):
            taken.append(
                Path(
                    path.steps,
                    path.conditions
                    + [
                        Condition(c.provider_id, c.description, True, c.certainty)
                        for c in conditions
                    ],
                )
            )
        skipped = [
            Path(
                [],
                [
                    Condition(c.provider_id, c.description, False, c.certainty)
                    for c in conditions
                ],
            )
        ]
        return taken + skipped

    return _enumerate_sequence(node.children)


def _enumerate_sequence(children: list[Node]) -> list[Path]:
    """Combine children in execution order.

    REQUIRED/CONDITIONAL children extend every partial path; consecutive
    ALTERNATIVE siblings form a single choice point; DISABLED is pruned.
    """
    paths = [Path()]
    index = 0
    active = [c for c in children if c.requirement != "DISABLED"]
    while index < len(active):
        child = active[index]
        if child.requirement == "ALTERNATIVE":
            choices: list[Path] = []
            while index < len(active) and active[index].requirement == "ALTERNATIVE":
                choices.extend(enumerate_paths(active[index]))
                index += 1
            paths = [prefix.merged(choice) for prefix in paths for choice in choices]
            continue
        branches = enumerate_paths(child)
        paths = [prefix.merged(branch) for prefix in paths for branch in branches]
        index += 1
    return paths


def categorize(provider_id: str) -> str:
    if provider_id in PASSWORD_PROVIDERS:
        return "password"
    if provider_id in SECOND_FACTOR_PROVIDERS:
        return "second-factor"
    if provider_id in STRONG_PASSWORDLESS_PROVIDERS:
        return "strong-passwordless"
    return "other"


def render_tree(node: Node, indent: int = 0) -> list[str]:
    marker = "flow" if node.is_flow else "exec"
    provider = f" ({node.provider_id})" if node.provider_id else ""
    line = f"{'  ' * indent}- [{node.requirement:<11}] {marker} {node.label}{provider}"
    lines = [line]
    for child in node.children:
        lines.extend(render_tree(child, indent + 1))
    return lines


def audit(bundle: dict, flow_alias: str | None = None) -> dict:
    flows = bundle["flows"]
    if flow_alias is None:
        top_level = [f for f in flows if f.get("topLevel")]
        if not top_level:
            raise AuditError("export contains no top-level flow; pass --flow explicitly")
        flow_alias = top_level[0].get("alias")

    tree = build_tree(bundle, flow_alias)
    paths = enumerate_paths(tree)

    analysed = []
    for path in paths:
        categories = {categorize(step) for step in path.steps}
        password_only = "password" in categories and not (
            categories & {"second-factor", "strong-passwordless"}
        )
        analysed.append(
            {
                "path": path,
                "password_only": password_only,
                "unknown_conditions": [
                    c for c in path.conditions if c.certainty == "unknown"
                ],
            }
        )

    confirmed = [
        a for a in analysed if a["password_only"] and not a["unknown_conditions"]
    ]
    conditional = [
        a for a in analysed if a["password_only"] and a["unknown_conditions"]
    ]
    if confirmed:
        verdict = "MFA_BYPASSABLE"
    elif conditional:
        verdict = "UNKNOWN_DEPENDENT"
    else:
        verdict = "MFA_ENFORCED"

    return {
        "snapshot_id": snapshot_id(bundle),
        "exported_at": bundle["export_meta"].get("exported_at"),
        "realm": bundle["export_meta"].get("realm"),
        "flow_alias": flow_alias,
        "tree": tree,
        "warnings": getattr(tree, "_warnings", []),
        "analysed": analysed,
        "verdict": verdict,
    }


def render_report(result: dict) -> str:
    lines = [
        "Keycloak authentication flow offline audit",
        f"  snapshot id : {result['snapshot_id']}",
        f"  exported at : {result['exported_at']}",
        f"  realm       : {result['realm']} (informational only; conclusions "
        "are bound to the snapshot id, not the realm name)",
        f"  flow        : {result['flow_alias']}",
        "",
        "Rebuilt hierarchy (execution order top to bottom):",
    ]
    lines.extend(render_tree(result["tree"]))
    for warning in result["warnings"]:
        lines.append(f"  WARNING: {warning}")
    lines.append("")
    lines.append("Enumerated successful login paths:")
    for number, item in enumerate(result["analysed"], start=1):
        path = item["path"]
        steps = " -> ".join(path.steps) if path.steps else "(no authenticator steps)"
        flag = "PASSWORD-ONLY" if item["password_only"] else "multi-factor"
        lines.append(f"  {number}. [{flag}] {steps}")
        for condition in path.conditions:
            lines.append(f"       depends on: {condition.render()}")
    lines.append("")
    verdict_text = {
        "MFA_ENFORCED": "MFA_ENFORCED - no password-only path exists in any "
        "enumerated branch",
        "MFA_BYPASSABLE": "MFA_BYPASSABLE - at least one password-only path "
        "exists (see dependencies above)",
        "UNKNOWN_DEPENDENT": "UNKNOWN_DEPENDENT - a password-only path exists "
        "only under custom conditions this tool cannot evaluate; manual "
        "review of those executors is required",
    }
    lines.append(f"Verdict: {verdict_text[result['verdict']]}")
    lines.append(
        "Scope: static analysis of one exported configuration snapshot. This "
        "does not replace login integration tests against a running server."
    )
    return "\n".join(lines)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("export", help="path to the exported flow bundle JSON")
    parser.add_argument("--flow", help="alias of the flow to audit "
                        "(default: first top-level flow)")
    args = parser.parse_args(argv)

    bundle = load_bundle(args.export)
    try:
        result = audit(bundle, args.flow)
    except AuditError as exc:
        print(f"audit failed: {exc}", file=sys.stderr)
        return 2
    print(render_report(result))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
