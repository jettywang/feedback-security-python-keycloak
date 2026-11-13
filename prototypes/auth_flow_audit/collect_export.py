"""Collect a read-only authentication flow export via python-keycloak.

Uses only GET-style admin calls (``get_authentication_flows`` and
``get_authentication_flow_executions``); it never creates, updates or
deletes anything on the server. The output is the bundle format consumed by
``auth_flow_audit.py``.

Example:
    python collect_export.py --server-url https://sso.example.com \
        --realm myrealm --username auditor --output flow-export.json
"""

from __future__ import annotations

import argparse
import getpass
import json
from datetime import datetime, timezone

from keycloak import KeycloakAdmin


def collect(admin: KeycloakAdmin) -> dict:
    flows = admin.get_authentication_flows()
    executions: dict[str, list] = {}

    def walk(flow_alias: str) -> None:
        if flow_alias in executions:
            return
        steps = admin.get_authentication_flow_executions(flow_alias=flow_alias)
        executions[flow_alias] = steps
        for step in steps:
            if step.get("authenticationFlow"):
                sub_alias = step.get("alias") or step.get("flowAlias")
                if sub_alias:
                    walk(sub_alias)

    for flow in flows:
        alias = flow.get("alias")
        if alias:
            walk(alias)

    return {
        "export_meta": {
            "tool": "collect_export.py (python-keycloak, read-only)",
            "exported_at": datetime.now(timezone.utc).isoformat(),
            "realm": admin.connection.realm_name,
        },
        "flows": flows,
        "executions": executions,
    }


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--server-url", required=True)
    parser.add_argument("--realm", required=True, help="realm to export flows from")
    parser.add_argument("--username", required=True)
    parser.add_argument("--output", required=True)
    args = parser.parse_args()

    admin = KeycloakAdmin(
        server_url=args.server_url,
        username=args.username,
        password=getpass.getpass("admin password: "),
        realm_name=args.realm,
        user_realm_name="master",
    )
    bundle = collect(admin)
    with open(args.output, "w", encoding="utf-8") as handle:
        json.dump(bundle, handle, indent=2, sort_keys=True)
    print(f"wrote {args.output}; audit it with: python auth_flow_audit.py {args.output}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
