# Review: python-keycloak local Authorization parsing vs. server-side decision

**Scope:** `src/keycloak/authorization/` (`Authorization.load_config`, `Policy`, `Permission`, `Role`)
and its consumers `KeycloakOpenID.get_policies` / `get_permissions`
(`src/keycloak/keycloak_openid.py:814` and `:858`, async mirrors `:1676` / `:1720`).
Baseline: upstream `c5848e8`. No application source was modified.

## Verdict

**The local parser is not fit to be the final authorization decision.** It is a
role-membership filter over a display object graph. It parses JSON into `Role`/`Policy`/
`Permission` objects but executes none of Keycloak's decision semantics. Of the semantic
inputs you listed, only *role membership* is evaluated; *decision strategy*, *logic
(negative)*, *required role*, *composite/aggregate* structure, *resource*, *scope*, and
*enforcement mode* are stored and then ignored or silently dropped. Therefore "JSON loads
successfully" must not be read as "server semantics executed."

Use it only for UI/display hints, e.g. listing candidate grants, pre-filtering, or
explaining which policy names a user touches. Route every allow/deny through the server
(`KeycloakUMA.permissions_check` at `src/keycloak/keycloak_uma.py:422`, or
`uma_permissions` / RPT with `response_mode=decision`).

## Path trace

### 1. Parse — `Authorization.load_config` (`src/keycloak/authorization/__init__.py:59`)

- `role` policy (`:66-79`): reads `name`, `type`, `logic`, `decisionStrategy`; parses
  `config.roles` as a JSON list of `{id, required}` and stores `Role(name=id, required=required)`.
  Duplicate names overwrite (`self.policies[name] = policy`).
- `scope` permission (`:81-94`): reads `config.scopes` via `ast.literal_eval`; binds to
  policies named in `applyPolicies` **only if that policy is already in the dict** (`:93`).
  Missing `applyPolicies` is silently skipped (guarded by `:91`).
- `resource` permission (`:96-108`): reads `config.resources` (defaults to `[]`); binds
  the same already-loaded-only way (`:107`), but missing `applyPolicies` is a hard
  `KeyError` (unguarded at `:106`).
- Any other `type` (`js`, `group`, `client`, `time`, `aggregate`, `regex`, ...) falls
  through every branch: not parsed, not registered, no error.
- Top-level `policyEnforcementMode`, `allowRemoteResourceManagement`, `decisionStrategy`
  and `scopes` are never read.
- The setter is replace-only (`:55-57`); `load_config` never clears `self._policies`,
  so repeated loads accumulate stale grants.

### 2. Role association — `get_policies` / `get_permissions` (`keycloak_openid.py:814`, `:858`)

- Token source (`_token_info`, `:250`): `introspect` by default, else `decode_token`.
  `decode_token` validates only when `validate=True`; `validate=False` skips signature
  and `alg` checks entirely (`_verify_token`, `:764-766` marks the token valid).
- `resource_access[client_id]["roles"]` → for each role, `_build_name_role(role)` =
  `client_id + "/" + role` (`:238-248`). This only matches **client** roles; realm roles
  and group membership are never consulted.
- Membership test `if self._build_name_role(role) in policy.roles` relies on
  `Role.__eq__` comparing only `name` (`src/keycloak/authorization/role.py:73-77`), so
  the `required` flag has **zero** effect on matching.
- `get_policies` returns the set of `Policy` objects whose role list intersects the token
  roles. `get_permissions` unions `policy.permissions` for the same intersection.
  Nothing evaluates `logic`, `decision_strategy`, resources, or scopes.
- `if not user_resources: return None` (`:846`, `:890`) — absence of client roles is
  indistinguishable from "no config" at the call site, except the latter raises
  `KeycloakAuthorizationConfigError` first (`:834-836`).

### 3. Result

The output is a set of policy/permission *objects*, deduplicated with `set(...)`.
`Permission.__hash__` is not defined, so effectively identity hashing: the same
permission loaded twice appears twice (confirmed by the reload counterexample).
No decision (`True`/`False`) is produced, no resource/scope is compared, and the function
returns `None` rather than a deny for missing roles.

## Field disposition

| Field | Supported | Ignored | Rejected | Notes |
|---|---|---|---|---|
| `type=role` | role membership | — | — | base is a match filter |
| `config.roles[].id` | yes | — | — | prefixed `client_id/` |
| `config.roles[].required` | — | yes (stored only) | — | `Role.__eq__` ignores it; missing key raises `KeyError` |
| `logic` (POSITIVE/NEGATIVE) | stored | **yes, never evaluated** | — | invert semantics lost |
| `decisionStrategy` (policy & permission) | stored | **yes, never evaluated** | — | UNANIMOUS/AFFIRMATIVE identical |
| `type=scope` | scopes stored | scopes never matched | — | `applyPolicies` optional |
| `type=resource` | resources stored | resources never matched | — | `applyPolicies` required (`KeyError`) |
| `type=aggregate` | — | **silently dropped** | — | children unmapped |
| `type=js` / `group` / `client` / `time` / `regex` | — | **silently dropped** | — | permission bound to these bind to nothing |
| `applyPolicies` forward ref | — | **silently dropped if target later** | — | order-dependent |
| `applyPolicies` unknown name | — | **silently dropped** | — | no error |
| `policyEnforcementMode` | — | yes | — | PERMISSIVE/DISABLED not represented |
| `allowRemoteResourceManagement` | — | yes | — | |
| top-level `decisionStrategy`, `scopes` | — | yes | — | |
| malformed shape (`policies` missing, role missing `logic`/`required`) | — | — | **`KeyError`** | exception, not a deny |
| duplicate policy names | — | last wins, stale kept | — | |
| token without `resource_access` | — | `None` | — | ambiguous |

`Ignored` means the value is stored, or discarded, without effect on the returned set.
`Silently dropped` means load succeeds and the rule vanishes.

## Minimal-indistinguishable-config check

Two configs with the **same** role memberships (`app/alice` required, `app/bob` required)
differing only in `decisionStrategy`:
`configs/01_unanymous_required_roles.json` vs `configs/02_affirmative_required_roles.json`.
For a token holding only `alice`, the server would deny the first (UNANIMOUS, bob missing)
and grant the second. Locally both return exactly
`['Permission: read-doc (resource)']` — confirmed by
`test_decision_strategy_is_ignored_unanymous_vs_affirmative` in
`counterexamples/test_local_authz_is_not_authorization.py`. The result is not merely
imprecise; it is **unable to distinguish grant from deny**.

The strongest same-membership inversion is `configs/03_negative_logic.json`: `alice` gets
the permission and `bob` does not, which is exactly opposite to NEGATIVE-logic server
truth.

## Silent-widening cases (must go to the server)

1. **Unmodeled policy type dropped from a permission.** A permission bound to
   `[alice-role, eng-group]` (`configs/04_role_and_group_to_same_permission.json`) is
   parsed as bound to `alice-role` alone; `type=group` is never registered. The composite
   AND collapses to a single clause, so an alice-only user is reported as granted while
   the server denies (not in `g-engineering`).
   **Call condition:** a resource/scope permission whose `applyPolicies` includes any
   non-role, non-`applyPolicies`-loading policy type, while the current user satisfies
   only the role clauses.
2. **Decision-strategy / negative-logic ignored.** Any local result where the matched
   policy carries `decisionStrategy=AFFIRMATIVE` or `logic=NEGATIVE`, or where a required
   role is absent, can report a grant the server denies. `required` is stored but not
   enforced (`get_policies` membership matching only compares names).
3. **Scope vs resource not differentiated.** `get_permissions` returns both
   `write-doc-1 (resource)` and `doc-2-any-scope (scope)` without any request context
   (`configs/05_scope_and_resource_same_policy.json`). A caller checking "may I read
   doc-1" cannot tell an unrestricted scope grant from a resource grant.
4. **Order-dependent binding.** If `applyPolicies` names a policy declared later in the
   array, the binding is dropped at `:93` / `:107` (`configs/06_permission_before_policy.json`).
   Server truth grants; local result denies. This is a **fail-closed** case, but the
   mirror-image of a permission declared earlier than a policy that later gets
   replaced/duplicated can also misbind.
5. **Stale accumulation.** A second `load_authorization_config` keeps prior policies/permissions
   (duplicate `read-doc` in the reload counterexample). If a policy is deleted server-side
   and the file re-exported, the old grant remains until process restart. A duplicate
   policy *name* within one file silently takes the last declaration, so an earlier
   grant is replaced without warning (`test_duplicate_policy_name_last_declaration_wins`).
6. **Unvalidated token.** With `method_token_info="decode"` and `validate=False`, a
   hand-built unsigned token with `resource_access` roles is accepted; a client that
   relies on local results can be given roles it never proved. Confirmed: a 3-part
   token with an arbitrary signature and `validate=False` returns
   `['Permission: PA (resource)']`; the library path is `_verify_token:764`.

## What must be decided server-side

- Any response that grants or denies a specific **resource/scope** request.
- Any config containing `type` other than `role` in an `applyPolicies` chain.
- Any policy with `logic=NEGATIVE`, any `decisionStrategy` other than the trivial case,
  any `required=true` role.
- Any user with realm-level roles or group memberships relevant to the decision.
- Any token path using `decode` (especially `validate=False`).

Use these APIs instead: `KeycloakUMA.permissions_check(token, [...], response_mode="decision")`
(`keycloak_uma.py:422`), `KeycloakOpenID.uma_permissions(...)` with the server response
(`keycloak_openid.py:902`), `has_uma_access(...)` which is backed by that server call
(`keycloak_openid.py:961`), or the resource-server's RPT.
Local `get_policies`/`get_permissions` are suitable only for display: showing "policies
that mention your roles" or "candidate permissions", never for enforcement.

## Minimal fix direction

- **Fail-closed by construction:** make `get_policies`/`get_permissions` refuse to
  return anything (raise `KeycloakAuthorizationConfigError`) when the loaded config
  contains any unmodeled type referenced by `applyPolicies`, or any `logic != POSITIVE`,
  `decisionStrategy` not uniformly representable, or `required=true`. Do not silently
  drop.
- **Reject rather than ignore:** raise on unknown `pol["type"]` and on an `applyPolicies`
  name with no policy, instead of the `if ... is not None` skips at `:93`/`:107`.
- **Clear on reload:** reset `self.policies = {}` at the start of `load_config`, and
  deduplicate by name.
- **Do not accept unvalidated decode:** require `validate=True` for any authorization
  path, or name it clearly display-only.
- **Return an explicit object** (`None` → `Denied`/`Unknown`) and document `None` as deny.
- **Document display-only:** mark `load_authorization_config` / `get_policies` /
  `get_permissions` in docstrings as non-enforcing, point to `permissions_check`.

These are the minimal directions; none changes the server-side decision path.

## Reproduce

```sh
.venv/bin/python -m pytest -q -o addopts= security_review/counterexamples/
```

All 12 counterexamples run offline (no Keycloak server): token introspection is
stubbed at `_token_info`, configs are under `counterexamples/configs/`.
