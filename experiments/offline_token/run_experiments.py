"""Deterministic state experiments against the scriptable fake Keycloak.

Run: .venv/bin/python experiments/offline_token/run_experiments.py

The *real* python-keycloak client is driven through an in-process requests
transport (no TCP port).  A ManualClock plus freezegun keep the realm state and
jwcrypto's clock in lockstep, so every revocation window is reproducible.
"""

from __future__ import annotations

import sys
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path

import freezegun

from keycloak import KeycloakOpenID
from keycloak.exceptions import KeycloakAuthenticationError, KeycloakConnectionError, KeycloakPostError

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE))

from fake_keycloak import (  # noqa: E402
    CLIENT_ID,
    CLIENT_SECRET,
    FakeRealm,
    ManualClock,
    REALM,
)
from fake_transport import FakeKeycloakTransport, mount as mount_transport  # noqa: E402
from job_token_manager import JobTokenManager, OfflineTokenStore  # noqa: E402

ACCESS_TTL = 60
ONLINE_REFRESH_TTL = 300
OFFLINE_REFRESH_TTL = 3600
BASE_URL = f"http://fake-keycloak.test/"


@dataclass
class Observation:
    strategy: str
    accepted: bool
    detail: str
    server_calls: int


class OutageTransport(FakeKeycloakTransport):
    """Models an authorization-server outage by failing every send."""

    def send(self, request, timeout=None, **kwargs):
        raise ConnectionRefusedError("simulated network outage")


class ExperimentHarness:
    def __init__(self, start: int) -> None:
        self.clock = ManualClock(start)
        self.freezer = freezegun.freeze_time(
            datetime.fromtimestamp(self.clock.time(), tz=timezone.utc)
        )
        self.freezer.start()
        self.realm = FakeRealm(
            access_lifetime=ACCESS_TTL,
            online_refresh_lifetime=ONLINE_REFRESH_TTL,
            offline_refresh_lifetime=OFFLINE_REFRESH_TTL,
            clock=self.clock,
        )
        self.oidc = KeycloakOpenID(
            server_url=BASE_URL,
            realm_name=REALM,
            client_id=CLIENT_ID,
            client_secret_key=CLIENT_SECRET,
            verify=False,
            timeout=5,
            max_retries=0,
        )
        self.transport = FakeKeycloakTransport(self.realm)
        self._sessions: list = [self.oidc.connection._s]
        mount_transport(self.oidc.connection._s, self.transport)

    def attach(self, manager: JobTokenManager) -> None:
        """Route a JobTokenManager's SDK session through this same fake realm."""
        session = manager.oidc.connection._s
        self._sessions.append(session)
        mount_transport(session, self.transport)

    def jump_to(self, absolute_time: int) -> None:
        self.clock.offset = absolute_time
        self.freezer.stop()
        self.freezer = freezegun.freeze_time(
            datetime.fromtimestamp(self.clock.time(), tz=timezone.utc)
        )
        self.freezer.start()

    def advance(self, seconds: int) -> None:
        self.jump_to(int(self.clock.time()) + seconds)

    def force_outage(self) -> None:
        for session in self._sessions:
            mount_transport(session, OutageTransport(self.realm))

    def stop(self) -> None:
        if getattr(self.freezer, "fake_names", None) is not None:
            self.freezer.stop()


def local_verify(oidc: KeycloakOpenID, token: str) -> Observation:
    """Strategy A: signature + exp only; a single JWKS fetch, cached per call."""
    try:
        claims = oidc.decode_token(token, validate=True)
        return Observation("local-sig+exp", True, f"exp={claims['exp']} sid={claims['sid'][:6]}", 0)
    except Exception as exc:
        return Observation("local-sig+exp", False, f"{type(exc).__name__}", 0)


def introspect_verify(oidc: KeycloakOpenID, token: str) -> Observation:
    """Strategy B: server-side introspection (RFC 7662)."""
    info = oidc.introspect(token)
    return Observation("introspect", bool(info.get("active")), f"active={info.get('active')}", 1)


def refresh_verify(oidc: KeycloakOpenID, refresh_token: str) -> Observation:
    """Strategy C: exercise the refresh grant; success proves the session is live."""
    try:
        oidc.refresh_token(refresh_token)
        return Observation("refresh-grant", True, "new tokens issued", 1)
    except KeycloakPostError as exc:
        return Observation("refresh-grant", False, f"{exc.response_code} {str(exc.error_message)[:48]}", 1)


def userinfo_verify(oidc: KeycloakOpenID, token: str) -> Observation:
    """Strategy D: hit a protected endpoint with the bearer token."""
    try:
        oidc.userinfo(token)
        return Observation("userinfo", True, "200 OK", 1)
    except KeycloakAuthenticationError as exc:
        return Observation("userinfo", False, f"{exc.response_code} {str(exc.error_message)[:40]}", 1)


def banner(title: str) -> None:
    print("\n" + "=" * 80)
    print(title)
    print("=" * 80)


def show(t0: int, offset: int, obs: Observation) -> None:
    verdict = "ACCEPT" if obs.accepted else "REJECT"
    print(f"  t0+{offset:>5}s | {obs.strategy:<15} | {verdict:<6} | calls={obs.server_calls} | {obs.detail}")


def scenario_revocation_windows() -> None:
    banner("1/3  Revocation window after LOGOUT — offline vs online session")
    for offline in (True, False):
        t0 = 1_000_000
        harness = ExperimentHarness(t0)
        scope = "openid offline_access" if offline else "openid"
        kind = "OFFLINE" if offline else "ONLINE"
        print(f"\n--- {kind} session, scope='{scope}' (access TTL={ACCESS_TTL}s) ---")
        token = harness.oidc.token(username="alice", password="x", grant_type="password", scope=scope)
        access, refresh = token["access_token"], token["refresh_token"]
        print(f"  issued: expires_in={token['expires_in']} refresh_expires_in={token['refresh_expires_in']}")
        harness.oidc.logout(refresh)  # user closes browser / logs out
        print("  logout applied -> server marks session logged_out and revokes tokens")
        for offset in (0, ACCESS_TTL - 1, ACCESS_TTL + 1, ACCESS_TTL + 61):
            harness.jump_to(t0 + offset)
            show(t0, offset, local_verify(harness.oidc, access))
            show(t0, offset, introspect_verify(harness.oidc, access))
            show(t0, offset, userinfo_verify(harness.oidc, access))
            show(t0, offset, refresh_verify(harness.oidc, refresh))
        harness.stop()


def scenario_admin_disable() -> None:
    banner("4  Admin disables the user while an access token is outstanding")
    t0 = 2_000_000
    harness = ExperimentHarness(t0)
    token = harness.oidc.token(
        username="alice", password="x", grant_type="password", scope="openid offline_access"
    )
    access, refresh = token["access_token"], token["refresh_token"]
    harness.realm.admin_disable_user("alice")
    print("  admin disabled alice -> server flips sessions to logged_out immediately")
    for offset in (0, ACCESS_TTL - 1, ACCESS_TTL + 1, ACCESS_TTL + 61):
        harness.jump_to(t0 + offset)
        show(t0, offset, local_verify(harness.oidc, access))
        show(t0, offset, introspect_verify(harness.oidc, access))
        show(t0, offset, refresh_verify(harness.oidc, refresh))
    harness.stop()


def scenario_rotation_reuse() -> None:
    banner("5  Refresh-token rotation and reuse detection")
    t0 = 3_000_000
    harness = ExperimentHarness(t0)
    token = harness.oidc.token(
        username="alice", password="x", grant_type="password", scope="openid offline_access"
    )
    old_refresh = token["refresh_token"]
    rotated = harness.oidc.refresh_token(old_refresh)
    print("  first refresh succeeds and rotates the refresh token")
    print("  reuse of the already-rotated OLD refresh token:")
    show(t0, 0, refresh_verify(harness.oidc, old_refresh))
    print("  after reuse, the previously-valid NEW refresh token is also dead:")
    show(t0, 0, refresh_verify(harness.oidc, rotated["refresh_token"]))
    harness.stop()


def scenario_restart_persistence(tmp_dir: Path) -> None:
    banner("2  Job restart reloads the offline token and continues, then reacts to revoke")
    t0 = 4_000_000
    harness = ExperimentHarness(t0)
    vault = tmp_dir / "vault.json"
    manager = JobTokenManager(
        BASE_URL, REALM, CLIENT_ID, CLIENT_SECRET, OfflineTokenStore(str(vault)), verify=False
    )
    harness.attach(manager)
    manager.provision_from_password("alice", "x")
    first_access = manager.current_access_token()
    print("  provisioned offline token into 0600 vault")

    harness.advance(ACCESS_TTL + 5)
    manager2 = JobTokenManager(
        BASE_URL, REALM, CLIENT_ID, CLIENT_SECRET, OfflineTokenStore(str(vault)), verify=False
    )
    harness.attach(manager2)
    second_access = manager2.current_access_token()
    print(f"  restart at t0+{ACCESS_TTL + 5}s transparently rotated access token: {second_access != first_access}")

    # Server-side revoke of the offline session (admin console / user logout).
    for sid in harness.realm.list_sessions("alice"):
        harness.realm.revoke_session(sid)

    # Next restart happens once the cached access token has expired, so the
    # manager must exercise the refresh grant and discover the revocation.
    harness.advance(ACCESS_TTL + 5)
    manager3 = JobTokenManager(
        BASE_URL, REALM, CLIENT_ID, CLIENT_SECRET, OfflineTokenStore(str(vault)), verify=False
    )
    harness.attach(manager3)
    try:
        manager3.current_access_token()
        print("  ERROR: expected PermissionError after revoke")
    except PermissionError as exc:
        print(f"  revoked offline token -> PermissionError: {exc}")
    print(f"  vault cleared after fatal invalid_grant: {not vault.exists()}")
    harness.stop()


def scenario_outage_keeps_token(tmp_dir: Path) -> None:
    banner("6  Authorization-server outage must not destroy the offline token")
    t0 = 5_000_000
    harness = ExperimentHarness(t0)
    vault = tmp_dir / "vault2.json"
    manager = JobTokenManager(
        BASE_URL, REALM, CLIENT_ID, CLIENT_SECRET, OfflineTokenStore(str(vault)), verify=False
    )
    harness.attach(manager)
    manager.provision_from_password("alice", "x")
    harness.advance(ACCESS_TTL + 1)
    harness.force_outage()
    try:
        manager.current_access_token()
    except (ConnectionError, KeycloakConnectionError) as exc:
        print(f"  outage -> {type(exc).__name__}: this run fails, offline token preserved")
    else:
        print("  ERROR: expected a connection failure during outage")
    print(f"  vault retained for a later retry: {vault.exists()}")
    harness.stop()


def main() -> None:
    tmp_dir = HERE / "_run_tmp"
    tmp_dir.mkdir(exist_ok=True)
    scenario_revocation_windows()
    scenario_admin_disable()
    scenario_rotation_reuse()
    scenario_restart_persistence(tmp_dir)
    scenario_outage_keeps_token(tmp_dir)
    print("\nAll scenarios executed.")


if __name__ == "__main__":
    main()
