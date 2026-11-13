"""Pytest assertions for the offline-token state experiments.

These run entirely in-process (no Keycloak, no TCP port) and pin down the
observation window of every validation strategy plus the failure-handling
contract of the job-side token manager.
"""

from __future__ import annotations

import sys
from datetime import datetime, timezone
from pathlib import Path

import freezegun
import pytest
from jwcrypto import jwt as jwcrypto_jwt

from keycloak.exceptions import KeycloakAuthenticationError, KeycloakConnectionError, KeycloakPostError

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE))

from fake_keycloak import CLIENT_ID, CLIENT_SECRET, FakeRealm, ManualClock, REALM  # noqa: E402
from fake_transport import FakeKeycloakTransport, mount as mount_transport  # noqa: E402
from job_token_manager import JobTokenManager, OfflineTokenStore  # noqa: E402
from keycloak import KeycloakOpenID  # noqa: E402

ACCESS_TTL = 60
BASE_URL = "http://fake-keycloak.test/"


class Harness:
    def __init__(self, start: int = 1_000_000) -> None:
        self.clock = ManualClock(start)
        self.freezer = freezegun.freeze_time(
            datetime.fromtimestamp(self.clock.time(), tz=timezone.utc)
        )
        self.freezer.start()
        self.realm = FakeRealm(access_lifetime=ACCESS_TTL, clock=self.clock)
        self.oidc = KeycloakOpenID(
            server_url=BASE_URL, realm_name=REALM, client_id=CLIENT_ID,
            client_secret_key=CLIENT_SECRET, verify=False, timeout=5, max_retries=0,
        )
        self.transport = FakeKeycloakTransport(self.realm)
        self.sessions = [self.oidc.connection._s]
        mount_transport(self.oidc.connection._s, self.transport)

    def jump(self, offset: int) -> None:
        self.clock.offset = 1_000_000 + offset
        self.freezer.stop()
        self.freezer = freezegun.freeze_time(
            datetime.fromtimestamp(self.clock.time(), tz=timezone.utc)
        )
        self.freezer.start()

    def attach(self, manager: JobTokenManager) -> None:
        session = manager.oidc.connection._s
        self.sessions.append(session)
        mount_transport(session, self.transport)

    def outage(self) -> None:
        class Boom(FakeKeycloakTransport):
            def send(self, request, timeout=None, **kwargs):
                raise ConnectionRefusedError("simulated outage")

        for session in self.sessions:
            mount_transport(session, Boom(self.realm))

    def stop(self) -> None:
        if getattr(self.freezer, "fake_names", None) is not None:
            self.freezer.stop()


@pytest.fixture()
def harness():
    h = Harness()
    yield h
    h.stop()


def _issue(h, offline=True):
    scope = "openid offline_access" if offline else "openid"
    return h.oidc.token(username="alice", password="x", grant_type="password", scope=scope)


def test_local_verify_cannot_see_logout_until_exp(harness):
    token = _issue(harness)
    harness.oidc.logout(token["refresh_token"])

    # Immediately after logout the signature+exp check still trusts the token.
    harness.jump(0)
    claims = harness.oidc.decode_token(token["access_token"], validate=True)
    assert claims["sub"] == "alice"

    # Within the SDK's 60s default leeway it is still accepted past nominal exp.
    harness.jump(ACCESS_TTL + 1)
    claims = harness.oidc.decode_token(token["access_token"], validate=True)
    assert claims["sub"] == "alice"

    # Beyond access TTL + leeway, local verification finally fails on exp alone.
    harness.jump(ACCESS_TTL + 61)
    with pytest.raises(jwcrypto_jwt.JWTExpired):
        harness.oidc.decode_token(token["access_token"], validate=True)


def test_introspection_detects_revocation_immediately(harness):
    token = _issue(harness)
    assert harness.oidc.introspect(token["access_token"])["active"] is True
    harness.oidc.logout(token["refresh_token"])
    for offset in (0, ACCESS_TTL - 1, ACCESS_TTL + 1):
        harness.jump(offset)
        assert harness.oidc.introspect(token["access_token"])["active"] is False


def test_protected_endpoint_rejects_revoked_token(harness):
    token = _issue(harness)
    harness.oidc.logout(token["refresh_token"])
    harness.jump(0)
    with pytest.raises(KeycloakAuthenticationError):
        harness.oidc.userinfo(token["access_token"])


def test_refresh_grant_dies_with_session(harness):
    token = _issue(harness)
    harness.oidc.logout(token["refresh_token"])
    harness.jump(0)
    with pytest.raises(KeycloakPostError) as exc:
        harness.oidc.refresh_token(token["refresh_token"])
    assert exc.value.response_code == 400


def test_admin_disable_blocks_server_checks_but_not_local_signature(harness):
    token = _issue(harness)
    harness.realm.admin_disable_user("alice")
    harness.jump(0)
    # Local verification is blind to the disabled-user event.
    assert harness.oidc.decode_token(token["access_token"])["sub"] == "alice"
    # Any server-mediated check learns the truth at once.
    assert harness.oidc.introspect(token["access_token"])["active"] is False
    with pytest.raises(KeycloakPostError):
        harness.oidc.refresh_token(token["refresh_token"])


def test_refresh_rotation_reuse_revokes_whole_session(harness):
    token = _issue(harness)
    rotated = harness.oidc.refresh_token(token["refresh_token"])
    # Replaying the rotated-out refresh token invalidates the session...
    with pytest.raises(KeycloakPostError):
        harness.oidc.refresh_token(token["refresh_token"])
    # ...including the freshly issued refresh token.
    with pytest.raises(KeycloakPostError):
        harness.oidc.refresh_token(rotated["refresh_token"])


def test_job_restart_rotates_access_and_tolerates_revoke(harness, tmp_path):
    vault = OfflineTokenStore(str(tmp_path / "vault.json"))
    manager = JobTokenManager(
        BASE_URL, REALM, CLIENT_ID, CLIENT_SECRET, vault, verify=False
    )
    harness.attach(manager)
    manager.provision_from_password("alice", "x")
    first = manager.current_access_token()

    harness.jump(ACCESS_TTL + 5)
    manager2 = JobTokenManager(BASE_URL, REALM, CLIENT_ID, CLIENT_SECRET,
                               OfflineTokenStore(str(tmp_path / "vault.json")), verify=False)
    harness.attach(manager2)
    assert manager2.current_access_token() != first

    for sid in harness.realm.list_sessions("alice"):
        harness.realm.revoke_session(sid)
    harness.jump(2 * (ACCESS_TTL + 5))
    manager3 = JobTokenManager(BASE_URL, REALM, CLIENT_ID, CLIENT_SECRET,
                               OfflineTokenStore(str(tmp_path / "vault.json")), verify=False)
    harness.attach(manager3)
    with pytest.raises(PermissionError):
        manager3.current_access_token()
    assert not (tmp_path / "vault.json").exists()


def test_outage_keeps_offline_token_for_retry(harness, tmp_path):
    vault = OfflineTokenStore(str(tmp_path / "vault2.json"))
    manager = JobTokenManager(BASE_URL, REALM, CLIENT_ID, CLIENT_SECRET, vault, verify=False)
    harness.attach(manager)
    manager.provision_from_password("alice", "x")
    harness.jump(ACCESS_TTL + 1)
    harness.outage()
    with pytest.raises((ConnectionError, KeycloakConnectionError)):
        manager.current_access_token()
    assert (tmp_path / "vault2.json").exists()


def test_offline_scope_yields_long_lived_refresh(harness):
    online = _issue(harness, offline=False)
    offline = _issue(harness, offline=True)
    assert offline["refresh_expires_in"] > online["refresh_expires_in"]
