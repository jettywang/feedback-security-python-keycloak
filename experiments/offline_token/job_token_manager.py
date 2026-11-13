"""Reference integration for a Python background job using an offline token.

The job is a *confidential* OIDC client.  A human (or a one-time provisioning
step) grants ``offline_access`` once; the job then persists only the offline
refresh token and exchanges it for short-lived access tokens on each run /
refresh cycle.
"""

from __future__ import annotations

import json
import os
from dataclasses import asdict, dataclass
from pathlib import Path
from typing import Any

from keycloak import KeycloakOpenID
from keycloak.exceptions import KeycloakError, KeycloakPostError

OFFLINE_SCOPE = "openid offline_access"


@dataclass
class StoredToken:
    """What the job persists between restarts."""

    refresh_token: str
    access_token: str | None = None
    access_expires_at: float = 0.0


class OfflineTokenStore:
    """File-backed token vault.  Deployment must protect it like a password."""

    def __init__(self, path: str) -> None:
        self.path = Path(path)

    def load(self) -> StoredToken | None:
        if not self.path.exists():
            return None
        return StoredToken(**json.loads(self.path.read_text(encoding="utf-8")))

    def save(self, token: StoredToken) -> None:
        self.path.parent.mkdir(parents=True, exist_ok=True)
        tmp = self.path.with_suffix(".tmp")
        tmp.write_text(json.dumps(asdict(token)), encoding="utf-8")
        os.replace(tmp, self.path)
        os.chmod(self.path, 0o600)

    def clear(self) -> None:
        self.path.unlink(missing_ok=True)


class JobTokenManager:
    def __init__(
        self,
        server_url: str,
        realm: str,
        client_id: str,
        client_secret: str,
        store: OfflineTokenStore,
        verify: bool | str = True,
        timeout: int = 10,
    ) -> None:
        self.store = store
        self.oidc = KeycloakOpenID(
            server_url=server_url,
            realm_name=realm,
            client_id=client_id,
            client_secret_key=client_secret,
            verify=verify,
            timeout=timeout,
            max_retries=0,
        )

    # ------------------------------------------------------- one-time grant
    def provision_from_password(self, username: str, password: str) -> StoredToken:
        """Used once by provisioning; the job itself never stores a password."""
        token = self.oidc.token(
            username=username,
            password=password,
            grant_type="password",
            scope=OFFLINE_SCOPE,
        )
        return self._persist(token)

    def provision_from_authz_code(self, code: str, redirect_uri: str) -> StoredToken:
        token = self.oidc.token(
            grant_type="authorization_code",
            code=code,
            redirect_uri=redirect_uri,
            scope=OFFLINE_SCOPE,
        )
        return self._persist(token)

    def _persist(self, token: dict[str, Any], now: float | None = None) -> StoredToken:
        import time

        now = time.time() if now is None else now
        stored = StoredToken(
            refresh_token=token["refresh_token"],
            access_token=token["access_token"],
            access_expires_at=now + int(token["expires_in"]),
        )
        self.store.save(stored)
        return stored

    # ------------------------------------------------------------ runtime
    def current_access_token(self, skew_seconds: int = 30) -> str:
        """Return a usable access token, refreshing proactively when near expiry."""
        import time

        stored = self.store.load()
        if stored is None:
            raise PermissionError("No offline token provisioned; run provisioning first.")

        if stored.access_token and time.time() < stored.access_expires_at - skew_seconds:
            return stored.access_token

        return self.rotate(stored)

    def rotate(self, stored: StoredToken | None = None) -> str:
        stored = stored or self.store.load()
        if stored is None:
            raise PermissionError("No offline token provisioned.")
        try:
            token = self.oidc.refresh_token(stored.refresh_token)
        except KeycloakPostError as exc:
            # 400 invalid_grant: offline session revoked, user disabled, token reused.
            self.store.clear()
            raise PermissionError(
                f"Offline token no longer accepted ({exc.response_code}); re-provision required."
            ) from exc
        except KeycloakError as exc:
            # Network/5xx: keep the stored token, fail this run, retry later.
            raise ConnectionError(
                f"Authorization server unreachable ({exc.response_code}); token retained."
            ) from exc
        self._persist(token)
        return token["access_token"]

    def logout(self) -> None:
        """Explicitly tear the offline session down."""
        stored = self.store.load()
        if stored:
            self.oidc.logout(stored.refresh_token)
            self.store.clear()
