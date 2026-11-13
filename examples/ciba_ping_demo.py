"""
End-to-end demonstration of the CIBA ping helpers.

Two authentications are started and deliberately interleaved so the output shows
that each notification and token exchange is bound to its own
``(auth_req_id, client, realm)`` triple. A local, in-process fake replaces the
identity provider, therefore the demo never opens a network connection.

Run it with::

    python examples/ciba_ping_demo.py

The printed walkthrough answers two questions explicitly:

* when is a token allowed to be delivered? Only after a successful token
  exchange, never on the back of a ping notification;
* why can an error notification never trigger an exchange? Because a
  notification that fails authentication is rejected before any state change
  and the transaction stays ``INITIATED``, which the service refuses to poll.
"""

# ruff: noqa: T201, S101, INP001

from __future__ import annotations

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))
sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from keycloak import (
    KeycloakCibaDeniedError,
    KeycloakCibaExpiredError,
    KeycloakCibaNotificationError,
    KeycloakCibaPendingError,
    KeycloakCibaUnknownResultError,
    KeycloakConnectionError,
)
from keycloak.ciba import (
    CibaNotification,
    CibaService,
    CibaStatus,
    InMemoryCibaStorage,
    SharedSecretAuthenticator,
)

from tests.ciba_support.fake_ciba_server import FakeCibaServer

REALM = "demo-realm"
CLIENT = "demo-client"
PING_SECRET = "demo-ping-secret"  # noqa: S105


def banner(title: str) -> None:
    """
    Print a visually distinct section header.

    :param title: Section title
    :type title: str
    """
    print("\n" + "=" * 72)
    print(title)
    print("=" * 72)


def main() -> None:
    """Run the interleaved CIBA demonstration."""
    storage = InMemoryCibaStorage()
    server = FakeCibaServer(
        realm_name=REALM,
        client_id=CLIENT,
        notification_credential=PING_SECRET,
    )
    openid_client = server.build_client()
    authenticator = SharedSecretAuthenticator(PING_SECRET, CLIENT, REALM)
    service = CibaService.for_client(storage, openid_client, authenticator)

    banner("1. Start two interleaved backchannel authentications")
    first = service.initiate(REALM, CLIENT, login_hint="alice", binding_message="Login A")
    second = service.initiate(REALM, CLIENT, login_hint="bob", binding_message="Login B")
    print(f"transaction A {first.auth_req_id} -> {first.status.value}")
    print(f"transaction B {second.auth_req_id} -> {second.status.value}")
    print("Neither transaction holds a token; the users have not been confirmed yet.")

    banner("2. A ping only notifies, it never authenticates the user")
    server.set_outcome(first.auth_req_id, "approved")
    notified_a = service.handle_notification(
        CibaNotification(**server.send_ping(first.auth_req_id)),
    )
    print(f"transaction A after valid ping -> {notified_a.status.value}")
    print(f"token delivered? {notified_a.token_ready} (expected False)")

    print("\nPolling before the user decision is complete returns authorization_pending.")
    server.set_outcome(second.auth_req_id, "pending", delay_exchanges=1)
    service.handle_notification(
        CibaNotification(**server.send_ping(second.auth_req_id)),
    )
    try:
        service.exchange_token(second.auth_req_id)
    except KeycloakCibaPendingError:
        print("transaction B poll answered authorization_pending; no token delivered.")

    banner("3. Duplicate pings are idempotent and stay bound to one transaction")
    again = service.handle_notification(
        CibaNotification(**server.send_ping(first.auth_req_id)),
    )
    print(f"repeated ping leaves transaction A at -> {again.status.value}")

    banner("4. A forged / wrong-credential notification cannot trigger an exchange")
    target = service.initiate(REALM, CLIENT, login_hint="frank", binding_message="Login F")
    forged = CibaNotification(auth_req_id=target.auth_req_id, credential="attacker-secret")
    try:
        service.handle_notification(forged)
    except KeycloakCibaNotificationError:
        print("forged notification rejected by the authenticator; storage was not changed.")
    target_record = storage.get(target.auth_req_id)
    print(f"transaction F stays {target_record.status.value}; it never received a valid ping.")
    try:
        service.exchange_token(target.auth_req_id)
    except KeycloakCibaPendingError:
        print("the service refuses to poll transaction F because no valid notification exists.")

    banner("5. A notification arriving before the initiation is stored is rejected")
    orphan = CibaNotification(auth_req_id="never-stored-id", credential=PING_SECRET)
    try:
        service.handle_notification(orphan)
    except KeycloakCibaNotificationError:
        print("unknown auth_req_id rejected; the provider can redeliver after storage settles.")

    banner("6. User denial and expiry are terminal and never yield a token")
    denied = service.initiate(REALM, CLIENT, login_hint="carol", binding_message="Login C")
    service.handle_notification(
        CibaNotification(**server.send_ping(denied.auth_req_id)),
    )
    server.set_outcome(denied.auth_req_id, "denied")
    try:
        service.exchange_token(denied.auth_req_id)
    except KeycloakCibaDeniedError:
        print(
            "transaction C denied by the user; status is now "
            f"{storage.get(denied.auth_req_id).status.value}."
        )

    expired = service.initiate(
        REALM,
        CLIENT,
        login_hint="dave",
        binding_message="Login D",
        requested_expiry=1,
    )
    try:
        service.exchange_token(expired.auth_req_id, now=expired.initiated_at + 10)
    except KeycloakCibaExpiredError:
        print("transaction D expired locally before any token exchange was attempted.")

    banner("7. An unknown exchange outcome stays retryable, never successful")
    unknown = service.initiate(REALM, CLIENT, login_hint="erin", binding_message="Login E")
    service.handle_notification(
        CibaNotification(**server.send_ping(unknown.auth_req_id)),
    )
    original_token = openid_client.token

    def broken_exchange(**_kwargs: object) -> None:
        reason = "simulated network outage"
        raise KeycloakConnectionError(reason)

    openid_client.token = broken_exchange  # type: ignore[method-assign]
    try:
        service.exchange_token(unknown.auth_req_id)
    except KeycloakCibaUnknownResultError:
        record = storage.get(unknown.auth_req_id)
        print(f"transaction E marked {record.status.value} after a connection failure.")
        print("It can be retried; the service never fabricated a successful token.")

    banner("8. Successful exchange: this is the only moment a token is delivered")
    openid_client.token = original_token  # type: ignore[method-assign]
    server.set_outcome(first.auth_req_id, "approved")
    completed_a = service.exchange_token(first.auth_req_id)
    server.set_outcome(second.auth_req_id, "approved")
    completed_b = service.exchange_token(second.auth_req_id)
    print(
        f"transaction A -> {completed_a.status.value}, "
        f"access_token={completed_a.token['access_token']}"
    )
    print(
        f"transaction B -> {completed_b.status.value}, "
        f"access_token={completed_b.token['access_token']}"
    )
    assert completed_a.token["access_token"] != completed_b.token["access_token"]
    print(
        "The two access tokens are distinct; one transaction's result never overwrote "
        "the other."
    )

    banner("Final transaction table")
    for transaction in storage.all():
        print(
            f"{transaction.auth_req_id[:8]}  user={transaction.binding_message:<8} "
            f"status={transaction.status.value:<9} attempts={transaction.attempts} "
            f"token_ready={transaction.token_ready}",
        )

    banner("9. Failure isolation: no failed transaction is marked successful")
    failed_states = [
        storage.get(denied.auth_req_id).status,
        storage.get(expired.auth_req_id).status,
        storage.get(unknown.auth_req_id).status,
    ]
    assert all(state is not CibaStatus.SUCCEEDED for state in failed_states)
    print("denied, expired and unknown transactions are all non-SUCCEEDED as required.")


if __name__ == "__main__":
    main()
