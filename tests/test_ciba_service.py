"""Tests for the CIBA ping service and its security state machine."""

from __future__ import annotations

import pytest
from keycloak import (
    KeycloakCibaDeniedError,
    KeycloakCibaExpiredError,
    KeycloakCibaNotificationError,
    KeycloakCibaPendingError,
    KeycloakCibaTransactionError,
    KeycloakCibaUnknownResultError,
    KeycloakConnectionError,
    KeycloakError,
)
from keycloak.ciba import (
    CibaNotification,
    CibaService,
    CibaStatus,
    CibaTransaction,
    HmacNotificationAuthenticator,
    InMemoryCibaStorage,
    SharedSecretAuthenticator,
)

from tests.ciba_support.fake_ciba_server import FakeCibaServer

REALM = "test-realm"
CLIENT = "test-client"
PING_SECRET = "ping-secret"  # noqa: S105


@pytest.fixture()
def server() -> FakeCibaServer:
    """
    Build a fresh fake provider.

    :returns: Fake CIBA server
    :rtype: FakeCibaServer
    """
    return FakeCibaServer(
        realm_name=REALM,
        client_id=CLIENT,
        notification_credential=PING_SECRET,
    )


@pytest.fixture()
def storage() -> InMemoryCibaStorage:
    """
    Build a fresh transaction store.

    :returns: In-memory storage
    :rtype: InMemoryCibaStorage
    """
    return InMemoryCibaStorage()


@pytest.fixture()
def service(
    server: FakeCibaServer,
    storage: InMemoryCibaStorage,
) -> CibaService:
    """
    Build a service wired to the fake provider.

    :param server: Fake provider
    :type server: FakeCibaServer
    :param storage: Transaction store
    :type storage: InMemoryCibaStorage
    :returns: Configured CIBA service
    :rtype: CibaService
    """
    openid_client = server.build_client()
    authenticator = SharedSecretAuthenticator(PING_SECRET, CLIENT, REALM)
    return CibaService.for_client(storage, openid_client, authenticator)


def ping(server: FakeCibaServer, auth_req_id: str) -> CibaNotification:
    """
    Build a notification exactly as the fake provider would send it.

    :param server: Fake provider
    :type server: FakeCibaServer
    :param auth_req_id: Target request id
    :type auth_req_id: str
    :returns: Notification object
    :rtype: CibaNotification
    """
    return CibaNotification(**server.send_ping(auth_req_id))


def test_initiate_persists_transaction_bound_to_triple(
    service: CibaService,
    server: FakeCibaServer,
    storage: InMemoryCibaStorage,
) -> None:
    """A backchannel response is stored with its auth_req_id, client and realm."""
    transaction = service.initiate(REALM, CLIENT, login_hint="alice")

    assert transaction.status is CibaStatus.INITIATED
    assert transaction.client_id == CLIENT
    assert transaction.realm_name == REALM
    assert storage.get(transaction.auth_req_id) is transaction
    assert server.backchannel_calls[0]["login_hint"] == "alice"
    assert server.backchannel_calls[0]["client_secret"] == "demo-secret"  # noqa: S105
    assert transaction.token is None


def test_initiate_rejects_unregistered_client(service: CibaService) -> None:
    """Only registered realm/client pairs may start a transaction."""
    with pytest.raises(KeycloakCibaTransactionError):
        service.initiate("other-realm", CLIENT, login_hint="alice")


def test_notification_marks_notified_but_does_not_authenticate(
    service: CibaService,
    server: FakeCibaServer,
) -> None:
    """A valid ping only moves INITIATED -> NOTIFIED and never delivers a token."""
    transaction = service.initiate(REALM, CLIENT, login_hint="alice")
    server.set_outcome(transaction.auth_req_id, "approved")

    updated = service.handle_notification(ping(server, transaction.auth_req_id))

    assert updated.status is CibaStatus.NOTIFIED
    assert updated.notified_at is not None
    assert updated.token_ready is False
    assert server.token_exchanges == []


def test_duplicate_notification_is_idempotent(
    service: CibaService,
    server: FakeCibaServer,
) -> None:
    """Repeated pings must not accumulate state or trigger an exchange."""
    transaction = service.initiate(REALM, CLIENT, login_hint="alice")
    service.handle_notification(ping(server, transaction.auth_req_id))
    first_notified_at = transaction.notified_at

    repeated = service.handle_notification(ping(server, transaction.auth_req_id))

    assert repeated.status is CibaStatus.NOTIFIED
    assert repeated.notified_at == first_notified_at
    assert server.token_exchanges == []


def test_notification_before_storage_is_rejected(
    service: CibaService,
) -> None:
    """An early ping referencing an unknown auth_req_id is refused, not created."""
    with pytest.raises(KeycloakCibaNotificationError):
        service.handle_notification(
            CibaNotification(auth_req_id="missing", credential=PING_SECRET),
        )


def test_notification_with_wrong_credential_is_rejected(
    service: CibaService,
    server: FakeCibaServer,
    storage: InMemoryCibaStorage,
) -> None:
    """A bad ping credential leaves the transaction untouched in INITIATED."""
    transaction = service.initiate(REALM, CLIENT, login_hint="alice")

    with pytest.raises(KeycloakCibaNotificationError):
        service.handle_notification(
            CibaNotification(auth_req_id=transaction.auth_req_id, credential="wrong"),
        )

    stored = storage.get(transaction.auth_req_id)
    assert stored.status is CibaStatus.INITIATED
    assert stored.notified_at is None


def test_notification_credential_is_bound_to_realm_and_client(
    storage: InMemoryCibaStorage,
    server: FakeCibaServer,
) -> None:
    """A secret is rejected when the realm/client binding does not match."""
    openid_client = server.build_client()
    matching = SharedSecretAuthenticator(PING_SECRET, CLIENT, REALM)
    bound_service = CibaService.for_client(storage, openid_client, matching)
    transaction = bound_service.initiate(REALM, CLIENT, login_hint="alice")

    # The same secret value presented by an authenticator scoped to another
    # realm must not validate the stored transaction.
    wrong_realm = SharedSecretAuthenticator(PING_SECRET, CLIENT, "other-realm")
    wrong_client = SharedSecretAuthenticator(PING_SECRET, "other-client", REALM)

    assert wrong_realm.authenticate(ping(server, transaction.auth_req_id), transaction) is False
    assert wrong_client.authenticate(ping(server, transaction.auth_req_id), transaction) is False
    assert matching.authenticate(ping(server, transaction.auth_req_id), transaction) is True


def test_hmac_authenticator_accepts_signature_and_rejects_tampering() -> None:
    """The HMAC credential is derived from the auth_req_id and key."""
    key = b"super-secret-key"
    authenticator = HmacNotificationAuthenticator(key, CLIENT, REALM)
    transaction = CibaTransaction(
        auth_req_id="req-1",
        client_id=CLIENT,
        realm_name=REALM,
    )
    valid = CibaNotification("req-1", authenticator.sign("req-1"))
    forged = CibaNotification("req-1", authenticator.sign("req-2"))

    assert authenticator.authenticate(valid, transaction) is True
    assert authenticator.authenticate(forged, transaction) is False


def test_exchange_before_notification_is_refused(
    service: CibaService,
    server: FakeCibaServer,
) -> None:
    """Polling the token endpoint without a valid ping is a pending error."""
    transaction = service.initiate(REALM, CLIENT, login_hint="alice")

    with pytest.raises(KeycloakCibaPendingError):
        service.exchange_token(transaction.auth_req_id)
    assert server.token_exchanges == []


def test_authorization_pending_keeps_transaction_retryable(
    service: CibaService,
    server: FakeCibaServer,
) -> None:
    """A provider 'authorization_pending' answer does not deliver a token."""
    transaction = service.initiate(REALM, CLIENT, login_hint="alice")
    service.handle_notification(ping(server, transaction.auth_req_id))
    server.set_outcome(transaction.auth_req_id, "pending", delay_exchanges=1)

    with pytest.raises(KeycloakCibaPendingError):
        service.exchange_token(transaction.auth_req_id)
    assert transaction.status is CibaStatus.NOTIFIED
    assert transaction.attempts == 1

    server.set_outcome(transaction.auth_req_id, "approved")
    completed = service.exchange_token(transaction.auth_req_id)
    assert completed.status is CibaStatus.SUCCEEDED
    assert completed.token["access_token"] == f"access-{transaction.auth_req_id}"


def test_successful_exchange_is_the_only_token_delivery_point(
    service: CibaService,
    server: FakeCibaServer,
) -> None:
    """The token becomes available only after a successful exchange."""
    transaction = service.initiate(REALM, CLIENT, login_hint="alice")
    service.handle_notification(ping(server, transaction.auth_req_id))
    assert transaction.token_ready is False

    server.set_outcome(transaction.auth_req_id, "approved")
    completed = service.exchange_token(transaction.auth_req_id)

    assert completed.token_ready is True
    assert completed.token["refresh_token"] == f"refresh-{transaction.auth_req_id}"
    assert completed.attempts == 1


def test_repeated_exchange_returns_cached_success_without_another_call(
    service: CibaService,
    server: FakeCibaServer,
) -> None:
    """A succeeded transaction is returned directly and not exchanged again."""
    transaction = service.initiate(REALM, CLIENT, login_hint="alice")
    service.handle_notification(ping(server, transaction.auth_req_id))
    server.set_outcome(transaction.auth_req_id, "approved")
    service.exchange_token(transaction.auth_req_id)

    again = service.exchange_token(transaction.auth_req_id)

    assert again.status is CibaStatus.SUCCEEDED
    assert len(server.token_exchanges) == 1


def test_user_denial_is_terminal_and_never_succeeds(
    service: CibaService,
    server: FakeCibaServer,
    storage: InMemoryCibaStorage,
) -> None:
    """An access_denied answer marks the transaction denied without a token."""
    transaction = service.initiate(REALM, CLIENT, login_hint="alice")
    service.handle_notification(ping(server, transaction.auth_req_id))
    server.set_outcome(transaction.auth_req_id, "denied")

    with pytest.raises(KeycloakCibaDeniedError):
        service.exchange_token(transaction.auth_req_id)

    stored = storage.get(transaction.auth_req_id)
    assert stored.status is CibaStatus.DENIED
    assert stored.token is None
    assert stored.error == "access_denied"

    with pytest.raises(KeycloakCibaDeniedError):
        service.exchange_token(transaction.auth_req_id)


def test_expired_transaction_never_calls_token_endpoint(
    service: CibaService,
    server: FakeCibaServer,
    storage: InMemoryCibaStorage,
) -> None:
    """Local expiry is enforced before any token exchange request."""
    transaction = service.initiate(
        REALM,
        CLIENT,
        login_hint="alice",
        requested_expiry=10,
    )
    service.handle_notification(ping(server, transaction.auth_req_id))

    with pytest.raises(KeycloakCibaExpiredError):
        service.exchange_token(
            transaction.auth_req_id,
            now=transaction.initiated_at + 11,
        )

    assert storage.get(transaction.auth_req_id).status is CibaStatus.EXPIRED
    assert server.token_exchanges == []


def test_provider_expired_token_maps_to_expired_status(
    service: CibaService,
    server: FakeCibaServer,
) -> None:
    """A provider 'expired_token' answer is stored as a terminal expiry."""
    transaction = service.initiate(REALM, CLIENT, login_hint="alice")
    service.handle_notification(ping(server, transaction.auth_req_id))
    server.set_outcome(transaction.auth_req_id, "expired")

    with pytest.raises(KeycloakCibaExpiredError):
        service.exchange_token(transaction.auth_req_id)
    assert transaction.status is CibaStatus.EXPIRED


def test_unknown_result_stays_retryable_not_successful(
    service: CibaService,
    server: FakeCibaServer,
    storage: InMemoryCibaStorage,
) -> None:
    """A connection failure marks the result unknown and keeps it retryable."""
    transaction = service.initiate(REALM, CLIENT, login_hint="alice")
    service.handle_notification(ping(server, transaction.auth_req_id))
    client = service._clients[(REALM, CLIENT)]
    original = client.token

    def broken(**kwargs: object) -> None:
        reason = "network down"
        raise KeycloakConnectionError(reason)

    client.token = broken  # type: ignore[method-assign]
    try:
        with pytest.raises(KeycloakCibaUnknownResultError):
            service.exchange_token(transaction.auth_req_id)
    finally:
        client.token = original  # type: ignore[method-assign]

    record = storage.get(transaction.auth_req_id)
    assert record.status is CibaStatus.UNKNOWN
    assert record.token is None

    # The retry after connectivity is restored can still complete the exchange.
    server.set_outcome(transaction.auth_req_id, "approved")
    completed = service.exchange_token(transaction.auth_req_id)
    assert completed.status is CibaStatus.SUCCEEDED


def test_unexpected_provider_error_is_unknown_and_not_success(
    service: CibaService,
    server: FakeCibaServer,
    storage: InMemoryCibaStorage,
) -> None:
    """Any unmapped provider error is treated as an unknown, retryable outcome."""
    transaction = service.initiate(REALM, CLIENT, login_hint="alice")
    service.handle_notification(ping(server, transaction.auth_req_id))
    client = service._clients[(REALM, CLIENT)]
    original = client.token

    def broken(**kwargs: object) -> None:
        reason = "internal"
        raise KeycloakError(
            error_message=reason,
            response_code=500,
            response_body=b'{"error": "server_error"}',
        )

    client.token = broken  # type: ignore[method-assign]
    try:
        with pytest.raises(KeycloakCibaUnknownResultError):
            service.exchange_token(transaction.auth_req_id)
    finally:
        client.token = original  # type: ignore[method-assign]

    assert storage.get(transaction.auth_req_id).status is CibaStatus.UNKNOWN


def test_two_interleaved_authentications_remain_isolated(
    service: CibaService,
    server: FakeCibaServer,
    storage: InMemoryCibaStorage,
) -> None:
    """Cross-wired notifications and one failure must never flip the other tx."""
    first = service.initiate(REALM, CLIENT, login_hint="alice", binding_message="A")
    second = service.initiate(REALM, CLIENT, login_hint="bob", binding_message="B")

    # Only the first transaction is notified; the second stays initiated.
    service.handle_notification(ping(server, first.auth_req_id))
    with pytest.raises(KeycloakCibaPendingError):
        service.exchange_token(second.auth_req_id)

    # The second user denies; the first user approves.
    server.set_outcome(second.auth_req_id, "denied")
    service.handle_notification(ping(server, second.auth_req_id))
    with pytest.raises(KeycloakCibaDeniedError):
        service.exchange_token(second.auth_req_id)

    server.set_outcome(first.auth_req_id, "approved")
    completed = service.exchange_token(first.auth_req_id)

    first_record = storage.get(first.auth_req_id)
    second_record = storage.get(second.auth_req_id)
    assert completed is first_record
    assert first_record.status is CibaStatus.SUCCEEDED
    assert first_record.token["access_token"] == f"access-{first.auth_req_id}"
    assert second_record.status is CibaStatus.DENIED
    assert second_record.token is None


def test_multiple_realms_and_clients_are_independent(
    storage: InMemoryCibaStorage,
) -> None:
    """Two realm/client pairs keep their transports and credentials separate."""
    first_server = FakeCibaServer("realm-a", "client-a", notification_credential="secret-a")
    second_server = FakeCibaServer("realm-b", "client-b", notification_credential="secret-b")
    service = CibaService(
        storage=storage,
        clients={
            ("realm-a", "client-a"): first_server.build_client(),
            ("realm-b", "client-b"): second_server.build_client(),
        },
        authenticators={
            ("realm-a", "client-a"): SharedSecretAuthenticator("secret-a", "client-a", "realm-a"),
            ("realm-b", "client-b"): SharedSecretAuthenticator("secret-b", "client-b", "realm-b"),
        },
    )

    first = service.initiate("realm-a", "client-a", login_hint="alice")
    second = service.initiate("realm-b", "client-b", login_hint="bob")

    # A credential from realm-a must not authenticate the realm-b transaction.
    with pytest.raises(KeycloakCibaNotificationError):
        service.handle_notification(
            CibaNotification(second.auth_req_id, "secret-a"),
        )

    service.handle_notification(
        CibaNotification(second.auth_req_id, "secret-b"),
    )
    second_server.set_outcome(second.auth_req_id, "approved")
    completed = service.exchange_token(second.auth_req_id)

    assert completed.realm_name == "realm-b"
    assert completed.client_id == "client-b"
    assert storage.get(first.auth_req_id).status is CibaStatus.INITIATED


def test_notification_on_expired_request_marks_expired(
    service: CibaService,
    server: FakeCibaServer,
    storage: InMemoryCibaStorage,
) -> None:
    """A late ping on an expired request is accepted for auth but flagged expired."""
    transaction = service.initiate(
        REALM,
        CLIENT,
        login_hint="alice",
        requested_expiry=5,
    )

    with pytest.raises(KeycloakCibaExpiredError):
        service.handle_notification(
            ping(server, transaction.auth_req_id),
            now=transaction.initiated_at + 6,
        )
    assert storage.get(transaction.auth_req_id).status is CibaStatus.EXPIRED


def test_transaction_expiry_helpers() -> None:
    """The model computes expiry and terminal flags correctly."""
    transaction = CibaTransaction(
        auth_req_id="req",
        client_id=CLIENT,
        realm_name=REALM,
        expires_in=10,
        initiated_at=100.0,
    )
    assert transaction.expires_at == 110.0
    assert transaction.is_expired(now=109.0) is False
    assert transaction.is_expired(now=110.0) is True
    assert transaction.is_terminal is False
    assert transaction.token_ready is False

    transaction.status = CibaStatus.SUCCEEDED
    transaction.token = {"access_token": "token"}
    assert transaction.is_terminal is True
    assert transaction.token_ready is True
