#
# The MIT License (MIT)
#
# Copyright (C) 2017 Marcos Pereira <marcospereira.mpj@gmail.com>
#
# Permission is hereby granted, free of charge, to any person obtaining a copy of
# this software and associated documentation files (the "Software"), to deal in
# the Software without restriction, including without limitation the rights to
# use, copy, modify, merge, publish, distribute, sublicense, and/or sell copies of
# the Software, and to permit persons to whom the Software is furnished to do so,
# subject to the following conditions:
#
# The above copyright notice and this permission notice shall be included in all
# copies or substantial portions of the Software.
#
# THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
# IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY, FITNESS
# FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR
# COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER
# IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN
# CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.


"""
Application service implementing the CIBA ping flow on top of python-keycloak.

The service owns the transaction state machine but stays free of transport and
persistence concerns:

* HTTP transport is the injected :class:`~keycloak.keycloak_openid.KeycloakOpenID`
  client (or several clients, keyed by realm and client id);
* persistence is any object implementing :class:`~keycloak.ciba.storage.CibaStorage`.

Security invariants enforced here:

* notifications are authenticated with a credential scoped to the
  ``(auth_req_id, client_id, realm_name)`` triple, which is never treated as an
  access token;
* a valid ping only flips a transaction to ``NOTIFIED``; no token is fetched or
  delivered until an explicit token exchange succeeds;
* every state change targets exactly the transaction identified by its
  ``auth_req_id``, so a failure of one transaction can never mark a different
  one as successful;
* unknown exchange outcomes are kept retryable instead of being reported as
  success.
"""

from __future__ import annotations

import json
import time
from typing import TYPE_CHECKING

from keycloak.exceptions import (
    KeycloakCibaDeniedError,
    KeycloakCibaExpiredError,
    KeycloakCibaNotificationError,
    KeycloakCibaPendingError,
    KeycloakCibaTransactionError,
    KeycloakCibaUnknownResultError,
    KeycloakConnectionError,
    KeycloakError,
)

from .models import CibaStatus, CibaTransaction

if TYPE_CHECKING:
    from collections.abc import Mapping

    from keycloak.keycloak_openid import KeycloakOpenID

    from .notification import CibaNotification, NotificationAuthenticator
    from .storage import CibaStorage

#: OAuth grant type urn for CIBA token exchanges.
GRANT_TYPE_CIBA = "urn:ietf:params:oauth:grant-type:ciba"

#: Provider error codes defined by the CIBA specification.
ERROR_AUTHORIZATION_PENDING = "authorization_pending"
ERROR_SLOW_DOWN = "slow_down"
ERROR_ACCESS_DENIED = "access_denied"
ERROR_EXPIRED_TOKEN = "expired_token"  # noqa: S105


class CibaService:
    """
    Coordinate CIBA ping authentications for one or more Keycloak clients.

    :param storage: Application provided transaction store
    :type storage: CibaStorage
    :param clients: KeycloakOpenID clients keyed by ``(realm_name, client_id)``
    :type clients: Mapping[tuple[str, str], KeycloakOpenID]
    :param authenticators: Notification authenticators keyed by
        ``(realm_name, client_id)``
    :type authenticators: Mapping[tuple[str, str], NotificationAuthenticator]
    """

    def __init__(
        self,
        storage: CibaStorage,
        clients: Mapping[tuple[str, str], KeycloakOpenID] | None = None,
        authenticators: Mapping[tuple[str, str], NotificationAuthenticator] | None = None,
    ) -> None:
        """
        Initialise the service with optional client and authenticator registries.

        :param storage: Application provided transaction store
        :type storage: CibaStorage
        :param clients: KeycloakOpenID clients keyed by ``(realm_name, client_id)``
        :type clients: Mapping[tuple[str, str], KeycloakOpenID]
        :param authenticators: Notification authenticators keyed by
            ``(realm_name, client_id)``
        :type authenticators: Mapping[tuple[str, str], NotificationAuthenticator]
        """
        self.storage = storage
        self._clients: dict[tuple[str, str], KeycloakOpenID] = dict(clients or {})
        self._authenticators: dict[tuple[str, str], NotificationAuthenticator] = dict(
            authenticators or {},
        )

    @classmethod
    def for_client(
        cls: type[CibaService],
        storage: CibaStorage,
        openid_client: KeycloakOpenID,
        authenticator: NotificationAuthenticator,
    ) -> CibaService:
        """
        Build a service for a single realm/client pair.

        :param storage: Application provided transaction store
        :type storage: CibaStorage
        :param openid_client: KeycloakOpenID client used for the backchannel calls
        :type openid_client: KeycloakOpenID
        :param authenticator: Authenticator validating ping notifications
        :type authenticator: NotificationAuthenticator
        :returns: Configured service
        :rtype: CibaService
        """
        key = (openid_client.realm_name, openid_client.client_id)
        return cls(
            storage=storage,
            clients={key: openid_client},
            authenticators={key: authenticator},
        )

    def add_client(
        self,
        openid_client: KeycloakOpenID,
        authenticator: NotificationAuthenticator,
    ) -> None:
        """
        Register another realm/client pair.

        :param openid_client: KeycloakOpenID client used for the backchannel calls
        :type openid_client: KeycloakOpenID
        :param authenticator: Authenticator validating ping notifications
        :type authenticator: NotificationAuthenticator
        """
        key = (openid_client.realm_name, openid_client.client_id)
        self._clients[key] = openid_client
        self._authenticators[key] = authenticator

    @staticmethod
    def _binding_key(transaction: CibaTransaction) -> tuple[str, str]:
        return transaction.realm_name, transaction.client_id

    def _require_transaction(self, auth_req_id: str) -> CibaTransaction:
        transaction = self.storage.get(auth_req_id)
        if transaction is None:
            msg = f"Unknown CIBA auth_req_id '{auth_req_id}'."
            raise KeycloakCibaTransactionError(msg)
        return transaction

    def initiate(
        self,
        realm_name: str,
        client_id: str,
        *,
        login_hint: str | None = None,
        login_hint_token: str | None = None,
        id_token_hint: str | None = None,
        scope: str = "openid",
        binding_message: str | None = None,
        requested_expiry: int | None = None,
        now: float | None = None,
    ) -> CibaTransaction:
        """
        Start a backchannel authentication and persist the pending transaction.

        Only the backchannel endpoint is called; no token is requested here.

        :param realm_name: Realm name
        :type realm_name: str
        :param client_id: OAuth client id
        :type client_id: str
        :param login_hint: Hint identifying the end user
        :type login_hint: str
        :param login_hint_token: Opaque token identifying the end user
        :type login_hint_token: str
        :param id_token_hint: ID token previously issued for the end user
        :type id_token_hint: str
        :param scope: Requested scope
        :type scope: str
        :param binding_message: Message shown on both devices
        :type binding_message: str
        :param requested_expiry: Requested auth_req_id lifetime in seconds
        :type requested_expiry: int
        :param now: Override for the current epoch seconds (testing)
        :type now: float
        :returns: Persisted transaction in ``INITIATED`` state
        :rtype: CibaTransaction
        :raises KeycloakCibaTransactionError: When the client is not registered
        """
        openid_client = self._clients.get((realm_name, client_id))
        if openid_client is None:
            msg = f"No Keycloak client registered for realm '{realm_name}', client '{client_id}'."
            raise KeycloakCibaTransactionError(msg)

        response = openid_client.ciba(
            login_hint=login_hint,
            login_hint_token=login_hint_token,
            id_token_hint=id_token_hint,
            scope=scope,
            binding_message=binding_message,
            requested_expiry=requested_expiry,
        )
        auth_req_id = response["auth_req_id"]
        transaction = CibaTransaction(
            auth_req_id=auth_req_id,
            client_id=client_id,
            realm_name=realm_name,
            scope=scope,
            binding_message=binding_message,
            expires_in=int(response.get("expires_in", 120)),
            interval=int(response.get("interval", 5)),
            initiated_at=time.time() if now is None else now,
            status=CibaStatus.INITIATED,
        )
        self.storage.save(transaction)
        return transaction

    def handle_notification(
        self,
        notification: CibaNotification,
        *,
        now: float | None = None,
    ) -> CibaTransaction:
        """
        Validate and record an inbound CIBA ping notification.

        A notification arriving before the initiation response has been stored
        is rejected, as are unknown or bad-credential notifications. A valid
        notification only marks the transaction ``NOTIFIED``: it never fetches a
        token and never marks the user as authenticated. Repeated notifications
        are idempotent.

        :param notification: Parsed ping notification
        :type notification: CibaNotification
        :param now: Override for the current epoch seconds (testing)
        :type now: float
        :returns: The updated, persisted transaction
        :rtype: CibaTransaction
        :raises KeycloakCibaNotificationError: When the notification is unknown
            or fails authentication
        :raises KeycloakCibaExpiredError: When the auth_req_id has expired
        """
        transaction = self.storage.get(notification.auth_req_id)
        if transaction is None:
            msg = (
                "CIBA notification references an unknown auth_req_id; it may have arrived "
                "before the initiation response was stored."
            )
            raise KeycloakCibaNotificationError(msg)

        authenticator = self._authenticators.get(self._binding_key(transaction))
        if authenticator is None:
            msg = (
                "No notification authenticator registered for realm "
                f"'{transaction.realm_name}', client '{transaction.client_id}'."
            )
            raise KeycloakCibaNotificationError(msg)

        if not authenticator.authenticate(notification, transaction):
            msg = "CIBA notification credential failed authentication."
            raise KeycloakCibaNotificationError(msg)

        if transaction.is_expired(now):
            transaction.status = CibaStatus.EXPIRED
            self.storage.save(transaction)
            msg = f"CIBA auth_req_id '{transaction.auth_req_id}' has expired."
            raise KeycloakCibaExpiredError(msg)

        if transaction.is_terminal:
            # Idempotent: duplicate pings must not change a terminal outcome.
            return transaction

        if transaction.status is CibaStatus.INITIATED:
            transaction.status = CibaStatus.NOTIFIED
            transaction.notified_at = time.time() if now is None else now
            self.storage.save(transaction)

        return transaction

    @staticmethod
    def _provider_error(error: KeycloakError) -> str | None:
        body = getattr(error, "response_body", None)
        if not body:
            return None
        try:
            payload = json.loads(body)
        except (TypeError, ValueError):
            return None
        if isinstance(payload, dict):
            value = payload.get("error")
            return value if isinstance(value, str) else None
        return None

    def exchange_token(
        self,
        auth_req_id: str,
        *,
        now: float | None = None,
    ) -> CibaTransaction:
        """
        Exchange a notified auth_req_id for the final token response.

        The token is delivered only after this method performs the token
        exchange and the provider answers successfully. Notifications, pending
        polls, denials and unknown outcomes never produce a deliverable token
        and never modify any other transaction.

        :param auth_req_id: Authentication request identifier
        :type auth_req_id: str
        :param now: Override for the current epoch seconds (testing)
        :type now: float
        :returns: Transaction containing the token on success
        :rtype: CibaTransaction
        :raises KeycloakCibaPendingError: Before a notification or while pending
        :raises KeycloakCibaDeniedError: When the user denied the request
        :raises KeycloakCibaExpiredError: When the request expired
        :raises KeycloakCibaUnknownResultError: When the exchange outcome is unknown
        """
        transaction = self._require_transaction(auth_req_id)
        openid_client = self._clients.get(self._binding_key(transaction))
        if openid_client is None:
            msg = (
                "No Keycloak client registered for realm "
                f"'{transaction.realm_name}', client '{transaction.client_id}'."
            )
            raise KeycloakCibaTransactionError(msg)

        if transaction.is_expired(now):
            transaction.status = CibaStatus.EXPIRED
            self.storage.save(transaction)
            msg = f"CIBA auth_req_id '{auth_req_id}' has expired."
            raise KeycloakCibaExpiredError(msg)

        if transaction.status is CibaStatus.SUCCEEDED:
            return transaction
        if transaction.status is CibaStatus.DENIED:
            msg = f"CIBA auth_req_id '{auth_req_id}' was denied by the user."
            raise KeycloakCibaDeniedError(msg)
        if transaction.status is CibaStatus.EXPIRED:
            msg = f"CIBA auth_req_id '{auth_req_id}' has expired."
            raise KeycloakCibaExpiredError(msg)
        if transaction.status is CibaStatus.FAILED:
            msg = f"CIBA auth_req_id '{auth_req_id}' failed permanently."
            raise KeycloakCibaTransactionError(msg)
        if transaction.status is CibaStatus.INITIATED:
            msg = (
                "No valid ping notification recorded for CIBA auth_req_id "
                f"'{auth_req_id}'; the token endpoint must not be polled yet."
            )
            raise KeycloakCibaPendingError(msg)

        transaction.attempts += 1
        try:
            token_response = openid_client.token(
                grant_type=GRANT_TYPE_CIBA,
                auth_req_id=auth_req_id,
            )
        except KeycloakConnectionError as error:
            # The provider never answered: the result is unknown, keep the
            # transaction retryable instead of claiming success or failure.
            transaction.status = CibaStatus.UNKNOWN
            self.storage.save(transaction)
            msg = (
                "CIBA token exchange could not reach the identity provider; the "
                "outcome is unknown and the exchange may be retried."
            )
            raise KeycloakCibaUnknownResultError(msg) from error
        except KeycloakError as error:
            self._handle_provider_error(transaction, error)

        transaction.status = CibaStatus.SUCCEEDED
        transaction.token = token_response
        self.storage.save(transaction)
        return transaction

    def _handle_provider_error(
        self,
        transaction: CibaTransaction,
        error: KeycloakError,
    ) -> None:
        code = self._provider_error(error)
        if code in (ERROR_AUTHORIZATION_PENDING, ERROR_SLOW_DOWN):
            self.storage.save(transaction)
            msg = f"CIBA auth_req_id '{transaction.auth_req_id}' is not finished yet."
            raise KeycloakCibaPendingError(
                msg,
                error.response_code,
                error.response_body,
            ) from error
        if code == ERROR_ACCESS_DENIED:
            transaction.status = CibaStatus.DENIED
            transaction.error = code
            transaction.error_description = str(error.error_message)
            self.storage.save(transaction)
            msg = f"CIBA auth_req_id '{transaction.auth_req_id}' was denied by the user."
            raise KeycloakCibaDeniedError(msg, error.response_code, error.response_body) from error
        if code == ERROR_EXPIRED_TOKEN:
            transaction.status = CibaStatus.EXPIRED
            transaction.error = code
            transaction.error_description = str(error.error_message)
            self.storage.save(transaction)
            msg = f"CIBA auth_req_id '{transaction.auth_req_id}' has expired."
            raise KeycloakCibaExpiredError(
                msg,
                error.response_code,
                error.response_body,
            ) from error

        # Any other provider error leaves the outcome unknown so the caller can
        # retry; it is never translated into a successful token delivery.
        transaction.status = CibaStatus.UNKNOWN
        transaction.error = code or "unknown_error"
        transaction.error_description = str(error.error_message)
        self.storage.save(transaction)
        msg = f"CIBA token exchange for '{transaction.auth_req_id}' returned an unknown result."
        raise KeycloakCibaUnknownResultError(
            msg,
            error.response_code,
            error.response_body,
        ) from error
