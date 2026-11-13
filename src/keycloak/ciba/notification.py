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
CIBA ping notification authentication.

In ping mode the identity provider calls a client-owned HTTP endpoint carrying
the ``auth_req_id`` and a bearer credential. That credential only proves that
the provider may nudge the client to poll; it is not the user's access token and
must be validated before any state changes.

Authenticators are deliberately stateless and receive the transaction so the
secret can be bound to the ``(auth_req_id, client_id, realm)`` triple rather
than shared globally.
"""

from __future__ import annotations

import hashlib
import hmac
from dataclasses import dataclass
from typing import TYPE_CHECKING, Protocol, runtime_checkable

if TYPE_CHECKING:
    from .models import CibaTransaction


@dataclass(frozen=True)
class CibaNotification:
    """
    Parsed body of an inbound ping notification.

    :param auth_req_id: Authentication request identifier referenced by the ping
    :type auth_req_id: str
    :param credential: Bearer credential presented in the Authorization header
    :type credential: str
    """

    auth_req_id: str
    credential: str


@runtime_checkable
class NotificationAuthenticator(Protocol):
    """Strategy used to decide whether a ping notification is genuine."""

    def authenticate(
        self,
        notification: CibaNotification,
        transaction: CibaTransaction,
    ) -> bool:
        """
        Validate a notification against the bound transaction.

        :param notification: Parsed inbound notification
        :type notification: CibaNotification
        :param transaction: Transaction looked up by auth_req_id
        :type transaction: CibaTransaction
        :returns: True when the credential is accepted for this transaction
        :rtype: bool
        """
        ...


class SharedSecretAuthenticator:
    """
    Constant-time authenticator comparing a per-realm/client shared secret.

    The same secret is accepted for every transaction of the configured client
    and realm; mixing realms or clients still fails because the transaction's
    bindings are checked by the service before this authenticator runs.

    :param expected_credential: Secret bearer token configured on the provider
    :type expected_credential: str
    :param client_id: Client the secret is scoped to
    :type client_id: str
    :param realm_name: Realm the secret is scoped to
    :type realm_name: str
    """

    def __init__(
        self,
        expected_credential: str,
        client_id: str,
        realm_name: str,
    ) -> None:
        """
        Initialise the authenticator.

        :param expected_credential: Secret bearer token configured on the provider
        :type expected_credential: str
        :param client_id: Client the secret is scoped to
        :type client_id: str
        :param realm_name: Realm the secret is scoped to
        :type realm_name: str
        """
        self._expected = expected_credential
        self.client_id = client_id
        self.realm_name = realm_name

    def authenticate(
        self,
        notification: CibaNotification,
        transaction: CibaTransaction,
    ) -> bool:
        """
        Compare the presented credential using a constant-time comparison.

        :param notification: Parsed inbound notification
        :type notification: CibaNotification
        :param transaction: Bound transaction
        :type transaction: CibaTransaction
        :returns: True when realm, client and secret all match
        :rtype: bool
        """
        binding_matches = (
            transaction.client_id == self.client_id and transaction.realm_name == self.realm_name
        )
        credential_matches = hmac.compare_digest(
            notification.credential,
            self._expected,
        )
        return binding_matches and credential_matches


class HmacNotificationAuthenticator:
    """
    Authenticator validating an HMAC-SHA256 signature over the auth_req_id.

    Each realm/client owns a signing key. The provider signs the auth_req_id and
    sends the hex digest as the bearer credential, keeping the notification
    credential distinct from any issued access token.

    :param signing_key: Symmetric key shared with the provider
    :type signing_key: bytes
    :param client_id: Client the key is scoped to
    :type client_id: str
    :param realm_name: Realm the key is scoped to
    :type realm_name: str
    """

    def __init__(self, signing_key: bytes, client_id: str, realm_name: str) -> None:
        """
        Initialise the authenticator.

        :param signing_key: Symmetric key shared with the provider
        :type signing_key: bytes
        :param client_id: Client the key is scoped to
        :type client_id: str
        :param realm_name: Realm the key is scoped to
        :type realm_name: str
        """
        self._signing_key = signing_key
        self.client_id = client_id
        self.realm_name = realm_name

    def sign(self, auth_req_id: str) -> str:
        """
        Compute the expected credential for an auth_req_id.

        :param auth_req_id: Authentication request identifier
        :type auth_req_id: str
        :returns: Hex encoded HMAC-SHA256 digest
        :rtype: str
        """
        digest = hmac.new(
            self._signing_key,
            auth_req_id.encode("utf-8"),
            hashlib.sha256,
        )
        return digest.hexdigest()

    def authenticate(
        self,
        notification: CibaNotification,
        transaction: CibaTransaction,
    ) -> bool:
        """
        Validate the HMAC credential and the realm/client binding.

        :param notification: Parsed inbound notification
        :type notification: CibaNotification
        :param transaction: Bound transaction
        :type transaction: CibaTransaction
        :returns: True when the signature and bindings all match
        :rtype: bool
        """
        binding_matches = (
            transaction.client_id == self.client_id and transaction.realm_name == self.realm_name
        )
        expected = self.sign(notification.auth_req_id)
        signature_matches = hmac.compare_digest(notification.credential, expected)
        return binding_matches and signature_matches
