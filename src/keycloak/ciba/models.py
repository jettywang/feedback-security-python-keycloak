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
Domain models for the CIBA ping flow.

These classes describe the state of a single backchannel authentication
transaction. They deliberately carry no persistence or transport logic: the
calling application provides both through the storage protocol and the
:class:`~keycloak.keycloak_openid.KeycloakOpenID` client.
"""

from __future__ import annotations

import time
from dataclasses import dataclass, field
from enum import Enum


class CibaStatus(str, Enum):
    """
    Lifecycle states of a CIBA transaction.

    A ping notification only ever moves a transaction to
    :attr:`NOTIFIED`, never directly to :attr:`SUCCEEDED`. A token is delivered
    only after a successful token exchange against the identity provider.
    """

    INITIATED = "initiated"
    NOTIFIED = "notified"
    SUCCEEDED = "succeeded"
    DENIED = "denied"
    EXPIRED = "expired"
    FAILED = "failed"
    UNKNOWN = "unknown"


@dataclass
class CibaTransaction:
    """
    A single CIBA authentication transaction.

    The transaction is bound to the triple ``(auth_req_id, client_id, realm)``.
    Notification credentials and access tokens must never be shared across
    transactions, so every persisted record keeps its own identifiers.

    :param auth_req_id: Identifier returned by the backchannel authentication
        endpoint
    :type auth_req_id: str
    :param client_id: OAuth client that initiated the request
    :type client_id: str
    :param realm_name: Keycloak realm the request belongs to
    :type realm_name: str
    :param scope: Requested scope
    :type scope: str
    :param binding_message: Binding message shown on both devices
    :type binding_message: str
    :param expires_in: Lifetime of ``auth_req_id`` in seconds
    :type expires_in: int
    :param interval: Minimum polling interval in seconds
    :type interval: int
    :param initiated_at: Epoch seconds at which the request was initiated
    :type initiated_at: float
    :param status: Current lifecycle state
    :type status: CibaStatus
    :param notified_at: Epoch seconds of the first valid ping notification
    :type notified_at: float
    :param token: Token response once the exchange succeeded
    :type token: dict
    :param error: Provider error code for terminal failures
    :type error: str
    :param error_description: Human readable provider error description
    :type error_description: str
    :param attempts: Number of token exchange attempts
    :type attempts: int
    """

    auth_req_id: str
    client_id: str
    realm_name: str
    scope: str = "openid"
    binding_message: str | None = None
    expires_in: int = 120
    interval: int = 5
    initiated_at: float = field(default_factory=time.time)
    status: CibaStatus = CibaStatus.INITIATED
    notified_at: float | None = None
    token: dict | None = None
    error: str | None = None
    error_description: str | None = None
    attempts: int = 0

    @property
    def expires_at(self) -> float:
        """
        Epoch seconds at which the authentication request expires.

        :returns: Initiation timestamp plus the granted lifetime
        :rtype: float
        """
        return self.initiated_at + self.expires_in

    def is_expired(self, now: float | None = None) -> bool:
        """
        Tell whether the auth_req_id lifetime has elapsed.

        :param now: Override the current epoch seconds, useful for testing
        :type now: float
        :returns: True when the request has expired
        :rtype: bool
        """
        if now is None:
            now = time.time()
        return now >= self.expires_at

    @property
    def is_terminal(self) -> bool:
        """
        Tell whether the transaction has reached a final state.

        :returns: True for succeeded, denied, expired and failed states
        :rtype: bool
        """
        return self.status in (
            CibaStatus.SUCCEEDED,
            CibaStatus.DENIED,
            CibaStatus.EXPIRED,
            CibaStatus.FAILED,
        )

    @property
    def token_ready(self) -> bool:
        """
        Tell whether an access token may be delivered to the caller.

        Only a completed token exchange makes the transaction token ready; a
        notification alone never does.

        :returns: True when a token response is stored
        :rtype: bool
        """
        return self.status is CibaStatus.SUCCEEDED and self.token is not None
