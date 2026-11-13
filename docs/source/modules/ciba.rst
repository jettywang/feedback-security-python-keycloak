.. _ciba:

CIBA Ping Mode
==============

Client Initiated Backchannel Authentication (CIBA) lets a client start an
authentication on the user's behalf while the user confirms it on a separate,
previously registered device. In **ping mode** the identity provider calls a
client-owned notification endpoint once the user has acted. That notification
is only a nudge to poll the token endpoint: it is not an access token and it
does not, by itself, mean the user is authenticated.

The :mod:`keycloak.ciba` package adds a transaction state machine on top of the
low-level :class:`~keycloak.keycloak_openid.KeycloakOpenID` calls. Transport and
persistence stay the application's responsibility:

* transport is the injected :class:`~keycloak.keycloak_openid.KeycloakOpenID`
  client;
* persistence is any object implementing
  :class:`~keycloak.ciba.storage.CibaStorage`.

Security model
--------------

* Every transaction is bound to the triple
  ``(auth_req_id, client_id, realm_name)``. Notification credentials are scoped
  to that triple and are never treated as access tokens.
* A valid ping only moves a transaction from ``INITIATED`` to ``NOTIFIED``. A
  token is delivered exclusively by a successful token exchange.
* Unknown, duplicate, expired or forged notifications cannot trigger an
  exchange. Repeated notifications are idempotent.
* Unknown exchange outcomes (for example a connection failure) are kept
  retryable and never reported as success. One transaction's failure can never
  mark another transaction as successful.

Starting an authentication
--------------------------

.. code-block:: python

    from keycloak import KeycloakOpenID
    from keycloak.ciba import (
        CibaService,
        InMemoryCibaStorage,
        SharedSecretAuthenticator,
    )

    openid_client = KeycloakOpenID(
        server_url="http://localhost:8080/",
        client_id="example_client",
        realm_name="example_realm",
        client_secret_key="secret",
    )
    storage = InMemoryCibaStorage()  # replace with a durable store in production
    authenticator = SharedSecretAuthenticator(
        expected_credential="provider-ping-secret",
        client_id="example_client",
        realm_name="example_realm",
    )
    service = CibaService.for_client(storage, openid_client, authenticator)

    transaction = service.initiate(
        "example_realm",
        "example_client",
        login_hint="alice",
        binding_message="Confirm login on your phone",
    )

Receiving a notification
------------------------

The HTTP layer that receives the provider callback parses the request and hands
a :class:`~keycloak.ciba.notification.CibaNotification` to the service. The
service authenticates the credential and records the nudge without fetching a
token.

.. code-block:: python

    from keycloak.ciba import CibaNotification, KeycloakCibaNotificationError

    notification = CibaNotification(
        auth_req_id=request.json["auth_req_id"],
        credential=request.headers["Authorization"].removeprefix("Bearer "),
    )
    try:
        transaction = service.handle_notification(notification)
    except KeycloakCibaNotificationError:
        # Unknown auth_req_id or bad credential: do nothing, do not poll.
        raise

Completing the token exchange
-----------------------------

Only after a valid notification may the token endpoint be polled. The token is
available on the transaction once the exchange succeeds.

.. code-block:: python

    from keycloak import (
        KeycloakCibaDeniedError,
        KeycloakCibaExpiredError,
        KeycloakCibaPendingError,
        KeycloakCibaUnknownResultError,
    )

    try:
        transaction = service.exchange_token(transaction.auth_req_id)
    except KeycloakCibaPendingError:
        # User has not finished yet; respect the polling interval and retry.
        pass
    except KeycloakCibaDeniedError:
        # User refused; the transaction is terminal and holds no token.
        pass
    except KeycloakCibaExpiredError:
        # The auth_req_id expired before the exchange completed.
        pass
    except KeycloakCibaUnknownResultError:
        # The outcome could not be determined; the exchange may be retried.
        pass
    else:
        access_token = transaction.token["access_token"]  # safe to deliver now

A runnable, self-contained walkthrough of two interleaved authentications,
including duplicate pings, forged credentials, denial, expiry and unknown
outcomes, lives in ``examples/ciba_ping_demo.py`` and uses an in-process fake
provider so it never contacts a real identity platform.
