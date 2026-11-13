"""Shared descriptions of the OpenID Connect form requests.

This module contains no I/O and no client state.  Every builder creates a new,
immutable :class:`FormRequest` from the values supplied by the caller, so the
synchronous and asynchronous transports consume exactly the same path, form
fields, and authentication placement.

Client authentication is always carried in the form body.  When
``bearer_auth`` is set, the caller must supply the user token to the transport
at dispatch time; the token is intentionally not stored on the description.
"""

from __future__ import annotations

from collections.abc import Mapping
from dataclasses import dataclass
from types import MappingProxyType
from typing import Any

from .exceptions import KeycloakRPTNotFound
from .urls_patterns import URL_INTROSPECT, URL_TOKEN

FORM_CONTENT_TYPE = "application/x-www-form-urlencoded"


@dataclass(frozen=True, slots=True)
class FormRequest:
    """
    Immutable form-encoded POST request description.

    :param path: Request path relative to the Keycloak base URL
    :type path: str
    :param form: Form fields to send in the request body
    :type form: Mapping[str, Any]
    :param content_type: Content type override for this request, if any
    :type content_type: str | None
    :param bearer_auth: Whether the transport must add a caller-supplied bearer header
    :type bearer_auth: bool
    """

    path: str
    form: Mapping[str, Any]
    content_type: str | None = None
    bearer_auth: bool = False

    def __post_init__(self) -> None:
        object.__setattr__(self, "form", MappingProxyType(dict(self.form)))


def _without_none(form: Mapping[str, Any]) -> dict[str, Any]:
    return {key: value for key, value in form.items() if value is not None}


def build_token_request(
    *,
    realm_name: str,
    client_id: str,
    client_secret: str | None,
    username: str | None,
    password: str | None,
    grant_type: str,
    code: str,
    redirect_uri: str,
    totp: int | None,
    scope: str,
    code_verifier: str | None,
    extra: Mapping[str, Any],
) -> FormRequest:
    """
    Build the password / authorization-code token request.

    :returns: Immutable request description
    :rtype: FormRequest
    """
    form: dict[str, Any] = {
        "username": username,
        "password": password,
        "client_id": client_id,
        "grant_type": grant_type,
        "code": code,
        "redirect_uri": redirect_uri,
        "scope": scope,
    }
    if code_verifier:
        form["code_verifier"] = code_verifier
    if extra:
        form.update(extra)
    if totp:
        form["totp"] = totp
    if client_secret:
        form["client_secret"] = client_secret

    return FormRequest(
        path=URL_TOKEN.format(**{"realm-name": realm_name}),
        form=_without_none(form),
        content_type=FORM_CONTENT_TYPE,
    )


def build_refresh_token_request(
    *,
    realm_name: str,
    client_id: str,
    client_secret: str | None,
    refresh_token: str,
    grant_type: str,
) -> FormRequest:
    """
    Build the refresh-token request.

    :returns: Immutable request description
    :rtype: FormRequest
    """
    form: dict[str, Any] = {
        "client_id": client_id,
        "grant_type": grant_type,
        "refresh_token": refresh_token,
    }
    if client_secret:
        form["client_secret"] = client_secret

    return FormRequest(
        path=URL_TOKEN.format(**{"realm-name": realm_name}),
        form=_without_none(form),
        content_type=FORM_CONTENT_TYPE,
    )


def build_exchange_token_request(
    *,
    realm_name: str,
    client_id: str,
    client_secret: str | None,
    token: str,
    audience: str | None,
    subject: str | None,
    subject_token_type: str | None,
    subject_issuer: str | None,
    requested_issuer: str | None,
    requested_token_type: str,
    scope: str,
) -> FormRequest:
    """
    Build the token-exchange request.

    :returns: Immutable request description
    :rtype: FormRequest
    """
    form: dict[str, Any] = {
        "grant_type": "urn:ietf:params:oauth:grant-type:token-exchange",
        "client_id": client_id,
        "subject_token": token,
        "subject_token_type": subject_token_type,
        "subject_issuer": subject_issuer,
        "requested_token_type": requested_token_type,
        "audience": audience,
        "requested_subject": subject,
        "requested_issuer": requested_issuer,
        "scope": scope,
    }
    if client_secret:
        form["client_secret"] = client_secret

    return FormRequest(
        path=URL_TOKEN.format(**{"realm-name": realm_name}),
        form=_without_none(form),
        content_type=FORM_CONTENT_TYPE,
    )


def build_introspection_request(
    *,
    realm_name: str,
    client_id: str,
    client_secret: str | None,
    token: str,
    rpt: str | None,
    token_type_hint: str | None,
) -> FormRequest:
    """
    Build the token-introspection request.

    The user token is only placed on the description when it is the token being
    introspected.  In the RPT flow it is the transport's bearer material and is
    supplied separately at dispatch time.

    :returns: Immutable request description
    :rtype: FormRequest
    :raises KeycloakRPTNotFound: If the RPT flow is requested without an RPT
    """
    rpt_flow = token_type_hint == "requesting_party_token"  # noqa: S105
    if rpt_flow:
        if not rpt:
            msg = "Can't find RPT"
            raise KeycloakRPTNotFound(msg)
        form: dict[str, Any] = {
            "client_id": client_id,
            "token": rpt,
            "token_type_hint": token_type_hint,
        }
    else:
        form = {"client_id": client_id, "token": token}
    if client_secret:
        form["client_secret"] = client_secret

    return FormRequest(
        path=URL_INTROSPECT.format(**{"realm-name": realm_name}),
        form=_without_none(form),
        bearer_auth=rpt_flow,
    )
