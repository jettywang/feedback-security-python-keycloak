"""
Offline contract tests for the token exchange grant (sync and async).

These tests never touch a real Keycloak server. The HTTP transport of the
client's own ``ConnectionManager`` is mocked one layer below
``KeycloakOpenID.exchange_token`` / ``a_exchange_token`` so the exact form
body that would go on the wire is captured, re-encoded with the real
``requests`` / ``httpx`` encoders and compared in full against the golden
request samples stored under ``tests/data/token_exchange_contract/``.

Pinned transport divergence: the sync stack (``requests``) silently drops
form fields whose value is ``None``, while the async stack (``httpx``)
serializes them as empty strings. The golden samples record both shapes
explicitly (``expected_form_sync`` / ``expected_form_async``).
"""

from __future__ import annotations

import json
from pathlib import Path
from unittest import mock
from urllib.parse import parse_qsl

import httpx
import pytest
import requests
from keycloak import KeycloakOpenID
from keycloak.exceptions import KeycloakAuthenticationError, KeycloakPostError

SAMPLES_DIR = Path(__file__).parent / "data" / "token_exchange_contract"
TOKEN_URL = "https://keycloak.contract.test/realms/contract-realm/protocol/openid-connect/token"  # noqa: S105
SUCCESS_PAYLOAD = {
    "access_token": "exchanged-access-token",
    "refresh_token": "exchanged-refresh-token",
    "token_type": "Bearer",
}


def load_samples() -> list[tuple[str, dict]]:
    """
    Load the golden request samples.

    :returns: List of (sample name, sample data) pairs
    :rtype: list
    """
    return [
        (path.stem, json.loads(path.read_text(encoding="utf-8")))
        for path in sorted(SAMPLES_DIR.glob("*.json"))
    ]


def build_oid(sample: dict) -> KeycloakOpenID:
    """
    Build an offline KeycloakOpenID client from a sample.

    :param sample: Golden sample data
    :type sample: dict
    :returns: Keycloak OpenID client
    :rtype: KeycloakOpenID
    """
    return KeycloakOpenID(
        server_url=sample["server_url"],
        realm_name=sample["realm_name"],
        client_id=sample["client_id"],
        client_secret_key=sample["client_secret_key"],
    )


def sync_response(
    status_code: int,
    payload: dict | None = None,
    raw: bytes | None = None,
) -> requests.Response:
    """
    Build a fake sync (requests) response.

    :param status_code: HTTP status code
    :type status_code: int
    :param payload: JSON payload
    :type payload: dict
    :param raw: Raw body bytes
    :type raw: bytes
    :returns: Fake response
    :rtype: requests.Response
    """
    response = requests.Response()
    response.status_code = status_code
    response._content = json.dumps(payload).encode() if payload is not None else raw
    response.headers["Content-Type"] = "application/json"
    response.url = TOKEN_URL
    return response


def async_response(
    status_code: int,
    payload: dict | None = None,
    raw: bytes | None = None,
) -> httpx.Response:
    """
    Build a fake async (httpx) response.

    :param status_code: HTTP status code
    :type status_code: int
    :param payload: JSON payload
    :type payload: dict
    :param raw: Raw body bytes
    :type raw: bytes
    :returns: Fake response
    :rtype: httpx.Response
    """
    if payload is not None:
        return httpx.Response(status_code, json=payload)
    return httpx.Response(status_code, content=raw)


def decode_form(body: str) -> dict:
    """
    Decode a urlencoded form body, keeping blank values.

    :param body: Urlencoded body
    :type body: str
    :returns: Decoded form fields
    :rtype: dict
    """
    return dict(parse_qsl(body, keep_blank_values=True))


def assert_form_matches(actual: dict, expected: dict) -> None:
    """
    Assert full equality of a decoded form body against the expected fields.

    A missing key, an unexpected key or a diverging value all fail the
    contract, so a swapped delegation identity field cannot slip through.

    :param actual: Decoded form fields captured from the wire
    :type actual: dict
    :param expected: Expected form fields from the golden sample
    :type expected: dict
    """
    assert actual == expected, (
        "Token exchange form body mismatch."
        f"\n  missing: { {k: v for k, v in expected.items() if k not in actual} }"
        f"\n  unexpected: { {k: v for k, v in actual.items() if k not in expected} }"
        "\n  diverging: "
        f"{ {k: (actual.get(k), v) for k, v in expected.items()
              if k in actual and actual.get(k) != v} }"
    )


def run_sync_exchange(oid: KeycloakOpenID, call: dict, response: requests.Response) -> tuple:
    """
    Run exchange_token with the transport mocked and capture the request.

    :param oid: Keycloak OpenID client
    :type oid: KeycloakOpenID
    :param call: Keyword arguments for exchange_token
    :type call: dict
    :param response: Fake response to return
    :type response: requests.Response
    :returns: (result, url, transport kwargs)
    :rtype: tuple
    """
    captured = {}

    def fake_post(*args: object, **kwargs: object) -> requests.Response:
        captured["args"] = args
        captured["kwargs"] = {
            key: dict(value) if isinstance(value, dict) else value for key, value in kwargs.items()
        }
        return response

    with mock.patch.object(oid.connection, "_s") as session:
        session.post.side_effect = fake_post
        result = oid.exchange_token(**call)
    return result, captured["args"][0], captured["kwargs"]


async def run_async_exchange(oid: KeycloakOpenID, call: dict, response: httpx.Response) -> tuple:
    """
    Run a_exchange_token with the transport mocked and capture the request.

    :param oid: Keycloak OpenID client
    :type oid: KeycloakOpenID
    :param call: Keyword arguments for a_exchange_token
    :type call: dict
    :param response: Fake response to return
    :type response: httpx.Response
    :returns: (result, url, transport kwargs)
    :rtype: tuple
    """
    captured = {}

    async def fake_request(**kwargs: object) -> httpx.Response:
        captured["kwargs"] = {
            key: dict(value) if isinstance(value, dict) else value for key, value in kwargs.items()
        }
        return response

    with mock.patch.object(oid.connection.async_s, "request", new=fake_request):
        result = await oid.a_exchange_token(**call)
    return result, captured["kwargs"]["url"], captured["kwargs"]


def sync_wire_body(url: str, headers: dict, data: dict) -> str:
    """
    Re-encode the captured sync request exactly as requests would send it.

    :param url: Request URL
    :type url: str
    :param headers: Request headers
    :type headers: dict
    :param data: Form data
    :type data: dict
    :returns: Urlencoded body
    :rtype: str
    """
    return requests.Request("POST", url, headers=headers, data=data).prepare().body


def async_wire_body(url: str, headers: dict, data: dict) -> str:
    """
    Re-encode the captured async request exactly as httpx would send it.

    :param url: Request URL
    :type url: str
    :param headers: Request headers
    :type headers: dict
    :param data: Form data
    :type data: dict
    :returns: Urlencoded body
    :rtype: str
    """
    return httpx.Request("POST", url, headers=headers, data=data).content.decode()


def assert_client_authentication(form: dict, sample: dict) -> None:
    """
    Assert the client authentication material carried by the form body.

    Confidential clients authenticate with client_id + client_secret in the
    form; public clients must not leak any client_secret field.

    :param form: Decoded form fields
    :type form: dict
    :param sample: Golden sample data
    :type sample: dict
    """
    secret = sample["client_secret_key"]
    if secret is None:
        assert "client_secret" not in form
    else:
        assert form["client_secret"] == secret
    assert form["client_id"] == sample["client_id"]


@pytest.mark.parametrize(("name", "sample"), load_samples())
def test_exchange_token_contract_sync(name: str, sample: dict) -> None:
    """
    Verify the sync exchange_token submits the golden form body.

    :param name: Sample name
    :type name: str
    :param sample: Golden sample data
    :type sample: dict
    """
    oid = build_oid(sample)
    result, url, kwargs = run_sync_exchange(
        oid,
        sample["call"],
        sync_response(200, payload=SUCCESS_PAYLOAD),
    )

    assert result == SUCCESS_PAYLOAD
    assert url == TOKEN_URL
    assert kwargs["headers"]["Content-Type"] == "application/x-www-form-urlencoded"
    assert "Authorization" not in kwargs["headers"]

    body = sync_wire_body(url, kwargs["headers"], kwargs["data"])
    form = decode_form(body)
    assert_form_matches(form, sample["expected_form_sync"])
    assert_client_authentication(form, sample)
    for field, encoded in sample["expected_encoded_pairs"].items():
        assert f"{field}={encoded}" in body

    # The Content-Type override must not leak into subsequent requests.
    assert "Content-Type" not in (oid.connection.headers or {})


@pytest.mark.parametrize(("name", "sample"), load_samples())
@pytest.mark.asyncio()
async def test_a_exchange_token_contract_async(name: str, sample: dict) -> None:
    """
    Verify the async a_exchange_token submits the golden form body.

    :param name: Sample name
    :type name: str
    :param sample: Golden sample data
    :type sample: dict
    """
    oid = build_oid(sample)
    result, url, kwargs = await run_async_exchange(
        oid,
        sample["call"],
        async_response(200, payload=SUCCESS_PAYLOAD),
    )

    assert result == SUCCESS_PAYLOAD
    assert url == TOKEN_URL
    assert kwargs["headers"]["Content-Type"] == "application/x-www-form-urlencoded"
    assert "Authorization" not in kwargs["headers"]

    body = async_wire_body(url, kwargs["headers"], kwargs["data"])
    form = decode_form(body)
    assert_form_matches(form, sample["expected_form_async"])
    assert_client_authentication(form, sample)
    for field, encoded in sample["expected_encoded_pairs"].items():
        assert f"{field}={encoded}" in body

    assert "Content-Type" not in (oid.connection.headers or {})


def test_exchange_token_bad_request_classified_as_post_error() -> None:
    """Verify a 400 from the token endpoint raises KeycloakPostError."""
    sample = dict(load_samples()[1][1])
    oid = build_oid(sample)
    error_body = {"error": "invalid_request", "error_description": "Invalid token"}
    with pytest.raises(KeycloakPostError) as excinfo:
        run_sync_exchange(oid, sample["call"], sync_response(400, payload=error_body))
    assert excinfo.value.response_code == 400
    assert b"invalid_request" in excinfo.value.response_body


def test_exchange_token_unauthorized_classified_as_authentication_error() -> None:
    """Verify a 401 is reclassified as KeycloakAuthenticationError, not KeycloakPostError."""
    sample = dict(load_samples()[1][1])
    oid = build_oid(sample)
    error_body = {"error": "invalid_client", "error_description": "Bad client credentials"}
    with pytest.raises(KeycloakAuthenticationError) as excinfo:
        run_sync_exchange(oid, sample["call"], sync_response(401, payload=error_body))
    assert excinfo.value.response_code == 401
    assert b"invalid_client" in excinfo.value.response_body


def test_exchange_token_non_dict_response_raises_type_error() -> None:
    """Verify a non-JSON 200 body surfaces as TypeError, not a bogus token dict."""
    sample = dict(load_samples()[1][1])
    oid = build_oid(sample)
    with pytest.raises(TypeError, match="Unexpected response type"):
        run_sync_exchange(oid, sample["call"], sync_response(200, raw=b"not-a-json-dict"))


@pytest.mark.asyncio()
async def test_a_exchange_token_bad_request_classified_as_post_error() -> None:
    """Verify a 400 from the token endpoint raises KeycloakPostError (async)."""
    sample = dict(load_samples()[1][1])
    oid = build_oid(sample)
    error_body = {"error": "invalid_request", "error_description": "Invalid token"}
    with pytest.raises(KeycloakPostError) as excinfo:
        await run_async_exchange(oid, sample["call"], async_response(400, payload=error_body))
    assert excinfo.value.response_code == 400
    assert b"invalid_request" in excinfo.value.response_body


@pytest.mark.asyncio()
async def test_a_exchange_token_unauthorized_classified_as_authentication_error() -> None:
    """Verify a 401 is reclassified as KeycloakAuthenticationError (async)."""
    sample = dict(load_samples()[1][1])
    oid = build_oid(sample)
    error_body = {"error": "invalid_client", "error_description": "Bad client credentials"}
    with pytest.raises(KeycloakAuthenticationError) as excinfo:
        await run_async_exchange(oid, sample["call"], async_response(401, payload=error_body))
    assert excinfo.value.response_code == 401
    assert b"invalid_client" in excinfo.value.response_body


@pytest.mark.asyncio()
async def test_a_exchange_token_non_dict_response_raises_type_error() -> None:
    """Verify a non-JSON 200 body surfaces as TypeError (async)."""
    sample = dict(load_samples()[1][1])
    oid = build_oid(sample)
    with pytest.raises(TypeError, match="Unexpected response type"):
        await run_async_exchange(oid, sample["call"], async_response(200, raw=b"not-a-json-dict"))


def test_contract_detects_swapped_subject_token_and_requested_subject() -> None:
    """
    Mutation check: swapping subject_token with requested_subject must fail the contract.

    Simulates a regression in which the library wires the caller's
    impersonation target into ``subject_token`` and the token to be exchanged
    into ``requested_subject`` -- the server would then delegate the wrong
    identity. The golden-sample comparison has to catch that swap.
    """
    samples = dict(load_samples())
    sample = samples["internal_impersonation_refresh_token"]
    oid = build_oid(sample)
    _, url, kwargs = run_sync_exchange(
        oid,
        sample["call"],
        sync_response(200, payload=SUCCESS_PAYLOAD),
    )
    actual = decode_form(sync_wire_body(url, kwargs["headers"], kwargs["data"]))

    # Sanity: the unmutated body satisfies the contract.
    assert_form_matches(actual, sample["expected_form_sync"])

    # Mutation: swap the two delegation identity fields.
    mutated = dict(actual)
    mutated["subject_token"], mutated["requested_subject"] = (
        mutated["requested_subject"],
        mutated["subject_token"],
    )
    with pytest.raises(AssertionError, match="form body mismatch"):
        assert_form_matches(mutated, sample["expected_form_sync"])


def test_contract_detects_swapped_issuer_fields() -> None:
    """
    Mutation check: swapping subject_issuer with requested_issuer must fail the contract.

    Simulates a regression in which the external issuer of the subject token
    is sent as ``requested_issuer`` instead -- the server would ask the wrong
    issuer for the resulting token.
    """
    samples = dict(load_samples())
    sample = samples["external_issuer_access_token"]
    oid = build_oid(sample)
    _, url, kwargs = run_sync_exchange(
        oid,
        sample["call"],
        sync_response(200, payload=SUCCESS_PAYLOAD),
    )
    actual = decode_form(sync_wire_body(url, kwargs["headers"], kwargs["data"]))

    assert_form_matches(actual, sample["expected_form_sync"])

    # Mutation: move the external issuer from subject_issuer to requested_issuer.
    mutated = dict(actual)
    mutated["requested_issuer"] = mutated.pop("subject_issuer")
    with pytest.raises(AssertionError, match="form body mismatch"):
        assert_form_matches(mutated, sample["expected_form_sync"])
