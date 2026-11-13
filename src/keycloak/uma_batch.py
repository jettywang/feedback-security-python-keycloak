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
Batch UMA permission processing.

This module keeps the correspondence between the individual permission requests
submitted by a caller and the merged payloads that are actually sent to
Keycloak, then maps the authorization response back to every original request.

Two UMA interaction styles are supported by the client wrappers, but both rely
on the same pure helpers defined here:

* the permission-ticket endpoint (resource id + scopes JSON payload) and
* the token endpoint ``response_mode=permissions`` (``resource#scope`` strings).

Merging is deliberately conservative: scope-level requests for the same
resource are combined into one entry, but a resource-level request is never
merged with scope-level requests, because that would widen the requested
authorization.
"""

from __future__ import annotations

from collections import OrderedDict
from collections.abc import Iterable, Iterator, Sequence
from dataclasses import dataclass, field
from enum import Enum
from typing import Any

from .uma_permissions import UMAPermission


class UMARequestStatus(str, Enum):
    """
    Outcome of a single permission request after the server response is mapped.

    :cvar GRANTED: Every requested scope was granted (or a resource-level
        request received a resource-level grant).
    :cvar PARTIAL: Only part of the requested scopes was granted. This status
        only applies to scope-level requests.
    :cvar DENIED: Nothing usable was granted for the request.
    """

    GRANTED = "granted"
    PARTIAL = "partial"
    DENIED = "denied"


@dataclass(frozen=True)
class UMARequest:
    """
    One normalized permission request as supplied by a caller.

    :param resource: Resource name (used by ``resource#scope`` style requests).
    :type resource: str
    :param scopes: Requested scopes. An empty tuple represents a resource-level
        request without any scope.
    :type scopes: tuple[str, ...]
    :param resource_id: Optional resource id used by permission tickets.
    :type resource_id: str | None
    :param index: Position of the request in the original caller input.
    :type index: int
    """

    resource: str
    scopes: tuple[str, ...]
    resource_id: str | None
    index: int

    @property
    def is_resource_level(self) -> bool:
        """
        Tell whether the request targets the whole resource.

        :returns: True when no scopes were requested.
        :rtype: bool
        """
        return not self.scopes

    @property
    def permission_string(self) -> str:
        """
        Render the request as a ``resource#scope`` permission string.

        :returns: The permission string accepted by the token endpoint.
        :rtype: str
        """
        return self.resource if self.is_resource_level else f"{self.resource}#{self.scopes[0]}"

    def permission_strings(self) -> tuple[str, ...]:
        """
        Render every requested resource/scope pair as permission strings.

        :returns: One ``resource`` entry for resource-level requests, otherwise
            one ``resource#scope`` entry per scope.
        :rtype: tuple[str, ...]
        """
        if self.is_resource_level:
            return (self.resource,)
        return tuple(f"{self.resource}#{scope}" for scope in self.scopes)


@dataclass(frozen=True)
class UMABatchEntry:
    """
    A merged payload entry covering several original requests.

    :param key: Merge key: ``(resource, True)`` for a resource-level entry and
        ``(resource, False)`` for the scope-level entry.
    :type key: tuple[str, bool]
    :param resource: Resource name.
    :type resource: str
    :param resource_id: Resource id when known.
    :type resource_id: str | None
    :param scopes: Union of the scopes contributed by the member requests.
    :type scopes: tuple[str, ...]
    :param member_indices: Original request indices served by this entry.
    :type member_indices: tuple[int, ...]
    """

    key: tuple[str, bool]
    resource: str
    resource_id: str | None
    scopes: tuple[str, ...]
    member_indices: tuple[int, ...]

    @property
    def is_resource_level(self) -> bool:
        """
        Tell whether the entry targets the whole resource.

        :returns: True for resource-level entries.
        :rtype: bool
        """
        return self.key[1]


@dataclass
class UMARequestResult:
    """
    The mapped outcome for one original permission request.

    :param request: The normalized original request.
    :type request: UMARequest
    :param status: Final status of the request.
    :type status: UMARequestStatus
    :param granted_scopes: Scopes actually granted for this request.
    :type granted_scopes: frozenset[str]
    :param missing_scopes: Scopes that were requested but not granted, or None
        for resource-level requests where missing scopes do not apply.
    :type missing_scopes: frozenset[str] | None
    """

    request: UMARequest
    status: UMARequestStatus
    granted_scopes: frozenset[str]
    missing_scopes: frozenset[str] | None

    @property
    def is_authorized(self) -> bool:
        """
        Tell whether the request is fully satisfied.

        :returns: True only for fully granted requests.
        :rtype: bool
        """
        return self.status is UMARequestStatus.GRANTED


@dataclass
class UMABatchResult:
    """
    Complete result of a batch authorization call.

    :param results: Per-request outcomes, kept in input order.
    :type results: list[UMARequestResult]
    :param entries: The merged entries that were sent to the server.
    :type entries: tuple[UMABatchEntry, ...]
    :param extra_permissions: Granted resource/scopes that were never requested.
        These are reported separately and never satisfy an original request.
    :type extra_permissions: list[dict[str, Any]]
    :param network_requests: Number of real HTTP requests performed.
    :type network_requests: int
    :param ticket: Permission ticket returned by the ticket endpoint, if any.
    :type ticket: str | None
    """

    results: list[UMARequestResult]
    entries: tuple[UMABatchEntry, ...]
    extra_permissions: list[dict[str, Any]] = field(default_factory=list)
    network_requests: int = 0
    ticket: str | None = None

    def __iter__(self) -> Iterator[UMARequestResult]:
        """
        Iterate over the per-request outcomes.

        :yields: Each request result in input order.
        :rtype: UMARequestResult
        """
        yield from self.results

    def __len__(self) -> int:
        """
        Count the original requests.

        :returns: Number of per-request results.
        :rtype: int
        """
        return len(self.results)


def _coerce_request(
    raw: UMAPermission | dict[str, Any] | tuple[str, Any] | str,
    index: int,
) -> UMARequest:
    if isinstance(raw, UMARequest):
        return UMARequest(
            resource=raw.resource,
            scopes=raw.scopes,
            resource_id=raw.resource_id,
            index=index,
        )

    resource = ""
    raw_scopes: Any = ()
    resource_id = None

    if isinstance(raw, str):
        resource, _, first_scope = raw.partition("#")
        raw_scopes = (first_scope,) if first_scope else ()
    elif isinstance(raw, dict):
        resource = str(raw.get("resource", "") or "")
        resource_id = raw.get("resource_id")
        raw_scopes = raw.get("scopes", ())
        if raw_scopes is None:
            raw_scopes = ()
        elif isinstance(raw_scopes, str):
            raw_scopes = (raw_scopes,)
    elif isinstance(raw, tuple):
        if not raw:
            msg = f"Empty permission tuple at index {index}"
            raise ValueError(msg)
        resource = str(raw[0])
        raw_scopes = raw[1] if len(raw) > 1 else ()
        if raw_scopes is None:
            raw_scopes = ()
        elif isinstance(raw_scopes, str):
            raw_scopes = (raw_scopes,)
    elif isinstance(raw, UMAPermission):
        resource = raw.resource
        raw_scopes = (raw.scope,) if raw.scope else ()
        resource_id = raw.resource_id
    else:
        msg = f"Unsupported permission request: {raw!r}"
        raise TypeError(msg)

    if not resource:
        msg = f"Permission request at index {index} has no resource"
        raise ValueError(msg)

    scopes = tuple(OrderedDict((str(scope), None) for scope in raw_scopes).keys())
    return UMARequest(
        resource=resource,
        scopes=scopes,
        resource_id=str(resource_id) if resource_id else None,
        index=index,
    )


def normalize_uma_requests(
    requests: Iterable[UMAPermission | dict[str, Any] | tuple[str, Any] | str]
    | UMAPermission
    | str
    | None,
) -> tuple[UMARequest, ...]:
    """
    Normalize caller input into ordered :class:`UMARequest` objects.

    Accepted item shapes are ``UMAPermission`` objects, ``"resource#scope"``
    strings, ``(resource, scopes)`` tuples and dictionaries with ``resource``,
    optional ``resource_id`` and optional ``scopes``. Scopes may be a single
    string, an iterable of strings or None.

    :param requests: Raw caller requests.
    :type requests: Iterable | UMAPermission | str | None
    :returns: Normalized requests in input order. Empty input yields an empty
        tuple and the client wrappers perform no network request.
    :rtype: tuple[UMARequest, ...]
    :raises ValueError: If a request has no resource.
    :raises TypeError: If an item cannot be interpreted as a permission.
    """
    if requests is None:
        return ()

    if isinstance(requests, (str, UMARequest)) or not isinstance(requests, Iterable):
        items: Sequence[Any] = (requests,)
    else:
        items = tuple(requests)

    return tuple(_coerce_request(item, index) for index, item in enumerate(items))


def merge_uma_requests(requests: Sequence[UMARequest]) -> tuple[UMABatchEntry, ...]:
    """
    Merge normalized requests into payload entries.

    Scope-level requests for the same resource share one entry whose scopes are
    the union of their scopes. A resource-level request gets its own entry and
    is never merged with scope-level requests, since merging would request a
    broader authorization than the caller asked for.

    :param requests: Normalized requests.
    :type requests: Sequence[UMARequest]
    :returns: Entries in first-seen order.
    :rtype: tuple[UMABatchEntry, ...]
    """
    grouped: OrderedDict[tuple[str, bool], dict[str, Any]] = OrderedDict()

    for req in requests:
        key = (req.resource, req.is_resource_level)
        bucket = grouped.get(key)
        if bucket is None:
            bucket = {
                "resource": req.resource,
                "resource_id": req.resource_id,
                "scopes": OrderedDict(),
                "indices": [],
            }
            grouped[key] = bucket

        if bucket["resource_id"] is None and req.resource_id is not None:
            bucket["resource_id"] = req.resource_id
        for scope in req.scopes:
            bucket["scopes"].setdefault(scope, None)
        bucket["indices"].append(req.index)

    return tuple(
        UMABatchEntry(
            key=key,
            resource=bucket["resource"],
            resource_id=bucket["resource_id"],
            scopes=tuple(bucket["scopes"].keys()),
            member_indices=tuple(bucket["indices"]),
        )
        for key, bucket in grouped.items()
    )


def build_ticket_payload(entries: Sequence[UMABatchEntry]) -> list[dict[str, Any]]:
    """
    Build the JSON payload for the permission-ticket endpoint.

    Resource-level entries omit ``resource_scopes`` instead of sending an empty
    list, matching UMA 2.0 semantics.

    :param entries: Merged entries.
    :type entries: Sequence[UMABatchEntry]
    :returns: Permission ticket payload.
    :rtype: list[dict[str, Any]]
    """
    payload = []
    for entry in entries:
        item: dict[str, Any] = {"resource_id": entry.resource_id or entry.resource}
        if not entry.is_resource_level:
            item["resource_scopes"] = list(entry.scopes)
        payload.append(item)
    return payload


def build_permission_strings(entries: Sequence[UMABatchEntry]) -> list[str]:
    """
    Build permission strings for the token endpoint payload.

    :param entries: Merged entries.
    :type entries: Sequence[UMABatchEntry]
    :returns: Distinct ``resource`` / ``resource#scope`` strings in entry order.
    :rtype: list[str]
    """
    strings: list[str] = []
    for entry in entries:
        if entry.is_resource_level:
            strings.append(entry.resource)
        else:
            strings.extend(f"{entry.resource}#{scope}" for scope in entry.scopes)
    return strings


def _index_grants(
    granted: Sequence[dict[str, Any]],
) -> dict[str, dict[str, Any]]:
    indexed: dict[str, dict[str, Any]] = {}
    for struct in granted:
        names = {struct.get("rsname"), struct.get("rsid")} - {None}
        scopes = struct.get("scopes") or []
        normalized = {
            "scopes": frozenset(str(scope) for scope in scopes),
            "resource_level": not scopes,
            "raw": struct,
        }
        for name in names:
            indexed[str(name)] = normalized
    return indexed


def evaluate_uma_batch(
    requests: Sequence[UMARequest],
    entries: Sequence[UMABatchEntry],
    granted: Sequence[dict[str, Any]],
    *,
    network_requests: int = 0,
    ticket: str | None = None,
) -> UMABatchResult:
    """
    Map an authorization response back to every original request.

    Grants are matched on either ``rsname`` or ``rsid``. Resource-level grants
    only satisfy resource-level requests; scope-level grants only contribute
    their scopes. Granted resources or scopes that no request asked for are
    collected in ``extra_permissions`` and never mark a request as satisfied.

    :param requests: Normalized original requests.
    :type requests: Sequence[UMARequest]
    :param entries: Merged entries sent to the server.
    :type entries: Sequence[UMABatchEntry]
    :param granted: Server response items with ``rsname``/``rsid``/``scopes``.
    :type granted: Sequence[dict[str, Any]]
    :param network_requests: Number of HTTP requests performed.
    :type network_requests: int
    :param ticket: Permission ticket when the ticket endpoint was used.
    :type ticket: str | None
    :returns: Per-request outcomes plus extra permissions.
    :rtype: UMABatchResult
    """
    grant_index = _index_grants(granted)

    requested_resources: set[str] = set()
    requested_scopes: dict[str, set[str]] = {}
    for req in requests:
        requested_resources.add(req.resource)
        if req.resource_id is not None:
            requested_resources.add(req.resource_id)
        requested_scopes.setdefault(req.resource, set()).update(req.scopes)

    results: list[UMARequestResult] = []
    for req in requests:
        grant = grant_index.get(req.resource)
        if grant is None and req.resource_id is not None:
            grant = grant_index.get(req.resource_id)

        if req.is_resource_level:
            satisfied = bool(grant and grant["resource_level"])
            results.append(
                UMARequestResult(
                    request=req,
                    status=UMARequestStatus.GRANTED if satisfied else UMARequestStatus.DENIED,
                    granted_scopes=frozenset(),
                    missing_scopes=None,
                )
            )
            continue

        granted_scopes = frozenset(req.scopes) & grant["scopes"] if grant else frozenset()
        missing_scopes = frozenset(req.scopes) - granted_scopes
        if not missing_scopes:
            status = UMARequestStatus.GRANTED
        elif granted_scopes:
            status = UMARequestStatus.PARTIAL
        else:
            status = UMARequestStatus.DENIED
        results.append(
            UMARequestResult(
                request=req,
                status=status,
                granted_scopes=granted_scopes,
                missing_scopes=missing_scopes,
            )
        )

    extra_permissions: list[dict[str, Any]] = []
    for resource, grant in grant_index.items():
        if resource not in requested_resources:
            extra_permissions.append(
                {
                    "resource": resource,
                    "scopes": sorted(grant["scopes"]),
                    "resource_level": grant["resource_level"],
                }
            )
            continue

        requested_here = requested_scopes.get(resource, set())
        extra_scopes = grant["scopes"] - requested_here
        if extra_scopes:
            extra_permissions.append(
                {
                    "resource": resource,
                    "scopes": sorted(extra_scopes),
                    "resource_level": False,
                }
            )

    return UMABatchResult(
        results=results,
        entries=tuple(entries),
        extra_permissions=extra_permissions,
        network_requests=network_requests,
        ticket=ticket,
    )
