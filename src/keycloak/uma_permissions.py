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

"""User-managed access permissions module."""

from __future__ import annotations

from enum import Enum

from keycloak.exceptions import KeycloakPermissionFormatError


class IdentityType(Enum):
    """
    Identify whether a permission request references a resource by its id or its name.

    Keycloak answers UMA permission tickets with both ``rsid`` (the resource id) and
    ``rsname`` (the resource display name). A requested permission can target either one,
    so the identity type is required to disambiguate them when a resource name happens to
    equal another resource id.
    """

    RSID = "rsid"
    RSNAME = "rsname"


class UMAPermission:
    """
    A class to conveniently assemble permissions.

    The class itself is callable, and will return the assembled permission.

    Usage example:

    >>> r = Resource("Users")
    >>> s = Scope("delete")
    >>> permission = r(s)
    >>> print(permission)
        'Users#delete'

    :param permission: Permission
    :type permission: UMAPermission
    :param resource: Resource
    :type resource: str
    :param scope: Scope
    :type scope: str
    """

    def __init__(
        self,
        permission: UMAPermission | None = None,
        resource: str = "",
        scope: str = "",
    ) -> None:
        """
        Init method.

        :param permission: Permission
        :type permission: UMAPermission
        :param resource: Resource
        :type resource: str
        :param scope: Scope
        :type scope: str
        :raises PermissionDefinitionError: In case bad permission definition
        """
        self.resource = resource
        self.scope = scope
        self.resource_id = None

        if permission is not None:
            if permission.resource:
                self.resource = str(permission.resource)
            if permission.scope:
                self.scope = str(permission.scope)

    def __str__(self) -> str:
        """
        Str method.

        :returns: String representation
        :rtype: str
        """
        scope = self.scope
        if scope:
            scope = "#" + scope
        return f"{self.resource}{scope}"

    def __eq__(self, other: object) -> bool:
        """
        Eq method.

        :param __o: The other object
        :type __o: object
        :returns: Equality boolean
        :rtype: bool
        """
        return str(self) == str(other)

    def __repr__(self) -> str:
        """
        Repr method.

        :returns: The object representation
        :rtype: str
        """
        return self.__str__()

    def __hash__(self) -> int:
        """
        Hash method.

        :returns: Hash of the object
        :rtype: int
        """
        return hash(str(self))

    def __call__(
        self,
        permission: UMAPermission | None = None,
        resource: str = "",
        scope: str = "",
    ) -> UMAPermission:
        """
        Call method.

        :param permission: Permission
        :type permission: UMAPermission
        :param resource: Resource
        :type resource: str
        :param scope: Scope
        :type scope: str
        :returns: The combined UMA permission
        :rtype: UMAPermission
        :raises PermissionDefinitionError: In case bad permission definition
        """
        result_resource = self.resource
        result_scope = self.scope

        if resource:
            result_resource = str(resource)
        if scope:
            result_scope = str(scope)

        if permission is not None:
            if permission.resource:
                result_resource = str(permission.resource)
            if permission.scope:
                result_scope = str(permission.scope)

        return UMAPermission(resource=result_resource, scope=result_scope)


class Resource(UMAPermission):
    """
    A UMAPermission Resource class to conveniently assemble permissions.

    The class itself is callable, and will return the assembled permission.

    :param resource: Resource
    :type resource: str
    """

    def __init__(self, resource: str) -> None:
        """
        Init method.

        :param resource: Resource
        :type resource: str
        """
        super().__init__(resource=resource)


class Scope(UMAPermission):
    """
    A UMAPermission Scope class to conveniently assemble permissions.

    The class itself is callable, and will return the assembled permission.

    :param scope: Scope
    :type scope: str
    """

    def __init__(self, scope: str) -> None:
        """
        Init method.

        :param scope: Scope
        :type scope: str
        """
        super().__init__(scope=scope)


class PermissionRequest(UMAPermission):
    """
    A requested UMA permission that remembers whether it targets an ``rsid`` or ``rsname``.

    The textual permission (``resource`` or ``resource#scope``) is kept identical to the
    wire format, which means the object is interchangeable with the plain string used by
    :func:`build_permission_param`. The :attr:`identity_type` additionally records how the
    resource component must be interpreted when matching a server response, allowing the
    resource name/id collision case to be handled deterministically.

    :param resource: Resource id or resource name
    :type resource: str
    :param scope: Scope
    :type scope: str
    :param identity_type: Whether the resource is an id (``rsid``) or a name (``rsname``)
    :type identity_type: IdentityType
    """

    def __init__(
        self,
        resource: str,
        scope: str = "",
        identity_type: IdentityType = IdentityType.RSNAME,
    ) -> None:
        """
        Init method.

        :param resource: Resource id or resource name
        :type resource: str
        :param scope: Scope
        :type scope: str
        :param identity_type: Whether the resource is an id (``rsid``) or a name (``rsname``)
        :type identity_type: IdentityType
        """
        super().__init__(resource=str(resource), scope=str(scope))
        self.identity_type = identity_type

    @classmethod
    def from_string(
        cls,
        permission: str,
        identity_type: IdentityType,
    ) -> PermissionRequest:
        """
        Build a permission request from the ``resource`` / ``resource#scope`` wire format.

        :param permission: Textual permission, optionally carrying a ``#scope`` suffix
        :type permission: str
        :param identity_type: Whether the resource component is an id or a name
        :type identity_type: IdentityType
        :returns: The typed permission request
        :rtype: PermissionRequest
        """
        resource, separator, scope = permission.partition("#")
        return cls(
            resource=resource,
            scope=scope if separator else "",
            identity_type=identity_type,
        )

    def __repr__(self) -> str:
        """
        Repr method.

        Kept identical to the plain string representation (including the surrounding quotes
        used by container repr) so that sets of permission requests render exactly like the
        sets of strings produced by :func:`build_permission_param`.

        :returns: The object representation
        :rtype: str
        """
        return repr(str(self))


class AuthStatus:
    """
    A class that represents the authorization/login status of a user associated with a token.

    This has to evaluate to True if and only if the user is properly authorized
    for the requested resource.

    :param is_logged_in: Is logged in indicator
    :type is_logged_in: bool
    :param is_authorized: Is authorized indicator
    :type is_authorized: bool
    :param missing_permissions: Missing permissions
    :type missing_permissions: set
    """

    def __init__(
        self, is_logged_in: bool, is_authorized: bool, missing_permissions: set | str
    ) -> None:
        """
        Init method.

        :param is_logged_in: Is logged in indicator
        :type is_logged_in: bool
        :param is_authorized: Is authorized indicator
        :type is_authorized: bool
        :param missing_permissions: Missing permissions
        :type missing_permissions: set
        """
        self.is_logged_in = is_logged_in
        self.is_authorized = is_authorized
        self.missing_permissions = missing_permissions

    def __bool__(self) -> bool:
        """
        Bool method.

        :returns: Boolean representation
        :rtype: bool
        """
        return self.is_authorized

    def __repr__(self) -> str:
        """
        Repr method.

        :returns: The object representation
        :rtype: str
        """
        return (
            f"AuthStatus("
            f"is_authorized={self.is_authorized}, "
            f"is_logged_in={self.is_logged_in}, "
            f"missing_permissions={self.missing_permissions})"
        )


def build_permission_param(
    permissions: str | list | dict | UMAPermission | None | tuple | set,
) -> set:
    """
    Transform permissions to a set, so they are usable for requests.

    :param permissions: Permissions
    :type permissions: str | Iterable[str] | dict[str, str] | dict[str, Iterabble[str]]
    :returns: Permission parameters
    :rtype: set
    :raises KeycloakPermissionFormatError: In case of bad permission format
    """
    if permissions is None or permissions == "":
        return set()
    if isinstance(permissions, str):
        return {permissions}
    if isinstance(permissions, UMAPermission):
        return {str(permissions)}
    if isinstance(permissions, (list, tuple, set)):
        return set(permissions)

    try:  # treat as dictionary of permissions
        result = set()
        for resource, scopes in permissions.items():
            if scopes is None:
                result.add(resource)
            elif isinstance(scopes, str):
                result.add(f"{resource}#{scopes}")
            else:
                try:
                    for scope in scopes:
                        if not isinstance(scope, str):
                            msg = f"misbuilt permission {permissions}"
                            raise KeycloakPermissionFormatError(msg)
                        result.add(f"{resource}#{scope}")
                except TypeError as e:
                    msg = f"misbuilt permission {permissions}"
                    raise KeycloakPermissionFormatError(msg) from e
    except AttributeError:
        pass
    else:
        return result

    result = set()
    for permission in permissions:
        if not isinstance(permission, (str, UMAPermission)):
            msg = f"misbuilt permission {permissions}"
            raise KeycloakPermissionFormatError(msg)
        result.add(str(permission))
    return result


def parse_permission_requests(
    permissions: str | list | dict | UMAPermission | None | tuple | set,
    default_identity: IdentityType,
) -> set[PermissionRequest]:
    """
    Parse the accepted permission inputs into typed :class:`PermissionRequest` objects.

    The accepted shapes are the same as :func:`build_permission_param`. Each textual
    permission is wrapped in a :class:`PermissionRequest` carrying an identity type:

    * an already typed :class:`PermissionRequest` keeps its own identity;
    * a plain string (or a generic :class:`UMAPermission`) receives ``default_identity``;
    * a dictionary resource key receives ``default_identity`` for every generated scope.

    Returning a set keeps the de-duplication semantics of the textual representation, so
    repeated permission items collapse deterministically and the first encountered identity
    wins for equal textual permissions.

    :param permissions: Permissions in any shape accepted by :func:`build_permission_param`
    :type permissions: str | Iterable[str] | dict[str, str] | dict[str, Iterable[str]]
    :param default_identity: Identity assigned to inputs that do not carry one explicitly
    :type default_identity: IdentityType
    :returns: Typed permission requests
    :rtype: set[PermissionRequest]
    :raises KeycloakPermissionFormatError: In case of bad permission format
    """
    if permissions is None or permissions == "":
        return set()
    if isinstance(permissions, PermissionRequest):
        return {permissions}
    if isinstance(permissions, str):
        return {PermissionRequest.from_string(permissions, default_identity)}
    if isinstance(permissions, UMAPermission):
        return {
            PermissionRequest(
                resource=permissions.resource,
                scope=permissions.scope,
                identity_type=default_identity,
            ),
        }
    if isinstance(permissions, (list, tuple, set)):
        result: set[PermissionRequest] = set()
        for permission in permissions:
            if isinstance(permission, PermissionRequest):
                result.add(permission)
            elif isinstance(permission, UMAPermission):
                result.add(
                    PermissionRequest(
                        resource=permission.resource,
                        scope=permission.scope,
                        identity_type=default_identity,
                    ),
                )
            elif isinstance(permission, str):
                result.add(PermissionRequest.from_string(permission, default_identity))
            else:
                msg = f"misbuilt permission {permissions}"
                raise KeycloakPermissionFormatError(msg)
        return result

    try:  # treat as dictionary of permissions
        result = set()
        for resource, scopes in permissions.items():
            if scopes is None:
                result.add(
                    PermissionRequest(resource=str(resource), identity_type=default_identity),
                )
            elif isinstance(scopes, str):
                result.add(
                    PermissionRequest(
                        resource=str(resource),
                        scope=scopes,
                        identity_type=default_identity,
                    ),
                )
            else:
                try:
                    for scope in scopes:
                        if not isinstance(scope, str):
                            msg = f"misbuilt permission {permissions}"
                            raise KeycloakPermissionFormatError(msg)
                        result.add(
                            PermissionRequest(
                                resource=str(resource),
                                scope=scope,
                                identity_type=default_identity,
                            ),
                        )
                except TypeError as e:
                    msg = f"misbuilt permission {permissions}"
                    raise KeycloakPermissionFormatError(msg) from e
    except AttributeError:
        pass
    else:
        return result

    result = set()
    for permission in permissions:
        if not isinstance(permission, (str, UMAPermission)):
            msg = f"misbuilt permission {permissions}"
            raise KeycloakPermissionFormatError(msg)
        if isinstance(permission, PermissionRequest):
            result.add(permission)
        elif isinstance(permission, UMAPermission):
            result.add(
                PermissionRequest(
                    resource=permission.resource,
                    scope=permission.scope,
                    identity_type=default_identity,
                ),
            )
        else:
            result.add(PermissionRequest.from_string(permission, default_identity))
    return result


def _grant_matches_request(
    request: PermissionRequest,
    grant: dict,
    strict_id_mode: bool,
) -> bool:
    """
    Decide whether a single granted resource struct satisfies a single request.

    A granted struct with no scopes (empty list, ``None`` or missing key) is a
    resource-level grant and only satisfies a resource-level request. A granted struct with
    scopes only satisfies a request carrying one of those exact scopes, so resource-level
    and scope-based permissions can never satisfy each other.

    In strict id mode the request resource is compared against ``rsid`` only, regardless of
    how the request was labeled, which prevents a display-name collision from granting access
    to a different resource. In compatibility mode an ``rsid`` request matches ``rsid`` and
    an ``rsname`` request matches ``rsname``; missing or empty server fields never match.

    :param request: The requested permission
    :type request: PermissionRequest
    :param grant: One entry of the Keycloak ``permissions`` response
    :type grant: dict
    :param strict_id_mode: Restrict every comparison to resource ids when ``True``
    :type strict_id_mode: bool
    :returns: Whether the grant satisfies the request
    :rtype: bool
    """
    if strict_id_mode or request.identity_type == IdentityType.RSID:
        granted_resource = grant.get("rsid")
    else:
        granted_resource = grant.get("rsname")

    if not granted_resource or granted_resource != request.resource:
        return False

    granted_scopes = grant.get("scopes") or []

    if not request.scope:
        return not granted_scopes

    return request.scope in granted_scopes


def evaluate_uma_access(
    requested: set[PermissionRequest],
    granted: list,
    strict_id_mode: bool = False,
) -> set[PermissionRequest]:
    """
    Compute the requested permissions that no granted entry satisfies.

    The function is shared by the synchronous and asynchronous clients, which guarantees
    identical authorization results. It never mutates ``requested`` and never raises on an
    incomplete server response: entries that are not dictionaries, that lack ``rsid`` or
    ``rsname`` or that carry malformed scopes are simply unable to satisfy a request.

    Repeated granted entries are handled idempotently: matching only removes requests from
    the missing set, so duplicates cannot change the outcome.

    :param requested: Typed permissions requested by the caller
    :type requested: set[PermissionRequest]
    :param granted: Keycloak ``permissions`` response entries
    :type granted: list
    :param strict_id_mode: Restrict every comparison to resource ids when ``True``
    :type strict_id_mode: bool
    :returns: The subset of ``requested`` that remains unsatisfied, identity types preserved
    :rtype: set[PermissionRequest]
    """
    missing = set(requested)
    if not missing:
        return missing

    for grant in granted:
        if not isinstance(grant, dict):
            continue
        for request in tuple(missing):
            if _grant_matches_request(request, grant, strict_id_mode):
                missing.discard(request)
        if not missing:
            break

    return missing
