"""The bearer gate: hal's access token alone opens the host's machine paths, and on its
person paths is the account behind the token."""

from __future__ import annotations

import logging
import re
from dataclasses import dataclass
from enum import Enum, auto
from functools import partial
from typing import TYPE_CHECKING, Final
from urllib.parse import urlsplit

from anyio import to_thread
from anyio.lowlevel import checkpoint_if_cancelled
from starlette.requests import HTTPConnection
from starlette.responses import JSONResponse

from webauth._validation import is_scope_token_tuple
from webauth.config import web_auth_config
from webauth.dependencies import (
    _ADMIN_REQUIRED_DETAIL,
    _AUTHENTICATION_REQUIRED_DETAIL,
    _PERSON_PATH_INSUFFICIENT_SCOPE,
    _bearer_admission,
    _mark_person_path,
    _record_bearer_admission,
)
from webauth.middleware._refusal import RefusalMiddleware
from webauth.middleware._route_path import route_path
from webauth.oidc import (
    _ACCESS_TOKEN,
    _PLAIN_AUTHORITY,
    OidcRefusal,
    OidcRefusalReason,
    OidcRelyingParty,
    VerifiedAccessToken,
    _is_endpoint_url,
    _names_another_audience,
)
from webauth.oidc_login import (
    AdmissionConfig,
    AdmissionRefusal,
    AppRole,
    NoAdmins,
    _admit_resource_holder,
    _admit_token_holder,
    _require_group_path,
    app_role,
)
from webauth.policies import AuthorizedParties, PathRules, PublicRule
from webauth.ports import AuthenticatedUser, BearerCaller

if TYPE_CHECKING:
    from collections.abc import Callable

    from fastapi import FastAPI
    from starlette.requests import Request
    from starlette.responses import Response
    from starlette.types import ASGIApp

    from webauth.ports import SignInTransaction

__all__ = [
    "BearerGate",
    "BearerGateMiddleware",
    "MachinePaths",
    "MarkedRoute",
    "PersonPaths",
    "ProtectedResource",
    "bearer_caller",
    "install_resource_metadata",
    "resource_person",
]

_LOGGER: Final = logging.getLogger(__name__)
_MACHINE_CHALLENGE: Final = ('realm="admin"',)
_METADATA_PREFIX: Final = "/.well-known/oauth-protected-resource"
_AUTH_SCHEME: Final = re.compile(r"[!#$%&'*+\-.^_`|~0-9A-Za-z]+")
_RESOURCE_PATH: Final = re.compile(r"(?:/[A-Za-z0-9._~-]+)+", re.ASCII)
_METHOD_TOKEN: Final = re.compile(r"[!#$%&'*+\-.^_`|~0-9A-Z]+", re.ASCII)
_LITERAL_SEGMENT: Final = re.compile(r"[A-Za-z0-9._~-]+", re.ASCII)
_PARAMETER_SEGMENT: Final = re.compile(r"\{[A-Za-z_][A-Za-z0-9_]*\}", re.ASCII)
_DOT_SEGMENTS: Final = frozenset({".", ".."})
_ONE_CREDENTIAL: Final = re.compile(r" +([^ \t,]+)")
_BEARER_SCHEME: Final = "bearer"
_ACCESS_TOKEN_QUERY_PARAMETER: Final = "access_token"  # noqa: S105 - query parameter name not a credential


def _require_parties(authorized_parties: AuthorizedParties) -> None:
    if not isinstance(authorized_parties, AuthorizedParties):
        raise TypeError("authorized_parties must be an AuthorizedParties")


@dataclass(frozen=True)
class MachinePaths:
    """The paths where a token is a machine's, and the clients allowed to hold it.

    ``paths`` are written as ``PathRules`` says. A token passes there only with an
    ``azp`` among ``authorized_parties``; a client listed here is not thereby
    admitted on the person paths. ``ValueError`` for no paths; ``TypeError`` for
    ``authorized_parties`` that is not an ``AuthorizedParties``.
    """

    paths: PathRules
    authorized_parties: AuthorizedParties

    def __post_init__(self) -> None:
        _require_parties(self.authorized_parties)
        if self.paths == PathRules():
            raise ValueError("machine paths must select at least one path")


@dataclass(frozen=True)
class PersonPaths:
    """The paths where a token is the person behind it, and the host's sign-in context.

    ``paths`` are written as ``PathRules`` says. A token passes there only with an
    ``azp`` among ``authorized_parties``; a client listed here is not thereby admitted
    on the machine paths. Each token request enters ``transaction`` once, as a sign-in
    does, to find or create the account. ``ValueError`` for no paths; ``TypeError`` for
    ``authorized_parties`` that is not an ``AuthorizedParties``.
    """

    paths: PathRules
    authorized_parties: AuthorizedParties
    transaction: SignInTransaction

    def __post_init__(self) -> None:
        _require_parties(self.authorized_parties)
        if self.paths == PathRules():
            raise ValueError("person paths must select at least one path")


def _is_resource_url(url: str) -> bool:
    parts = urlsplit(url)
    segments = parts.path.split("/")[1:]
    return (
        _PLAIN_AUTHORITY.fullmatch(parts.netloc) is not None
        and _RESOURCE_PATH.fullmatch(parts.path) is not None
        and not {".", ".."} & set(segments)
    )


def _is_template_segment(segment: str) -> bool:
    if _PARAMETER_SEGMENT.fullmatch(segment):
        return True
    return _LITERAL_SEGMENT.fullmatch(segment) is not None and segment not in _DOT_SEGMENTS


def _is_route_template(template: object) -> bool:
    if not isinstance(template, str):
        return False
    first, *segments = template.split("/")
    return first == "" and bool(segments) and all(map(_is_template_segment, segments))


@dataclass(frozen=True)
class MarkedRoute:
    """One operation of the host a protected resource's token may reach: a method and a path
    template.

    ``method`` is one upper-case HTTP method token. ``template`` is one or more
    ``/``-separated segments, each a literal of unreserved characters (RFC 3986, never ``.``
    or ``..``) or one ``{name}`` filling the whole segment: no converter, no partial
    parameter, no empty segment, no trailing slash. A request matches when its method equals
    ``method``, its route path has as many segments, each literal segment is equal, and each
    parameter is one non-empty segment other than ``.`` and ``..``; a decoded ``/`` reads as
    a longer path, so no parameter holds one. ``ValueError`` for anything else.
    """

    method: str
    template: str

    def __post_init__(self) -> None:
        if not isinstance(self.method, str) or _METHOD_TOKEN.fullmatch(self.method) is None:
            raise ValueError("MarkedRoute.method must be one upper-case HTTP method token")
        if not _is_route_template(self.template):
            raise ValueError(
                "MarkedRoute.template must be segments of unreserved characters or {name}, "
                "each after a slash, without a trailing slash",
            )

    def matches(self, method: str, path: str) -> bool:
        if method != self.method or not path.startswith("/"):
            return False
        template_segments = self.template.split("/")[1:]
        segments = path.split("/")[1:]
        return len(segments) == len(template_segments) and all(
            segment not in {"", *_DOT_SEGMENTS}
            if _PARAMETER_SEGMENT.fullmatch(template_segment)
            else segment == template_segment
            for segment, template_segment in zip(segments, template_segments, strict=True)
        )


@dataclass(frozen=True)
class ProtectedResource:
    """The resource a client finds by its URL and signs in to at the issuer.

    ``url`` is the resource's identifier and entry point: its path is the one path where
    the gate answers the challenge. The metadata document sits at the path RFC 9728
    section 3.1 derives from it. ``scope`` is the one scope the challenge asks for and a token
    must hold. A token passes there only with an ``azp`` among ``authorized_parties``, which
    no other kind's parties extend, and groups that hold ``required_group`` or a path below it
    besides the admission's login group. The gate then looks the token's subject up in one
    entry of ``transaction``, a read: a person must have signed in once, and is admitted
    with the configured person role whatever role is stored. ``TypeError`` for
    ``authorized_parties`` that is not an ``AuthorizedParties``. ``ValueError`` for a
    ``required_group`` that is not a group path, and for a ``url`` that is
    not an endpoint URL with a plain host, an optional port and a path of one or more
    segments of unreserved characters (RFC 3986), none being ``.`` or ``..``, without a
    trailing slash, and for a ``scope`` that is not one scope token. So the path needs no
    decoding and reads the same in a header, in the ASGI path and in a route.

    ``marked_routes`` are the host's operations, besides the entry point, that take the same
    token: on a request one of them matches, a bearer credential is checked as at the entry
    point and a token that holds is the capped person; without a bearer credential, and for a
    token whose audience is not ``url``, the request is decided as if unmarked. ``TypeError``
    for ``marked_routes`` that is not a ``frozenset`` of ``MarkedRoute``. The gate runs before
    routing, so a match must resolve to the host's marked operation: the host proves it.
    """

    url: str
    scope: str
    required_group: str
    authorized_parties: AuthorizedParties
    transaction: SignInTransaction
    marked_routes: frozenset[MarkedRoute] = frozenset()

    def __post_init__(self) -> None:
        _require_parties(self.authorized_parties)
        if not isinstance(self.marked_routes, frozenset) or not all(
            isinstance(route, MarkedRoute) for route in self.marked_routes
        ):
            raise TypeError("ProtectedResource.marked_routes must be a frozenset of MarkedRoute")
        _require_group_path("ProtectedResource.required_group", self.required_group)
        if not _is_endpoint_url(self.url) or not _is_resource_url(self.url):
            raise ValueError(
                "ProtectedResource.url must be an endpoint URL with a plain host and a path"
                " of unreserved segments"
            )
        if not is_scope_token_tuple((self.scope,)):
            raise ValueError("ProtectedResource.scope must be one scope token")

    @property
    def entry_point(self) -> str:
        """The path of ``url``."""
        return urlsplit(self.url).path

    @property
    def entry_point_rule(self) -> PathRules:
        return PathRules(exact=frozenset({self.entry_point}))

    def marks(self, method: str, path: str) -> bool:
        return any(route.matches(method, path) for route in self.marked_routes)

    @property
    def metadata_path(self) -> str:
        return f"{_METADATA_PREFIX}{self.entry_point}"

    @property
    def metadata_url(self) -> str:
        parts = urlsplit(self.url)
        return f"{parts.scheme}://{parts.netloc}{self.metadata_path}"

    @property
    def public_rule(self) -> PublicRule:
        """``GET`` of the metadata path, for ``SessionGate.public``."""
        return PublicRule(
            PathRules(exact=frozenset({self.metadata_path})), methods=frozenset({"GET"}),
        )

    @property
    def challenge_parameters(self) -> tuple[str, ...]:
        return (f'resource_metadata="{self.metadata_url}"', f'scope="{self.scope}"')


@dataclass(frozen=True)
class BearerGate:
    """Which paths take hal's bearer access token, and whose tokens count.

    ``machine_paths``, ``resource`` and ``person_paths`` are the host's three kinds of
    path; each kind has its own authorized parties, and a path two
    kinds select belongs to the first of machine, resource, person. At the
    resource's entry point, and on a marked route when the request carries a bearer credential
    whose token does not belong to another audience, a token the resource's check refuses is
    answered 401, one without the resource's scope 403, and one that holds but whose person the
    resource does not admit a plain 403, each without any session; an admitted token is the
    capped person, recorded for ``resource_person`` and for this request's method alone. A
    marked route without a bearer credential, or with a token whose audience is not the
    resource, is decided as an unmarked path. On the other paths
    the token must come from ``relying_party``'s issuer, name its client as the only
    audience and carry an ``azp`` among the parties of the path's kind. At the entry point
    the only audience is the resource's URL and the parties are the resource's. A machine
    path also needs ``admission.admin_group`` or a group below it. On a person path
    the token is the account behind its subject, admitted as a sign-in admits it.
    ``ValueError`` when the gate has no kind, for ``NoAdmins`` with machine
    paths (no token could pass there) and for an ``admission`` bound to another
    issuer.
    """

    relying_party: OidcRelyingParty
    admission: AdmissionConfig
    machine_paths: MachinePaths | None = None
    person_paths: PersonPaths | None = None
    resource: ProtectedResource | None = None

    def __post_init__(self) -> None:
        if self.machine_paths is None and self.person_paths is None and self.resource is None:
            raise ValueError(
                "the gate must name machine paths, a protected resource or person paths",
            )
        if isinstance(self.admission.admin_group, NoAdmins) and self.machine_paths is not None:
            raise ValueError("admission.admin_group is NoAdmins: no token could pass the gate")
        if self.admission.bound_issuer != self.relying_party.issuer:
            raise ValueError("admission.bound_issuer must be the relying party's issuer")


class _Refusal(Enum):
    """The cases the gate refuses, each with its status, challenge error and detail.

    The first four refuse a machine path, which names its realm; the first three and
    ``RESOURCE_INSUFFICIENT_SCOPE`` refuse the resource's entry point, which names its
    metadata and scope; on a person path ``INVALID_REQUEST`` and ``INVALID_TOKEN`` carry
    neither and ``NOT_A_MEMBER`` and ``USERNAME_TAKEN`` belong to it alone.
    ``RESOURCE_NOT_ADMITTED`` is the entry point's answer to a token that holds but whose
    person is unknown or outside the required group; a new sign-in cannot change it, so it
    carries no challenge a client would answer with one.
    """

    NO_CREDENTIALS = (401, None, _AUTHENTICATION_REQUIRED_DETAIL)
    INVALID_REQUEST = (401, "invalid_request", "Invalid request")
    INVALID_TOKEN = (401, "invalid_token", "Invalid token")
    INSUFFICIENT_SCOPE = (403, "insufficient_scope", _ADMIN_REQUIRED_DETAIL)
    RESOURCE_INSUFFICIENT_SCOPE = (403, "insufficient_scope", "Insufficient scope")
    RESOURCE_NOT_ADMITTED = (403, None, "Access denied")
    NOT_A_MEMBER = (403, None, "No access")
    USERNAME_TAKEN = (403, None, "Login failed")

    def __init__(self, status_code: int, error: str | None, detail: str) -> None:
        self.status_code = status_code
        self.error = error
        self.detail = detail

    @property
    def case(self) -> str:
        return self.name.lower().replace("_", "-")

    def challenge(self, kind_parameters: tuple[str, ...]) -> str | None:
        if self is _Refusal.NOT_A_MEMBER:
            return _PERSON_PATH_INSUFFICIENT_SCOPE
        parameters = list(kind_parameters)
        if self.error is not None:
            parameters.append(f'error="{self.error}"')
        return f"Bearer {', '.join(parameters)}" if parameters else None

    def response(self, kind_parameters: tuple[str, ...]) -> JSONResponse:
        challenge = self.challenge(kind_parameters)
        return JSONResponse(
            {"detail": self.detail},
            status_code=self.status_code,
            headers=None if challenge is None else {"WWW-Authenticate": challenge},
        )


class _Continue(Enum):
    """A marked route's request the resource does not decide: it goes on as if unmarked."""

    AS_UNMARKED = auto()


_REFUSAL_OF_ADMISSION: Final = {
    AdmissionRefusal.NOT_A_MEMBER: _Refusal.NOT_A_MEMBER,
    AdmissionRefusal.USERNAME_TAKEN: _Refusal.USERNAME_TAKEN,
}


class BearerGateMiddleware(RefusalMiddleware[BearerGate]):
    """Admit a request on a gated path only with a valid access token.

    Every request the paths select is verified from its own ``Authorization``
    header; the cookie, CSRF and the session gate decide nothing there. On a machine
    path only an admin's token passes and the caller is recorded for
    ``bearer_caller``. The resource's entry point is decided on every method, and a marked
    route on its method, before CSRF and the session gate: a refusal carries the challenge of
    its metadata, except a token that holds whose person is not admitted, which gets a plain
    403; an admitted agent is the capped person. On a person path a bearer
    credential is the account behind the token, recorded for the session readers; a request
    with no bearer credential is decided by the session as it is outside the gate. Every
    method is gated, HEAD and OPTIONS included.
    """

    def __init__(self, app: ASGIApp, policy: BearerGate) -> None:
        super().__init__(app, policy)
        resource = policy.resource
        self._resource_verifier = None if resource is None else (
            policy.relying_party.resource_token_verifier(
                resource_url=resource.url,
                scope=resource.scope,
                authorized_parties=resource.authorized_parties,
            )
        )

    async def _refusal(self, request: Request) -> Response | None:
        path = route_path(request.scope)
        machine_paths = self._policy.machine_paths
        person_paths = self._policy.person_paths
        if machine_paths is not None and machine_paths.paths.matches(path):
            return await self._machine_refusal(request, machine_paths)
        resource = self._policy.resource
        verify = self._resource_verifier
        if resource is not None and verify is not None:
            on_entry_point = resource.entry_point_rule.matches(path)
            if on_entry_point or resource.marks(request.method, path):
                decided = await self._resource_refusal(
                    request, resource, verify, on_marked_route=not on_entry_point,
                )
                if decided is not _Continue.AS_UNMARKED:
                    return decided
        if person_paths is not None and person_paths.paths.matches(path):
            _mark_person_path(request)
            return await self._person_refusal(request, person_paths)
        return None

    async def _machine_refusal(
        self, request: Request, machine_paths: MachinePaths,
    ) -> Response | None:
        credential = _credential_of(request)
        if isinstance(credential, _Refusal):
            return self._refused(credential, challenge=_MACHINE_CHALLENGE)
        verified = await self._verified(credential, machine_paths.authorized_parties)
        if isinstance(verified, OidcRefusal):
            return self._refused(_Refusal.INVALID_TOKEN, verified, challenge=_MACHINE_CHALLENGE)
        if app_role(verified.groups, self._policy.admission) is not AppRole.ADMIN:
            return self._refused(_Refusal.INSUFFICIENT_SCOPE, challenge=_MACHINE_CHALLENGE)
        _record_bearer_admission(request, BearerCaller(subject=verified.subject))
        return None

    async def _resource_refusal(
        self,
        request: Request,
        resource: ProtectedResource,
        verify: Callable[[str], VerifiedAccessToken | OidcRefusal],
        *,
        on_marked_route: bool,
    ) -> JSONResponse | _Continue | None:
        challenge = resource.challenge_parameters
        credential = _credential_of(request)
        if isinstance(credential, _Refusal):
            if on_marked_route and credential is _Refusal.NO_CREDENTIALS:
                return _Continue.AS_UNMARKED
            return self._refused(credential, challenge=challenge)
        verified = await _on_worker(partial(verify, credential))
        if isinstance(verified, OidcRefusal):
            if on_marked_route and _names_another_audience(verified):
                return _Continue.AS_UNMARKED
            refusal = (
                _Refusal.RESOURCE_INSUFFICIENT_SCOPE
                if verified.reason is OidcRefusalReason.INSUFFICIENT_SCOPE
                else _Refusal.INVALID_TOKEN
            )
            return self._refused(refusal, verified, challenge=challenge)
        person = await _on_worker(
            partial(
                _admit_resource_holder,
                resource.transaction,
                verified,
                required_group=resource.required_group,
                admission=self._policy.admission,
                config=web_auth_config(request),
            ),
        )
        if person is None:
            return self._refused(_Refusal.RESOURCE_NOT_ADMITTED)
        _record_bearer_admission(request, person, resource_method=request.method)
        return None

    async def _person_refusal(
        self, request: Request, person_paths: PersonPaths,
    ) -> Response | None:
        credential = _credential_of(request)
        if credential is _Refusal.NO_CREDENTIALS:
            return None
        if isinstance(credential, _Refusal):
            return self._refused(credential)
        verified = await self._verified(credential, person_paths.authorized_parties)
        if isinstance(verified, OidcRefusal):
            return self._refused(_Refusal.INVALID_TOKEN, verified)
        person = await _on_worker(
            partial(
                _admit_token_holder,
                person_paths.transaction,
                verified,
                admission=self._policy.admission,
                config=web_auth_config(request),
            ),
        )
        if isinstance(person, AdmissionRefusal):
            return self._refused(_REFUSAL_OF_ADMISSION[person])
        _record_bearer_admission(request, person)
        return None

    async def _verified(
        self, credential: str, authorized_parties: AuthorizedParties,
    ) -> VerifiedAccessToken | OidcRefusal:
        return await _on_worker(
            partial(
                self._policy.relying_party.verify_access_token,
                credential,
                authorized_parties=authorized_parties,
            ),
        )

    def _refused(
        self,
        refusal: _Refusal,
        reason: OidcRefusal | None = None,
        *,
        challenge: tuple[str, ...] = (),
    ) -> JSONResponse:
        level = logging.INFO if refusal is _Refusal.NO_CREDENTIALS else logging.WARNING
        if reason is None:
            _LOGGER.log(level, "Bearer request refused: %s", refusal.case)
        else:
            _LOGGER.log(
                level,
                "Bearer request refused: %s (%s, %s)",
                refusal.case,
                reason.reason.value,
                None if reason.token_rejection is None else reason.token_rejection.value,
            )
        return refusal.response(challenge)


async def _on_worker[Result](work: Callable[[], Result]) -> Result:
    try:
        return await to_thread.run_sync(work)
    finally:
        await checkpoint_if_cancelled()


def _credential_of(request: Request) -> str | _Refusal:
    """The bearer credential of the one ``Authorization`` line, or why there is none.

    The first rule that applies decides: no or empty value; repeated line; no
    auth-scheme; another scheme; not exactly one credential; a second method
    (``access_token`` in the query); not a b64token.
    """
    lines = request.headers.getlist("authorization")
    if len(lines) > 1:
        return _Refusal.INVALID_REQUEST
    value = lines[0].strip(" \t") if lines else ""
    if not value:
        return _Refusal.NO_CREDENTIALS
    scheme = _AUTH_SCHEME.match(value)
    if scheme is None:
        return _Refusal.INVALID_REQUEST
    if scheme.group().lower() != _BEARER_SCHEME:
        return _Refusal.NO_CREDENTIALS
    credential = _ONE_CREDENTIAL.fullmatch(value, scheme.end())
    if credential is None or _ACCESS_TOKEN_QUERY_PARAMETER in request.query_params:
        return _Refusal.INVALID_REQUEST
    if _ACCESS_TOKEN.fullmatch(credential.group(1)) is None:
        return _Refusal.INVALID_TOKEN
    return credential.group(1)


def bearer_caller(connection: HTTPConnection) -> BearerCaller:
    """The caller the bearer gate admitted for this request: ``Depends(bearer_caller)``.

    Raises ``RuntimeError`` when no gate admitted a machine caller for this request:
    the gate is not installed or does not select this path as a machine path, the
    path is a person path (read ``current_user`` there), the connection is a
    WebSocket, the route runs in a sub-app below the gated path, or a middleware
    changed the ``Authorization`` header after admission. A forgotten gate never
    reads as a caller.
    """
    admission = _bearer_admission(connection)
    if admission is None or not isinstance(admission.principal, BearerCaller):
        raise RuntimeError(
            "The bearer gate admitted no caller for this request: install it with "
            "install_web_auth_middleware(bearer_gate=...) on the app that serves the "
            "route, and select the route's path as a machine path.",
        )
    return admission.principal


def resource_person(connection: HTTPConnection) -> AuthenticatedUser:
    """The capped person the resource admitted for this request, at its entry point or on one
    of its marked routes.

    Raises ``RuntimeError`` when the gate admitted no resource person for this request: the
    request is a session, person or machine request, the route runs in a sub-app, or a
    middleware changed the ``Authorization`` header or the method after admission. A
    forgotten gate never reads as a person.
    """
    admission = _bearer_admission(connection)
    if (
        admission is None
        or admission.resource_method is None
        or not isinstance(admission.principal, AuthenticatedUser)
    ):
        raise RuntimeError(
            "The bearer gate admitted no resource person for this request: install it with "
            "install_web_auth_middleware(bearer_gate=...) on the app that serves the "
            "route, and read the person on the resource's entry point or marked route itself.",
        )
    return admission.principal


def install_resource_metadata(app: FastAPI, resource: ProtectedResource, *, issuer: str) -> None:
    """Register ``GET`` of the resource's metadata path (RFC 9728) on ``app``: the resource,
    its one authorization server ``issuer`` and its one scope.

    Install it ahead of any catch-all route, and list ``resource.public_rule`` in
    ``SessionGate.public`` so a client without a session reads it.
    """
    document = {
        "resource": resource.url,
        "authorization_servers": [issuer],
        "scopes_supported": [resource.scope],
    }

    def metadata() -> dict[str, object]:
        return document

    app.add_api_route(resource.metadata_path, metadata, methods=["GET"], include_in_schema=False)
