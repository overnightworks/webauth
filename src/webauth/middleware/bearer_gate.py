"""The bearer gate: hal's access token alone opens the host's machine paths, and on its
person paths is the account behind the token."""

from __future__ import annotations

import logging
import re
from dataclasses import dataclass
from enum import Enum
from functools import partial
from typing import TYPE_CHECKING, Final

from anyio import to_thread
from anyio.lowlevel import checkpoint_if_cancelled
from starlette.requests import HTTPConnection
from starlette.responses import JSONResponse

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
from webauth.oidc import _ACCESS_TOKEN, OidcRefusal, OidcRelyingParty, VerifiedAccessToken
from webauth.oidc_login import (
    AdmissionConfig,
    AdmissionRefusal,
    AppRole,
    NoAdmins,
    _admit_token_holder,
    app_role,
)
from webauth.policies import AuthorizedParties, PathRules
from webauth.ports import BearerCaller

if TYPE_CHECKING:
    from collections.abc import Callable

    from starlette.requests import Request
    from starlette.responses import Response

    from webauth.ports import SignInTransaction

__all__ = [
    "BearerGate",
    "BearerGateMiddleware",
    "PersonPaths",
    "bearer_caller",
]

_LOGGER: Final = logging.getLogger(__name__)
_MACHINE_REALM: Final = "admin"
_AUTH_SCHEME: Final = re.compile(r"[!#$%&'*+\-.^_`|~0-9A-Za-z]+")
_ONE_CREDENTIAL: Final = re.compile(r" +([^ \t,]+)")
_BEARER_SCHEME: Final = "bearer"
_ACCESS_TOKEN_QUERY_PARAMETER: Final = "access_token"  # noqa: S105 - query parameter name not a credential


@dataclass(frozen=True)
class PersonPaths:
    """The paths where a token is the person behind it, and the host's sign-in context.

    ``paths`` are written as ``PathRules`` says. Each token request enters
    ``transaction`` once, as a sign-in does, to find or create the account.
    ``ValueError`` for no paths.
    """

    paths: PathRules
    transaction: SignInTransaction

    def __post_init__(self) -> None:
        if self.paths == PathRules():
            raise ValueError("person paths must select at least one path")


@dataclass(frozen=True)
class BearerGate:
    """Which paths take hal's bearer access token, and whose tokens count.

    ``paths`` are the machine paths and ``person_paths`` the host's API paths, each
    written as ``PathRules`` says; a path both select is a machine path. The token
    must come from ``relying_party``'s issuer, name its client as the only
    audience and carry an ``azp`` among ``authorized_parties``. A machine path
    also needs ``admission.admin_group`` or a group below it. On a person path
    the token is the account behind its subject, admitted as a sign-in admits it.
    ``ValueError`` when neither rule selects a path, for ``NoAdmins`` while the
    machine paths select something (no token could pass there) and for an
    ``admission`` bound to another issuer; ``TypeError`` for ``authorized_parties``
    that is not an ``AuthorizedParties``.
    """

    paths: PathRules
    relying_party: OidcRelyingParty
    admission: AdmissionConfig
    authorized_parties: AuthorizedParties
    person_paths: PersonPaths | None = None

    def __post_init__(self) -> None:
        if not isinstance(self.authorized_parties, AuthorizedParties):
            raise TypeError("authorized_parties must be an AuthorizedParties")
        if self.paths == PathRules() and self.person_paths is None:
            raise ValueError("paths must select at least one path")
        if isinstance(self.admission.admin_group, NoAdmins) and self.paths != PathRules():
            raise ValueError("admission.admin_group is NoAdmins: no token could pass the gate")
        if self.admission.bound_issuer != self.relying_party.issuer:
            raise ValueError("admission.bound_issuer must be the relying party's issuer")


class _Refusal(Enum):
    """The cases the gate refuses, each with its status, challenge error and detail.

    The first four refuse a machine path, which names its realm; on a person path
    ``INVALID_REQUEST`` and ``INVALID_TOKEN`` carry no realm and the last two
    belong to it alone.
    """

    NO_CREDENTIALS = (401, None, _AUTHENTICATION_REQUIRED_DETAIL)
    INVALID_REQUEST = (401, "invalid_request", "Invalid request")
    INVALID_TOKEN = (401, "invalid_token", "Invalid token")
    INSUFFICIENT_SCOPE = (403, "insufficient_scope", _ADMIN_REQUIRED_DETAIL)
    NOT_A_MEMBER = (403, "insufficient_scope", "No access")
    USERNAME_TAKEN = (403, None, "Login failed")

    def __init__(self, status_code: int, error: str | None, detail: str) -> None:
        self.status_code = status_code
        self.error = error
        self.detail = detail

    @property
    def case(self) -> str:
        return self.name.lower().replace("_", "-")

    def challenge(self, realm: str | None) -> str | None:
        if self is _Refusal.NOT_A_MEMBER:
            return _PERSON_PATH_INSUFFICIENT_SCOPE
        parameters = [] if realm is None else [f'realm="{realm}"']
        if self.error is not None:
            parameters.append(f'error="{self.error}"')
        return f"Bearer {', '.join(parameters)}" if parameters else None

    def response(self, realm: str | None) -> JSONResponse:
        challenge = self.challenge(realm)
        return JSONResponse(
            {"detail": self.detail},
            status_code=self.status_code,
            headers=None if challenge is None else {"WWW-Authenticate": challenge},
        )


_REFUSAL_OF_ADMISSION: Final = {
    AdmissionRefusal.NOT_A_MEMBER: _Refusal.NOT_A_MEMBER,
    AdmissionRefusal.USERNAME_TAKEN: _Refusal.USERNAME_TAKEN,
}


class BearerGateMiddleware(RefusalMiddleware[BearerGate]):
    """Admit a request on a gated path only with a valid access token.

    Every request the paths select is verified from its own ``Authorization``
    header; the cookie, CSRF and the session gate decide nothing there. On a machine
    path only an admin's token passes and the caller is recorded for
    ``bearer_caller``. On a person path a bearer credential is the account behind
    the token, recorded for the session readers; a request with no bearer credential
    is decided by the session as it is outside the gate. Every method is gated, HEAD
    and OPTIONS included.
    """

    async def _refusal(self, request: Request) -> Response | None:
        path = route_path(request.scope)
        person_paths = self._policy.person_paths
        if self._policy.paths.matches(path):
            return await self._machine_refusal(request)
        if person_paths is not None and person_paths.paths.matches(path):
            _mark_person_path(request)
            return await self._person_refusal(request, person_paths)
        return None

    async def _machine_refusal(self, request: Request) -> Response | None:
        credential = _credential_of(request)
        if isinstance(credential, _Refusal):
            return self._refused(credential, realm=_MACHINE_REALM)
        verified = await self._verified(credential)
        if isinstance(verified, OidcRefusal):
            return self._refused(_Refusal.INVALID_TOKEN, verified, realm=_MACHINE_REALM)
        if app_role(verified.groups, self._policy.admission) is not AppRole.ADMIN:
            return self._refused(_Refusal.INSUFFICIENT_SCOPE, realm=_MACHINE_REALM)
        _record_bearer_admission(request, BearerCaller(subject=verified.subject))
        return None

    async def _person_refusal(
        self, request: Request, person_paths: PersonPaths,
    ) -> Response | None:
        credential = _credential_of(request)
        if credential is _Refusal.NO_CREDENTIALS:
            return None
        if isinstance(credential, _Refusal):
            return self._refused(credential)
        verified = await self._verified(credential)
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

    async def _verified(self, credential: str) -> VerifiedAccessToken | OidcRefusal:
        return await _on_worker(
            partial(
                self._policy.relying_party.verify_access_token,
                credential,
                authorized_parties=self._policy.authorized_parties,
            ),
        )

    def _refused(
        self,
        refusal: _Refusal,
        reason: OidcRefusal | None = None,
        *,
        realm: str | None = None,
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
        return refusal.response(realm)


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
