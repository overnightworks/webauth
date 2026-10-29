"""The bearer gate: hal's access token alone opens the host's machine paths."""

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

from webauth.dependencies import (
    _ADMIN_REQUIRED_DETAIL,
    _AUTHENTICATION_REQUIRED_DETAIL,
    _bearer_admission,
    _record_bearer_admission,
)
from webauth.middleware._refusal import RefusalMiddleware
from webauth.middleware._route_path import route_path
from webauth.oidc import _ACCESS_TOKEN, OidcRefusal, OidcRelyingParty
from webauth.oidc_login import AdmissionConfig, AppRole, NoAdmins, app_role
from webauth.policies import AuthorizedParties, PathRules
from webauth.ports import BearerCaller

if TYPE_CHECKING:
    from starlette.requests import Request
    from starlette.responses import Response

__all__ = [
    "BearerGate",
    "BearerGateMiddleware",
    "bearer_caller",
]

_LOGGER: Final = logging.getLogger(__name__)
_REALM: Final = 'Bearer realm="admin"'
_AUTH_SCHEME: Final = re.compile(r"[!#$%&'*+\-.^_`|~0-9A-Za-z]+")
_ONE_CREDENTIAL: Final = re.compile(r" +([^ \t,]+)")
_BEARER_SCHEME: Final = "bearer"
_ACCESS_TOKEN_QUERY_PARAMETER: Final = "access_token"  # noqa: S105 - query parameter name not a credential


@dataclass(frozen=True)
class BearerGate:
    """Which paths take hal's bearer access token alone, and whose tokens count.

    ``paths`` are written as ``PathRules`` says. The token must come from
    ``relying_party``'s issuer, name its client as the only audience, carry an
    ``azp`` among ``authorized_parties`` and hold ``admission.admin_group`` or a
    group below it. ``ValueError`` for no paths, for ``NoAdmins`` (no token could
    pass) and for an ``admission`` bound to another issuer; ``TypeError`` for
    ``authorized_parties`` that is not an ``AuthorizedParties``.
    """

    paths: PathRules
    relying_party: OidcRelyingParty
    admission: AdmissionConfig
    authorized_parties: AuthorizedParties

    def __post_init__(self) -> None:
        if not isinstance(self.authorized_parties, AuthorizedParties):
            raise TypeError("authorized_parties must be an AuthorizedParties")
        if self.paths == PathRules():
            raise ValueError("paths must select at least one path")
        if isinstance(self.admission.admin_group, NoAdmins):
            raise ValueError("admission.admin_group is NoAdmins: no token could pass the gate")
        if self.admission.bound_issuer != self.relying_party.issuer:
            raise ValueError("admission.bound_issuer must be the relying party's issuer")


class _Refusal(Enum):
    """The cases the gate refuses, each with its status, challenge error and detail."""

    NO_CREDENTIALS = (401, None, _AUTHENTICATION_REQUIRED_DETAIL)
    INVALID_REQUEST = (401, "invalid_request", "Invalid request")
    INVALID_TOKEN = (401, "invalid_token", "Invalid token")
    INSUFFICIENT_SCOPE = (403, "insufficient_scope", _ADMIN_REQUIRED_DETAIL)

    def __init__(self, status_code: int, error: str | None, detail: str) -> None:
        self.status_code = status_code
        self.detail = detail
        self.challenge = _REALM if error is None else f'{_REALM}, error="{error}"'

    @property
    def case(self) -> str:
        return self.name.lower().replace("_", "-")

    def response(self) -> JSONResponse:
        return JSONResponse(
            {"detail": self.detail},
            status_code=self.status_code,
            headers={"WWW-Authenticate": self.challenge},
        )


class BearerGateMiddleware(RefusalMiddleware[BearerGate]):
    """Admit a request on a gated path only with a valid admin access token.

    Every request the paths select is verified from its own ``Authorization``
    header; the cookie, CSRF and the session gate decide nothing there. The
    admitted caller is recorded for ``bearer_caller``. Every method is gated,
    HEAD and OPTIONS included.
    """

    async def _refusal(self, request: Request) -> Response | None:
        if not self._policy.paths.matches(route_path(request.scope)):
            return None
        credential = _credential_of(request)
        if isinstance(credential, _Refusal):
            return self._refused(credential)
        try:
            verified = await to_thread.run_sync(
                partial(
                    self._policy.relying_party.verify_access_token,
                    credential,
                    authorized_parties=self._policy.authorized_parties,
                )
            )
        finally:
            await checkpoint_if_cancelled()
        if isinstance(verified, OidcRefusal):
            return self._refused(_Refusal.INVALID_TOKEN, verified)
        if app_role(verified.groups, self._policy.admission) is not AppRole.ADMIN:
            return self._refused(_Refusal.INSUFFICIENT_SCOPE)
        _record_bearer_admission(request, BearerCaller(subject=verified.subject))
        return None

    def _refused(self, refusal: _Refusal, reason: OidcRefusal | None = None) -> JSONResponse:
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
        return refusal.response()


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

    Raises ``RuntimeError`` when no gate admitted this request: the gate is not
    installed or does not select this path, the connection is a WebSocket, the
    route runs in a sub-app below the gated path, or a middleware changed the
    ``Authorization`` header after admission. A forgotten gate never reads as a
    caller.
    """
    admission = _bearer_admission(connection)
    if admission is None:
        raise RuntimeError(
            "The bearer gate admitted no caller for this request: install it with "
            "install_web_auth_middleware(bearer_gate=...) on the app that serves the "
            "route, and select the route's path.",
        )
    return admission.caller
