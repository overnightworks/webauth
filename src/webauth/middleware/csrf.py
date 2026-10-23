"""CSRF protection -- double-submit cookie and origin checking."""

from __future__ import annotations

from typing import TYPE_CHECKING, Final

from starlette.responses import JSONResponse

from webauth._origins import origin_is_allowed
from webauth.config import web_auth_config
from webauth.cookies import _verify_csrf_token
from webauth.dependencies import _bearer_admission, session_id_from_request
from webauth.middleware._refusal import RefusalMiddleware
from webauth.middleware._route_path import route_path
from webauth.policies import CsrfPolicy

if TYPE_CHECKING:
    from starlette.requests import Request

__all__ = [
    "CsrfOriginMiddleware",
    "CsrfTokenMiddleware",
]

_MUTATING_METHODS: Final = frozenset({"POST", "PUT", "PATCH", "DELETE"})

_CSRF_REFUSAL_DETAIL: Final = "CSRF token missing or invalid"
_SEC_FETCH_SITE: Final = "sec-fetch-site"
_SAME_ORIGIN: Final = "same-origin"
_SAME_SITE: Final = "same-site"


class CsrfTokenMiddleware(RefusalMiddleware[CsrfPolicy]):
    """Reject a state-changing request whose CSRF token does not match its session.

    For a state-changing request whose path the policy does not exempt, a request
    is refused with 403 when it sends no token header, a token that does not
    belong to its session, or no usable session cookie to bind a token to: a
    session cookie that is missing, forged, too long or present more than once
    reads as no session (``session_id_from_request``).
    """

    async def _refusal(self, request: Request) -> JSONResponse | None:
        if (
            request.method in _MUTATING_METHODS
            and self._policy.requires_token(route_path(request.scope))
            and _bearer_admission(request) is None
        ):
            config = web_auth_config(request)
            header_token = request.headers.get(config.csrf_header_name)
            if not header_token:
                return JSONResponse(
                    {"detail": _CSRF_REFUSAL_DETAIL}, status_code=403,
                )
            session_id = session_id_from_request(request, config)
            if session_id is None or not _verify_csrf_token(
                header_token, session_id, config.signing_key,
            ):
                return JSONResponse(
                    {"detail": _CSRF_REFUSAL_DETAIL}, status_code=403,
                )
        return None


def _sec_fetch_site_allows(fetch_site: str) -> bool | None:
    if fetch_site == _SAME_ORIGIN:
        return True
    if fetch_site == _SAME_SITE:
        return None
    return False


def _cross_origin_rejection() -> JSONResponse:
    return JSONResponse({"detail": "Cross-origin request rejected"}, status_code=403)


def _origin_check_refusal(request: Request) -> JSONResponse | None:
    fetch_site = request.headers.get(_SEC_FETCH_SITE)
    if fetch_site is not None:
        allowed = _sec_fetch_site_allows(fetch_site)
        if allowed is True:
            return None
        if allowed is False:
            return _cross_origin_rejection()
    origin = request.headers.get("origin")
    if origin is None:
        return JSONResponse({"detail": "Missing Origin header"}, status_code=403)
    if origin_is_allowed(origin, web_auth_config(request)):
        return None
    return _cross_origin_rejection()


class CsrfOriginMiddleware(RefusalMiddleware[CsrfPolicy]):
    """Reject a state-changing request that a foreign page originated.

    Sec-Fetch-Site is read first: the header overrides the Origin
    allowlist for same-origin (passes) and cross-site (refused), while
    same-site is decided by the allowlist; when the header is absent
    the allowlist alone decides. A request with neither header is refused
    whatever its content type or body, and ``Referer`` is never read.

    An ``Origin`` that is ``null``, empty, has no host, carries userinfo or a
    non-numeric port, or cannot be parsed is refused like a foreign origin.
    How allowed hosts match is described on ``WebAuthConfig``.
    """

    async def _refusal(self, request: Request) -> JSONResponse | None:
        if (
            request.method in _MUTATING_METHODS
            and self._policy.requires_same_origin(route_path(request.scope))
            and _bearer_admission(request) is None
        ):
            return _origin_check_refusal(request)
        return None
