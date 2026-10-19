"""CSRF protection -- double-submit cookie and origin checking."""

from __future__ import annotations

from typing import TYPE_CHECKING, Final

from starlette.responses import JSONResponse

from webauth._origins import origin_is_allowed
from webauth.config import web_auth_config
from webauth.cookies import verify_csrf_token
from webauth.dependencies import session_id_from_request
from webauth.middleware._refusal import RefusalMiddleware
from webauth.policies import CsrfPolicy

if TYPE_CHECKING:
    from starlette.requests import Request

__all__ = [
    "CsrfOriginMiddleware",
    "CsrfTokenMiddleware",
]

_MUTATING_METHODS: Final = frozenset({"POST", "PUT", "PATCH", "DELETE"})

_FORM_CONTENT_TYPES: Final = frozenset({
    "application/x-www-form-urlencoded",
    "multipart/form-data",
    "text/plain",
})

_CSRF_REFUSAL_DETAIL: Final = "CSRF token missing or invalid"
_SEC_FETCH_SITE: Final = "sec-fetch-site"
_SAME_ORIGIN: Final = "same-origin"
_SAME_SITE: Final = "same-site"


class CsrfTokenMiddleware(RefusalMiddleware[CsrfPolicy]):
    """Reject a state-changing request whose CSRF token does not match its session."""

    async def _refusal(self, request: Request) -> JSONResponse | None:
        if (
            request.method in _MUTATING_METHODS
            and self._policy.requires_token(request.url.path)
        ):
            config = web_auth_config(request)
            header_token = request.headers.get(config.csrf_header_name)
            if not header_token:
                return JSONResponse(
                    {"detail": _CSRF_REFUSAL_DETAIL}, status_code=403,
                )
            session_id = session_id_from_request(request, config)
            if session_id is None or not verify_csrf_token(
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


def _is_form_submission(request: Request) -> bool:
    content_type = (request.headers.get("content-type") or "").split(";")[0].strip()
    return content_type in _FORM_CONTENT_TYPES


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
        origin = request.headers.get("referer")
    if origin is not None:
        if origin_is_allowed(origin, web_auth_config(request)):
            return None
        return _cross_origin_rejection()
    if _is_form_submission(request):
        return JSONResponse(
            {"detail": "Missing Origin header on form submission"},
            status_code=403,
        )
    return None


class CsrfOriginMiddleware(RefusalMiddleware[CsrfPolicy]):
    """Reject a state-changing request that a foreign page originated.

    Sec-Fetch-Site is read first: the header overrides the Origin
    allowlist for same-origin (passes) and cross-site (refused), while
    same-site is decided by the allowlist; when the header is absent
    the allowlist is applied as before. When both are absent, a form
    POST is refused.
    """

    async def _refusal(self, request: Request) -> JSONResponse | None:
        if (
            request.method in _MUTATING_METHODS
            and self._policy.requires_same_origin(request.url.path)
        ):
            return _origin_check_refusal(request)
        return None
