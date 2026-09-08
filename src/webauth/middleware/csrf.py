"""CSRF protection -- double-submit cookie and origin checking."""

from __future__ import annotations

import re
from typing import TYPE_CHECKING, Final
from urllib.parse import urlparse

from starlette.middleware.base import BaseHTTPMiddleware
from starlette.responses import JSONResponse

from webauth.config import web_auth_config
from webauth.cookies import verify_csrf_token, verify_session_cookie

if TYPE_CHECKING:
    from starlette.requests import Request

    from webauth.policies import CsrfPolicy

_MUTATING_METHODS: Final = frozenset({"POST", "PUT", "PATCH", "DELETE"})

_FORM_CONTENT_TYPES: Final = frozenset({
    "application/x-www-form-urlencoded",
    "multipart/form-data",
    "text/plain",
})

_LOCALHOST_PATTERN: Final = re.compile(r"^(localhost|127\.0\.0\.1)(:\d+)?$")

_SEC_FETCH_SITE: Final = "sec-fetch-site"
_SAME_ORIGIN: Final = "same-origin"
_NONE: Final = "none"


class CsrfTokenMiddleware(BaseHTTPMiddleware):
    """Reject a state-changing request whose CSRF token does not match its session."""

    def __init__(self, app, policy: CsrfPolicy, **kwargs):  # type: ignore[no-untyped-def]
        super().__init__(app, **kwargs)
        self._policy = policy

    async def dispatch(self, request: Request, call_next):  # type: ignore[override]
        if (
            request.method in _MUTATING_METHODS
            and self._policy.requires_token(request.url.path)
        ):
            config = web_auth_config(request)
            header_token = request.headers.get(config.csrf_header_name)
            if not header_token:
                return JSONResponse(
                    {"detail": "CSRF token missing or invalid"}, status_code=403,
                )
            raw_cookie = request.cookies.get(config.session_cookie_name)
            secret = config.signing_key
            session_id = verify_session_cookie(raw_cookie, secret) if raw_cookie else None
            if not session_id or not verify_csrf_token(header_token, session_id, secret):
                return JSONResponse(
                    {"detail": "CSRF token missing or invalid"}, status_code=403,
                )
        return await call_next(request)


def _is_allowed_host(
    netloc: str,
    exact: frozenset[str],
    patterns: tuple[re.Pattern[str], ...],
) -> bool:
    host_without_port = netloc.rsplit(":", 1)[0] if ":" in netloc else netloc
    if exact or patterns:
        if netloc in exact or host_without_port in exact:
            return True
        return any(p.match(netloc) for p in patterns)
    return bool(_LOCALHOST_PATTERN.match(netloc))


def _sec_fetch_site_allows(fetch_site: str, method: str) -> bool:
    if fetch_site == _SAME_ORIGIN:
        return True
    if fetch_site == _NONE:
        return method not in _MUTATING_METHODS
    return False


class CsrfOriginMiddleware(BaseHTTPMiddleware):
    """Reject a state-changing request that a foreign page originated.

    Sec-Fetch-Site is read first: same-origin passes; cross-site and
    same-site are refused; none (a typed address or a bookmark) passes
    for a safe method only. When that header is absent, the Origin
    allowlist is applied as before. When both are absent, a form POST
    is refused — the named rule for a client that sends neither.
    """

    def __init__(self, app, policy: CsrfPolicy, **kwargs):  # type: ignore[no-untyped-def]
        super().__init__(app, **kwargs)
        self._policy = policy

    async def dispatch(self, request: Request, call_next):  # type: ignore[override]
        if (
            request.method in _MUTATING_METHODS
            and self._policy.requires_same_origin(request.url.path)
        ):
            fetch_site = request.headers.get(_SEC_FETCH_SITE)
            if fetch_site is not None:
                if _sec_fetch_site_allows(fetch_site, request.method):
                    return await call_next(request)
                return JSONResponse(
                    {"detail": "Cross-origin request rejected"},
                    status_code=403,
                )
            origin = request.headers.get("origin") or request.headers.get("referer")
            if origin:
                config = web_auth_config(request)
                parsed = urlparse(origin)
                origin_host = parsed.netloc
                if origin_host and not _is_allowed_host(
                    origin_host,
                    config.allowed_hosts_exact,
                    config.allowed_hosts_patterns,
                ):
                    return JSONResponse(
                        {"detail": "Cross-origin request rejected"},
                        status_code=403,
                    )
            else:
                content_type = (request.headers.get("content-type") or "").split(";")[0].strip()
                if content_type in _FORM_CONTENT_TYPES:
                    return JSONResponse(
                        {"detail": "Missing Origin header on form submission"},
                        status_code=403,
                    )
        return await call_next(request)
