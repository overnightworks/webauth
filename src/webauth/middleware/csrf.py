"""CSRF protection -- double-submit cookie and origin checking."""

from __future__ import annotations

import re
from typing import TYPE_CHECKING, Final
from urllib.parse import urlparse

from starlette.middleware.base import BaseHTTPMiddleware
from starlette.responses import JSONResponse

from webauth.config import web_auth_config
from webauth.cookies import verify_csrf_token
from webauth.dependencies import session_id_from_request

if TYPE_CHECKING:
    from starlette.requests import Request

    from webauth.config import WebAuthConfig
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
_SAME_SITE: Final = "same-site"


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
            session_id = session_id_from_request(request, config)
            if session_id is None or not verify_csrf_token(
                header_token, session_id, config.signing_key,
            ):
                return JSONResponse(
                    {"detail": "CSRF token missing or invalid"}, status_code=403,
                )
        return await call_next(request)


def _is_allowed_host(
    hostname: str,
    host_and_port: str,
    exact: frozenset[str],
    patterns: tuple[re.Pattern[str], ...],
) -> bool:
    if exact or patterns:
        if host_and_port in exact or hostname in exact:
            return True
        return any(p.fullmatch(host_and_port) for p in patterns)
    return bool(_LOCALHOST_PATTERN.match(host_and_port))


def _sec_fetch_site_allows(fetch_site: str) -> bool | None:
    if fetch_site == _SAME_ORIGIN:
        return True
    if fetch_site == _SAME_SITE:
        return None
    return False


def _origin_is_allowed(origin: str, config: WebAuthConfig) -> bool:
    try:
        parsed = urlparse(origin)
        hostname = parsed.hostname
        port = parsed.port
    except ValueError:
        return False
    if not hostname or parsed.username is not None or parsed.password is not None:
        return False
    if ":" in hostname:
        hostname = f"[{hostname}]"
    host_and_port = hostname if port is None else f"{hostname}:{port}"
    return _is_allowed_host(
        hostname,
        host_and_port,
        config.allowed_hosts_exact,
        config.allowed_hosts_patterns,
    )


def _is_form_submission(request: Request) -> bool:
    content_type = (request.headers.get("content-type") or "").split(";")[0].strip()
    return content_type in _FORM_CONTENT_TYPES


def _cross_origin_rejection() -> JSONResponse:
    return JSONResponse({"detail": "Cross-origin request rejected"}, status_code=403)


class CsrfOriginMiddleware(BaseHTTPMiddleware):
    """Reject a state-changing request that a foreign page originated.

    Sec-Fetch-Site is read first: the header overrides the Origin
    allowlist for same-origin (passes) and cross-site (refused), while
    same-site is decided by the allowlist; when the header is absent
    the allowlist is applied as before. When both are absent, a form
    POST is refused.
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
                allowed = _sec_fetch_site_allows(fetch_site)
                if allowed is True:
                    return await call_next(request)
                if allowed is False:
                    return _cross_origin_rejection()
            origin = request.headers.get("origin")
            if origin is None:
                origin = request.headers.get("referer")
            if origin is not None:
                if not _origin_is_allowed(origin, web_auth_config(request)):
                    return _cross_origin_rejection()
            elif _is_form_submission(request):
                return JSONResponse(
                    {"detail": "Missing Origin header on form submission"},
                    status_code=403,
                )
        return await call_next(request)
