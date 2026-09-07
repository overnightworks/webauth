"""Per-IP rate limiting: one budget class per request, one counter per class."""

from __future__ import annotations

import logging
from typing import TYPE_CHECKING, Final

from starlette.middleware.base import BaseHTTPMiddleware
from starlette.responses import JSONResponse

from webauth.config import web_auth_config
from webauth.policies import RateLimitClass
from webauth.proxies import resolve_client_ip

if TYPE_CHECKING:
    from starlette.requests import Request

    from webauth.policies import RateLimitPolicy

log = logging.getLogger(__name__)

LIMITER_UNAVAILABLE_RETRY_AFTER_SECONDS: Final = 5


def _rate_limit_key(rate_limit_class: RateLimitClass, ip: str) -> str:
    """One key space per class, so no budget spends another's counter."""
    return f"{rate_limit_class.name}:{ip}"


class IpRateLimitMiddleware(BaseHTTPMiddleware):
    """Spend one request of the address's budget for the class it falls into."""

    def __init__(self, app, policy: RateLimitPolicy, **kwargs):  # type: ignore[no-untyped-def]
        super().__init__(app, **kwargs)
        self._policy = policy

    async def dispatch(self, request: Request, call_next):  # type: ignore[override]
        path = request.url.path
        if self._policy.is_exempt(path):
            return await call_next(request)
        ip = resolve_client_ip(request)
        rate_limit_class = self._policy.classify(path)
        budget = self._policy.budget(rate_limit_class)
        try:
            allowed = web_auth_config(request).rate_limits.is_allowed(
                _rate_limit_key(rate_limit_class, ip),
                limit=budget.max_requests,
                window_seconds=budget.window_seconds,
            )
        except Exception:
            log.warning("IP rate limiter unavailable -- rejecting request")
            return JSONResponse(
                {"detail": "Rate limiter unavailable"}, status_code=503,
                headers={"Retry-After": str(LIMITER_UNAVAILABLE_RETRY_AFTER_SECONDS)},
            )
        if not allowed:
            return JSONResponse(
                {"detail": "Too many requests"}, status_code=429,
                headers={"Retry-After": str(budget.window_seconds)},
            )
        return await call_next(request)
