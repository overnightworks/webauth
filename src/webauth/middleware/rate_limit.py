"""Per-IP rate limiting: one budget per request, one counter per budget."""

from __future__ import annotations

import logging
from functools import partial
from typing import TYPE_CHECKING, Final

from anyio import to_thread
from anyio.lowlevel import checkpoint_if_cancelled
from starlette.responses import JSONResponse

from webauth.config import web_auth_config
from webauth.middleware._refusal import RefusalMiddleware
from webauth.policies import RateLimitBudget, RateLimitPolicy
from webauth.proxies import _budget_address, resolve_client_ip

if TYPE_CHECKING:
    from starlette.requests import Request

__all__ = [
    "IpRateLimitMiddleware",
]

log = logging.getLogger(__name__)

LIMITER_UNAVAILABLE_RETRY_AFTER_SECONDS: Final = 5


def _rate_limit_key(budget: RateLimitBudget, budget_identity: str) -> str:
    """One key space per budget; a name holds no ``:``, so the first one ends it."""
    return f"{budget.name}:{budget_identity}"


class IpRateLimitMiddleware(RefusalMiddleware[RateLimitPolicy]):
    """Spend one request of the client's budget for the budget it falls into.

    The budget belongs to the client's address, or to its whole IPv6 network
    of the configured prefix -- see ``_budget_address``.
    """

    async def _refusal(self, request: Request) -> JSONResponse | None:
        path = request.url.path
        if self._policy.is_exempt(path):
            return None
        config = web_auth_config(request)
        budget_identity = _budget_address(resolve_client_ip(request), config.ipv6_budget_prefix)
        budget = self._policy.budget_for(path)
        try:
            allowed = await to_thread.run_sync(
                partial(
                    config.rate_limits.is_allowed,
                    _rate_limit_key(budget, budget_identity),
                    limit=budget.max_requests,
                    window_seconds=budget.window_seconds,
                )
            )
        except Exception:
            # The worker call is shielded: a cancellation arriving during it is delivered only here.
            await checkpoint_if_cancelled()
            log.exception("IP rate limiter unavailable -- rejecting request")
            return JSONResponse(
                {"detail": "Rate limiter unavailable"}, status_code=503,
                headers={"Retry-After": str(LIMITER_UNAVAILABLE_RETRY_AFTER_SECONDS)},
            )
        await checkpoint_if_cancelled()
        if not allowed:
            return JSONResponse(
                {"detail": "Too many requests"}, status_code=429,
                headers={"Retry-After": str(budget.window_seconds)},
            )
        return None
