"""Per-IP rate limiting: one budget per request, one counter per budget."""

from __future__ import annotations

import logging
from functools import partial
from typing import TYPE_CHECKING, Final

from anyio import to_thread
from anyio.lowlevel import checkpoint_if_cancelled
from starlette.responses import JSONResponse

from webauth._outage import _OutageTracker, _unavailable_answer
from webauth.config import web_auth_config
from webauth.middleware._refusal import RefusalMiddleware
from webauth.middleware._route_path import route_path
from webauth.policies import RateLimitBudget, RateLimitPolicy
from webauth.proxies import _budget_address, client_address

if TYPE_CHECKING:
    from starlette.requests import Request
    from starlette.types import ASGIApp

__all__: list[str] = []

_log = logging.getLogger(__name__)

_OUTAGE_STARTED_EVENT: Final = "rate_limit_outage.started"
_OUTAGE_ENDED_EVENT: Final = "rate_limit_outage.ended"


def _rate_limit_key(budget: RateLimitBudget, budget_identity: str) -> str:
    """One key space per budget; a name holds no ``:``, so the first one ends it."""
    return f"{budget.name}:{budget_identity}"


class _IpRateLimitMiddleware(RefusalMiddleware[RateLimitPolicy]):
    """Spend one request of the client's budget for the budget it falls into.

    The budget belongs to the client's address, or to its IPv6 /64 -- see
    ``_budget_address``. A path in the policy's ``exempt`` spends nothing. The
    limiter key is ``<name>:<address>``, so renaming a budget starts it fresh.

    A limiter that raises answers 503 with ``Retry-After``, failing closed; so
    does a Redis that refuses the script. What other refusals spend, when the
    path is not exempt and the limiter is reached:

    - a 413 by Content-Length spends nothing;
    - a 413 for a streamed body the route reads spends one;
    - a CSRF 403 spends one;
    - the library 500 spends one, except a missing-config 500, which fails
      before rate admission.
    """

    def __init__(self, app: ASGIApp, policy: RateLimitPolicy) -> None:
        super().__init__(app, policy)
        self._outage = _OutageTracker(_log, _OUTAGE_STARTED_EVENT, _OUTAGE_ENDED_EVENT)

    async def _refusal(self, request: Request) -> JSONResponse | None:
        client_ip = client_address(request)
        path = route_path(request.scope)
        if self._policy.is_exempt(path):
            return None
        config = web_auth_config(request)
        budget_identity = _budget_address(client_ip)
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
        except Exception as failure:
            # The worker call is shielded: a cancellation arriving during it is delivered only here.
            await checkpoint_if_cancelled()
            self._outage.note_failure(failure)
            return _unavailable_answer("Rate limiter unavailable")
        await checkpoint_if_cancelled()
        self._outage.note_answered()
        if not allowed:
            return JSONResponse(
                {"detail": "Too many requests"},
                status_code=429,
                headers={"Retry-After": str(budget.window_seconds)},
            )
        return None
