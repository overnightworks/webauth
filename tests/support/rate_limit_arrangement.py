"""Doubles for the `RateLimitBackend` port."""

from __future__ import annotations

from dataclasses import dataclass

from webauth.rate_limit import SingleProcessRateLimitBackend


@dataclass(frozen=True)
class CheckedBudget:
    limit: int
    window_seconds: int


class AlwaysFailingRateLimitBackend:
    """A backend that can never answer, to prove the middleware fails closed."""

    def is_allowed(self, key: str, *, limit: int, window_seconds: int) -> bool:
        raise ConnectionError("rate limiter down")


class RecordingRateLimitBackend:
    """A working backend that remembers the limit and window each key was checked with."""

    def __init__(self) -> None:
        self.checked: dict[str, set[CheckedBudget]] = {}
        self._counting = SingleProcessRateLimitBackend()

    def is_allowed(self, key: str, *, limit: int, window_seconds: int) -> bool:
        self.checked.setdefault(key, set()).add(CheckedBudget(limit, window_seconds))
        return self._counting.is_allowed(key, limit=limit, window_seconds=window_seconds)

    def budgets_checked(self) -> set[CheckedBudget]:
        return {budget for budgets in self.checked.values() for budget in budgets}
