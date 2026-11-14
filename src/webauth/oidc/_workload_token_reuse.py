"""The reuse of a client's own access token, per scope tuple.

`WorkloadTokenReuse` answers a token from its entry while the injected monotonic
clock, read before the post, has advanced less than the answer's lifetime less a
margin, and otherwise posts a grant through the function it is given. At most one
grant per scope tuple is in flight across threads; callers that arrive meanwhile
share its outcome, a refusal or a raised error included. A refusal, a raised error
and an answer without a lifetime worth keeping end the grant without an entry.
"""

from __future__ import annotations

import threading
from collections.abc import Callable
from concurrent.futures import Future
from dataclasses import dataclass, field

from pydantic import SecretStr

from webauth.jwt_verification import MonotonicClock
from webauth.oidc._token_endpoint import OidcRefusal

__all__ = ["WorkloadGrant", "WorkloadTokenReuse"]

WorkloadGrant = Callable[[tuple[str, ...]], tuple[SecretStr, int | None] | OidcRefusal]
"""Posts the grant for the scope tuple and answers the token with the lifetime its answer
states, or the refusal."""

# The time from hand-out to the receiver's one check at opening (a speech render takes up to
# 20 s) plus clock skew; a token that lives no longer than this is never kept, so the margin
# cannot cause endless replacement.
_MARGIN_SECONDS = 30
# The largest whole number of seconds a float deadline holds exactly; a longer lifetime is
# not a usable one and the token it came with is not kept.
_MAX_LIFETIME_SECONDS = 2**53


@dataclass(frozen=True)
class _HeldToken:
    token: SecretStr = field(repr=False)
    usable_until: float


@dataclass(frozen=True)
class _GrantLead:
    in_flight: Future[SecretStr | OidcRefusal]
    started_at: float


class WorkloadTokenReuse:
    def __init__(self, grant: WorkloadGrant, *, monotonic_clock: MonotonicClock) -> None:
        self._grant = grant
        self._monotonic_clock = monotonic_clock
        self._guard = threading.Lock()
        self._held: dict[tuple[str, ...], _HeldToken] = {}
        self._grants_in_flight: dict[tuple[str, ...], Future[SecretStr | OidcRefusal]] = {}

    def token(self, scopes: tuple[str, ...]) -> SecretStr | OidcRefusal:
        match self._held_or_joined_or_led(scopes):
            case SecretStr() as held:
                return held
            case Future() as shared:
                return shared.result()
            case _GrantLead() as lead:
                return self._lead(scopes, lead)

    def _held_or_joined_or_led(
        self, scopes: tuple[str, ...]
    ) -> SecretStr | Future[SecretStr | OidcRefusal] | _GrantLead:
        """The held token, the grant in flight to wait on, or the grant this caller now leads.

        The clock is read under the guard once the grant in flight exists or is found."""
        with self._guard:
            in_flight = self._grants_in_flight.get(scopes)
            if in_flight is None:
                in_flight = self._grants_in_flight[scopes] = Future()
                started_at = self._monotonic_clock()
                held = self._held.get(scopes)
                if held is None or started_at >= held.usable_until:
                    return _GrantLead(in_flight, started_at)
                del self._grants_in_flight[scopes]
                return held.token
            self._monotonic_clock()
            return in_flight

    def _lead(self, scopes: tuple[str, ...], lead: _GrantLead) -> SecretStr | OidcRefusal:
        try:
            outcome, kept = self._outcome(scopes, lead.started_at)
        except BaseException as error:
            self._end(scopes, kept=None)
            lead.in_flight.set_exception(error)
            raise
        self._end(scopes, kept)
        lead.in_flight.set_result(outcome)
        return outcome

    def _outcome(
        self, scopes: tuple[str, ...], started_at: float
    ) -> tuple[SecretStr | OidcRefusal, _HeldToken | None]:
        """The grant's outcome and the entry it earns, if any."""
        result = self._grant(scopes)
        if isinstance(result, OidcRefusal):
            return result, None
        token, lifetime = result
        if lifetime is None or not _MARGIN_SECONDS < lifetime <= _MAX_LIFETIME_SECONDS:
            return token, None
        return token, _HeldToken(token, started_at + lifetime - _MARGIN_SECONDS)

    def _end(self, scopes: tuple[str, ...], kept: _HeldToken | None) -> None:
        with self._guard:
            del self._grants_in_flight[scopes]
            if kept is None:
                self._held.pop(scopes, None)
            else:
                self._held[scopes] = kept
