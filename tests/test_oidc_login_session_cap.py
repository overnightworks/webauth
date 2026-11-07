"""A sign-in's session ends at its absolute cap, whatever the issuer says afterwards."""

from __future__ import annotations

from tests.support.oidc_arrangement import FakeClock
from tests.support.oidc_login_host import LOGIN_GROUP, an_oidc_host
from tests.support.webauth_arrangement import (
    FIXED_INSTANT,
    SESSION_ABSOLUTE_MAX_AGE_SECONDS,
    SESSION_IDLE_SECONDS,
)


def test_a_removed_persons_open_session_works_to_its_cap_and_the_next_sign_in_is_refused() -> None:
    """APP-09: after a login-group removal, an open session is admitted and renewed to its cap."""
    groups = [LOGIN_GROUP]
    clock = FakeClock(FIXED_INSTANT.timestamp())
    host = an_oidc_host(groups_claim=groups, wall_clock=clock)
    host.callback(host.sign_in_at_issuer())
    groups[:] = []
    half_idle = SESSION_IDLE_SECONDS // 2
    ages = (
        *range(half_idle, SESSION_ABSOLUTE_MAX_AGE_SECONDS, half_idle),
        SESSION_ABSOLUTE_MAX_AGE_SECONDS - 1,
    )
    statuses = []

    for age in ages:
        clock.now = FIXED_INSTANT.timestamp() + age
        statuses.append(host.client.get("/me").status_code)
    clock.now = FIXED_INSTANT.timestamp() + SESSION_ABSOLUTE_MAX_AGE_SECONDS + 1
    past_the_cap = host.client.get("/me").status_code
    host.client.cookies.clear()
    refused = host.callback(host.sign_in_at_issuer())

    assert set(statuses) == {200}
    assert past_the_cap == 401
    assert (refused.status_code, refused.json()) == (403, {"refusal": "not-a-member"})
