"""Whether the callback stores the login's ID token in the new session's row.

Each case signs in through a host's callback over a shared in-memory store, then reads the row
through the logout route, ``fresh_access_token`` and ``admit_session``.
"""

from __future__ import annotations

from pydantic import SecretStr

from tests.support.oidc_arrangement import (
    ISSUED_REFRESH_TOKEN,
    FakeClock,
    LogoutPage,
    a_fake_id_token,
)
from tests.support.oidc_login_host import (
    SAME_ORIGIN_FORM,
    OidcHost,
    an_oidc_host,
    post_logout,
)
from tests.support.webauth_arrangement import FIXED_INSTANT, SESSION_IDLE_SECONDS
from webauth.dependencies import admit_session
from webauth.oidc_login import fresh_access_token
from webauth.ports import AuthenticatedUser, SessionRecord


def signed_in(*, keeps_id_token: bool) -> tuple[OidcHost, SessionRecord, FakeClock]:
    clock = FakeClock(FIXED_INSTANT.timestamp())
    host = an_oidc_host(keeps_id_token=keeps_id_token, wall_clock=clock)
    assert host.callback(host.sign_in_at_issuer()).status_code == 303
    return host, host.sessions.stored_record, clock


def logout_page(host: OidcHost) -> LogoutPage:
    return LogoutPage(post_logout(host, SAME_ORIGIN_FORM).text)


def test_a_host_that_keeps_the_id_token_stores_it_and_the_logout_posts_it_as_the_hint() -> None:
    host, session, _clock = signed_in(keeps_id_token=True)
    [login_id_token] = host.issued_id_tokens

    assert session.id_token == SecretStr(login_id_token)
    assert logout_page(host).hidden_fields.get("id_token_hint") == login_id_token


def test_a_host_that_keeps_no_id_token_stores_the_refresh_token_and_no_id_token() -> None:
    host, session, _clock = signed_in(keeps_id_token=False)

    assert (session.refresh_token, session.id_token) == (SecretStr(ISSUED_REFRESH_TOKEN), None)
    assert host.sessions.load(session.id) == session


def test_a_logout_after_a_host_kept_no_id_token_ends_the_session_and_posts_no_hint() -> None:
    host, session, _clock = signed_in(keeps_id_token=False)

    page = logout_page(host)

    assert (page.hidden_fields.get("id_token_hint"), host.sessions.load(session.id)) == (None, None)


def test_rotation_and_renewal_keep_no_id_token_for_a_host_that_keeps_none() -> None:
    host, session, clock = signed_in(keeps_id_token=False)
    expiry_before_renewal = session.expires_at
    host.issuer.refresh_answer_members = {"id_token": a_fake_id_token("issued-by-the-refresh")}
    clock.now += SESSION_IDLE_SECONDS / 2

    renewed = admit_session(session.id, sessions=host.sessions, config=host.config)
    rotated = fresh_access_token(
        host.relying_party, session.id,
        session_transaction=host.sessions.in_transaction, config=host.config,
    )

    assert isinstance(renewed, AuthenticatedUser)
    assert isinstance(rotated, SecretStr)
    [after] = host.sessions.list_active()
    assert (after.id, after.id_token) == (session.id, None)
    assert after.expires_at > expiry_before_renewal
    assert after.refresh_token is not None
    stored_refresh_token = after.refresh_token.get_secret_value()
    assert stored_refresh_token != ISSUED_REFRESH_TOKEN
    assert stored_refresh_token in host.issuer.refresh_tokens
