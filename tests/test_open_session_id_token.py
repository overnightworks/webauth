"""Whether ``open_session`` stores the login's ID token in the new session's row.

Each case drives ``open_session`` over a shared in-memory store, then reads the row
through ``log_out``, ``fresh_access_token`` and ``admit_session``.
"""

from __future__ import annotations

from dataclasses import dataclass

import pytest
from fastapi import FastAPI, Request
from pydantic import SecretStr

from tests.support.oidc_arrangement import (
    ISSUED_REFRESH_TOKEN,
    FakeClock,
    FakeIssuer,
    LogoutPage,
    a_fake_id_token,
    a_relying_party,
    opened_session,
)
from tests.support.webauth_arrangement import (
    FIXED_INSTANT,
    SESSION_IDLE_SECONDS,
    FakeUser,
    SessionRecordsInMemory,
    UsersInMemory,
    WriteLockInMemory,
    a_web_auth_config,
    an_http_scope,
    session_cookie_header,
)
from webauth.config import WebAuthConfig, install_web_auth_config
from webauth.cookies import sign_session_id
from webauth.dependencies import admit_session
from webauth.oidc import OidcRelyingParty
from webauth.oidc_login import AdmittedLogin, fresh_access_token, log_out, open_session
from webauth.ports import AuthenticatedUser, SessionRecord

ACCOUNT = FakeUser()
LOGIN_ID_TOKEN = a_fake_id_token("issued-by-the-login")
LOGOUT_BUTTON_LABEL = "Sign out"


@dataclass
class Host:
    """The store, clock, issuer and relying party a host's routes share."""

    sessions: SessionRecordsInMemory
    lock: WriteLockInMemory
    clock: FakeClock
    config: WebAuthConfig
    issuer: FakeIssuer
    relying_party: OidcRelyingParty

    def open_session(self, *, keeps_id_token: bool) -> SessionRecord:
        return opened_session(
            self.config,
            AdmittedLogin(
                account=ACCOUNT, return_to=None,
                refresh_token=SecretStr(ISSUED_REFRESH_TOKEN), id_token=SecretStr(LOGIN_ID_TOKEN),
            ),
            sessions=self.sessions, lock=self.lock, keeps_id_token=keeps_id_token,
        )

    def log_out(self, session_id: str) -> LogoutPage:
        app = FastAPI()
        install_web_auth_config(app, self.config)
        headers = [(b"cookie", session_cookie_header(self.signed(session_id)).encode())]
        answer = log_out(
            self.relying_party, Request(an_http_scope(app, headers=headers)), self.config,
            sessions=self.sessions, lock=self.lock, button_label=LOGOUT_BUTTON_LABEL,
        )
        return LogoutPage(bytes(answer.body).decode())

    def signed(self, session_id: str) -> str:
        return sign_session_id(session_id, self.config.signing_key)


def a_host() -> Host:
    clock = FakeClock(FIXED_INSTANT.timestamp())
    config = a_web_auth_config(wall_clock=clock)
    lock = WriteLockInMemory()
    issuer = FakeIssuer(mint_id_token=a_fake_id_token)
    relying_party = a_relying_party(post_token_request=issuer, wall_clock=clock)
    sessions = SessionRecordsInMemory(users=UsersInMemory(ACCOUNT, lock=lock), lock=lock)
    return Host(sessions, lock, clock, config, issuer, relying_party)


def test_a_host_that_keeps_the_id_token_stores_it_and_the_logout_posts_it_as_the_hint() -> None:
    host = a_host()

    session = host.open_session(keeps_id_token=True)

    assert session.id_token == SecretStr(LOGIN_ID_TOKEN)
    assert host.log_out(session.id).hidden_fields.get("id_token_hint") == LOGIN_ID_TOKEN


def test_a_host_that_keeps_no_id_token_stores_the_refresh_token_and_no_id_token() -> None:
    host = a_host()

    session = host.open_session(keeps_id_token=False)

    assert (session.refresh_token, session.id_token) == (SecretStr(ISSUED_REFRESH_TOKEN), None)
    assert host.sessions.load(session.id) == session


def test_a_logout_after_a_host_kept_no_id_token_ends_the_session_and_posts_no_hint() -> None:
    host = a_host()
    session = host.open_session(keeps_id_token=False)

    page = host.log_out(session.id)

    assert (page.hidden_fields.get("id_token_hint"), host.sessions.load(session.id)) == (None, None)


def test_rotation_and_renewal_keep_no_id_token_for_a_host_that_keeps_none() -> None:
    host = a_host()
    session = host.open_session(keeps_id_token=False)
    expiry_before_renewal = session.expires_at
    host.issuer.refresh_answer_members = {"id_token": a_fake_id_token("issued-by-the-refresh")}
    host.clock.now += SESSION_IDLE_SECONDS / 2

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


def test_opening_a_session_without_stating_whether_the_host_keeps_the_id_token_raises() -> None:
    host = a_host()
    kept = host.open_session(keeps_id_token=True)
    app = FastAPI()
    install_web_auth_config(app, host.config)
    request = Request(an_http_scope(app))
    admitted = AdmittedLogin(
        account=ACCOUNT, return_to=None, refresh_token=None, id_token=SecretStr(LOGIN_ID_TOKEN),
    )

    with pytest.raises(TypeError, match="keeps_id_token"):
        open_session(  # type: ignore[call-arg]
            request, host.config, admitted,
            sessions=host.sessions, lock=host.lock, max_sessions=None,
        )

    assert [row.id for row in host.sessions.list_active()] == [kept.id]
