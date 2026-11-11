"""A recorded admission belongs to the request it was recorded for."""

from __future__ import annotations

from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from typing import Any

import pytest

from tests.support.account_arrangement import MEMBER_ROLE, FakeUser, UsersInMemory
from tests.support.gate_arrangement import (
    ADMITTED_ADMIN_PATH,
    ScopeRelay,
    relayed,
    with_admitted_admin_routes,
)
from tests.support.session_gate_arrangement import (
    ONLY_LOGIN_AND_HEALTH,
    a_gated_app,
    a_plain_app,
    ask,
    counted,
    signed_in,
)
from tests.support.session_store_arrangement import SessionsRecordingTheirTransaction
from tests.support.webauth_arrangement import (
    LOGIN_REDIRECT,
    AuthApp,
    a_session,
    an_auth_app,
    session_cookie_header,
)
from webauth.ports import AuthenticatedUser


class TestARecordedAdmissionBelongsToItsRequest:
    @dataclass
    class Arrangement:
        first: AuthApp
        first_relay: ScopeRelay
        gate_entries: dict[str, Any]
        users: UsersInMemory
        sessions: SessionsRecordingTheirTransaction
        second_cookie: str

    @pytest.fixture
    def arrangement(self) -> TestARecordedAdmissionBelongsToItsRequest.Arrangement:
        first_user, second_user = FakeUser("user-1", "alice"), FakeUser("user-2", "bruno")
        users = UsersInMemory(first_user, second_user)
        now = datetime.now(UTC)
        record = a_session(user=first_user, now=now)
        sessions = SessionsRecordingTheirTransaction(record, users=users)
        second = sessions.create(
            second_user.id,
            now=now,
            expires_at=now + timedelta(minutes=30),
            refresh_token=None,
            id_token=None,
            account_language=None,
        )
        first = a_gated_app(
            record,
            sessions=sessions,
            public=ONLY_LOGIN_AND_HEALTH,
        )
        relay = relayed(first)
        assert ask(first, "/me", cookie=signed_in(first)).json()["username"] == "alice"
        control = a_plain_app(a_session())
        control_relay = relayed(control)
        ask(control, "/me", cookie=signed_in(control))
        return self.Arrangement(
            first=first,
            first_relay=relay,
            gate_entries={
                key: value for key, value in relay.added.items() if key not in control_relay.added
            },
            users=users,
            sessions=sessions,
            second_cookie=session_cookie_header(first.signed_cookie(second.id)),
        )

    def test_a_replay_on_the_gated_app_is_decided_by_the_gate_itself(
        self,
        arrangement: Arrangement,
    ) -> None:
        assert arrangement.gate_entries
        arrangement.first_relay.replay = arrangement.gate_entries
        assert ask(arrangement.first, "/me").json() == {"detail": "Authentication required"}
        assert ask(arrangement.first, "/health").json() == {"username": None}

    @pytest.mark.parametrize("planted", ["replayed", "an-account-under-each-key"])
    def test_a_replay_on_an_app_with_its_own_config_is_ignored(
        self,
        arrangement: Arrangement,
        planted: str,
    ) -> None:
        other = with_admitted_admin_routes(an_auth_app(None, login_redirect=LOGIN_REDIRECT))
        relay = relayed(other)
        relay.replay = (
            arrangement.gate_entries
            if planted == "replayed"
            else {
                key: AuthenticatedUser(id="user-1", username="alice", role=MEMBER_ROLE, agent=None)
                for key in arrangement.gate_entries
            }
        )
        cookie = signed_in(arrangement.first)
        assert ask(other, "/me", cookie=cookie).json() == {"detail": "Session expired"}
        with pytest.raises(RuntimeError):
            ask(other, "/health", cookie=cookie)
        with pytest.raises(RuntimeError):
            ask(other, ADMITTED_ADMIN_PATH, cookie=cookie)

    def test_a_replay_on_a_shared_config_is_ignored_for_another_sessions_cookie(
        self,
        arrangement: Arrangement,
    ) -> None:
        shared = with_admitted_admin_routes(
            an_auth_app(
                None,
                sessions=arrangement.sessions,
                config=arrangement.first.config,
                login_redirect=LOGIN_REDIRECT,
            )
        )
        relay = relayed(shared)
        relay.replay = arrangement.gate_entries
        arrangement.sessions.events.clear()
        answer = ask(shared, "/me", cookie=arrangement.second_cookie)
        assert answer.json()["username"] == "bruno"
        assert (
            counted(arrangement.sessions, "load"),
            counted(arrangement.sessions, "touch"),
        ) == (1, 1)
        assert ask(shared, "/me").json() == {"detail": "Authentication required"}
        with pytest.raises(RuntimeError):
            ask(shared, "/health", cookie=arrangement.second_cookie)
        with pytest.raises(RuntimeError):
            ask(shared, ADMITTED_ADMIN_PATH, cookie=arrangement.second_cookie)
        with pytest.raises(RuntimeError):
            ask(shared, "/health")

    def test_a_replay_for_the_same_cookie_is_reused_without_a_store_read(
        self,
        arrangement: Arrangement,
    ) -> None:
        shared = an_auth_app(
            None,
            sessions=arrangement.sessions,
            config=arrangement.first.config,
            login_redirect=LOGIN_REDIRECT,
        )
        relay = relayed(shared)
        relay.replay = arrangement.gate_entries
        arrangement.sessions.events.clear()
        cookie = signed_in(arrangement.first)
        assert ask(shared, "/me", cookie=cookie).json()["username"] == "alice"
        assert ask(shared, "/health", cookie=cookie).json() == {"username": "alice"}
        assert (
            counted(arrangement.sessions, "load"),
            counted(arrangement.sessions, "touch"),
        ) == (0, 0)
