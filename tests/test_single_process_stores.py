"""The in-process stores: the ports' duties, the transaction, and the sign-in routes over them."""

from __future__ import annotations

import dataclasses
import re
import threading
import urllib.parse
from collections.abc import Callable
from datetime import UTC, datetime, timedelta
from itertools import chain

import pytest
from fastapi import Depends, FastAPI
from fastapi.testclient import TestClient
from pydantic import SecretStr

from tests.support.oidc_arrangement import (
    FakeClock,
    FakeIssuer,
    a_key_set_endpoint,
    a_logout_token,
    a_relying_party,
)
from tests.support.oidc_login_host import (
    ADMISSION,
    BACKCHANNEL_LOGOUT_PATH,
    BOUND_ISSUER,
    CALLBACK_PATH,
    CLIENT_ID,
    LOGIN_GROUP,
    NOW,
    SAME_ORIGIN_FORM,
    SIGN_IN_PATHS,
    START_PATH,
    SUBJECT,
    StoreDown,
    a_client_config,
    an_id_token,
    failing,
)
from tests.support.webauth_arrangement import (
    HTTPS_TEST_SERVER,
    RecordingAuditSink,
    a_web_auth_config,
)
from webauth.config import install_web_auth_config
from webauth.dependencies import current_user_dependency
from webauth.middleware import install_web_auth_middleware
from webauth.policies import BodySizePolicy, CsrfPolicy, SecurityHeadersPolicy
from webauth.ports import (
    AccountEvent,
    AccountEventKind,
    AccountKind,
    AuthenticatedUser,
    SessionRecord,
    UserRecord,
)
from webauth.sign_in_routes import LogoutPageText, install_sign_in_routes
from webauth.single_process_stores import (
    SingleProcessAccountStore,
    SingleProcessSessionStore,
    SingleProcessSignInTransaction,
    SingleProcessStores,
)

START = datetime(2026, 1, 1, tzinfo=UTC)
LATER = START + timedelta(hours=1)
SUBJECT_ONE = "subject-one"
SUBJECT_TWO = "subject-two"
SESSION_ID_PATTERN = re.compile(r"[A-Za-z0-9_-]{43,135}")


def an_event(subject: str = SUBJECT_ONE) -> AccountEvent:
    return AccountEvent(kind=AccountEventKind.USER_CREATED, actor_id=None, subject_id=subject)


@pytest.fixture
def audit() -> RecordingAuditSink:
    return RecordingAuditSink()


@pytest.fixture
def stores(audit: RecordingAuditSink) -> SingleProcessStores:
    return SingleProcessStores(audit=audit)


def with_account(stores: SingleProcessStores, subject: str = SUBJECT_ONE) -> None:
    stores.accounts.create_for_subject(subject, "name", "member", AccountKind.PERSON)


def open_session(
    stores: SingleProcessStores,
    subject: str = SUBJECT_ONE,
    *,
    now: datetime = START,
    expires_at: datetime = LATER,
    refresh_token: str | None = "refresh",
    id_token: str | None = "identity",
) -> str:
    return stores.sessions.create(
        subject,
        now=now,
        expires_at=expires_at,
        refresh_token=None if refresh_token is None else SecretStr(refresh_token),
        id_token=None if id_token is None else SecretStr(id_token),
    ).id


def held_ids(stores: SingleProcessStores, ids: list[str]) -> list[str]:
    return [session_id for session_id in ids if stores.sessions.load(session_id) is not None]


class TestTheBundle:
    def test_the_bundle_shares_one_set_of_tables(self, stores: SingleProcessStores) -> None:
        """MEMSTORE-02: accounts, sessions and the transaction work over one set of tables."""
        with stores.transaction() as inside:
            inside.accounts.create_for_subject(SUBJECT_ONE, "name", "member", AccountKind.PERSON)
            session_id = inside.sessions.create(
                SUBJECT_ONE, now=START, expires_at=LATER, refresh_token=None, id_token=None
            ).id

        loaded = stores.sessions.load(session_id)
        assert loaded is not None
        assert loaded.user == stores.accounts.get(SUBJECT_ONE)

    def test_the_records_implement_the_ports_records(self, stores: SingleProcessStores) -> None:
        """MEMSTORE-21: the stored records are the ports' user and session records."""
        with_account(stores)
        account: UserRecord | None = stores.accounts.get(SUBJECT_ONE)
        session: SessionRecord | None = stores.sessions.load(open_session(stores))

        assert account is not None
        assert session is not None
        assert session.user.id == account.id


class TestAccounts:
    @pytest.mark.parametrize(
        "asked",
        ["SUBJECT-\u00e9", "subject-\u00e9 ", "subject-e\u0301"],
        ids=["case", "trailing-space", "decomposed-unicode"],
    )
    def test_get_matches_the_subject_exactly(self, stores: SingleProcessStores, asked: str) -> None:
        """MEMSTORE-04: get compares the subject character for character."""
        stores.accounts.create_for_subject("subject-\u00e9", "name", "member", AccountKind.PERSON)

        assert stores.accounts.get(asked) is None
        assert stores.accounts.get("subject-\u00e9") is not None

    @pytest.mark.parametrize(
        "call",
        [
            lambda stores: stores.accounts.set_role("absent", "admin"),
            lambda stores: stores.accounts.set_kind("absent", AccountKind.AGENT),
            lambda stores: open_session(stores, "absent"),
        ],
        ids=["set_role", "set_kind", "create-session"],
    )
    def test_a_write_on_a_missing_account_raises(
        self, stores: SingleProcessStores, call: Callable[[SingleProcessStores], object]
    ) -> None:
        """MEMSTORE-05: a write on a missing account raises."""
        with pytest.raises(KeyError):
            call(stores)

        assert stores.accounts.get("absent") is None

    def test_set_role_and_set_kind_change_only_their_field(
        self, stores: SingleProcessStores
    ) -> None:
        """MEMSTORE-05: set_role and set_kind return the changed account."""
        with_account(stores)

        stores.accounts.set_role(SUBJECT_ONE, "admin")
        account = stores.accounts.set_kind(SUBJECT_ONE, AccountKind.AGENT)

        assert (account.id, account.username, account.role, account.kind) == (
            SUBJECT_ONE,
            "name",
            "admin",
            AccountKind.AGENT,
        )
        assert stores.accounts.get(SUBJECT_ONE) == account

    def test_a_second_subject_with_a_taken_username_keeps_both_accounts(
        self, stores: SingleProcessStores
    ) -> None:
        """MEMSTORE-11: a taken username never raises."""
        first = stores.accounts.create_for_subject(
            SUBJECT_ONE, "same", "member", AccountKind.PERSON
        )
        second = stores.accounts.create_for_subject(
            SUBJECT_TWO, "same", "member", AccountKind.PERSON
        )

        assert (stores.accounts.get(SUBJECT_ONE), stores.accounts.get(SUBJECT_TWO)) == (
            first,
            second,
        )


class TestSessions:
    def test_session_ids_are_distinct_url_safe_and_long_enough(
        self, stores: SingleProcessStores
    ) -> None:
        """MEMSTORE-03: a session id is distinct, URL-safe and 43 to 135 characters."""
        with_account(stores)

        ids = [open_session(stores) for _ in range(200)]

        assert len(set(ids)) == 200
        assert all(SESSION_ID_PATTERN.fullmatch(session_id) for session_id in ids)

    @pytest.mark.parametrize(
        "write",
        [
            lambda stores, session_id: stores.sessions.touch(session_id, expires_at=LATER),
            lambda stores, session_id: stores.sessions.replace_refresh_token(
                session_id, refresh_token=SecretStr("new")
            ),
        ],
        ids=["touch", "replace_refresh_token"],
    )
    def test_a_write_on_a_missing_session_answers_false_and_creates_no_row(
        self,
        stores: SingleProcessStores,
        write: Callable[[SingleProcessStores, str], object],
    ) -> None:
        """MEMSTORE-06: touch and replace_refresh_token on a missing row answer False."""
        assert write(stores, "absent") is False
        assert stores.sessions.load("absent") is None

    def test_touch_writes_the_given_expiry_and_keeps_both_tokens(
        self, stores: SingleProcessStores
    ) -> None:
        """MEMSTORE-07: touch writes the given expiry and keeps both tokens."""
        with_account(stores)
        session_id = open_session(stores)
        renewed = LATER + timedelta(days=1)

        assert stores.sessions.touch(session_id, expires_at=renewed) is True

        session = stores.sessions.load(session_id)
        assert session is not None
        assert session.expires_at == renewed
        assert session.refresh_token == SecretStr("refresh")
        assert session.id_token == SecretStr("identity")

    def test_replacing_the_refresh_token_keeps_the_id_token(
        self, stores: SingleProcessStores
    ) -> None:
        """MEMSTORE-07: replace_refresh_token keeps the ID token."""
        with_account(stores)
        session_id = open_session(stores)

        assert (
            stores.sessions.replace_refresh_token(session_id, refresh_token=SecretStr("rotated"))
            is True
        )

        session = stores.sessions.load(session_id)
        assert session is not None
        assert session.refresh_token == SecretStr("rotated")
        assert session.id_token == SecretStr("identity")

    def test_deleting_an_unknown_id_changes_nothing(self, stores: SingleProcessStores) -> None:
        """MEMSTORE-08: delete of an unknown id is a no-op."""
        with_account(stores)
        session_id = open_session(stores)

        stores.sessions.delete("absent")

        assert stores.sessions.load(session_id) is not None

    @pytest.mark.parametrize("keep_newest", [0, 1, 2, 5])
    def test_prune_overflow_keeps_the_newest_by_creation(
        self, stores: SingleProcessStores, keep_newest: int
    ) -> None:
        """MEMSTORE-09: prune_overflow keeps the newest N by creation."""
        with_account(stores)
        with_account(stores, SUBJECT_TWO)
        created = [
            open_session(
                stores, now=START + timedelta(minutes=minute), expires_at=LATER + timedelta(days=1)
            )
            for minute in (3, 1, 4, 2)
        ]
        other = open_session(stores, SUBJECT_TWO, expires_at=LATER + timedelta(days=1))
        newest_first = [created[2], created[0], created[3], created[1]]

        stores.sessions.prune_overflow(SUBJECT_ONE, keep_newest)

        assert held_ids(stores, newest_first) == newest_first[:keep_newest]
        assert stores.sessions.load(other) is not None

    def test_delete_for_user_ends_every_session_counts_them_and_removes_the_account(
        self, stores: SingleProcessStores
    ) -> None:
        """MEMSTORE-10: delete_for_user ends every session, counts them and removes the account."""
        with_account(stores)
        with_account(stores, SUBJECT_TWO)
        mine = [open_session(stores) for _ in range(3)]
        theirs = open_session(stores, SUBJECT_TWO)

        assert stores.sessions.delete_for_user(SUBJECT_ONE) == 3

        assert held_ids(stores, mine) == []
        assert stores.accounts.get(SUBJECT_ONE) is None
        assert stores.sessions.load(theirs) is not None

    def test_delete_for_user_without_sessions_still_removes_the_account(
        self, stores: SingleProcessStores
    ) -> None:
        """MEMSTORE-10: delete_for_user removes the account when no session is left."""
        with_account(stores)

        assert stores.sessions.delete_for_user(SUBJECT_ONE) == 0
        assert stores.accounts.get(SUBJECT_ONE) is None

    def test_load_returns_an_expired_row(self, stores: SingleProcessStores) -> None:
        """MEMSTORE-12: load returns an expired row."""
        with_account(stores)
        session_id = open_session(stores, expires_at=START)

        session = stores.sessions.load(session_id)

        assert session is not None
        assert session.expires_at == START

    def test_delete_expired_removes_the_expired_rows_and_counts_them(
        self, stores: SingleProcessStores
    ) -> None:
        """MEMSTORE-13: delete_expired removes the expired rows and counts them."""
        with_account(stores)
        expired = [open_session(stores, expires_at=START + timedelta(seconds=n)) for n in (1, 2)]
        alive = open_session(stores, expires_at=LATER)

        assert stores.sessions.delete_expired(START + timedelta(minutes=1)) == 2

        assert held_ids(stores, expired) == []
        assert stores.sessions.load(alive) is not None

    def test_create_drops_the_rows_expired_at_its_time(self, stores: SingleProcessStores) -> None:
        """MEMSTORE-13: create prunes the rows expired at its time."""
        with_account(stores)
        expired = open_session(stores, expires_at=START + timedelta(seconds=1))

        open_session(stores, now=START + timedelta(minutes=1))

        assert stores.sessions.load(expired) is None

    def test_calls_from_several_threads_leave_a_consistent_store(
        self, stores: SingleProcessStores
    ) -> None:
        """MEMSTORE-15: calls from several threads leave a consistent store."""
        with_account(stores)
        ids_by_thread: list[list[str]] = [[] for _ in range(8)]

        def work(ids: list[str]) -> None:
            for _ in range(100):
                session_id = open_session(stores)
                stores.sessions.touch(session_id, expires_at=LATER + timedelta(days=1))
                ids.append(session_id)

        threads = [threading.Thread(target=work, args=(ids,)) for ids in ids_by_thread]
        for thread in threads:
            thread.start()
        for thread in threads:
            thread.join()

        every_id = list(chain.from_iterable(ids_by_thread))
        assert len(set(every_id)) == 800
        assert held_ids(stores, every_id) == every_id
        assert len(stores.sessions.records_of(SUBJECT_ONE).sessions) == 800


class TestRecordsOf:
    def test_records_carry_the_times_and_no_session_id_or_token(
        self, stores: SingleProcessStores
    ) -> None:
        """MEMSTORE-19: records_of carries no session id and no token."""
        with_account(stores)
        session_id = open_session(
            stores, refresh_token="secret-refresh", id_token="secret-identity"
        )
        open_session(stores, now=START + timedelta(minutes=1), refresh_token=None, id_token=None)

        records = stores.sessions.records_of(SUBJECT_ONE)

        assert [
            (times.started_at, times.holds_refresh_token, times.holds_id_token)
            for times in records.sessions
        ] == [(START, True, True), (START + timedelta(minutes=1), False, False)]
        shown = repr(records) + repr(dataclasses.astuple(records))
        for secret in (session_id, "secret-refresh", "secret-identity"):
            assert secret not in shown

    def test_records_of_an_unknown_subject_are_empty(self, stores: SingleProcessStores) -> None:
        """MEMSTORE-19: records_of an unknown subject holds nothing."""
        records = stores.sessions.records_of("absent")

        assert (records.account, records.sessions) == (None, ())


class TestSignInTransaction:
    def test_a_block_that_raises_restores_both_stores_and_drops_its_audit(
        self, stores: SingleProcessStores, audit: RecordingAuditSink
    ) -> None:
        """MEMSTORE-16: a raise inside an entry restores both stores and drops its audit."""
        with_account(stores)
        kept = open_session(stores)

        def a_block_that_raises() -> None:
            with stores.transaction() as inside:
                inside.accounts.create_for_subject(
                    SUBJECT_TWO, "name", "member", AccountKind.PERSON
                )
                inside.accounts.set_role(SUBJECT_ONE, "admin")
                inside.sessions.delete(kept)
                inside.audit.account_event(an_event())
                raise RuntimeError("boom")

        with pytest.raises(RuntimeError, match="boom"):
            a_block_that_raises()

        account = stores.accounts.get(SUBJECT_ONE)
        assert account is not None
        assert account.role == "member"
        assert stores.accounts.get(SUBJECT_TWO) is None
        assert stores.sessions.load(kept) is not None
        assert audit.account_events == []

    def test_a_clean_block_keeps_its_writes_and_reports_its_events_at_the_exit(
        self, stores: SingleProcessStores, audit: RecordingAuditSink
    ) -> None:
        """MEMSTORE-16: a clean entry keeps its writes and reports its events at the exit."""
        with stores.transaction() as inside:
            inside.accounts.create_for_subject(SUBJECT_ONE, "name", "member", AccountKind.PERSON)
            inside.audit.account_event(an_event())
            assert audit.account_events == []

        assert stores.accounts.get(SUBJECT_ONE) is not None
        assert audit.account_events == [an_event()]

    def test_a_failing_sink_at_the_exit_rolls_the_entry_back(
        self,
        stores: SingleProcessStores,
        audit: RecordingAuditSink,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        """MEMSTORE-17: a failing audit sink at the exit rolls the entry back."""
        failing(audit, "account_event", monkeypatch)

        def an_entry_whose_sink_fails() -> None:
            with stores.transaction() as inside:
                inside.accounts.create_for_subject(
                    SUBJECT_ONE, "name", "member", AccountKind.PERSON
                )
                inside.audit.account_event(an_event())

        with pytest.raises(StoreDown):
            an_entry_whose_sink_fails()

        assert stores.accounts.get(SUBJECT_ONE) is None

    def test_a_transaction_over_a_session_store_restores_that_stores_sessions(
        self, audit: RecordingAuditSink
    ) -> None:
        """MEMSTORE-16: the transaction restores the tables of the session store it is built on."""
        accounts = SingleProcessAccountStore()
        sessions = SingleProcessSessionStore(accounts)
        transaction = SingleProcessSignInTransaction(sessions, audit=audit)
        accounts.create_for_subject(SUBJECT_ONE, "name", "member", AccountKind.PERSON)

        def a_block_that_raises() -> None:
            with transaction() as inside:
                inside.sessions.create(
                    SUBJECT_ONE,
                    now=START,
                    expires_at=LATER,
                    refresh_token=None,
                    id_token=None,
                )
                raise RuntimeError("boom")

        with pytest.raises(RuntimeError, match="boom"):
            a_block_that_raises()

        assert sessions.records_of(SUBJECT_ONE).sessions == ()

    def test_an_entry_cannot_be_entered_twice(self, stores: SingleProcessStores) -> None:
        """MEMSTORE-18: re-entering an entry raises."""
        entry = stores.transaction()
        with entry:
            pass

        with pytest.raises(RuntimeError, match="entered once"), entry:
            pass

    def test_a_second_entry_waits_until_the_first_has_exited(
        self, stores: SingleProcessStores
    ) -> None:
        """MEMSTORE-14: a second entry waits until the first exits."""
        order: list[str] = []
        second_asking = threading.Event()

        def second() -> None:
            second_asking.set()
            with stores.transaction():
                order.append("second entered")

        thread = threading.Thread(target=second)
        with stores.transaction():
            thread.start()
            second_asking.wait()
            order.append("first leaving")
        thread.join()

        assert order == ["first leaving", "second entered"]


class Browser:
    """A host over the stores, with the sign-in routes, the gate and a fake issuer."""

    def __init__(self, stores: SingleProcessStores) -> None:
        self.stores = stores
        self.config = a_web_auth_config()
        clock = FakeClock(float(NOW))
        self.issuer = FakeIssuer(
            mint_id_token=lambda nonce: an_id_token(nonce, clock, (LOGIN_GROUP,))
        )
        relying_party = a_relying_party(
            config=a_client_config(),
            post_token_request=self.issuer,
            fetch_key_set=a_key_set_endpoint("issuer"),
            wall_clock=clock,
        )
        app = FastAPI()
        install_web_auth_config(app, self.config)
        install_web_auth_middleware(
            app,
            security_headers=SecurityHeadersPolicy(
                content_security_policy="default-src 'self'",
                cache_control_rules=(SIGN_IN_PATHS.cache_control_rule,),
            ),
            body_size=BodySizePolicy(
                default_max_bytes=1024, rules=(SIGN_IN_PATHS.backchannel_body_size_rule,)
            ),
            csrf_origin=CsrfPolicy(exempt=SIGN_IN_PATHS.backchannel),
        )
        install_sign_in_routes(
            app,
            paths=SIGN_IN_PATHS,
            relying_party=lambda _request: relying_party,
            admission=ADMISSION,
            transaction=stores.transaction,
            refused=lambda _request, _refusal: pytest.fail("the sign-in was refused"),
            keeps_id_token=True,
            max_sessions=None,
            logout_page_text=lambda _request: LogoutPageText(language="en", button_label="Out"),
            backchannel_dependencies=(),
        )
        dependencies = current_user_dependency(
            session_store=lambda: stores.sessions, on_authenticated=lambda _user: None
        )

        @app.get("/me")
        def me(user: AuthenticatedUser = Depends(dependencies.current_user)) -> dict[str, str]:
            return {"username": user.username}

        self.client = TestClient(
            app,
            base_url=HTTPS_TEST_SERVER,
            follow_redirects=False,
            raise_server_exceptions=False,
        )

    def sign_in(self) -> int:
        start = self.client.get(START_PATH).headers["location"]
        return self.client.get(f"{CALLBACK_PATH}?{self.issuer.authorize(start)}").status_code

    def logout(self) -> int:
        return self.client.post("/logout", headers=SAME_ORIGIN_FORM).status_code

    def issuer_logs_out(self) -> int:
        token = a_logout_token(
            issuer=BOUND_ISSUER,
            audience=CLIENT_ID,
            subject=SUBJECT,
            now=NOW,
            key_id="issuer-key",
            key_name="issuer",
        )
        return self.client.post(
            BACKCHANNEL_LOGOUT_PATH,
            content=urllib.parse.urlencode({"logout_token": token}).encode(),
            headers={"content-type": "application/x-www-form-urlencoded"},
        ).status_code

    def gate_status(self) -> int:
        return self.client.get("/me").status_code


class TestSignInRoutesOverTheStores:
    def test_the_callback_opens_a_session_the_gate_admits(
        self, stores: SingleProcessStores, audit: RecordingAuditSink
    ) -> None:
        """MEMSTORE-22: the callback opens a session the gate admits."""
        browser = Browser(stores)

        assert browser.sign_in() == 303

        assert browser.gate_status() == 200
        assert [event.kind for event in audit.account_events] == [AccountEventKind.USER_CREATED]
        assert stores.sessions.records_of(SUBJECT).sessions[0].holds_id_token is True

    def test_logout_ends_the_session_the_gate_then_refuses(
        self, stores: SingleProcessStores
    ) -> None:
        """MEMSTORE-22: logout ends the session."""
        browser = Browser(stores)
        browser.sign_in()

        assert browser.logout() == 200

        assert browser.gate_status() == 401
        assert stores.sessions.records_of(SUBJECT).sessions == ()

    def test_back_channel_logout_ends_every_session_and_the_next_sign_in_creates_the_account_again(
        self, stores: SingleProcessStores, audit: RecordingAuditSink
    ) -> None:
        """MEMSTORE-22: back-channel logout ends every session and the account."""
        browser = Browser(stores)
        browser.sign_in()

        assert browser.issuer_logs_out() == 200

        assert browser.gate_status() == 401
        assert stores.accounts.get(SUBJECT) is None
        assert browser.sign_in() == 303
        assert browser.gate_status() == 200
        created = [e for e in audit.account_events if e.kind is AccountEventKind.USER_CREATED]
        assert len(created) == 2
