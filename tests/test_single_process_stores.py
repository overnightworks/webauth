"""The in-process stores: the ports' duties, the transaction, and the sign-in routes over them."""

from __future__ import annotations

import dataclasses
import threading
import urllib.parse
import uuid
from collections.abc import Callable
from contextlib import nullcontext
from datetime import UTC, datetime, timedelta
from itertools import chain

import pytest
from fastapi import Depends, FastAPI
from fastapi.testclient import TestClient
from pydantic import SecretStr

from tests.support.gated_stack_arrangement import install_the_gated_stack
from tests.support.oidc_arrangement import (
    FakeClock,
    FakeIssuer,
    a_key_set_endpoint,
    a_logout_token,
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
from webauth.dependencies import current_user
from webauth.policies import BodySizePolicy
from webauth.ports import (
    AccountEvent,
    AccountEventKind,
    AccountKind,
    AuthenticatedUser,
    SessionRecord,
    UserRecord,
)
from webauth.sign_in_routes import LogoutPageText
from webauth.single_process_stores import (
    SingleProcessAccountStore,
    SingleProcessSessionStore,
    SingleProcessSignInTransaction,
    SingleProcessStores,
    _Tables,
)
from webauth.web_auth import IssuerCalls, SignInPages

START = datetime(2026, 1, 1, tzinfo=UTC)
LATER = START + timedelta(hours=1)
SUBJECT_ONE = "subject-one"
SUBJECT_TWO = "subject-two"


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
    account_language: str | None = None,
    session_id: str | None = None,
) -> str:
    return stores.sessions.create(
        subject,
        session_id=session_id or f"session-{uuid.uuid4().hex}",
        now=now,
        expires_at=expires_at,
        refresh_token=None if refresh_token is None else SecretStr(refresh_token),
        id_token=None if id_token is None else SecretStr(id_token),
        account_language=account_language,
    ).id


def held_ids(stores: SingleProcessStores, ids: list[str]) -> list[str]:
    return [session_id for session_id in ids if stores.sessions.load(session_id) is not None]


class TestTheBundle:
    def test_the_bundle_shares_one_set_of_tables(self, stores: SingleProcessStores) -> None:
        """MEMSTORE-01: accounts, sessions and the transaction work over one set of tables."""
        with stores.transaction() as inside:
            inside.accounts.create_for_subject(SUBJECT_ONE, "name", "member", AccountKind.PERSON)
            session_id = inside.sessions.create(
                SUBJECT_ONE,
                session_id="given",
                now=START,
                expires_at=LATER,
                refresh_token=None,
                id_token=None,
                account_language=None,
            ).id

        loaded = stores.sessions.load(session_id)
        assert loaded is not None
        assert loaded.user == stores.accounts.get(SUBJECT_ONE)

    def test_the_records_implement_the_ports_records(self, stores: SingleProcessStores) -> None:
        """MEMSTORE-19: the stored records are the ports' user and session records."""
        with_account(stores)
        account: UserRecord | None = stores.accounts.get(SUBJECT_ONE)
        session: SessionRecord | None = stores.sessions.load(open_session(stores))

        assert account is not None
        assert session is not None
        assert session.user.id == account.id


class TestAccounts:
    def test_set_role_and_set_kind_change_only_their_field(
        self, stores: SingleProcessStores
    ) -> None:
        """MEMSTORE-04: set_role and set_kind return the changed account."""
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
        """MEMSTORE-10: a taken username never raises."""
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
    @pytest.mark.parametrize(
        "second_now",
        [START, START + timedelta(hours=2)],
        ids=["while the stored session lives", "after the stored session expired"],
    )
    def test_create_with_a_stored_id_raises_and_keeps_the_stored_session(
        self, stores: SingleProcessStores, second_now: datetime
    ) -> None:
        """MEMSTORE-22: create with an id already stored raises and never overwrites its row."""
        with_account(stores)
        open_session(stores, session_id="taken", refresh_token="first", expires_at=LATER)

        with pytest.raises(ValueError, match="already stored"):
            open_session(stores, session_id="taken", refresh_token="second", now=second_now)

        kept = stores.sessions.load("taken")
        assert kept is not None
        assert kept.refresh_token == SecretStr("first")

    def test_touch_writes_the_given_expiry_and_keeps_both_tokens(
        self, stores: SingleProcessStores
    ) -> None:
        """MEMSTORE-06: touch writes the given expiry and keeps both tokens."""
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
        """MEMSTORE-06: replace_refresh_token keeps the ID token."""
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
        """MEMSTORE-07: delete of an unknown id is a no-op."""
        with_account(stores)
        session_id = open_session(stores)

        stores.sessions.delete("absent")

        assert stores.sessions.load(session_id) is not None

    def test_delete_for_user_ends_every_session_counts_them_and_keeps_the_account(
        self, stores: SingleProcessStores
    ) -> None:
        """MEMSTORE-09: delete_for_user ends every session, counts them and keeps the account."""
        with_account(stores)
        with_account(stores, SUBJECT_TWO)
        mine = [open_session(stores) for _ in range(3)]
        theirs = open_session(stores, SUBJECT_TWO)

        assert stores.sessions.delete_for_user(SUBJECT_ONE) == 3

        assert held_ids(stores, mine) == []
        assert stores.accounts.get(SUBJECT_ONE) is not None
        assert stores.sessions.load(theirs) is not None

    def test_delete_for_user_without_sessions_still_keeps_the_account(
        self, stores: SingleProcessStores
    ) -> None:
        """MEMSTORE-09: delete_for_user keeps the account when no session is left."""
        with_account(stores)

        assert stores.sessions.delete_for_user(SUBJECT_ONE) == 0
        assert stores.accounts.get(SUBJECT_ONE) is not None

    def test_load_returns_an_expired_row(self, stores: SingleProcessStores) -> None:
        """MEMSTORE-11: load returns an expired row."""
        with_account(stores)
        session_id = open_session(stores, expires_at=START)

        session = stores.sessions.load(session_id)

        assert session is not None
        assert session.expires_at == START

    def test_delete_expired_removes_the_expired_rows_and_counts_them(
        self, stores: SingleProcessStores
    ) -> None:
        """MEMSTORE-12: delete_expired removes the expired rows and counts them."""
        with_account(stores)
        expired = [open_session(stores, expires_at=START + timedelta(seconds=n)) for n in (1, 2)]
        alive = open_session(stores, expires_at=LATER)
        now = START + timedelta(minutes=1)
        due_now = open_session(stores, expires_at=now)

        assert stores.sessions.delete_expired(now) == 2

        assert held_ids(stores, expired) == []
        assert stores.sessions.load(alive) is not None
        assert stores.sessions.load(due_now) is not None

    def test_a_row_expiring_within_the_current_second_survives_the_sweep(
        self, stores: SingleProcessStores
    ) -> None:
        """MEMSTORE-12: the sweep reads its time in whole seconds, as the session gate does."""
        with_account(stores)
        session_id = open_session(stores, expires_at=START)

        assert stores.sessions.delete_expired(START + timedelta(milliseconds=500)) == 0

        assert stores.sessions.load(session_id) is not None

    def test_create_drops_the_rows_expired_at_its_time(self, stores: SingleProcessStores) -> None:
        """MEMSTORE-12: create prunes the rows expired at its time."""
        with_account(stores)
        expired = open_session(stores, expires_at=START + timedelta(seconds=1))

        open_session(stores, now=START + timedelta(minutes=1))

        assert stores.sessions.load(expired) is None

    def test_calls_from_several_threads_leave_a_consistent_store(
        self, stores: SingleProcessStores
    ) -> None:
        """MEMSTORE-14: calls from several threads leave a consistent store."""
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

    @pytest.mark.parametrize("account_language", ["de-CH", None])
    def test_a_session_keeps_the_account_language_it_was_created_with(
        self, stores: SingleProcessStores, account_language: str | None
    ) -> None:
        """MEMSTORE-21: create stores the account's language and load returns it."""
        with_account(stores)

        loaded = stores.sessions.load(open_session(stores, account_language=account_language))

        assert loaded is not None
        assert loaded.account_language == account_language


class TestRecordsOf:
    def test_records_carry_the_times_and_no_session_id_or_token(
        self, stores: SingleProcessStores
    ) -> None:
        """MEMSTORE-18: records_of carries no session id and no token."""
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
        """MEMSTORE-18: records_of an unknown subject holds nothing."""
        records = stores.sessions.records_of("absent")

        assert (records.account, records.sessions) == (None, ())


def enter_and_leave(stores: SingleProcessStores) -> None:
    with stores.transaction():
        pass


class TestSignInTransaction:
    @pytest.mark.parametrize("raised", [RuntimeError, KeyboardInterrupt])
    def test_a_block_that_raises_restores_both_stores_and_drops_its_audit(
        self, stores: SingleProcessStores, audit: RecordingAuditSink, raised: type[BaseException]
    ) -> None:
        """MEMSTORE-15: a raise inside an entry restores both stores and drops its audit."""
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
                raise raised("boom")

        with pytest.raises(raised, match="boom"):
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
        """MEMSTORE-15: a clean entry keeps its writes and reports its events at the exit."""
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
        """MEMSTORE-16: a failing audit sink at the exit rolls the entry back."""
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
        """MEMSTORE-15: the transaction restores the tables of the session store it is built on."""
        accounts = SingleProcessAccountStore()
        sessions = SingleProcessSessionStore(accounts)
        transaction = SingleProcessSignInTransaction(sessions, audit=audit)
        accounts.create_for_subject(SUBJECT_ONE, "name", "member", AccountKind.PERSON)

        def a_block_that_raises() -> None:
            with transaction() as inside:
                inside.sessions.create(
                    SUBJECT_ONE,
                    session_id="given",
                    now=START,
                    expires_at=LATER,
                    refresh_token=None,
                    id_token=None,
                    account_language=None,
                )
                raise RuntimeError("boom")

        with pytest.raises(RuntimeError, match="boom"):
            a_block_that_raises()

        assert sessions.records_of(SUBJECT_ONE).sessions == ()

    def test_an_entry_cannot_be_entered_twice(self, stores: SingleProcessStores) -> None:
        """MEMSTORE-17: re-entering an entry raises."""
        entry = stores.transaction()
        with entry:
            pass

        with pytest.raises(RuntimeError, match="entered once"), entry:
            pass

    @pytest.mark.parametrize(
        "second_call",
        [
            enter_and_leave,
            lambda stores: stores.accounts.get(SUBJECT_ONE),
            lambda stores: stores.sessions.load("unknown"),
            lambda stores: open_session(stores),
        ],
        ids=["entry", "accounts.get", "sessions.load", "sessions.create"],
    )
    def test_a_second_caller_waits_until_the_first_entry_has_exited(
        self, stores: SingleProcessStores, second_call: Callable[[SingleProcessStores], object]
    ) -> None:
        """MEMSTORE-13: a second entry or a plain store call waits until the first entry exits."""
        with_account(stores)
        finished = threading.Event()

        def second() -> None:
            second_call(stores)
            finished.set()

        thread = threading.Thread(target=second, daemon=True)
        with stores.transaction():
            thread.start()
            finished_while_open = finished.wait(timeout=0.3)

        thread.join(timeout=10)

        assert not finished_while_open
        assert finished.is_set()

    def test_a_failed_enter_gives_the_guard_back(
        self, stores: SingleProcessStores, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """MEMSTORE-13: an entry whose snapshot fails does not keep the guard."""
        failing(_Tables, "snapshot", monkeypatch)
        with pytest.raises(StoreDown), stores.transaction():
            pass
        monkeypatch.undo()
        finished = threading.Event()

        def another_thread() -> None:
            stores.accounts.get(SUBJECT_ONE)
            finished.set()

        thread = threading.Thread(target=another_thread, daemon=True)
        thread.start()
        thread.join(timeout=10)

        assert not thread.is_alive()
        assert finished.is_set()


class Browser:
    """A host over the stores, with the sign-in routes, the gate and a fake issuer."""

    def __init__(self, stores: SingleProcessStores) -> None:
        self.stores = stores
        self.config = a_web_auth_config()
        clock = FakeClock(float(NOW))
        self.issuer = FakeIssuer(
            mint_id_token=lambda nonce: an_id_token(nonce, clock, (LOGIN_GROUP,))
        )
        app = FastAPI()

        @app.get("/me")
        def me(user: AuthenticatedUser = Depends(current_user)) -> dict[str, str]:
            return {"username": user.username}

        install_the_gated_stack(
            app,
            config=dataclasses.replace(self.config, wall_clock=clock),
            sessions=lambda: nullcontext(stores.sessions),
            sign_in=stores.transaction,
            sign_in_paths=SIGN_IN_PATHS,
            keeps_id_token=True,
            client=a_client_config(),
            groups=ADMISSION,
            pages=SignInPages(
                refused=lambda _request, _refusal: pytest.fail("the sign-in was refused"),
                logout_page_text=lambda _request: LogoutPageText(language="en", button_label="Out"),
                ui_language=lambda _request: None,
            ),
            body_size=BodySizePolicy(default_max_bytes=1024),
            issuer_calls=IssuerCalls(
                post_token_request=self.issuer,
                fetch_key_set=a_key_set_endpoint("issuer"),
                monotonic_clock=FakeClock(5_000.0),
            ),
        )
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
        """MEMSTORE-20: the callback opens a session the gate admits."""
        browser = Browser(stores)

        assert browser.sign_in() == 303

        assert browser.gate_status() == 200
        assert [event.kind for event in audit.account_events] == [AccountEventKind.USER_CREATED]
        assert stores.sessions.records_of(SUBJECT).sessions[0].holds_id_token is True

    def test_logout_ends_the_session_the_gate_then_refuses(
        self, stores: SingleProcessStores
    ) -> None:
        """MEMSTORE-20: logout ends the session."""
        browser = Browser(stores)
        browser.sign_in()

        assert browser.logout() == 200

        assert browser.gate_status() == 401
        assert stores.sessions.records_of(SUBJECT).sessions == ()

    def test_back_channel_logout_ends_every_session_and_the_next_sign_in_adds_no_second_account(
        self, stores: SingleProcessStores, audit: RecordingAuditSink
    ) -> None:
        """MEMSTORE-20: back-channel logout ends every session and keeps the account."""
        browser = Browser(stores)
        browser.sign_in()

        assert browser.issuer_logs_out() == 200

        assert browser.gate_status() == 401
        assert stores.accounts.get(SUBJECT) is not None
        assert browser.sign_in() == 303
        assert browser.gate_status() == 200
        created = [e for e in audit.account_events if e.kind is AccountEventKind.USER_CREATED]
        assert len(created) == 1
