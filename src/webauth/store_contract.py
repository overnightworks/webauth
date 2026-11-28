"""Checks that prove a host's store adapters keep the duties of the ports in `webauth.ports`.

A host builds one `StoreAdapter` in its own fixture and runs every check of `STORE_CHECKS`
against it, for example by parametrizing its database test over the tuple. The module adds no
dependency beyond webauth's own, which includes pydantic's `SecretStr` that the ports take, and
needs no test framework: a check raises `AssertionError` when the adapter breaks a duty and returns
when it keeps it.

Each check mints its own random subjects, usernames and session ids, so checks run in parallel
against a shared database. The host owns the cleanup of the rows they leave. Every call takes its
times from the check, so the adapter needs no clock.

The cross-process check proves that two `SignInTransaction` entries exclude each other across
processes, which a host with several workers or pods needs and an in-process lock does not give. It
starts a second process with the `spawn` method, so that process inherits no connection or lock from
this one, and builds its transaction there from `StoreAdapter.transaction_in_another_process`. A
correct adapter always passes. A broken one is caught unless the second process is scheduled later
than the window this check holds its own entry open.

No check covers `SessionTransaction`.
"""

from __future__ import annotations

import multiprocessing
import unicodedata
import uuid
from collections.abc import Callable
from contextlib import ExitStack
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from typing import TYPE_CHECKING, Final

from pydantic import SecretStr

from webauth._validation import is_whole_number
from webauth.ports import (
    AccountKind,
    SessionRecordStore,
    SignInTransaction,
    SubjectUserStore,
)
from webauth.sessions import new_session_id

if TYPE_CHECKING:
    from multiprocessing.connection import Connection
    from multiprocessing.process import BaseProcess

__all__ = [
    "STORE_CHECKS",
    "StoreAdapter",
    "StoreCheck",
]

_WINDOW_SECONDS: Final = 0.5
"""How long the first entry stays open after the second process signals that it is about to enter.
The second process needs that long to reach its store call if nothing holds it back, and an adapter
that serialises it holds it back for the whole window."""

_OTHER_PROCESS_SECONDS: Final = 60.0
"""How long the check waits for the second process to start and, once the first entry has
exited, to finish its own entry; a spawned process imports the host's modules first."""

_ABOUT_TO_ENTER: Final = "about to enter"
_CALLED_THE_STORE: Final = "called the store"
_SESSION_LIFETIME: Final = timedelta(hours=1)


@dataclass(frozen=True)
class StoreAdapter:
    """What the host supplies: its adapters over one database.

    ``transaction_in_another_process`` is any picklable callable without arguments that builds, in a
    process that shares nothing with this one, a ``SignInTransaction`` over the same database as
    ``transaction``, for example a frozen dataclass that carries the database location. A host that
    runs one worker leaves it ``None`` and runs the checks whose ``crosses_processes`` is false.
    """

    accounts: SubjectUserStore
    sessions: SessionRecordStore
    transaction: SignInTransaction
    transaction_in_another_process: Callable[[], SignInTransaction] | None = None


@dataclass(frozen=True)
class StoreCheck:
    """One duty of the ports and the function that proves it."""

    name: str
    run: Callable[[StoreAdapter], None]
    crosses_processes: bool = False


def _require(condition: object, message: str) -> None:
    if not condition:
        raise AssertionError(message)


def _require_raises(call: Callable[[], object], message: str) -> None:
    try:
        call()
    except Exception:
        # The port requires a raise and leaves its type to the adapter.
        return
    raise AssertionError(message)


def _a_subject() -> str:
    return str(uuid.uuid4())


def _a_session_id() -> str:
    return new_session_id()


def _an_account(adapter: StoreAdapter) -> str:
    subject = _a_subject()
    adapter.accounts.create_for_subject(subject, subject, "user", AccountKind.PERSON)
    return subject


def _a_session(
    adapter: StoreAdapter,
    subject: str,
    *,
    session_id: str | None = None,
    now: datetime | None = None,
    refresh_token: SecretStr | None = None,
) -> str:
    created_at = datetime.now(UTC) if now is None else now
    stored_id = _a_session_id() if session_id is None else session_id
    adapter.sessions.create(
        subject,
        session_id=stored_id,
        now=created_at,
        expires_at=created_at + _SESSION_LIFETIME,
        refresh_token=refresh_token,
        id_token=SecretStr("identity"),
        account_language="de",
    )
    return stored_id


def _stored_fields(adapter: StoreAdapter, session_id: str) -> tuple[object, ...] | None:
    session = adapter.sessions.load(session_id)
    return (
        None
        if session is None
        else (
            session.id,
            session.user.id,
            session.created_at,
            session.expires_at,
            session.refresh_token,
            session.id_token,
            session.account_language,
        )
    )


def _stored_ids(adapter: StoreAdapter, session_ids: list[str]) -> list[str]:
    return [session_id for session_id in session_ids if adapter.sessions.load(session_id)]


def _create_keeps_the_given_id(adapter: StoreAdapter) -> None:
    subject = _an_account(adapter)
    session_id = _a_session_id()

    created = adapter.sessions.create(
        subject,
        session_id=session_id,
        now=datetime.now(UTC),
        expires_at=datetime.now(UTC) + _SESSION_LIFETIME,
        refresh_token=None,
        id_token=None,
        account_language=None,
    )

    loaded = adapter.sessions.load(session_id)
    _require(
        created.id == session_id, "create stored the session under another id than it was given"
    )
    _require(loaded is not None and loaded.id == session_id, "load did not find the created id")


def _a_stored_id_is_refused_and_its_row_kept(adapter: StoreAdapter) -> None:
    subject = _an_account(adapter)
    now = datetime.now(UTC)
    first = SecretStr(uuid.uuid4().hex)
    session_id = _a_session(adapter, subject, now=now, refresh_token=first)
    stored = _stored_fields(adapter, session_id)

    for second_now in (now, now + 2 * _SESSION_LIFETIME):
        _require_raises(
            lambda second_now=second_now: _a_session(
                adapter,
                subject,
                session_id=session_id,
                now=second_now,
                refresh_token=SecretStr(uuid.uuid4().hex),
            ),
            "create accepted an id the store already holds",
        )

    _require(
        stored is not None and _stored_fields(adapter, session_id) == stored,
        "a refused create changed the stored row",
    )


def _load_answers_none_for_unknown_and_deleted_ids(adapter: StoreAdapter) -> None:
    subject = _an_account(adapter)
    session_id = _a_session(adapter, subject)
    _require(adapter.sessions.load(_a_session_id()) is None, "load of an unknown id answered a row")

    _require(adapter.sessions.load(session_id) is not None, "load did not find a stored session")

    adapter.sessions.delete(session_id)

    _require(adapter.sessions.load(session_id) is None, "load of a deleted id answered a row")


def _prune_overflow_keeps_the_newest(adapter: StoreAdapter) -> None:
    subject = _an_account(adapter)
    other_subject = _an_account(adapter)
    base = datetime.now(UTC)
    created = [
        _a_session(adapter, subject, now=base + timedelta(minutes=minute))
        for minute in (3, 1, 4, 2)
    ]
    newest_first = [created[2], created[0], created[3], created[1]]
    other = _a_session(adapter, other_subject)

    adapter.sessions.prune_overflow(subject, 2)

    _require(
        _stored_ids(adapter, newest_first) == newest_first[:2],
        "prune_overflow did not keep the two newest sessions by created_at",
    )
    _require(
        adapter.sessions.load(other) is not None, "prune_overflow ended another account's session"
    )

    adapter.sessions.prune_overflow(subject, 0)

    _require(_stored_ids(adapter, newest_first) == [], "prune_overflow with 0 kept a session")


def _delete_for_user_returns_how_many_ended(adapter: StoreAdapter) -> None:
    subject = _an_account(adapter)
    sessions = [_a_session(adapter, subject) for _ in range(3)]
    other_subject = _an_account(adapter)

    ended = adapter.sessions.delete_for_user(subject)

    _require(
        is_whole_number(ended) and ended == len(sessions),
        "delete_for_user did not return how many sessions ended",
    )
    _require(_stored_ids(adapter, sessions) == [], "delete_for_user left a session")
    _require(
        adapter.sessions.delete_for_user(other_subject) == 0,
        "delete_for_user did not return 0 for an account without sessions",
    )


def _delete_for_user_keeps_the_account(adapter: StoreAdapter) -> None:
    subject = _an_account(adapter)
    _a_session(adapter, subject)

    adapter.sessions.delete_for_user(subject)

    _require(adapter.accounts.get(subject) is not None, "delete_for_user removed the account")


def _touch_and_replace_refresh_token_answer_a_bool(adapter: StoreAdapter) -> None:
    subject = _an_account(adapter)
    session_id = _a_session(adapter, subject)
    later = datetime.now(UTC) + 2 * _SESSION_LIFETIME
    missing = _a_session_id()

    _require(
        adapter.sessions.touch(session_id, expires_at=later) is True, "touch did not answer True"
    )
    _require(
        adapter.sessions.replace_refresh_token(session_id, refresh_token=SecretStr("rotated"))
        is True,
        "replace_refresh_token did not answer True",
    )
    _require(
        adapter.sessions.touch(missing, expires_at=later) is False, "touch did not answer False"
    )
    _require(
        adapter.sessions.replace_refresh_token(missing, refresh_token=SecretStr("rotated"))
        is False,
        "replace_refresh_token did not answer False",
    )
    _require(adapter.sessions.load(missing) is None, "a write on a missing session created a row")


def _get_compares_the_subject_exactly(adapter: StoreAdapter) -> None:
    subject = f"é{uuid.uuid4().hex}"
    adapter.accounts.create_for_subject(subject, subject, "user", AccountKind.PERSON)
    folded = {
        "case": subject.upper(),
        "trailing space": f"{subject} ",
        "accent": subject.replace("é", "e"),
        "unicode normalization": unicodedata.normalize("NFD", subject),
    }

    _require(adapter.accounts.get(subject) is not None, "get did not find the exact subject")
    for kind, asked in folded.items():
        _require(adapter.accounts.get(asked) is None, f"get folded the subject ({kind})")


def _a_write_on_a_missing_account_raises(adapter: StoreAdapter) -> None:
    missing = _a_subject()
    session_id = _a_session_id()
    now = datetime.now(UTC)

    _require_raises(lambda: adapter.accounts.set_role(missing, "admin"), "set_role did not raise")
    _require_raises(
        lambda: adapter.accounts.set_kind(missing, AccountKind.AGENT), "set_kind did not raise"
    )
    _require_raises(
        lambda: adapter.sessions.create(
            missing,
            session_id=session_id,
            now=now,
            expires_at=now + _SESSION_LIFETIME,
            refresh_token=None,
            id_token=None,
            account_language=None,
        ),
        "create for a missing account did not raise",
    )
    _require(adapter.accounts.get(missing) is None, "a write on a missing account created it")


def _enter_in_the_other_process(
    build_transaction: Callable[[], SignInTransaction], subject: str, messages: Connection
) -> None:
    transaction = build_transaction()
    messages.send(_ABOUT_TO_ENTER)
    with transaction() as stores:
        stores.accounts.get(subject)
        messages.send(_CALLED_THE_STORE)


def _heard(messages: Connection, within_seconds: float) -> str | None:
    try:
        return str(messages.recv()) if messages.poll(within_seconds) else None
    except EOFError:
        return None


def _end(process: BaseProcess) -> None:
    process.terminate()
    process.join()
    process.close()


def _sign_in_entries_serialise_across_processes(adapter: StoreAdapter) -> None:
    build_transaction = adapter.transaction_in_another_process
    _require(
        build_transaction is not None,
        "the adapter supplies no transaction_in_another_process to enter from a second process",
    )
    subject = _a_subject()
    context = multiprocessing.get_context("spawn")
    messages, other_end = context.Pipe(duplex=False)
    other = context.Process(
        target=_enter_in_the_other_process,
        args=(build_transaction, subject, other_end),
    )
    with ExitStack() as cleanup:
        cleanup.callback(messages.close)
        cleanup.callback(other_end.close)
        with adapter.transaction() as stores:
            stores.accounts.get(subject)
            other.start()
            # Registered once the process exists: a start that fails, for example on a factory
            # that cannot be pickled, must surface as itself.
            cleanup.callback(_end, other)
            other_end.close()
            _require(
                _heard(messages, _OTHER_PROCESS_SECONDS) == _ABOUT_TO_ENTER,
                "the second process did not reach its entry",
            )
            served_while_held = _heard(messages, _WINDOW_SECONDS) == _CALLED_THE_STORE
        _require(
            not served_while_held,
            "a second process made a store call inside its entry while the first entry was open",
        )
        _require(
            _heard(messages, _OTHER_PROCESS_SECONDS) == _CALLED_THE_STORE,
            "the second process did not complete its entry after the first entry exited",
        )
        other.join(timeout=_OTHER_PROCESS_SECONDS)
        _require(
            other.exitcode == 0,
            "the second process did not leave its entry cleanly after the first entry exited",
        )


STORE_CHECKS: Final = (
    StoreCheck("create_keeps_the_given_id", _create_keeps_the_given_id),
    StoreCheck("a_stored_id_is_refused_and_its_row_kept", _a_stored_id_is_refused_and_its_row_kept),
    StoreCheck(
        "load_answers_none_for_unknown_and_deleted_ids",
        _load_answers_none_for_unknown_and_deleted_ids,
    ),
    StoreCheck("prune_overflow_keeps_the_newest", _prune_overflow_keeps_the_newest),
    StoreCheck("delete_for_user_returns_how_many_ended", _delete_for_user_returns_how_many_ended),
    StoreCheck("delete_for_user_keeps_the_account", _delete_for_user_keeps_the_account),
    StoreCheck(
        "touch_and_replace_refresh_token_answer_a_bool",
        _touch_and_replace_refresh_token_answer_a_bool,
    ),
    StoreCheck("get_compares_the_subject_exactly", _get_compares_the_subject_exactly),
    StoreCheck("a_write_on_a_missing_account_raises", _a_write_on_a_missing_account_raises),
    StoreCheck(
        "sign_in_entries_serialise_across_processes",
        _sign_in_entries_serialise_across_processes,
        crosses_processes=True,
    ),
)
