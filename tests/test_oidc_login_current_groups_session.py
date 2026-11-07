"""A person's current groups: rotation, session, transactions, tokens and overlapping calls."""

from __future__ import annotations

from dataclasses import replace
from threading import get_ident
from typing import TYPE_CHECKING, Any

import pytest
from pydantic import SecretStr

from tests.support.current_groups_arrangement import (
    GROUPS,
    ROTATIONS,
    SESSION_ENDED,
    SESSION_ID,
    SHAPES,
    STORED_ID_TOKEN,
    Arrangement,
    an_arrangement,
)
from tests.support.oidc_arrangement import (
    ISSUED_REFRESH_TOKEN,
)
from tests.support.webauth_arrangement import (
    SESSION_IDLE_SECONDS,
    SessionsAnsweringReplace,
    SessionsEndedBeforeReplacingTheRefreshToken,
    SessionsFailingToLoad,
    SessionsRecordingTheirTransaction,
)
from webauth.oidc_login import (
    fresh_access_token,
)

if TYPE_CHECKING:
    from collections.abc import Callable

    from webauth.ports import SessionTransaction


class TestTheRotationSurvives:
    @SHAPES
    @ROTATIONS
    @pytest.mark.parametrize("id_token_holds", [True, False], ids=["holds", "refused"])
    def test_a_replacement_refresh_token_is_stored_whatever_the_id_token_said(
        self,
        provider_of: Any,
        rotation: dict[str, Any],
        id_token_holds: bool,
    ) -> None:
        """GROUPS-23: a replacement refresh token is stored whether the ID token held or was
        refused."""

        arrangement = an_arrangement(answer=False)
        arrangement.answer_with_id_token(sub="x" if not id_token_holds else "user-1")
        arrangement.issuer.refresh_answer_members |= rotation

        arrangement.current_groups(provider_of(arrangement.sessions))

        rotated = "refresh_token" not in rotation
        stored_a_replacement = arrangement.stored_refresh_token != ISSUED_REFRESH_TOKEN
        assert stored_a_replacement is rotated


class TestADeletedSessionIsNeverRecreated:
    @SHAPES
    @ROTATIONS
    @pytest.mark.parametrize("id_token_holds", [True, False], ids=["holds", "refused"])
    def test_a_session_deleted_during_the_grant_ends_whatever_the_id_token_said(
        self,
        provider_of: Any,
        rotation: dict[str, Any],
        id_token_holds: bool,
    ) -> None:
        """GROUPS-06, GROUPS-24: a session deleted during the grant ends and is not recreated."""

        arrangement = an_arrangement(answer=False)
        arrangement.answer_with_id_token(sub="user-1" if id_token_holds else "x")
        arrangement.issuer.refresh_answer_members |= rotation
        arrangement.issuer.before_exchange = lambda: arrangement.sessions.delete(SESSION_ID)

        outcome = arrangement.current_groups(provider_of(arrangement.sessions))

        assert outcome == SESSION_ENDED
        assert arrangement.sessions.list_active() == []

    @SHAPES
    @ROTATIONS
    @pytest.mark.parametrize("id_token_holds", [True, False], ids=["holds", "refused"])
    def test_a_session_past_its_expiry_after_the_grant_ends_and_keeps_its_row(
        self,
        provider_of: Any,
        rotation: dict[str, Any],
        id_token_holds: bool,
    ) -> None:
        """GROUPS-06, GROUPS-24: a session that expired during the grant ends and its row is not
        rewritten."""

        arrangement = an_arrangement(answer=False)
        arrangement.issuer.before_exchange = lambda: setattr(
            arrangement.clock,
            "now",
            arrangement.clock.now + SESSION_IDLE_SECONDS + 1,
        )
        arrangement.answer_with_id_token(
            exp=4_000_000_000,
            sub="user-1" if id_token_holds else "x",
        )
        arrangement.issuer.refresh_answer_members |= rotation

        outcome = arrangement.current_groups(provider_of(arrangement.sessions))

        assert outcome == SESSION_ENDED
        assert arrangement.stored_refresh_token == ISSUED_REFRESH_TOKEN

    def test_a_row_deleted_between_the_second_load_and_the_replace_ends_the_session(self) -> None:
        """GROUPS-06, GROUPS-24: a row deleted before the replace ends the session and is not
        recreated."""

        arrangement = an_arrangement(SessionsEndedBeforeReplacingTheRefreshToken)

        outcome = arrangement.current_groups(arrangement.sessions.in_transaction)

        assert outcome == SESSION_ENDED
        assert arrangement.sessions.list_active() == []

    @pytest.mark.parametrize("id_token_holds", [True, False], ids=["holds", "refused"])
    def test_a_replace_that_stores_nothing_ends_the_session_whatever_the_id_token_said(
        self,
        id_token_holds: bool,
    ) -> None:
        """GROUPS-06, GROUPS-24: a replace that stores nothing ends the session."""

        arrangement = an_arrangement(
            lambda record: SessionsAnsweringReplace(record, False),
            answer=False,
        )
        arrangement.answer_with_id_token(sub="user-1" if id_token_holds else "x")

        assert arrangement.current_groups(arrangement.sessions.in_transaction) == SESSION_ENDED


class TestNothingElseIsStored:
    def test_only_the_refresh_token_changes(self) -> None:
        """GROUPS-02: the call changes the stored refresh token and nothing else of the record."""

        arrangement = an_arrangement()
        before = replace(arrangement.sessions.stored_record)

        arrangement.current_groups(arrangement.sessions.in_transaction)

        after = arrangement.sessions.stored_record
        assert replace(after, refresh_token=None) == replace(before, refresh_token=None)
        assert after.refresh_token != SecretStr(ISSUED_REFRESH_TOKEN)


class TestTheTransactions:
    def test_no_transaction_is_open_during_the_grant(self) -> None:
        """GROUPS-25: one grant is made, between two transactions."""

        arrangement = an_arrangement(SessionsRecordingTheirTransaction)
        sessions = arrangement.sessions
        assert isinstance(sessions, SessionsRecordingTheirTransaction)
        arrangement.issuer.before_exchange = lambda: sessions.events.append(("grant", get_ident()))

        outcome = arrangement.current_groups(sessions.in_transaction)

        assert outcome == tuple(GROUPS)
        assert sessions.event_names == [
            "open",
            "load",
            "commit",
            "grant",
            "open",
            "load",
            "replace",
            "commit",
        ]

    def test_a_load_failing_in_the_first_transaction_raises_before_any_grant(self) -> None:
        """GROUPS-10: a failing load raises before any grant."""

        arrangement = an_arrangement(SessionsFailingToLoad)

        with pytest.raises(ConnectionError):
            arrangement.current_groups(arrangement.sessions.in_transaction)

        assert arrangement.requests_made == 0

    def test_an_exit_failing_in_the_first_transaction_raises_before_any_grant(self) -> None:
        """GROUPS-11: a failing exit raises before any grant."""

        arrangement = an_arrangement()
        arrangement.sessions.commit_failure = RuntimeError("commit failed")

        with pytest.raises(RuntimeError, match="commit failed"):
            arrangement.current_groups(arrangement.sessions.in_transaction)

        assert arrangement.requests_made == 0

    def test_a_load_failing_in_the_second_transaction_raises_with_the_groups_in_hand(self) -> None:
        """GROUPS-10: a failing load raises and hands out no groups."""

        arrangement = an_arrangement(SessionsFailingToLoad)
        sessions = arrangement.sessions
        assert isinstance(sessions, SessionsFailingToLoad)
        sessions.failing = False
        arrangement.issuer.before_exchange = lambda: setattr(sessions, "failing", True)

        with pytest.raises(ConnectionError):
            arrangement.current_groups(sessions.in_transaction)

        assert arrangement.requests_made == 1

    def test_an_exit_failing_in_the_second_transaction_raises_with_the_groups_in_hand(self) -> None:
        """GROUPS-11: a failing exit raises and hands out no groups."""

        arrangement = an_arrangement()
        arrangement.issuer.before_exchange = lambda: setattr(
            arrangement.sessions,
            "commit_failure",
            RuntimeError("commit failed"),
        )

        with pytest.raises(RuntimeError, match="commit failed"):
            arrangement.current_groups(arrangement.sessions.in_transaction)

        assert arrangement.requests_made == 1

    def test_a_replace_failing_raises_and_hands_out_no_groups(self) -> None:
        """GROUPS-10: a failing replace raises and hands out no groups."""

        arrangement = an_arrangement()

        def failing_replace(session_id: str, *, refresh_token: SecretStr) -> bool:
            raise ConnectionError("session store down")

        arrangement.sessions.replace_refresh_token = failing_replace  # type: ignore[method-assign]

        with pytest.raises(ConnectionError):
            arrangement.current_groups(arrangement.sessions.in_transaction)

        assert arrangement.requests_made == 1

    def test_a_replace_answering_a_non_bool_raises(self) -> None:
        arrangement = an_arrangement(lambda record: SessionsAnsweringReplace(record, "yes"))

        with pytest.raises(TypeError, match="bool"):
            arrangement.current_groups(arrangement.sessions.in_transaction)


class TestTheTokenNeverLeaves:
    @pytest.mark.parametrize("id_token_holds", [True, False], ids=["holds", "refused"])
    def test_no_token_is_in_the_outcome_its_repr_or_the_log(
        self,
        id_token_holds: bool,
        caplog: pytest.LogCaptureFixture,
    ) -> None:
        """GROUPS-03: no token is in the outcome, its text or the log."""

        arrangement = an_arrangement(answer=False)
        arrangement.answer_with_id_token(sub="user-1" if id_token_holds else "someone-else")
        arrangement.answer_with_access_token()
        caplog.set_level(0)

        outcome = arrangement.current_groups(arrangement.sessions.in_transaction)

        shown = f"{outcome!r} {outcome} {caplog.text}"
        assert not any(secret in shown for secret in _secrets_of(arrangement))

    def test_no_token_is_in_the_text_of_a_raised_exception(
        self,
        caplog: pytest.LogCaptureFixture,
    ) -> None:
        """GROUPS-03: no token is in a raised exception or the log."""

        arrangement = an_arrangement(lambda record: SessionsAnsweringReplace(record, "yes"))
        arrangement.answer_with_access_token()
        caplog.set_level(0)

        with pytest.raises(TypeError) as raised:
            arrangement.current_groups(arrangement.sessions.in_transaction)

        shown = f"{raised.value!r} {raised.value} {caplog.text}"
        assert not any(secret in shown for secret in _secrets_of(arrangement))


def _secrets_of(arrangement: Arrangement) -> list[str]:
    return [
        *arrangement.answered_tokens,
        *arrangement.issuer.refresh_tokens,
        STORED_ID_TOKEN.get_secret_value(),
    ]


def _a_current_groups_call(arrangement: Arrangement, provider: SessionTransaction) -> bool:
    return arrangement.current_groups(provider) == tuple(GROUPS)


def _a_fresh_access_token_call(arrangement: Arrangement, provider: SessionTransaction) -> bool:
    return isinstance(
        fresh_access_token(
            arrangement.relying_party,
            SESSION_ID,
            session_transaction=provider,
            config=arrangement.config,
        ),
        SecretStr,
    )


_PARTNERS = pytest.mark.parametrize(
    "partner",
    [
        pytest.param(_a_current_groups_call, id="current_groups"),
        pytest.param(_a_fresh_access_token_call, id="fresh_access_token"),
    ],
)


class TestOverlap:
    @_PARTNERS
    def test_the_last_replacement_wins_when_two_calls_overlap(
        self, partner: Callable[[Arrangement, SessionTransaction], bool]
    ) -> None:
        """GROUPS-26: two overlapping calls each succeed and the last replacement written wins."""

        arrangement = an_arrangement()
        provider = arrangement.sessions.in_transaction
        inner: list[bool] = []
        stored_by_inner: list[str | None] = []

        def overlapping_call() -> None:
            arrangement.issuer.before_exchange = lambda: None
            inner.append(partner(arrangement, provider))
            stored_by_inner.append(arrangement.stored_refresh_token)

        arrangement.issuer.before_exchange = overlapping_call

        outer = arrangement.current_groups(provider)

        assert (outer, inner) == (tuple(GROUPS), [True])
        assert stored_by_inner[0] not in (None, ISSUED_REFRESH_TOKEN)
        assert arrangement.stored_refresh_token not in (stored_by_inner[0], ISSUED_REFRESH_TOKEN)
        assert arrangement.stored_refresh_token in arrangement.issuer.refresh_tokens

    @_PARTNERS
    def test_an_echoed_token_never_overwrites_a_replacement(
        self, partner: Callable[[Arrangement, SessionTransaction], bool]
    ) -> None:
        """GROUPS-27: an echoed refresh token never overwrites a replacement."""

        arrangement = an_arrangement()
        provider = arrangement.sessions.in_transaction
        arrangement.issuer.refresh_answer_members["refresh_token"] = ISSUED_REFRESH_TOKEN
        replaced: list[bool] = []
        stored_by_other: list[str | None] = []

        def beside_the_echoing_call() -> None:
            arrangement.issuer.before_exchange = lambda: None
            echoed = arrangement.issuer.refresh_answer_members.pop("refresh_token")
            replaced.append(partner(arrangement, provider))
            stored_by_other.append(arrangement.stored_refresh_token)
            arrangement.issuer.refresh_answer_members["refresh_token"] = echoed

        arrangement.issuer.before_exchange = beside_the_echoing_call

        outcome = arrangement.current_groups(provider)

        assert outcome == tuple(GROUPS)
        assert replaced == [True]
        assert stored_by_other[0] not in (None, ISSUED_REFRESH_TOKEN)
        assert arrangement.stored_refresh_token == stored_by_other[0]
