"""One dependency outage: its opening and closing in the log, and the answer that refuses meanwhile.

The rate limiter and the session store each keep one tracker per handle. Both answer an outage with
the same 503, so a host's monitoring reads one shape.
"""

from __future__ import annotations

import logging
import threading
from contextlib import ExitStack
from typing import TYPE_CHECKING, Final

from starlette.responses import JSONResponse

from webauth.ports import StoreUnavailableError

if TYPE_CHECKING:
    from collections.abc import Callable
    from contextlib import AbstractContextManager
    from types import TracebackType

    from webauth.ports import SessionTransaction, SignInTransaction

__all__: list[str] = []

_log = logging.getLogger(__name__)

_RETRY_AFTER_SECONDS: Final = 5
_SESSION_STORE_STARTED_EVENT: Final = "session_store_outage.started"
_SESSION_STORE_ENDED_EVENT: Final = "session_store_outage.ended"


def _unavailable_answer(detail: str) -> JSONResponse:
    """The 503 that refuses a request while a dependency is out; it carries no failure text."""
    return JSONResponse(
        {"detail": detail},
        status_code=503,
        headers={"Retry-After": str(_RETRY_AFTER_SECONDS)},
    )


def _session_store_unavailable_answer() -> JSONResponse:
    return _unavailable_answer("Session store unavailable")


class _OutageTracker:
    """Opens an outage on the first failure and closes it on the next answer, one log line each.

    The started line carries the class name of the failure it is given and the ended line the
    failures counted in between; no line carries an error text. Calls come from the event loop and
    from worker threads, so the state sits behind a lock.
    """

    def __init__(self, log: logging.Logger, started_event: str, ended_event: str) -> None:
        self._log = log
        self._started_event = started_event
        self._ended_event = ended_event
        self._lock = threading.Lock()
        self._refused: int | None = None

    def note_failure(self, failure: BaseException) -> None:
        with self._lock:
            if self._refused is None:
                self._refused = 0
                self._log.error(self._started_event, extra={"error_type": type(failure).__name__})
            self._refused += 1

    def note_answered(self) -> None:
        with self._lock:
            if self._refused is not None:
                self._log.info(self._ended_event, extra={"refused_count": self._refused})
                self._refused = None


class _TrackedTransaction[StoresT]:
    """The host's transaction, with an outage noted when a ``StoreUnavailableError`` leaves it
    (entry, body or exit), by the class of its cause when it has one, and closed at the next clean
    exit."""

    def __init__(
        self, transaction: Callable[[], AbstractContextManager[StoresT]], tracker: _OutageTracker
    ) -> None:
        self._transaction = transaction
        self._tracker = tracker
        self._entered = ExitStack()

    def __enter__(self) -> StoresT:
        try:
            return self._entered.enter_context(self._transaction())
        except StoreUnavailableError as failure:
            self._note(failure)
            raise

    def __exit__(
        self,
        exc_type: type[BaseException] | None,
        exc: BaseException | None,
        traceback: TracebackType | None,
    ) -> bool | None:
        try:
            suppressed = self._entered.__exit__(exc_type, exc, traceback)
        except StoreUnavailableError as failure:
            self._note(failure)
            raise
        if isinstance(exc, StoreUnavailableError):
            self._note(exc)
        elif exc is None:
            self._tracker.note_answered()
        return suppressed

    def _note(self, failure: StoreUnavailableError) -> None:
        self._tracker.note_failure(failure.__cause__ or failure)


def _tracked_transactions(
    sign_in: SignInTransaction, sessions: SessionTransaction
) -> tuple[SignInTransaction, SessionTransaction]:
    """The host's two transactions, both noting their outages on one tracker."""
    tracker = _OutageTracker(_log, _SESSION_STORE_STARTED_EVENT, _SESSION_STORE_ENDED_EVENT)
    return (
        lambda: _TrackedTransaction(sign_in, tracker),
        lambda: _TrackedTransaction(sessions, tracker),
    )
