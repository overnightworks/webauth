"""One dependency outage: its opening and closing in the log, and the answer that refuses meanwhile.

The rate limiter and the session store each keep one tracker per handle. Both answer an outage with
the same 503, so a host's monitoring reads one shape.
"""

from __future__ import annotations

import logging
import threading
from contextlib import contextmanager
from typing import TYPE_CHECKING, Final

from starlette.responses import JSONResponse

from webauth.ports import StoreUnavailableError

if TYPE_CHECKING:
    from collections.abc import Callable, Iterator
    from contextlib import AbstractContextManager

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


def _session_store_outage() -> _OutageTracker:
    """The tracker one handle's two transactions share."""
    return _OutageTracker(_log, _SESSION_STORE_STARTED_EVENT, _SESSION_STORE_ENDED_EVENT)


def _tracking[StoresT](
    transaction: Callable[[], AbstractContextManager[StoresT]], tracker: _OutageTracker
) -> Callable[[], AbstractContextManager[StoresT]]:
    """The host's transaction, with an outage noted when a ``StoreUnavailableError`` leaves it
    (entry, body or exit), by the class of its cause when it has one, and closed at the next clean
    exit."""

    @contextmanager
    def tracked() -> Iterator[StoresT]:
        try:
            with transaction() as stores:
                yield stores
        except StoreUnavailableError as failure:
            tracker.note_failure(failure.__cause__ or failure)
            raise
        tracker.note_answered()

    return tracked
