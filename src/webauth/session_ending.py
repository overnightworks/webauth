"""The one place a session ends in the host's store.

The store is the record of truth and decides every request, so ending a
session is a delete there and nothing else: the next request carrying the
ended session's cookie finds no record and is refused.
"""

from __future__ import annotations

from webauth.ports import SessionRecordStore

__all__ = [
    "end_session",
    "end_user_sessions",
    "prune_sessions",
]


def end_session(sessions: SessionRecordStore, *, session_id: str) -> None:
    """End one session, as on logout or an administrator's revocation."""
    sessions.delete(session_id)


def end_user_sessions(sessions: SessionRecordStore, user_id: str) -> int:
    """End every session of one account, returning the number the store held."""
    return sessions.delete_for_user(user_id)


def prune_sessions(sessions: SessionRecordStore, user_id: str, max_sessions: int) -> list[str]:
    """End the oldest sessions above ``max_sessions``, returning their ids."""
    return sessions.prune_overflow(user_id, max_sessions)
