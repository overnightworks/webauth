"""The one place a session ends in both the host's store and the cache.

Two orderings keep the cache from outliving the store. Ending deletes from
the store before the cache, because the store is the record of truth; a cache
that then fails to delete raises to the host, which answers with an error
rather than report a logout the cache would still honour. Filling the cache
happens only after ``SessionRecordStore.load`` has found the session, so a
session the store already dropped is never cached again.
"""

from __future__ import annotations

from webauth.ports import SessionCache, SessionRecordStore


def end_session(
    sessions: SessionRecordStore, cache: SessionCache | None, *, session_id: str, user_id: str,
) -> None:
    """End one session, as on logout or an administrator's revocation."""
    sessions.delete(session_id)
    if cache is not None:
        cache.delete(session_id, user_id)


def end_user_sessions(
    sessions: SessionRecordStore, cache: SessionCache | None, user_id: str,
) -> int:
    """End every session of one account, returning the number the store held."""
    session_count = sessions.delete_for_user(user_id)
    if cache is not None:
        cache.delete_user_sessions(user_id)
    return session_count


def prune_sessions(
    sessions: SessionRecordStore, cache: SessionCache | None, user_id: str, max_sessions: int,
) -> list[str]:
    """End the oldest sessions above ``max_sessions``, returning their ids."""
    pruned = sessions.prune_overflow(user_id, max_sessions)
    if cache is not None:
        for session_id in pruned:
            cache.delete(session_id, user_id)
    return pruned
