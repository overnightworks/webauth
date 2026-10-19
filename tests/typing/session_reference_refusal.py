# pyright: reportUnnecessaryTypeIgnoreComment=true
"""A raw session id is refused where an audit event wants a session reference.

Every refusal below carries an ignore for ``reportArgumentType``; the check on
unnecessary ignores fails this file if the type ever stops refusing a ``str``.
"""

from webauth.cookies import session_reference
from webauth.ports import (
    AccountEvent,
    AccountEventKind,
    SessionIdentityChange,
    SessionIdentityChanged,
)
from webauth.session_administration import SessionSummary

RAW_SESSION_ID = "a-bearer-secret"

SessionIdentityChanged(
    change=SessionIdentityChange.IP_ADDRESS, user_id="u",
    session_ref=session_reference(RAW_SESSION_ID), previous="a", current="b",
)
AccountEvent(
    kind=AccountEventKind.SESSION_REVOKED, actor_id=None, subject_id="u",
    session_ref=session_reference(RAW_SESSION_ID),
)
SessionSummary(
    session_ref=session_reference(RAW_SESSION_ID),
    user_id="u", username="n", ip_address="a", user_agent="b",
)

SessionIdentityChanged(
    change=SessionIdentityChange.IP_ADDRESS, user_id="u",
    session_ref=RAW_SESSION_ID,  # pyright: ignore[reportArgumentType] - raw id
    previous="a", current="b",
)
AccountEvent(
    kind=AccountEventKind.SESSION_REVOKED, actor_id=None, subject_id="u",
    session_ref=RAW_SESSION_ID,  # pyright: ignore[reportArgumentType] - raw id
)
SessionSummary(
    session_ref=RAW_SESSION_ID,  # pyright: ignore[reportArgumentType] - raw id
    user_id="u", username="n", ip_address="a", user_agent="b",
)
SessionSummary(
    RAW_SESSION_ID,  # pyright: ignore[reportArgumentType] - raw id, positional
    "u", "n", "a", "b",
)
