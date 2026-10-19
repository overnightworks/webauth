# pyright: reportUnnecessaryTypeIgnoreComment=true
"""A raw session id is refused where an audit event wants a session reference.

Every refusal below carries an ignore for ``reportArgumentType``; the check on
unnecessary ignores fails this file if the type ever stops refusing a ``str``.
"""

from webauth.cookies import session_reference
from webauth.ports import (
    SessionIdentityChange,
    SessionIdentityChanged,
)

RAW_SESSION_ID = "a-bearer-secret"

SessionIdentityChanged(
    change=SessionIdentityChange.IP_ADDRESS, user_id="u",
    session_ref=session_reference(RAW_SESSION_ID), previous="a", current="b",
)

SessionIdentityChanged(
    change=SessionIdentityChange.IP_ADDRESS, user_id="u",
    session_ref=RAW_SESSION_ID,  # pyright: ignore[reportArgumentType] - raw id
    previous="a", current="b",
)
