"""The audit sink a sign-in entry hands its block, so the events reach the host's sink only when the
block has ended without an exception."""

from __future__ import annotations

from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from webauth.ports import AccountEvent, AuditSink

__all__ = ["DeferredAudit"]


class DeferredAudit:
    """Holds an entry's events until the entry commits, so a rolled-back entry reports none."""

    def __init__(self) -> None:
        self._events: list[AccountEvent] = []

    def account_event(self, event: AccountEvent) -> None:
        self._events.append(event)

    def flush_to(self, audit: AuditSink) -> None:
        for event in self._events:
            audit.account_event(event)
