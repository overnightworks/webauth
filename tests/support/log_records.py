"""Reading a captured log record the way a log shipper does: its event and its fields."""

from __future__ import annotations

import logging

_STANDARD_ATTRIBUTES = frozenset(vars(logging.makeLogRecord({}))) | {"message", "asctime"}


def fields_of(record: logging.LogRecord) -> dict[str, object]:
    """The scalar `extra=` fields of `record`, which logline writes beside its event."""
    return {name: value for name, value in vars(record).items() if name not in _STANDARD_ATTRIBUTES}
