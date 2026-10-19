"""Checks shared by the modules that validate their own configuration."""

from __future__ import annotations

from typing import TypeGuard

__all__: list[str] = []


def _is_whole_number(value: object) -> TypeGuard[int]:
    return isinstance(value, int) and not isinstance(value, bool)


def require_non_negative_whole_number(field: str, value: object, *, unit: str) -> None:
    """Refuse a quantity that is not a whole number of ``unit`` from zero up."""
    if not _is_whole_number(value) or value < 0:
        raise ValueError(f"{field} must be a whole number of {unit} from 0 up, not {value!r}")


def require_positive_whole_number(field: str, value: object, *, unit: str) -> None:
    """Refuse a quantity that is not a positive whole number of ``unit``.

    A zero or negative lifetime or window would not fail loudly later: it
    would expire every session at once, or make a limiter admit every request.
    """
    if not _is_whole_number(value) or value <= 0:
        raise ValueError(f"{field} must be a positive whole number of {unit}, not {value!r}")
