"""Checks shared by the modules that validate their own configuration."""

from __future__ import annotations

from typing import TypeGuard

__all__: list[str] = []


def is_utf8(text: str) -> bool:
    """Whether ``text`` holds no byte that failed to decode as UTF-8."""
    try:
        text.encode()
    except UnicodeEncodeError:
        return False
    return True


def require_non_empty_string(field: str, value: object) -> None:
    """Refuse a non-string or empty value, naming the field and never the value."""
    if not isinstance(value, str) or not value:
        raise ValueError(f"{field} must be a non-empty string")


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


def require_collection_not_one_string(
    field: str, value: object, *, noun: str, example: str | None = None,
) -> None:
    """Refuse one string where a set of ``noun`` belongs.

    Membership in a string is a substring test, so ``"/hooks/stripe"`` would
    admit ``"/"`` and ``"XPOST"`` would admit ``"POST"``.
    """
    if isinstance(value, str):
        hint = f", for example {example}" if example else ""
        raise ValueError(
            f"{field} must be a set of {noun}s, not one string; list each {noun} in a set{hint}",
        )
