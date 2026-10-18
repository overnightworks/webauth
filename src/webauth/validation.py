"""Checks shared by the modules that validate their own configuration."""

from __future__ import annotations

__all__: list[str] = []


def require_positive_whole_number(field: str, value: object, *, unit: str) -> None:
    """Refuse a quantity that is not a positive whole number of ``unit``.

    A zero or negative lifetime or window would not fail loudly later: it
    would expire every session at once, or make a limiter admit every request.
    """
    if isinstance(value, bool) or not isinstance(value, int) or value <= 0:
        raise ValueError(f"{field} must be a positive whole number of {unit}, not {value!r}")
