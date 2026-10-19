"""Whether a request asks for an HTML page rather than a JSON answer."""

from __future__ import annotations

from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from starlette.requests import Request


def prefers_html(request: Request) -> bool:
    accept = request.headers.get("accept", "")
    if not accept:
        return False
    return _accepted_quality(accept, "text/html") > _accepted_quality(accept, "application/json")


def _media_range_and_quality(entry: str) -> tuple[str, float]:
    type_part, *params = entry.split(";")
    quality = 1.0
    for param in params:
        name, _, value = param.strip().partition("=")
        if name.strip() == "q":
            try:
                quality = float(value.strip())
            except ValueError:
                quality = 1.0
    return type_part.strip(), quality


def _accepted_quality(accept_header: str, media_type: str) -> float:
    """The quality ``accept_header`` assigns ``media_type``: exact, wildcard, or 0.

    An entry naming ``media_type`` exactly wins outright; a type or ``*/*``
    wildcard sets the floor everything unnamed falls back to; a ``media_type``
    neither named nor covered by a wildcard is not accepted at all.
    """
    main_type, _, _ = media_type.partition("/")
    wildcard_quality = 0.0
    for raw_entry in accept_header.split(","):
        entry = raw_entry.strip()
        if not entry:
            continue
        type_part, quality = _media_range_and_quality(entry)
        if type_part == media_type:
            return quality
        if type_part in (f"{main_type}/*", "*/*"):
            wildcard_quality = max(wildcard_quality, quality)
    return wildcard_quality
