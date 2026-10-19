"""The one decider of which addresses a browser may be sent back to.

A return path is a same-origin path of this app, written the way the app saw
it on the wire: raw, percent-encoded, with ``root_path`` in front. Everything
else is ``None``, so a caller falls back to its default page and never sends a
browser to another site.
"""

from __future__ import annotations

import re
from typing import TYPE_CHECKING, Final
from urllib.parse import quote, quote_from_bytes

if TYPE_CHECKING:
    from starlette.requests import HTTPConnection

__all__ = []

MAX_RETURN_PATH_BYTES: Final = 512
_BROWSER_STRIPPED_CHARACTERS = str.maketrans("", "", "\t\r\n")
_ANOTHER_HOST_PREFIXES = ("//", "/\\", "\\/", "\\\\")
_CONTROL_CHARACTER: Final = re.compile(r"[\x00-\x1f\x7f]")
_FRAGMENT_MARK: Final = "#"
_ALREADY_ASCII_SAFE: Final = "".join(chr(code) for code in range(0x21, 0x7F))
_PATH_ENDS: Final = ("/", "?")
_SEGMENT_SEPARATORS: Final = re.compile(r"[/\\]")
_DOT_SEGMENT: Final = re.compile(r"(?:\.|%2e){1,2}", re.IGNORECASE)


def reads_as_another_host(path: str) -> bool:
    """Whether a browser reads ``path`` as an address on another host.

    Browsers drop tab, CR and LF and treat a backslash as a slash, so ``/\\x``
    and ``/<tab>/x`` lead off the site exactly as ``//x`` does.
    """
    return path.translate(_BROWSER_STRIPPED_CHARACTERS).startswith(_ANOTHER_HOST_PREFIXES)


def same_app_path(connection: HTTPConnection, candidate: str | None) -> str | None:
    """``candidate`` as an ASCII path of the app serving ``connection``, or ``None``.

    The app is the one running the connection's route, so a login inside a
    mounted sub-app judges against that mount's ``root_path``. Non-ASCII
    characters are percent-encoded; the cap on length applies to that encoded
    form. A browser resolves ``.`` and ``..`` segments before it sends a
    request, so a path carrying one is not a deep link and is refused; so is a
    literal ``#``, which a browser reads as the start of a fragment before it
    resolves those segments and which a request never carries.
    """
    root_path = connection.scope.get("root_path", "")
    if not candidate or not candidate.startswith("/") or _CONTROL_CHARACTER.search(candidate):
        return None
    if _FRAGMENT_MARK in candidate:
        return None
    if reads_as_another_host(candidate) or not _is_under(root_path, candidate):
        return None
    if _has_dot_segment(candidate):
        return None
    try:
        encoded = quote_from_bytes(candidate.encode("utf-8"), safe=_ALREADY_ASCII_SAFE)
    except UnicodeEncodeError:
        return None
    return encoded if len(encoded) <= MAX_RETURN_PATH_BYTES else None


def requested_address(connection: HTTPConnection) -> str:
    """The raw path and raw query the app was asked for, ``root_path`` included."""
    scope = connection.scope
    raw_path = scope.get("raw_path") or quote(scope["path"]).encode()
    encoded_root = quote(scope.get("root_path", "")).encode()
    if not _carries_root(raw_path, encoded_root):
        raw_path = encoded_root + raw_path
    address = raw_path.decode("utf-8", errors="surrogateescape")
    query = scope.get("query_string", b"").decode("utf-8", errors="surrogateescape")
    return f"{address}?{query}" if query else address


def _carries_root(raw_path: bytes, encoded_root: bytes) -> bool:
    if not encoded_root or not raw_path.startswith(encoded_root):
        return not encoded_root
    return raw_path[len(encoded_root):len(encoded_root) + 1] in (b"", b"/")


def _has_dot_segment(path: str) -> bool:
    segments = _SEGMENT_SEPARATORS.split(path.partition("?")[0])
    return any(_DOT_SEGMENT.fullmatch(segment) for segment in segments)


def _is_under(root_path: str, path: str) -> bool:
    return (
        not root_path
        or path == root_path
        or path.startswith(tuple(root_path + end for end in _PATH_ENDS))
    )
