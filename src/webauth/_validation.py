"""The well-formedness checks that configuration, documents and claims share."""

from __future__ import annotations

import json
import re
from collections.abc import Mapping
from typing import TypeGuard

__all__: list[str] = []


# RFC 6749 section 3.3: a scope token is one or more printable ASCII
# characters other than space, `"` and `\`.
_SCOPE_TOKEN = re.compile(r"[\x21\x23-\x5b\x5d-\x7e]+")


def is_scope_token_tuple(scopes: object) -> TypeGuard[tuple[str, ...]]:
    """Whether ``scopes`` is a tuple whose every item is one RFC 6749 scope token."""
    return isinstance(scopes, tuple) and all(
        isinstance(scope, str) and _SCOPE_TOKEN.fullmatch(scope) for scope in scopes
    )


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


def is_whole_number(value: object) -> TypeGuard[int]:
    """Whether ``value`` is an ``int`` and not a ``bool``."""
    return isinstance(value, int) and not isinstance(value, bool)


def json_object(document: bytes) -> dict[str, object] | None:
    """The JSON object `document` holds, or `None` for anything else. The
    issuer is trusted for what it serves, so the stdlib parser reads it as is:
    a member named twice keeps its last value."""
    try:
        parsed = json.loads(document)
    except ValueError, RecursionError:
        return None
    return parsed if isinstance(parsed, dict) else None


def string_list_claim(claims: Mapping[str, object], claim_name: str) -> list[str] | None:
    """The strings the claim lists (none when missing), or `None` when it is no list of strings."""
    value = claims.get(claim_name, [])
    if not isinstance(value, list) or not all(isinstance(item, str) for item in value):
        return None
    return value


def require_non_negative_whole_number(field: str, value: object, *, unit: str) -> None:
    """Refuse a quantity that is not a whole number of ``unit`` from zero up."""
    if not is_whole_number(value) or value < 0:
        raise ValueError(f"{field} must be a whole number of {unit} from 0 up, not {value!r}")


def require_positive_whole_number(field: str, value: object, *, unit: str) -> None:
    """Refuse a quantity that is not a positive whole number of ``unit``.

    A zero or negative lifetime or window would not fail loudly later: it
    would expire every session at once, or make a limiter admit every request.
    """
    if not is_whole_number(value) or value <= 0:
        raise ValueError(f"{field} must be a positive whole number of {unit}, not {value!r}")


def require_collection_not_one_string(
    field: str,
    value: object,
    *,
    noun: str,
    example: str | None = None,
) -> None:
    """Refuse one string where a collection of ``noun`` belongs.

    Membership in a string is a substring test, so ``"/hooks/stripe"`` would
    admit ``"/"`` and ``"XPOST"`` would admit ``"POST"``.
    """
    if isinstance(value, str):
        hint = f", for example {example}" if example else ""
        raise ValueError(
            f"{field} must be a collection of {noun}s, not one string; "
            f"list each {noun} in a collection{hint}",
        )
