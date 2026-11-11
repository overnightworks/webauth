"""The account's language tag, read from a verified ID token's claims."""

from __future__ import annotations

from typing import TYPE_CHECKING

from webauth.ports import MAX_ACCOUNT_LANGUAGE_CHARS

if TYPE_CHECKING:
    from collections.abc import Mapping

__all__ = ["account_language_claim"]


def account_language_claim(claims: Mapping[str, object]) -> str | None:
    """The ``locale`` claim as the issuer gave it, or ``None`` when it is missing, no string,
    empty or longer than ``MAX_ACCOUNT_LANGUAGE_CHARS``. Never refuses: a claim webauth
    cannot keep reads as no language."""
    locale = claims.get("locale")
    if isinstance(locale, str) and 0 < len(locale) <= MAX_ACCOUNT_LANGUAGE_CHARS:
        return locale
    return None
