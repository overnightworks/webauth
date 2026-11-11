"""The language a person's page is answered in, resolved from the account's tag, the browser's
``Accept-Language`` header and the app's own languages.

``resolve_language`` is the one decider of that order and holds no state and does no I/O. It
answers one of the app's offered tags, as the app spelled it, or the app's default.
``is_language_tag`` is the one owner of what a language tag looks like.
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from typing import TypeIs

__all__ = ["AppLanguages", "is_language_tag", "resolve_language"]

_LANGUAGE_TAG = re.compile(r"[A-Za-z]{2,8}(-[A-Za-z0-9]{1,8})*")
_WEIGHT = re.compile(r"[qQ]=(0(?:\.[0-9]{0,3})?|1(?:\.0{0,3})?)")
_OWS = " \t"


def is_language_tag(value: object) -> TypeIs[str]:
    """Whether ``value`` is a string of letters and digits joined by hyphens, the first subtag of
    2 to 8 letters and each later one of 1 to 8 letters or digits."""
    return isinstance(value, str) and _LANGUAGE_TAG.fullmatch(value) is not None


@dataclass(frozen=True)
class AppLanguages:
    """The languages an app answers in: ``offered`` as the app spells them, and the ``default``,
    which is one of them."""

    offered: tuple[str, ...]
    default: str

    def __post_init__(self) -> None:
        object.__setattr__(self, "offered", tuple(self.offered))
        for tag in (*self.offered, self.default):
            if not is_language_tag(tag):
                raise ValueError(f"not a language tag in shape: {tag!r}")
        if self.default not in self.offered:
            raise ValueError(f"default {self.default!r} is not one of the offered languages")
        if len({tag.lower() for tag in self.offered}) != len(self.offered):
            raise ValueError("two offered languages are equal ignoring case")


def resolve_language(
    languages: AppLanguages,
    *,
    account_tag: str | None,
    accept_language: str | None,
) -> str:
    """The app's language for one request: the first of the account's tag and the header's
    ranges, heaviest first, that finds an offered tag, or the default."""
    spelled_by_lowercase = {tag.lower(): tag for tag in languages.offered}
    for candidate in _candidate_ranges(account_tag, accept_language):
        spelled = _spelled_match(spelled_by_lowercase, candidate)
        if spelled is not None:
            return spelled
    return languages.default


def _candidate_ranges(account_tag: str | None, accept_language: str | None) -> list[str]:
    ranges = _acceptable_ranges(accept_language)
    if is_language_tag(account_tag):
        return [account_tag, *ranges]
    return ranges


def _spelled_match(spelled_by_lowercase: dict[str, str], language_range: str) -> str | None:
    """RFC 4647 Lookup: the range as given, then with its last subtag and any singleton left at
    the end removed, until an offered tag matches ignoring case or nothing is left."""
    subtags = language_range.split("-")
    while True:
        spelled = spelled_by_lowercase.get("-".join(subtags).lower())
        if spelled is not None or len(subtags) == 1:
            return spelled
        subtags.pop()
        while len(subtags) > 1 and len(subtags[-1]) == 1:
            subtags.pop()


def _acceptable_ranges(accept_language: str | None) -> list[str]:
    """RFC 9110 section 12.5.4: the header's ranges with a weight above 0, heaviest first, equal
    weights in header order. A malformed element is dropped alone."""
    if accept_language is None:
        return []
    weighted = [
        parsed
        for element in accept_language.split(",")
        if (parsed := _weighted_range(element)) is not None and parsed[1] > 0
    ]
    weighted.sort(key=lambda pair: -pair[1])
    return [language_range for language_range, _weight in weighted]


def _weighted_range(element: str) -> tuple[str, float] | None:
    language_range, *parameters = element.split(";")
    language_range = language_range.strip(_OWS)
    if not is_language_tag(language_range):
        return None
    if not parameters:
        return language_range, 1.0
    if len(parameters) == 1 and (weight := _WEIGHT.fullmatch(parameters[0].strip(_OWS))) is not None:
        return language_range, float(weight.group(1))
    return None
