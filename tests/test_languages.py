"""The language a person's page is answered in: the account's tag, the browser's header and the
app's languages, resolved by one pure function.

The expected answers come from RFC 4647 section 3.4 (Lookup), RFC 9110 section 12.5.4
(Accept-Language) and the host contract's LANGUAGE- sentences, never from the implementation.
"""

from __future__ import annotations

import pytest

from webauth.languages import AppLanguages, resolve_language


@pytest.fixture
def app_languages() -> AppLanguages:
    return AppLanguages(offered=("en", "de", "fr"), default="en")


def _answer(
    languages: AppLanguages, *, account: str | None = None, header: str | None = None
) -> str:
    return resolve_language(languages, account_tag=account, accept_language=header)


@pytest.mark.parametrize(
    "bad_tag",
    [
        "",
        "pt_BR",
        "x-private",
        "i-klingon",
        "de-*",
        "de-",
        "-de",
        "1de",
        "d",
        "de-ä",
        "de\n",
        "en US",
    ],
)
def test_an_offered_tag_or_default_not_in_shape_is_refused_when_the_app_languages_are_built(
    bad_tag: str,
) -> None:
    """LANGUAGE-01: each offered tag and the default is a tag in shape, else `ValueError`."""
    with pytest.raises(ValueError, match="language tag"):
        AppLanguages(offered=("en", bad_tag), default="en")


@pytest.mark.parametrize(
    ("offered", "default"),
    [(("en", "de"), "fr"), ((), "en"), (("en", "de"), "EN")],
    ids=["default-not-offered", "nothing-offered", "default-spelled-differently"],
)
def test_the_default_is_one_of_the_offered_tags_exactly_as_spelled(
    offered: tuple[str, ...], default: str
) -> None:
    """LANGUAGE-02: `default` is one of `offered` as spelled, else `ValueError`, even if none."""
    with pytest.raises(ValueError):
        AppLanguages(offered=offered, default=default)


@pytest.mark.parametrize(
    "offered", [("de", "DE", "en"), ("de-CH", "de-ch", "en"), ("de", "de", "en")]
)
def test_two_offered_tags_equal_ignoring_case_are_refused_when_the_app_languages_are_built(
    offered: tuple[str, ...],
) -> None:
    """LANGUAGE-03: offered tags equal ignoring case, one tag twice included, raise `ValueError`."""
    with pytest.raises(ValueError):
        AppLanguages(offered=offered, default="en")


@pytest.mark.parametrize(
    ("account", "header", "expected"),
    [("de", "fr", "de"), (None, "fr", "fr"), (None, None, "en")],
    ids=["account-beats-header", "header-beats-default", "default-when-nothing-answers"],
)
def test_the_account_tag_answers_before_the_header_and_the_header_before_the_default(
    app_languages: AppLanguages, account: str | None, header: str | None, expected: str
) -> None:
    """LANGUAGE-04: the account's tag, then the header's ranges, then the default answers."""
    assert _answer(app_languages, account=account, header=header) == expected


@pytest.mark.parametrize(
    ("header", "offered", "expected"),
    [
        ("de-DE-u-co-phonebk", ("de-DE-u-co", "en"), "de-DE-u-co"),
        ("de-DE-u-co-phonebk", ("de-DE", "de", "en"), "de-DE"),
        ("de-DE-u-co-phonebk", ("de", "en"), "de"),
        ("de-DE-u-co-phonebk", ("de-DE-u", "de", "en"), "de"),
        ("de-1-2996", ("de-1", "en"), "en"),
    ],
    ids=[
        "whole-range",
        "drops-subtags-to-a-match",
        "to-the-language",
        "singleton-goes-in-the-same-step",
        "digit-singleton-goes-too",
    ],
)
def test_a_range_loses_its_last_subtag_and_trailing_singletons_until_an_offered_tag_matches(
    header: str, offered: tuple[str, ...], expected: str
) -> None:
    """LANGUAGE-05: Lookup drops the last subtag and any singleton left at the end, and retries."""
    assert _answer(AppLanguages(offered=offered, default="en"), header=header) == expected


@pytest.mark.parametrize(
    ("header", "offered", "expected"),
    [
        ("de", ("de-CH", "en"), "en"),
        ("de-DE", ("de-CH", "en"), "en"),
        ("de-CH", ("de", "en"), "de"),
    ],
    ids=["less-specific-range", "other-region", "more-specific-range-finds-the-language"],
)
def test_a_range_never_matches_an_offered_tag_more_specific_than_itself(
    header: str, offered: tuple[str, ...], expected: str
) -> None:
    """LANGUAGE-06: a range never finds an offered tag more specific than itself."""
    assert _answer(AppLanguages(offered=offered, default="en"), header=header) == expected


@pytest.mark.parametrize(
    ("header", "offered", "expected"),
    [
        ("DE", ("de", "en"), "de"),
        ("de-de", ("de-DE", "en"), "de-DE"),
        ("EN-us", ("en", "de"), "en"),
    ],
)
def test_the_answer_is_the_offered_tag_as_the_app_spelled_it(
    header: str, offered: tuple[str, ...], expected: str
) -> None:
    """LANGUAGE-07: a tag given in another case is answered in the app's own spelling."""
    assert _answer(AppLanguages(offered=offered, default="en"), header=header) == expected


@pytest.mark.parametrize(
    ("header", "expected"),
    [
        ("fr;q=0.5, de;q=0.9", "de"),
        ("fr;q=0.5, de", "de"),
        ("fr, de", "fr"),
        ("de;q=0.8, fr;q=0.8", "de"),
        ("fr;q=0.501, de;q=0.5", "fr"),
        ("de ; q=0.5, fr;q=0.4", "de"),
        ("fr;q=1.000, de;q=0.9", "fr"),
    ],
    ids=[
        "heavier-later-wins",
        "no-weight-is-one",
        "tie-keeps-header-order",
        "tie-later-weight-equal",
        "three-decimals",
        "whitespace-before-q",
        "weight-one-with-decimals",
    ],
)
def test_the_header_answers_by_descending_weight_and_keeps_the_header_order_on_ties(
    app_languages: AppLanguages, header: str, expected: str
) -> None:
    """LANGUAGE-08: the header's ranges answer by descending weight, ties in header order."""
    assert _answer(app_languages, header=header) == expected


@pytest.mark.parametrize(
    ("header", "expected"),
    [("de;q=0", "en"), ("de;q=0, de", "de"), ("de;q=0, fr", "fr")],
    ids=[
        "alone-falls-to-default",
        "excludes-nothing-of-the-same-tag",
        "excludes-nothing-of-another-tag",
    ],
)
def test_a_range_with_weight_zero_is_skipped_and_excludes_nothing(
    app_languages: AppLanguages, header: str, expected: str
) -> None:
    """LANGUAGE-09: an element with weight 0 is skipped and excludes no other element."""
    assert _answer(app_languages, header=header) == expected


@pytest.mark.parametrize(
    ("header", "expected"),
    [("*", "en"), ("*, fr;q=0.5", "fr"), ("*;q=0.9, de;q=0.1", "de")],
    ids=["alone-falls-to-default", "after-a-lower-range", "heavier-than-the-range"],
)
def test_the_wildcard_range_is_skipped(
    app_languages: AppLanguages, header: str, expected: str
) -> None:
    """LANGUAGE-10: `*` is skipped, whatever its weight."""
    assert _answer(app_languages, header=header) == expected


@pytest.mark.parametrize(
    ("header", "expected"),
    [
        ("de-*, fr", "fr"),
        ("pt_BR;q=0.9, fr;q=0.5", "fr"),
        ("de;q=2, fr", "fr"),
        ("de;q=x, fr", "fr"),
        ("de;q=1.5, fr", "fr"),
        ("de;q=0.1234, fr;q=0.5", "fr"),
        ("de;level=1, fr", "fr"),
    ],
    ids=[
        "bad-range",
        "bad-range-with-weight",
        "weight-above-one",
        "weight-not-a-number",
        "weight-above-one-decimal",
        "weight-four-decimals",
        "parameter-not-weight",
    ],
)
def test_a_malformed_element_is_dropped_alone_and_the_rest_of_the_header_counts(
    app_languages: AppLanguages, header: str, expected: str
) -> None:
    """LANGUAGE-11: an element with a range not in shape or a malformed weight is dropped alone."""
    assert _answer(app_languages, header=header) == expected


@pytest.mark.parametrize(
    "account",
    [None, "", "pt_BR", "x-private", "i-klingon", "de-ä", " de", "es"],
    ids=[
        "none",
        "empty",
        "underscore",
        "private-use",
        "klingon",
        "non-ascii",
        "leading-space",
        "matches-nothing",
    ],
)
def test_an_account_tag_that_is_absent_or_matches_nothing_lets_the_header_decide(
    app_languages: AppLanguages, account: str | None
) -> None:
    """LANGUAGE-12: an account tag that is none, not in shape or unmatched counts as absent."""
    assert _answer(app_languages, account=account, header="fr") == "fr"
