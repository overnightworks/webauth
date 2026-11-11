"""The account's language at the issuer: read from the ID token at sign-in, kept on the session
row, and answered for a request by one read-only function.

The expected answers come from the host contract's LANGUAGE- sentences and RFC 5646 section
4.4.1 (an implementation supports tags of at least 35 characters), never from the implementation.
Each case signs in through a host's callback route over the shared in-memory store.
"""

from __future__ import annotations

from collections.abc import Callable
from datetime import timedelta

import pytest
from starlette.requests import Request

from tests.support.gate_arrangement import (
    A_TOKEN,
    MACHINE_LANGUAGE_PATH,
    a_bearer_app,
    bearing,
)
from tests.support.oidc_arrangement import ABSENT, FakeClock
from tests.support.oidc_login_host import (
    LANGUAGE_PATH,
    SUBJECT,
    OidcHost,
    StoreDown,
    an_oidc_host,
    failing,
)
from tests.support.webauth_arrangement import FIXED_INSTANT, SESSION_IDLE_SECONDS
from webauth.dependencies import account_language_of_session, admit_session
from webauth.oidc_login import fresh_access_token
from webauth.ports import SessionRecord

LONGEST_TAG_EVERY_IMPLEMENTATION_SUPPORTS = 35
THE_LONGEST_TAG = "a" * LONGEST_TAG_EVERY_IMPLEMENTATION_SUPPORTS
ONE_CHARACTER_TOO_MANY = "a" * (LONGEST_TAG_EVERY_IMPLEMENTATION_SUPPORTS + 1)
CLAIMS_NOT_KEPT = {
    "a number": 42,
    "a list": ["de"],
    "the empty string": "",
    "one character past the bound": ONE_CHARACTER_TOO_MANY,
}


def signed_in(*, locale_claim: object) -> tuple[OidcHost, SessionRecord, FakeClock]:
    clock = FakeClock(FIXED_INSTANT.timestamp())
    host = an_oidc_host(locale_claim=locale_claim, wall_clock=clock)
    assert host.callback(host.sign_in_at_issuer()).status_code == 303
    return host, host.sessions.stored_record, clock


@pytest.mark.parametrize(
    ("claim", "stored"),
    [
        pytest.param("de-CH", "de-CH", id="a tag"),
        pytest.param(THE_LONGEST_TAG, THE_LONGEST_TAG, id="the longest tag kept"),
        pytest.param(ABSENT, None, id="no claim"),
        *[pytest.param(claim, None, id=name) for name, claim in CLAIMS_NOT_KEPT.items()],
    ],
)
def test_the_sign_in_keeps_the_locale_claim_of_at_most_35_characters_and_else_none(
    claim: object, stored: str | None
) -> None:
    """LANGUAGE-13: the ID token's `locale` claim is the account's language when it is a non-empty
    string of at most 35 characters, and `None` otherwise."""
    _host, session, _clock = signed_in(locale_claim=claim)

    assert session.account_language == stored


@pytest.mark.parametrize("claim", ["pt_BR", "DE-ch", " de", "x-private", "i-klingon", "de-*"])
def test_the_tag_is_kept_as_the_issuer_gave_it(claim: str) -> None:
    """LANGUAGE-14: webauth neither checks the tag's shape nor normalises it."""
    _host, session, _clock = signed_in(locale_claim=claim)

    assert session.account_language == claim


@pytest.mark.parametrize("claim", CLAIMS_NOT_KEPT.values(), ids=CLAIMS_NOT_KEPT)
def test_a_locale_claim_never_refuses_the_sign_in(claim: object) -> None:
    """LANGUAGE-15: a `locale` claim that cannot be kept reads as no language, and the sign-in
    still opens its session."""
    host = an_oidc_host(locale_claim=claim)

    response = host.callback(host.sign_in_at_issuer())

    assert (response.status_code, host.sessions.count_active()) == (303, 1)


def _renewed_by_the_gate(host: OidcHost, session: SessionRecord, clock: FakeClock) -> None:
    clock.now += SESSION_IDLE_SECONDS / 2
    admit_session(session.id, sessions=host.sessions, config=host.config)


def _rotated_with_the_issuer(host: OidcHost, session: SessionRecord, _clock: FakeClock) -> None:
    fresh_access_token(
        host.relying_party,
        session.id,
        session_transaction=host.sessions.in_transaction,
        config=host.config,
    )


def _touched(host: OidcHost, session: SessionRecord, _clock: FakeClock) -> None:
    host.sessions.touch(session.id, expires_at=session.expires_at + timedelta(minutes=1))


@pytest.mark.parametrize(
    ("write", "changed_member"),
    [
        pytest.param(_renewed_by_the_gate, "expires_at", id="renewal by the gate"),
        pytest.param(_rotated_with_the_issuer, "refresh_token", id="refresh-token rotation"),
        pytest.param(_touched, "expires_at", id="touch"),
    ],
)
def test_nothing_after_the_sign_in_writes_the_language_again(
    write: Callable[[OidcHost, SessionRecord, FakeClock], None], changed_member: str
) -> None:
    """LANGUAGE-16: the language is written once, when the callback creates the session."""
    host, session, clock = signed_in(locale_claim="de-CH")
    before = (session.account_language, getattr(session, changed_member))

    write(host, session, clock)

    after = host.sessions.stored_record
    assert after.account_language == before[0] == "de-CH"
    assert getattr(after, changed_member) != before[1]


def test_the_function_answers_the_language_of_the_session_the_request_carries() -> None:
    """LANGUAGE-17: a request with a live session's cookie reads the account's language."""
    host, _session, clock = signed_in(locale_claim="de-CH")

    assert host.account_language() == "de-CH"


def _without_a_cookie(host: OidcHost, _clock: FakeClock) -> None:
    host.client.cookies.clear()


def _with_a_forged_cookie(host: OidcHost, _clock: FakeClock) -> None:
    host.client.cookies.clear()
    host.client.cookies.set(host.config.session_cookie_name, "forged.value")


def _with_the_row_gone(host: OidcHost, _clock: FakeClock) -> None:
    host.sessions.delete_for_user(SUBJECT)


def _with_the_row_expired(_host: OidcHost, clock: FakeClock) -> None:
    clock.now += SESSION_IDLE_SECONDS + 1


@pytest.mark.parametrize(
    "spoil",
    [
        pytest.param(_without_a_cookie, id="no cookie"),
        pytest.param(_with_a_forged_cookie, id="a forged cookie"),
        pytest.param(_with_the_row_gone, id="a row the store does not know"),
        pytest.param(_with_the_row_expired, id="a row outside its lifetime"),
    ],
)
def test_the_function_answers_none_when_the_request_names_no_live_session(
    spoil: Callable[[OidcHost, FakeClock], None],
) -> None:
    """LANGUAGE-18: no cookie, a forged one, an unknown row and an expired row read `None`."""
    host, _session, clock = signed_in(locale_claim="de-CH")
    assert host.account_language() == "de-CH"

    spoil(host, clock)

    assert host.account_language() is None


def test_the_function_answers_none_to_a_request_the_bearer_gate_admitted() -> None:
    """LANGUAGE-18: a request admitted by its bearer token carries no session, its cookie
    notwithstanding."""
    app = a_bearer_app()
    app.auth.sessions.stored_record.account_language = "de-CH"

    response = app.ask(MACHINE_LANGUAGE_PATH, authorization=bearing(A_TOKEN), cookie=True)

    assert (response.status_code, response.json()) == (200, {"language": None})


def test_the_function_only_loads_and_never_renews_or_sets_a_cookie() -> None:
    """LANGUAGE-19: the read leaves the row's `expires_at` as it is and sets no cookie, where a
    request the gate admits at the same instant renews it."""
    host, session, clock = signed_in(locale_claim="de-CH")
    expiry = session.expires_at
    clock.now += SESSION_IDLE_SECONDS / 2

    response = host.client.get(LANGUAGE_PATH)

    assert response.json() == {"language": "de-CH"}
    assert "set-cookie" not in response.headers
    assert host.sessions.stored_record.expires_at == expiry
    admit_session(session.id, sessions=host.sessions, config=host.config)
    assert host.sessions.stored_record.expires_at > expiry


def test_a_failing_store_lets_the_function_raise(monkeypatch: pytest.MonkeyPatch) -> None:
    """LANGUAGE-20: a store that cannot load raises; the function never answers `None` for it."""
    host, _session, clock = signed_in(locale_claim="de-CH")
    cookie = host.client.cookies[host.config.session_cookie_name]
    request = Request(
        {
            "type": "http",
            "method": "GET",
            "path": "/",
            "headers": [(b"cookie", f"{host.config.session_cookie_name}={cookie}".encode())],
        }
    )
    failing(host.sessions, "load", monkeypatch)

    with pytest.raises(StoreDown):
        account_language_of_session(request, sessions=host.sessions, config=host.config)
