"""Signing in from a host's start and callback routes.

The tests drive a FastAPI host through a `TestClient` whose cookie jar is the
browser, against a stateful fake issuer that answers each code once.
"""

from __future__ import annotations

import base64
import secrets
import threading
import urllib.parse
from collections.abc import Callable
from concurrent.futures import ThreadPoolExecutor
from copy import deepcopy
from dataclasses import dataclass, replace
from datetime import timedelta

import pytest

from tests.support.oidc_arrangement import (
    ABSENT,
    ISSUED_ACCESS_TOKEN_CANARY,
    ISSUED_REFRESH_TOKEN,
    FakeClock,
    a_token_of_length,
    assert_holds_only_the_refresh_token,
)
from tests.support.oidc_login_host import (
    ADMIN_GROUP,
    LEGACY_ADMIN,
    LOGIN_GROUP,
    NOW,
    SAME_ORIGIN_FORM,
    OidcHost,
    a_client_config,
    after_signing_in,
    an_id_token,
    an_oidc_host,
    hint_of,
    is_cleared,
    post_logout,
    set_cookies,
    stored_id_tokens,
    stored_refresh_tokens,
)
from tests.support.oidc_relying_party import OUTSIDE_THE_REFRESH_TOKEN_GRAMMAR
from tests.support.webauth_arrangement import (
    FIXED_INSTANT,
    SESSION_IDLE_SECONDS,
    signed_without_bound,
)
from webauth.cookies import (
    PendingLogin,
    _pending_login_cookie_prefix,
    _sign_pending_login,
    _verify_pending_login,
)
from webauth.jwt_verification import MAX_TOKEN_CHARACTERS
from webauth.oidc import (
    PENDING_LOGIN_MAX_AGE_SECONDS,
)
from webauth.ports import (
    AccountEventKind,
)

MAX_PENDING_LOGIN_COOKIE_CHARS = 896
MAX_PENDING_LOGINS = 5


@pytest.mark.parametrize(("cookie_secure", "prefix", "secure_attribute"), [
    pytest.param(True, "__Host-oidc_pending_", {"secure"}, id="secure"),
    pytest.param(False, "oidc_pending_", set(), id="insecure-development"),
])
def test_a_start_sets_one_lax_http_only_pending_cookie_and_answers_the_issuer_url(
    *, cookie_secure: bool, prefix: str, secure_attribute: set[str],
) -> None:
    host = an_oidc_host(cookie_secure=cookie_secure)

    response = host.client.get("/login/oidc")

    url = response.headers["location"]
    assert response.status_code == 303
    assert url.startswith(a_client_config().authorization_endpoint + "?")
    name = host.pending_cookie_name(urllib.parse.urlsplit(url).query)
    assert name.startswith(prefix)
    assert set_cookies(response) == {
        name: {
            "httponly",
            f"max-age={PENDING_LOGIN_MAX_AGE_SECONDS}",
            "path=/",
            "samesite=lax",
            *secure_attribute,
        },
    }


def test_an_admitted_callback_signs_the_browser_in_with_the_configured_cookies() -> None:
    host = an_oidc_host()

    response = host.callback(host.sign_in_at_issuer())

    configured = {"path=/", f"max-age={host.config.session_lifetime.absolute_max_age_seconds}",
                  f"samesite={host.config.cookie_samesite}", "secure"}
    assert (response.status_code, response.headers["location"]) == (303, "/")
    assert set_cookies(response)[host.config.session_cookie_name] == configured | {"httponly"}
    assert set(host.client.cookies) == {host.config.session_cookie_name}
    assert host.client.get("/me").json() == {"username": "lena"}


def test_an_admitted_callback_stores_the_refresh_token_and_nothing_of_the_access_token() -> None:
    host = an_oidc_host()

    response = host.callback(host.sign_in_at_issuer())

    record = host.sessions.stored_record
    assert stored_refresh_tokens(host) == [ISSUED_REFRESH_TOKEN]
    visible = repr(record) + repr(host.sessions.list_active()) + str(response.headers)
    assert ISSUED_ACCESS_TOKEN_CANARY not in visible
    assert ISSUED_REFRESH_TOKEN not in visible
    assert_holds_only_the_refresh_token(record)


@pytest.mark.parametrize(("members", "stored"), [
    pytest.param({"refresh_token": ABSENT}, [], id="an-answer-without-a-refresh-token"),
    pytest.param(
        {"access_token": ABSENT, "token_type": ABSENT}, [ISSUED_REFRESH_TOKEN],
        id="an-answer-without-an-access-token",
    ),
    pytest.param({"refresh_token": " ~"}, [" ~"], id="a-refresh-token-at-the-grammars-ends"),
])
def test_an_admitted_callback_stores_what_the_code_answer_issued(
    members: dict[str, object], stored: list[str],
) -> None:
    host = an_oidc_host()
    host.issuer.code_answer_members.update(members)

    response = host.callback(host.sign_in_at_issuer())

    assert response.status_code == 303
    assert stored_refresh_tokens(host) == stored
    assert host.sessions.count_active() == 1


@pytest.mark.parametrize(
    "refresh_token",
    OUTSIDE_THE_REFRESH_TOKEN_GRAMMAR.values(),
    ids=list(OUTSIDE_THE_REFRESH_TOKEN_GRAMMAR),
)
def test_a_refresh_token_outside_the_grammar_refuses_the_login_and_provisions_nothing(
    refresh_token: object,
) -> None:
    host = an_oidc_host()
    host.issuer.code_answer_members["refresh_token"] = refresh_token

    response = host.callback(host.sign_in_at_issuer())

    assert (response.status_code, response.json()) == (403, {"refusal": "token-endpoint-failed"})
    assert host.sessions.count_active() == 0
    assert host.accounts.list() == []


@pytest.mark.parametrize(("seconds_into_the_instant", "seconds_per_reading"), [
    pytest.param(0.0, 0.0, id="a fixed clock"),
    pytest.param(0.9, 0.4, id="an advancing clock"),
])
def test_an_admitted_callback_opens_the_session_for_one_idle_from_one_whole_second_reading(
    seconds_into_the_instant: float, seconds_per_reading: float,
) -> None:
    clock = FakeClock(FIXED_INSTANT.timestamp() + seconds_into_the_instant, seconds_per_reading)
    host = an_oidc_host(wall_clock=clock)

    host.callback(host.sign_in_at_issuer())

    record = host.sessions.stored_record
    assert (record.created_at, record.expires_at) == (
        FIXED_INSTANT, FIXED_INSTANT + timedelta(seconds=SESSION_IDLE_SECONDS),
    )
    assert host.client.get("/me").json() == {"username": "lena"}


@pytest.mark.parametrize("cookie_secure", [True, False])
def test_the_callback_hands_the_browser_no_id_token_and_each_login_replaces_the_rows_token(
    *, cookie_secure: bool,
) -> None:
    host = an_oidc_host(cookie_secure=cookie_secure)
    host.callback(host.sign_in_at_issuer())

    response = host.callback(host.sign_in_at_issuer())

    first, second = host.issued_id_tokens
    shown = " ".join([
        repr(host.sessions.list_active()),
        *(value for _, value in response.headers.multi_items()),
    ])
    assert first != second
    assert second not in shown
    assert not [name for name in set_cookies(response) if "id_token" in name]
    assert stored_id_tokens(host) == [second]


def test_an_id_token_of_the_verifiers_longest_length_is_stored_and_sent_whole() -> None:
    host = an_oidc_host()
    host.issuer.mint_id_token = lambda nonce: a_token_of_length(
        MAX_TOKEN_CHARACTERS,
        lambda header_padding, groups_padding: an_id_token(
            nonce, host.wall_clock, [LOGIN_GROUP, groups_padding], header_padding,
        ),
    )
    host.callback(host.sign_in_at_issuer())
    [stored] = stored_id_tokens(host)

    response = post_logout(host, SAME_ORIGIN_FORM)

    assert (len(stored), hint_of(response)) == (MAX_TOKEN_CHARACTERS, stored)


@dataclass(frozen=True)
class RefusedCallback:
    """A callback that does not sign in: the callback query the browser brings
    back given the issuer's."""

    refusal: str
    groups_claim: object = (LOGIN_GROUP,)
    returned_query: Callable[[OidcHost, str], str] = lambda _host, query: query


def _with_another_code(_host: OidcHost, query: str) -> str:
    return query.replace("code=", "code=not-issued-")


def _after_the_pending_lifetime(host: OidcHost, query: str) -> str:
    host.wall_clock.now += PENDING_LOGIN_MAX_AGE_SECONDS + 1
    return query


def _with_the_code_twice(_host: OidcHost, query: str) -> str:
    return f"{query}&code=another"


def _with_an_undecodable_parameter(_host: OidcHost, query: str) -> str:
    return f"{query}&note=%ff"


_REFUSED_CALLBACKS = [
    pytest.param(
        RefusedCallback("token-request-refused", returned_query=_with_another_code),
        id="a code the issuer never issued",
    ),
    pytest.param(
        RefusedCallback("pending-login-expired", returned_query=_after_the_pending_lifetime),
        id="a pending login past its lifetime",
    ),
    pytest.param(
        RefusedCallback("malformed-callback", returned_query=_with_the_code_twice),
        id="its one state beside a code named twice",
    ),
    pytest.param(
        RefusedCallback("malformed-callback", returned_query=_with_an_undecodable_parameter),
        id="its one state beside an undecodable parameter",
    ),
    pytest.param(
        RefusedCallback("not-a-member", groups_claim=["/apps/other"]),
        id="a person in another app's group only",
    ),
    pytest.param(
        RefusedCallback("not-a-member", groups_claim=[]),
        id="a person whose groups claim is empty",
    ),
    pytest.param(
        RefusedCallback("invalid-identity-claim", groups_claim="/apps/lab"),
        id="a groups claim that is not a list",
    ),
]


@pytest.mark.parametrize("refused", _REFUSED_CALLBACKS)
def test_a_refused_callback_issues_no_session_leaves_no_account_and_consumes_its_cookie(
    refused: RefusedCallback,
) -> None:
    host = an_oidc_host(groups_claim=refused.groups_claim)
    other_tab = host.sign_in_at_issuer()
    query = host.sign_in_at_issuer()

    response = host.callback(refused.returned_query(host, query))

    assert (response.status_code, response.json()) == (403, {"refusal": refused.refusal})
    assert host.config.session_cookie_name not in set_cookies(response)
    assert host.sessions.count_active() == 0
    assert host.accounts.list() == []
    assert is_cleared(response, host.pending_cookie_name(query))
    assert host.pending_cookie_names() == {host.pending_cookie_name(other_tab)}


def test_a_callback_demotes_a_legacy_admin_without_the_admin_group() -> None:
    host = an_oidc_host(deepcopy(LEGACY_ADMIN))

    response = host.callback(host.sign_in_at_issuer())

    assert response.status_code == 303
    assert host.sessions.count_active() == 1
    assert host.client.get("/me").json() == {"username": "lena.legacy"}
    assert host.client.get("/admin").status_code == 403
    assert [event.kind for event in host.audit.account_events] == [
        AccountEventKind.ROLE_CHANGED,
    ]


def test_a_callback_keeps_a_legacy_admin_in_the_admin_group_as_admin() -> None:
    host = an_oidc_host(deepcopy(LEGACY_ADMIN), groups_claim=[ADMIN_GROUP])

    response = host.callback(host.sign_in_at_issuer())

    assert response.status_code == 303
    assert host.client.get("/admin").json() == {"username": "lena.legacy"}
    assert host.audit.account_events == []


@pytest.mark.parametrize(("before", "after", "status_before", "status_after"), [
    pytest.param([LOGIN_GROUP], [ADMIN_GROUP], 403, 200, id="put into the admin group"),
    pytest.param([ADMIN_GROUP], [LOGIN_GROUP], 200, 403, id="taken out of the admin group"),
])
def test_a_role_changed_at_login_reaches_the_persons_other_open_session_at_once(
    before: list[str], after: list[str], status_before: int, status_after: int,
) -> None:
    groups = list(before)
    host = an_oidc_host(groups_claim=groups)
    host.callback(host.sign_in_at_issuer())
    session_cookie = host.client.cookies[host.config.session_cookie_name]
    assert host.client.get("/admin").status_code == status_before

    groups[:] = after
    host.client.cookies.clear()
    host.callback(host.sign_in_at_issuer())
    host.client.cookies.clear()
    host.client.cookies.set(host.config.session_cookie_name, session_cookie)

    assert host.client.get("/admin").status_code == status_after


@pytest.mark.parametrize(("asked_for", "returned"), [
    pytest.param("/albums/42", "/albums/42", id="a deep link"),
    pytest.param("//evil.example", "/", id="another host"),
])
def test_a_login_returns_only_a_path_of_this_app_and_otherwise_the_app_root(
    asked_for: str, returned: str,
) -> None:
    host = an_oidc_host()

    response = host.callback(host.sign_in_at_issuer(return_to=asked_for))

    assert (response.status_code, response.headers["location"]) == (303, returned)


def test_a_login_started_without_a_return_path_lands_on_the_app_root() -> None:
    host = an_oidc_host()

    response = host.callback(host.sign_in_at_issuer())

    assert response.headers["location"] == "/"


@pytest.mark.parametrize("signed", ["//evil.example", "/albums/42#top"])
def test_a_return_path_signed_by_another_build_is_judged_again_at_the_callback(
    signed: str,
) -> None:
    host = an_oidc_host()
    query = host.sign_in_at_issuer()
    name = host.pending_cookie_name(query)
    pending = _verify_pending_login(host.client.cookies[name], host.config.signing_key)
    assert pending is not None
    resigned = _sign_pending_login(
        replace(pending, return_to=signed), host.config.signing_key,
    )

    response = host.callback(query, cookie=f"{name}={resigned}")

    assert (response.status_code, response.headers["location"]) == (303, "/")


def test_the_return_path_of_a_refused_login_is_not_handed_out() -> None:
    host = an_oidc_host(groups_claim=())

    response = host.callback(host.sign_in_at_issuer(return_to="/albums/42"))

    assert (response.status_code, "location" in response.headers) == (403, False)


def test_an_admitted_callback_consumes_its_cookie_and_keeps_the_other_tabs() -> None:
    host = an_oidc_host()
    other_tab = host.sign_in_at_issuer()
    query = host.sign_in_at_issuer()

    response = host.callback(query)

    assert response.status_code == 303
    assert is_cleared(response, host.pending_cookie_name(query))
    assert host.pending_cookie_names() == {host.pending_cookie_name(other_tab)}


def _tampered(host: OidcHost, query: str) -> str:
    cookie = host.pending_cookie(query)
    return cookie[:-1] + ("0" if cookie[-1] != "0" else "1")


def _signed_under_another_key(host: OidcHost, query: str) -> str:
    return _forged(host, query, NOW, secret=b"k" * 64)


def _signed_as_a_session(host: OidcHost, query: str) -> str:
    name, _, value = host.pending_cookie(query).partition("=")
    payload = value.rpartition(".")[0]
    return f"{name}={signed_without_bound(payload, host.config.signing_key)}"


def _oversized(host: OidcHost, query: str) -> str:
    return host.pending_cookie(query) + "0" * MAX_PENDING_LOGIN_COOKIE_CHARS


def _of_another_version(host: OidcHost, query: str) -> str:
    return host.pending_cookie(query).replace("=v2.", "=v3.", 1)


def _with_a_return_path_added_after_signing(host: OidcHost, query: str) -> str:
    name, _, value = host.pending_cookie(query).partition("=")
    *signed_fields, _return_path, signature = value.split(".")
    altered_path = base64.urlsafe_b64encode(b"/albums/42").decode().rstrip("=")
    return f"{name}={'.'.join([*signed_fields, altered_path, signature])}"


def _twice(host: OidcHost, query: str) -> str:
    cookie = host.pending_cookie(query)
    return f"{cookie}; {cookie}"


def _absent(_host: OidcHost, _query: str) -> str:
    return "unrelated=1"


def _another_logins_under_this_name(host: OidcHost, query: str) -> str:
    other_value = host.pending_cookie(host.sign_in_at_issuer()).partition("=")[2]
    return f"{host.pending_cookie_name(query)}={other_value}"


def _forged(host: OidcHost, query: str, issued_at: int, *, secret: bytes | None = None) -> str:
    """A pending login for the callback's state that the host never began."""
    [state] = urllib.parse.parse_qs(query)["state"]
    pending = PendingLogin(
        state=state,
        nonce=secrets.token_urlsafe(32),
        code_verifier=secrets.token_urlsafe(32),
        issued_at=issued_at,
    )
    value = _sign_pending_login(pending, secret or host.config.signing_key)
    return f"{host.pending_cookie_name(query)}={value}"


@pytest.mark.parametrize(("pending_cookie", "refusal"), [
    pytest.param(_absent, "state-mismatch", id="no pending cookie for the state"),
    pytest.param(_tampered, "state-mismatch", id="a tampered signature"),
    pytest.param(_signed_under_another_key, "state-mismatch", id="signed under another key"),
    pytest.param(_signed_as_a_session, "state-mismatch", id="signed as a session cookie"),
    pytest.param(_oversized, "state-mismatch", id="oversized"),
    pytest.param(_of_another_version, "state-mismatch", id="another version"),
    pytest.param(
        _with_a_return_path_added_after_signing, "state-mismatch",
        id="a return path altered after signing",
    ),
    pytest.param(_twice, "state-mismatch", id="the genuine cookie twice"),
    pytest.param(
        _another_logins_under_this_name, "state-mismatch",
        id="another login's genuine cookie under this state's name",
    ),
    pytest.param(
        lambda host, query: _forged(host, query, NOW - PENDING_LOGIN_MAX_AGE_SECONDS - 1),
        "pending-login-expired",
        id="signed but issued before the lifetime",
    ),
    pytest.param(
        lambda host, query: _forged(host, query, NOW + 1),
        "pending-login-expired",
        id="signed but dated in the future",
    ),
])
def test_an_invalid_pending_cookie_is_refused_before_any_token_request_and_cleared(
    pending_cookie: Callable[[OidcHost, str], str], refusal: str,
) -> None:
    host = an_oidc_host()
    query = host.sign_in_at_issuer()
    cookie = pending_cookie(host, query)

    response = host.callback(query, cookie=cookie)

    assert (response.status_code, response.json()) == (403, {"refusal": refusal})
    assert host.issuer.requests == []
    assert host.transaction.entries == 0
    assert is_cleared(response, host.pending_cookie_name(query))
    assert host.accounts.list() == []


@pytest.mark.parametrize(("returned_query", "refusal"), [
    pytest.param(lambda query: query.replace("state=", "other="), "state-mismatch",
                 id="without a state"),
    pytest.param(lambda query: f"{query}&{query.partition('&')[0]}", "malformed-callback",
                 id="naming its state twice"),
    pytest.param(lambda query: query.replace("state=", "state=&other=", 1), "state-mismatch",
                 id="naming an empty state"),
    pytest.param(lambda query: query.replace("state=", "state=%ff", 1), "malformed-callback",
                 id="naming an undecodable state"),
])
def test_a_callback_without_one_state_is_refused_and_selects_no_cookie(
    returned_query: Callable[[str], str], refusal: str,
) -> None:
    host = an_oidc_host()
    query = host.sign_in_at_issuer()

    response = host.callback(returned_query(query))

    assert (response.status_code, response.json()) == (403, {"refusal": refusal})
    assert host.issuer.requests == []
    assert host.transaction.entries == 0
    assert set_cookies(response) == {}
    assert host.pending_cookie_names() == {host.pending_cookie_name(query)}


def test_a_pending_login_is_single_use() -> None:
    host = an_oidc_host()
    query = host.sign_in_at_issuer()
    kept_cookie = host.pending_cookie(query)
    host.callback(query)

    replayed_by_the_browser = host.callback(query)
    replayed_with_a_kept_cookie = host.callback(query, cookie=kept_cookie)

    assert replayed_by_the_browser.json() == {"refusal": "state-mismatch"}
    assert replayed_with_a_kept_cookie.json() == {"refusal": "token-request-refused"}
    assert len(host.issuer.requests) == 2
    assert host.transaction.entries == 1
    assert host.sessions.count_active() == 1


def test_a_concurrent_replay_of_one_callback_signs_in_exactly_once() -> None:
    host = an_oidc_host()
    query = host.sign_in_at_issuer()
    cookie = host.pending_cookie(query)
    host.issuer.before_exchange = threading.Barrier(2, timeout=10).wait

    with ThreadPoolExecutor(max_workers=2) as pool:
        responses = list(pool.map(lambda _: host.callback(query, cookie=cookie), range(2)))

    assert sorted(response.status_code for response in responses) == [303, 403]
    [refused] = [response for response in responses if response.status_code == 403]
    assert refused.json() == {"refusal": "token-request-refused"}
    assert host.sessions.count_active() == 1
    assert len(host.accounts.list()) == 1


@pytest.mark.parametrize("second_returns_first", [False, True], ids=["in order", "reversed"])
def test_two_tabs_both_sign_in_and_the_later_session_replaces_the_earlier(
    *, second_returns_first: bool,
) -> None:
    host = an_oidc_host()
    tabs = [host.sign_in_at_issuer(), host.sign_in_at_issuer()]
    if second_returns_first:
        tabs.reverse()

    first, second = (host.callback(query) for query in tabs)

    assert (first.status_code, second.status_code) == (303, 303)
    assert host.sessions.count_active() == 1
    assert host.pending_cookie_names() == set()


def test_starts_beyond_the_cap_evict_the_oldest_pending_cookie_and_keep_the_session() -> None:
    host = after_signing_in(an_oidc_host())
    queries = []
    for _ in range(MAX_PENDING_LOGINS + 1):
        queries.append(host.sign_in_at_issuer())
        host.wall_clock.now += 1

    assert host.pending_cookie_names() == {host.pending_cookie_name(q) for q in queries[1:]}
    assert set(host.client.cookies) >= {host.config.session_cookie_name}
    assert host.client.get("/me").json() == {"username": "lena"}
    assert host.callback(queries[0]).json() == {"refusal": "state-mismatch"}


def _a_forged_pending_cookie(host: OidcHost) -> str:
    name = f"{_pending_login_cookie_prefix(secure=True)}{'f' * 16}"
    host.client.cookies.set(name, "v2.forged", domain="testserver.local", path="/")
    return name


def _the_newest_genuine_pending_cookie_twice(host: OidcHost) -> str:
    name = host.pending_cookie_name(host.sign_in_at_issuer())
    value = host.client.cookies[name]
    host.client.cookies.set(name, value, domain="testserver.local", path="/login")
    return name


@pytest.mark.parametrize("unranked_cookie", [
    pytest.param(_a_forged_pending_cookie, id="a forged value"),
    pytest.param(_the_newest_genuine_pending_cookie_twice, id="a name sent twice"),
])
def test_a_start_at_the_cap_evicts_an_unranked_pending_cookie_before_any_genuine_one(
    unranked_cookie: Callable[[OidcHost], str],
) -> None:
    host = an_oidc_host()
    for _ in range(MAX_PENDING_LOGINS - 1):
        host.sign_in_at_issuer()
        host.wall_clock.now += 1
    unranked = unranked_cookie(host)

    response = host.client.get("/login/oidc")

    assert [name for name in set_cookies(response) if is_cleared(response, name)] == [unranked]


def test_a_start_at_the_cap_leaves_a_prefixed_cookie_of_another_shape_alone() -> None:
    host = an_oidc_host()
    genuine = {host.pending_cookie_name(host.sign_in_at_issuer()) for _ in range(4)}
    stranger = f"{_pending_login_cookie_prefix(secure=True)}a@b"
    host.client.cookies.set(stranger, "x", domain="testserver.local", path="/")

    response = host.client.get("/login/oidc")

    newest = host.pending_cookie_name(
        urllib.parse.urlsplit(response.headers["location"]).query
    )
    assert host.pending_cookie_names() == genuine | {stranger, newest}
