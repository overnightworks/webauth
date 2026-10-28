"""Form logout from a host's logout route, through the same host and fake issuer."""

from __future__ import annotations

import urllib.parse
from collections.abc import Callable
from datetime import UTC, datetime, timedelta

import pytest
from fastapi import HTTPException, Request
from httpx import Response as HttpxResponse
from pydantic import SecretStr

from tests.support.oidc_arrangement import (
    FakeClock,
    LogoutPage,
    a_fake_id_token,
)
from tests.support.oidc_login_host import (
    CLIENT_ID,
    END_SESSION_ENDPOINT,
    LOGOUT_BUTTON_LABEL,
    LOGOUT_PATH,
    NOW,
    SAME_ORIGIN_FORM,
    SUBJECT,
    OidcHost,
    StoreDown,
    TransactionKind,
    a_client_config,
    after_signing_in,
    an_oidc_host,
    failing,
    hint_of,
    is_cleared,
    post_logout,
    set_cookies,
    stored_id_tokens,
    stored_refresh_tokens,
)
from tests.support.webauth_arrangement import (
    HTTPS_TEST_SERVER,
    SESSION_IDLE_SECONDS,
)
from webauth.oidc import OidcRelyingParty
from webauth.oidc_login import (
    fresh_access_token,
)

BOUND_ISSUER_ORIGIN = "https://id.example"
OLD_HINT_COOKIE_NAME = "__Secure-oidc_id_token_hint"  # noqa: S105
OLD_CSRF_COOKIE_NAME = "__Host-csrf_token"  # noqa: S105


def content_security_policy_of(response: HttpxResponse) -> dict[str, list[str]]:
    directives = (
        directive.split() for directive in response.headers["content-security-policy"].split("; ")
    )
    return {name: sources for name, *sources in directives}


def test_the_logout_page_posts_the_client_and_the_hint_to_the_end_session_endpoint() -> None:
    host = after_signing_in(an_oidc_host())

    response = post_logout(host, SAME_ORIGIN_FORM)

    page = LogoutPage(response.text)
    assert response.status_code == 200
    assert response.headers["content-type"] == "text/html; charset=utf-8"
    assert page.attributes_of("form") == [{"method": "post", "action": END_SESSION_ENDPOINT}]
    assert page.attributes_of("input") == [
        {"type": "hidden", "name": "client_id", "value": CLIENT_ID},
        {
            "type": "hidden",
            "name": "post_logout_redirect_uri",
            "value": a_client_config().post_logout_redirect_uri,
        },
        {"type": "hidden", "name": "id_token_hint", "value": host.issued_id_tokens[-1]},
    ]
    assert page.attributes_of("button") == [{"type": "submit"}]
    assert (page.texts["button"], page.texts["title"]) == (LOGOUT_BUTTON_LABEL, LOGOUT_BUTTON_LABEL)
    assert {tag for tag, _ in page.elements} == {
        "html", "head", "meta", "title", "body", "form", "input", "button", "script",
    }


def test_the_logout_policy_admits_the_one_inline_script_by_hash_and_posts_to_two_origins() -> None:
    host = after_signing_in(an_oidc_host())

    response = post_logout(host, SAME_ORIGIN_FORM)

    page = LogoutPage(response.text)
    policy = content_security_policy_of(response)
    assert policy["script-src"] == [page.script_source]
    assert policy["form-action"] == [BOUND_ISSUER_ORIGIN, HTTPS_TEST_SERVER]
    assert [name for _, attributes in page.elements for name in attributes
            if name.startswith("on")] == []


def test_rotation_and_renewal_keep_the_logins_id_token_for_the_logout() -> None:
    session_clock = FakeClock(float(NOW))
    host = after_signing_in(an_oidc_host(wall_clock=session_clock))
    login_token = host.issued_id_tokens[-1]
    host.issuer.refresh_answer_members = {"id_token": a_fake_id_token("issued-by-the-refresh")}
    [session] = host.sessions.list_active()
    expiry_before_renewal = session.expires_at
    session_clock.now += SESSION_IDLE_SECONDS / 2

    renewed = host.client.get("/me")
    rotated = fresh_access_token(
        host.relying_party, session.id,
        session_transaction=host.sessions.in_transaction, config=host.config,
    )
    held_after_rotation = stored_id_tokens(host)
    response = post_logout(host, SAME_ORIGIN_FORM)

    assert (renewed.status_code, isinstance(rotated, SecretStr)) == (200, True)
    assert session.expires_at > expiry_before_renewal
    assert held_after_rotation == [login_token]
    assert hint_of(response) == login_token


def the_session_cookie_is_cleared(host: OidcHost, response: HttpxResponse) -> bool:
    return is_cleared(response, host.config.session_cookie_name)


def test_the_answer_carries_the_rows_token_ends_the_row_and_sets_only_clearings() -> None:
    host = after_signing_in(an_oidc_host())
    record = host.sessions.stored_record
    record.id_token = SecretStr(a_fake_id_token("held-by-the-row"))
    [rows_token] = stored_id_tokens(host)

    response = post_logout(host, SAME_ORIGIN_FORM)

    header_values = " ".join(value for _, value in response.headers.multi_items())
    assert set(set_cookies(response)) == {host.config.session_cookie_name}
    assert the_session_cookie_is_cleared(host, response)
    assert "location" not in response.headers
    assert rows_token not in header_values
    assert hint_of(response) == rows_token
    assert (host.sessions.count_active(), stored_id_tokens(host), stored_refresh_tokens(host)) == (
        0, [], [],
    )


def _no_session(_host: OidcHost) -> dict[str, str]:
    return {}


def _forged_session_cookie(host: OidcHost) -> dict[str, str]:
    name = host.config.session_cookie_name
    forged = f"{name}={host.client.cookies[name]}tampered"
    host.client.cookies.clear()
    return {"cookie": forged}


def _session_cookie_dropped(host: OidcHost) -> dict[str, str]:
    host.client.cookies.delete(host.config.session_cookie_name)
    return {}


def _session_ended_in_the_store(host: OidcHost) -> dict[str, str]:
    host.sessions.delete_for_user(SUBJECT)
    return {}


def _session_expired_but_stored(host: OidcHost) -> dict[str, str]:
    record = host.sessions.stored_record
    record.expires_at = datetime.now(UTC) - timedelta(days=1)
    return {}


def _row_stored_before_the_upgrade(host: OidcHost) -> dict[str, str]:
    record = host.sessions.stored_record
    record.id_token = None
    return {}


@pytest.mark.parametrize(("arrange", "sessions_kept", "hint_sent", "entered"), [
    pytest.param(_no_session, 0, False, False, id="no-session"),
    pytest.param(_forged_session_cookie, 1, False, False, id="forged-cookie-ends-nothing"),
    pytest.param(_session_cookie_dropped, 1, False, False, id="session-cookie-gone"),
    pytest.param(_session_ended_in_the_store, 0, False, True, id="session-already-ended"),
    pytest.param(_session_expired_but_stored, 0, True, True, id="session-expired-but-stored"),
    pytest.param(_row_stored_before_the_upgrade, 0, False, True, id="stored-before-upgrade"),
])
def test_a_same_origin_logout_still_answers_the_page(
    arrange: Callable[[OidcHost], dict[str, str]],
    sessions_kept: int,
    *,
    hint_sent: bool,
    entered: bool,
) -> None:
    host = an_oidc_host()
    if arrange is not _no_session:
        host.callback(host.sign_in_at_issuer())
    extra_headers = arrange(host)
    entries_before = host.transaction.entries

    response = post_logout(host, {**SAME_ORIGIN_FORM, **extra_headers})

    page = LogoutPage(response.text)
    assert response.status_code == 200
    assert page.attributes_of("form") == [{"method": "post", "action": END_SESSION_ENDPOINT}]
    assert hint_of(response) == (host.issued_id_tokens[-1] if hint_sent else None)
    assert the_session_cookie_is_cleared(host, response)
    assert host.sessions.count_active() == sessions_kept
    assert host.transaction.entries - entries_before == entered


@pytest.mark.parametrize("old_cookie_name", [OLD_HINT_COOKIE_NAME, OLD_CSRF_COOKIE_NAME])
@pytest.mark.parametrize("signed_in", [True, False])
def test_an_old_cookie_changes_no_decision_and_is_neither_read_nor_cleared(
    *, signed_in: bool, old_cookie_name: str,
) -> None:
    def decisions(*, carrying_old_cookie: bool) -> tuple[int, object, int, int, int]:
        host = after_signing_in(an_oidc_host()) if signed_in else an_oidc_host()
        if carrying_old_cookie:
            host.client.cookies.set(old_cookie_name, a_fake_id_token("set-before-the-upgrade"))
        refused = post_logout(host, {**SAME_ORIGIN_FORM, "sec-fetch-site": "cross-site"})
        refusal = (refused.status_code, refused.json(), host.sessions.count_active())
        reply = post_logout(host, SAME_ORIGIN_FORM)
        assert old_cookie_name not in set_cookies(reply)
        assert hint_of(reply) == (host.issued_id_tokens[-1] if signed_in else None)
        return (*refusal, reply.status_code, host.sessions.count_active())
    expected = (403, {"detail": "Cross-origin request rejected"}, int(signed_in), 200, 0)
    assert decisions(carrying_old_cookie=True) == decisions(carrying_old_cookie=False) == expected


@pytest.mark.parametrize("headers", [
    pytest.param({"sec-fetch-site": "cross-site"}, id="cross-site-fetch-metadata"),
    pytest.param({"origin": "https://evil.test"}, id="foreign-origin"),
    pytest.param({}, id="form-with-neither-header"),
])
def test_a_cross_site_logout_is_refused_and_ends_nothing(headers: dict[str, str]) -> None:
    host = after_signing_in(an_oidc_host())

    response = post_logout(host, {"content-type": "application/x-www-form-urlencoded", **headers})

    assert response.status_code == 403
    assert host.sessions.count_active() == 1
    assert set_cookies(response) == {}


def test_a_logout_reaches_no_issuer_endpoint() -> None:
    host = after_signing_in(an_oidc_host())
    exchanges_before = len(host.issuer.requests)
    fetches_before = len(host.key_set.fetched_urls)

    def unreachable() -> None:
        raise OSError("the issuer is down")

    host.issuer.before_exchange = unreachable
    host.key_set.before_answer = unreachable

    response = post_logout(host, SAME_ORIGIN_FORM)

    assert hint_of(response) == host.issued_id_tokens[-1]
    assert host.sessions.count_active() == 0
    assert len(host.issuer.requests) == exchanges_before
    assert len(host.key_set.fetched_urls) == fetches_before


def test_the_logout_form_carries_the_configured_values_whatever_the_request_names() -> None:
    host = after_signing_in(an_oidc_host())
    query = urllib.parse.urlencode({
        "post_logout_redirect_uri": "https://evil.test/",
        "redirect": "https://evil.test/",
        "client_id": "someone-else",
    })

    response = host.client.post(
        f"{LOGOUT_PATH}?{query}", headers=SAME_ORIGIN_FORM, content=query,
    )

    assert LogoutPage(response.text).hidden_fields == {
        "client_id": CLIENT_ID,
        "post_logout_redirect_uri": a_client_config().post_logout_redirect_uri,
        "id_token_hint": host.issued_id_tokens[-1],
    }


def test_a_get_of_the_logout_path_ends_nothing() -> None:
    host = after_signing_in(an_oidc_host())

    response = host.client.get(LOGOUT_PATH)

    assert response.status_code == 405
    assert (host.sessions.count_active(), host.transaction.entries) == (1, 1)


@pytest.mark.parametrize("strict_records", [False, True], ids=["plain", "strict"])
@pytest.mark.parametrize("kind", list(TransactionKind), ids=lambda kind: kind.name.lower())
def test_a_logout_enters_the_transaction_once_and_reads_no_record_after_its_exit(
    kind: TransactionKind, *, strict_records: bool,
) -> None:
    host = after_signing_in(an_oidc_host(transaction_kind=kind, strict_records=strict_records))
    entries_before = host.transaction.entries

    response = post_logout(host, SAME_ORIGIN_FORM)

    assert response.status_code == 200
    assert hint_of(response) == host.issued_id_tokens[-1]
    assert host.transaction.entries - entries_before == 1


def _answers_a_plain_500_and_clears_no_cookie(response: HttpxResponse) -> bool:
    return (
        response.status_code == 500
        and set_cookies(response) == {}
        and response.text == "Internal Server Error"
    )


@pytest.mark.parametrize("store_call", ["load", "delete"])
@pytest.mark.parametrize("kind", list(TransactionKind), ids=lambda kind: kind.name.lower())
def test_a_failure_in_the_logout_answers_500_with_no_page_and_clears_no_cookie(
    kind: TransactionKind, store_call: str, monkeypatch: pytest.MonkeyPatch,
) -> None:
    host = after_signing_in(an_oidc_host(transaction_kind=kind))
    with monkeypatch.context() as patch:
        failing(host.sessions, store_call, patch)

        response = post_logout(host, SAME_ORIGIN_FORM)

    assert _answers_a_plain_500_and_clears_no_cookie(response)
    assert host.sessions.count_active() == 1
    retry = post_logout(host, SAME_ORIGIN_FORM)
    assert hint_of(retry) == host.issued_id_tokens[-1]
    assert host.sessions.count_active() == 0


def test_a_failing_commit_in_the_logout_leaves_the_session_for_a_retry_with_its_hint() -> None:
    host = after_signing_in(an_oidc_host(transaction_kind=TransactionKind.ROLLING_BACK))
    host.sessions.commit_failure = StoreDown()

    response = post_logout(host, SAME_ORIGIN_FORM)

    assert _answers_a_plain_500_and_clears_no_cookie(response)
    assert host.sessions.count_active() == 1
    host.sessions.commit_failure = None
    assert hint_of(post_logout(host, SAME_ORIGIN_FORM)) == host.issued_id_tokens[-1]


def test_an_uncertain_exit_that_ended_the_row_leaves_a_retry_the_page_without_the_hint() -> None:
    host = after_signing_in(an_oidc_host())
    host.transaction.exit_failure = StoreDown()

    response = post_logout(host, SAME_ORIGIN_FORM)

    assert _answers_a_plain_500_and_clears_no_cookie(response)
    assert host.sessions.count_active() == 0
    host.transaction.exit_failure = None
    retry = post_logout(host, SAME_ORIGIN_FORM)
    assert retry.status_code == 200
    assert hint_of(retry) is None


def _a_label_that_raises(_request: Request) -> str:
    raise StoreDown


def _a_label_that_raises_an_http_exception(_request: Request) -> str:
    raise HTTPException(status_code=403)


def _a_label(_request: Request) -> str:
    return LOGOUT_BUTTON_LABEL


def _a_relying_party_that_raises(_request: Request) -> OidcRelyingParty:
    raise StoreDown


@pytest.mark.parametrize(
    ("label", "relying_party_of"),
    [
        pytest.param(_a_label_that_raises, None, id="label"),
        pytest.param(_a_label_that_raises_an_http_exception, None, id="label-http-exception"),
        pytest.param(_a_label, _a_relying_party_that_raises, id="relying-party"),
    ],
)
def test_a_label_or_relying_party_that_raises_answers_500_and_ends_nothing(
    label: Callable[[Request], str],
    relying_party_of: Callable[[Request], OidcRelyingParty] | None,
) -> None:
    host = after_signing_in(an_oidc_host(logout_button_label=label))
    host.relying_party_of = relying_party_of
    entries_before = host.transaction.entries

    response = post_logout(host, SAME_ORIGIN_FORM)

    assert _answers_a_plain_500_and_clears_no_cookie(response)
    assert host.transaction.entries == entries_before
    assert host.sessions.count_active() == 1


def test_the_logout_button_reads_its_label_from_the_request() -> None:
    host = after_signing_in(an_oidc_host(
        logout_button_label=lambda request: request.headers["x-label"],
    ))

    response = post_logout(host, {**SAME_ORIGIN_FORM, "x-label": "Abmelden"})

    assert LogoutPage(response.text).texts["button"] == "Abmelden"
