"""Back-channel logout: the issuer posts a logout token to the host's route."""

from __future__ import annotations

import urllib.parse
from collections.abc import Callable, Iterator
from dataclasses import asdict
from datetime import UTC, datetime, timedelta
from typing import NoReturn

import pytest
from pydantic import SecretStr

from tests.support.oidc_arrangement import (
    ABSENT,
    key_set_document,
    public_jwk,
    rsa_key,
)
from tests.support.oidc_login_host import (
    BACKCHANNEL_LOGOUT_MAX_BODY_BYTES,
    BACKCHANNEL_LOGOUT_PATH,
    DEFAULT_MAX_BODY_BYTES,
    FORM,
    FORM_MEDIA_TYPE,
    LOGIN_GROUP,
    LOGOUT_PATH,
    OTHER_SUBJECT,
    SAME_ORIGIN_FORM,
    SUBJECT,
    OidcHost,
    a_form_of,
    a_logout_token_of_the_issuer,
    after_signing_in,
    an_id_token,
    an_oidc_host,
    post_backchannel_logout,
    post_logout,
    post_logout_token,
    stored_id_tokens,
    stored_refresh_tokens,
)
from tests.support.webauth_arrangement import (
    SESSION_IDLE_SECONDS,
    FakeUser,
    seeded_session,
    session_cookie_header,
)
from webauth.cookies import (
    sign_session_id,
)
from webauth.oidc_login import (
    BackchannelLogoutResult,
    receive_backchannel_logout,
)
from webauth.ports import (
    AccountEventKind,
)


def a_host_with_sessions(
    *, subject_sessions: int, other_sessions: int = 0, address_budget: int | None = None,
    max_sessions: int | None = None,
) -> OidcHost:
    host = an_oidc_host(
        FakeUser(id=SUBJECT, username="lena"), FakeUser(id=OTHER_SUBJECT, username="omar"),
        address_budget=address_budget, max_sessions=max_sessions,
    )
    open_sessions(host, SUBJECT, subject_sessions)
    open_sessions(host, OTHER_SUBJECT, other_sessions)
    return host







def open_sessions(host: OidcHost, user_id: str, count: int) -> None:
    first_created_at = datetime.now(UTC) - timedelta(minutes=30)
    for minute in range(count):
        created_at = first_created_at + timedelta(minutes=minute)
        seeded_session(
            host.sessions, host.lock.hold_uncounted(), user_id,
            created_at, created_at + timedelta(seconds=SESSION_IDLE_SECONDS),
            SecretStr(f"{user_id}-refresh-token-{minute}"),
        )


def sessions_of(host: OidcHost, user_id: str) -> int:
    return len(host.sessions.sessions_of(user_id))










def test_a_valid_logout_token_ends_every_session_of_its_subject_and_keeps_anothers() -> None:
    host = a_host_with_sessions(subject_sessions=3, other_sessions=2)

    response = post_logout_token(host, a_logout_token_of_the_issuer())

    assert response.status_code == 200
    assert (sessions_of(host, SUBJECT), sessions_of(host, OTHER_SUBJECT)) == (0, 2)
    assert not [token for token in stored_refresh_tokens(host) if token.startswith(SUBJECT)]


def the_cookie_header_of(host: OidcHost, session_id: str) -> dict[str, str]:
    return {"cookie": session_cookie_header(sign_session_id(session_id, host.config.signing_key))}


def _logged_out_holding_the_second_session(host: OidcHost, session_ids: list[str]) -> None:
    headers = {**SAME_ORIGIN_FORM, **the_cookie_header_of(host, session_ids[1])}
    assert post_logout(host, headers).status_code == 200


def _logged_out_by_the_issuer(host: OidcHost, _session_ids: list[str]) -> None:
    assert post_logout_token(host, a_logout_token_of_the_issuer()).status_code == 200


def _logged_in_again_at_the_cap(host: OidcHost, _session_ids: list[str]) -> None:
    assert host.callback(host.sign_in_at_issuer()).status_code == 200


@pytest.mark.parametrize(("ending", "ended"), [
    pytest.param(_logged_out_holding_the_second_session, {1}, id="logout-route"),
    pytest.param(_logged_out_by_the_issuer, {0, 1, 2}, id="back-channel-logout-route"),
    pytest.param(_logged_in_again_at_the_cap, {0}, id="login-at-the-session-cap"),
])
def test_after_a_session_ends_its_cookie_is_refused_and_every_other_sessions_cookie_still_works(
    ending: Callable[[OidcHost, list[str]], None], ended: set[int],
) -> None:
    host = a_host_with_sessions(subject_sessions=3, other_sessions=1, max_sessions=3)
    session_ids = [record.id for record in host.sessions.list_active()]
    refresh_tokens = stored_refresh_tokens(host)
    ended_tokens = [refresh_tokens[index] for index in ended]

    ending(host, session_ids)

    statuses = [
        host.client.get("/me", headers=the_cookie_header_of(host, session_id)).status_code
        for session_id in session_ids
    ]
    assert statuses == [401 if index in ended else 200 for index in range(len(session_ids))]
    assert not set(ended_tokens) & set(stored_refresh_tokens(host))


def test_a_logout_for_an_unknown_subject_is_accepted_without_provisioning_an_account() -> None:
    host = an_oidc_host(FakeUser(id=OTHER_SUBJECT, username="omar"))
    open_sessions(host, OTHER_SUBJECT, 1)

    response = post_logout_token(host, a_logout_token_of_the_issuer())

    assert response.status_code == 200
    assert [account.id for account in host.accounts.list()] == [OTHER_SUBJECT]
    assert sessions_of(host, OTHER_SUBJECT) == 1
    assert host.audit.account_events == []


def test_a_logout_for_a_subject_without_sessions_is_accepted_and_audits_nothing() -> None:
    host = a_host_with_sessions(subject_sessions=0, other_sessions=1)

    response = post_logout_token(host, a_logout_token_of_the_issuer())

    assert (response.status_code, sessions_of(host, OTHER_SUBJECT)) == (200, 1)
    assert host.audit.account_events == []


def test_a_logout_that_ended_sessions_audits_one_event_for_the_account_and_no_actor() -> None:
    host = a_host_with_sessions(subject_sessions=3)

    post_logout_token(host, a_logout_token_of_the_issuer())

    assert [asdict(event) for event in host.audit.account_events] == [{
        "kind": AccountEventKind.BACKCHANNEL_LOGOUT,
        "actor_id": None,
        "subject_id": SUBJECT,
        "role": None,
        "previous_role": None,
    }]


def test_an_accepted_logout_takes_the_lock_once_and_calls_no_issuer_endpoint() -> None:
    host = a_host_with_sessions(subject_sessions=1)
    exchanges_before = len(host.issuer.requests)

    post_logout_token(host, a_logout_token_of_the_issuer())

    assert host.lock.times_taken == 1
    assert len(host.issuer.requests) == exchanges_before


@pytest.mark.parametrize("logout_token", [
    pytest.param(a_logout_token_of_the_issuer(key_name="forger"), id="forged-signature"),
    pytest.param("not-a-token", id="malformed"),
])
def test_a_logout_token_that_does_not_hold_is_refused_before_the_lock_and_ends_nothing(
    logout_token: str,
) -> None:
    host = a_host_with_sessions(subject_sessions=2)

    response = post_logout_token(host, logout_token)

    assert (response.status_code, response.content) == (400, b"")
    assert sessions_of(host, SUBJECT) == 2
    assert host.lock.times_taken == 0
    assert host.audit.account_events == []


def test_an_id_token_posted_as_a_logout_token_ends_nothing() -> None:
    host = a_host_with_sessions(subject_sessions=1)

    response = post_logout_token(host, an_id_token("nonce", host.wall_clock, [LOGIN_GROUP]))

    assert (response.status_code, sessions_of(host, SUBJECT)) == (400, 1)


@pytest.mark.parametrize(("body", "content_type"), [
    pytest.param(b"", FORM_MEDIA_TYPE, id="empty-body"),
    pytest.param(b"other=1", FORM_MEDIA_TYPE, id="token-missing"),
    pytest.param(b"logout_token=", FORM_MEDIA_TYPE, id="token-empty"),
    pytest.param(b"logout_token", FORM_MEDIA_TYPE, id="field-without-a-value"),
    pytest.param(b"logout_token=%ff", FORM_MEDIA_TYPE, id="undecodable-token"),
    pytest.param(b"logout_token=a&logout_token=b", FORM_MEDIA_TYPE, id="token-twice"),
    pytest.param(b"\xff\xfe", FORM_MEDIA_TYPE, id="body-not-utf-8"),
    pytest.param(
        a_form_of(a_logout_token_of_the_issuer()), "application/json", id="json-media-type",
    ),
    pytest.param(a_form_of(a_logout_token_of_the_issuer()), "text/plain", id="text-media-type"),
    pytest.param(
        a_form_of(a_logout_token_of_the_issuer()), "multipart/form-data", id="multipart-media-type",
    ),
    pytest.param(a_form_of(a_logout_token_of_the_issuer()), None, id="no-media-type"),
])
def test_the_library_refuses_what_is_not_one_well_formed_logout_token_form_before_it_locks(
    body: bytes, content_type: str | None,
) -> None:
    host = a_host_with_sessions(subject_sessions=1)

    result = receive_in_a_transaction(host, body, content_type)

    assert result is BackchannelLogoutResult.REFUSED
    assert (sessions_of(host, SUBJECT), host.lock.times_taken) == (1, 0)


@pytest.mark.parametrize("content_type", [
    pytest.param(f"{FORM_MEDIA_TYPE}; charset=UTF-8", id="media-type-with-parameter"),
    pytest.param(FORM_MEDIA_TYPE.upper(), id="media-type-in-capitals"),
])
def test_a_form_media_type_with_a_parameter_or_in_capitals_is_read(content_type: str) -> None:
    host = a_host_with_sessions(subject_sessions=1)

    result = receive_in_a_transaction(
        host, a_form_of(a_logout_token_of_the_issuer()), content_type,
    )

    assert result is BackchannelLogoutResult.ACCEPTED
    assert sessions_of(host, SUBJECT) == 0


def receive_in_a_transaction(
    host: OidcHost, body: bytes, content_type: str | None,
) -> BackchannelLogoutResult:
    with host.sessions.transaction():
        return receive_backchannel_logout(
            host.relying_party, body, content_type,
            accounts=host.accounts, sessions=host.sessions, lock=host.lock, audit=host.audit,
        )


def test_a_malformed_logout_token_form_gets_an_empty_400() -> None:
    host = a_host_with_sessions(subject_sessions=1)

    response = post_backchannel_logout(host, b"logout_token")

    assert (response.status_code, response.content) == (400, b"")


def test_two_logout_tokens_in_one_form_are_refused_even_when_one_is_valid() -> None:
    host = a_host_with_sessions(subject_sessions=1)
    form = urllib.parse.urlencode([
        ("logout_token", a_logout_token_of_the_issuer()), ("logout_token", "another"),
    ])

    response = post_backchannel_logout(host, form.encode())

    assert (response.status_code, sessions_of(host, SUBJECT)) == (400, 1)


def test_an_unknown_form_field_beside_a_valid_token_is_ignored_past_the_default_limit() -> None:
    host = a_host_with_sessions(subject_sessions=1)

    response = post_logout_token(
        host, a_logout_token_of_the_issuer(), unknown="x" * (2 * DEFAULT_MAX_BODY_BYTES),
    )

    assert (response.status_code, sessions_of(host, SUBJECT)) == (200, 0)


def an_oversized_streamed_body() -> Iterator[bytes]:
    for _ in range(BACKCHANNEL_LOGOUT_MAX_BODY_BYTES // 1024 + 1):
        yield b"x" * 1024


@pytest.mark.parametrize("body", [
    pytest.param(b"x" * (BACKCHANNEL_LOGOUT_MAX_BODY_BYTES + 1), id="declared"),
    pytest.param(an_oversized_streamed_body(), id="streamed"),
])
def test_an_oversized_logout_body_is_refused_and_ends_nothing(
    body: bytes | Iterator[bytes],
) -> None:
    host = a_host_with_sessions(subject_sessions=1)

    response = post_backchannel_logout(host, body)

    assert (response.status_code, sessions_of(host, SUBJECT)) == (413, 1)


@pytest.mark.parametrize("path", [
    pytest.param(f"{BACKCHANNEL_LOGOUT_PATH}/", id="trailing-slash"),
    pytest.param(f"{BACKCHANNEL_LOGOUT_PATH}-other", id="longer-name"),
    pytest.param(LOGOUT_PATH, id="the-browser-logout"),
])
def test_a_path_next_to_the_callback_stays_csrf_protected(path: str) -> None:
    host = after_signing_in(an_oidc_host())

    response = host.client.post(path, headers=FORM, content=b"logout_token=x")

    assert (response.status_code, host.sessions.count_active()) == (403, 1)


def fails_with_the_store_down(*_arguments: object, **_keywords: object) -> NoReturn:
    raise ConnectionError("the store is down")


@pytest.mark.parametrize("failing_part", [
    pytest.param("sessions.delete_for_user", id="deletion-fails"),
    pytest.param("audit.account_event", id="audit-fails-after-deletion"),
    pytest.param("sessions.commit_failure", id="commit-fails"),
])
def test_a_store_audit_or_commit_failure_answers_400_and_leaves_every_session_in_place(
    failing_part: str, monkeypatch: pytest.MonkeyPatch,
) -> None:
    host = a_host_with_sessions(subject_sessions=2)
    owner, _, part = failing_part.partition(".")
    if part == "commit_failure":
        host.sessions.commit_failure = ConnectionError("the commit failed")
    else:
        monkeypatch.setattr(getattr(host, owner), part, fails_with_the_store_down)

    response = post_logout_token(host, a_logout_token_of_the_issuer())

    answer = (response.status_code, response.headers["cache-control"])
    assert (answer, sessions_of(host, SUBJECT)) == ((400, "no-store"), 2)


@pytest.mark.parametrize(("other_keys", "status", "sessions_left"), [
    pytest.param(0, 200, 0, id="sole-key"),
    pytest.param(1, 400, 1, id="several-keys"),
])
def test_a_logout_token_without_kid_is_verified_only_against_a_sole_issuer_key(
    other_keys: int, status: int, sessions_left: int,
) -> None:
    host = a_host_with_sessions(subject_sessions=1)
    host.key_set.response = key_set_document(
        public_jwk(rsa_key("issuer"), "issuer-key", kid=ABSENT),
        *(public_jwk(rsa_key(f"other-{index}"), f"other-{index}") for index in range(other_keys)),
    )

    response = post_logout_token(host, a_logout_token_of_the_issuer(header={"kid": ABSENT}))

    assert (response.status_code, sessions_of(host, SUBJECT)) == (status, sessions_left)


def test_the_callback_bypasses_an_exhausted_address_budget() -> None:
    host = a_host_with_sessions(subject_sessions=1, address_budget=1)
    host.client.get("/me")
    assert host.client.get("/me").status_code == 429

    response = post_logout_token(host, a_logout_token_of_the_issuer())

    assert (response.status_code, sessions_of(host, SUBJECT)) == (200, 0)


@pytest.mark.parametrize(("body", "status"), [
    pytest.param(None, 200, id="accepted"),
    pytest.param(b"logout_token=x", 400, id="refused"),
    pytest.param(b"x" * (BACKCHANNEL_LOGOUT_MAX_BODY_BYTES + 1), 413, id="oversized"),
])
def test_every_answer_of_the_callback_carries_no_store(body: bytes | None, status: int) -> None:
    host = a_host_with_sessions(subject_sessions=1)
    content = (
        a_form_of(a_logout_token_of_the_issuer()) if body is None else body
    )

    response = post_backchannel_logout(host, content)

    assert (response.status_code, response.headers["cache-control"]) == (status, "no-store")


def test_the_callback_needs_neither_an_origin_nor_a_cookie() -> None:
    host = a_host_with_sessions(subject_sessions=1)
    assert not host.client.cookies

    response = post_logout_token(host, a_logout_token_of_the_issuer())

    assert (response.status_code, "origin" in response.request.headers) == (200, False)


def test_after_back_channel_logout_no_stored_row_holds_the_login_token() -> None:
    host = after_signing_in(an_oidc_host())

    post_logout_token(host, a_logout_token_of_the_issuer())

    assert host.issued_id_tokens[-1] not in stored_id_tokens(host)
