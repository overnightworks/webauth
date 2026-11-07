"""Back-channel logout: the issuer posts a logout token to the host's route."""

from __future__ import annotations

import urllib.parse
from collections.abc import Callable, Iterator
from dataclasses import asdict
from datetime import UTC, datetime, timedelta
from typing import NoReturn

import anyio
import pytest
from fastapi import Depends, FastAPI, Request, Response
from httpx import Response as HttpxResponse
from pydantic import SecretStr

from tests.support.oidc_arrangement import (
    ABSENT,
    a_logout_token,
    key_set_document,
    public_jwk,
    rsa_key,
)
from tests.support.oidc_login_host import (
    BACKCHANNEL_LOGOUT_MAX_BODY_BYTES,
    BACKCHANNEL_LOGOUT_PATH,
    BOUND_ISSUER,
    CLIENT_ID,
    DEFAULT_MAX_BODY_BYTES,
    LOGIN_GROUP,
    LOGOUT_PATH,
    NOW,
    OTHER_SUBJECT,
    SAME_ORIGIN_FORM,
    SUBJECT,
    OidcHost,
    StoreDown,
    TransactionKind,
    after_signing_in,
    an_id_token,
    an_oidc_host,
    failing,
    post_logout,
    set_cookies,
    stored_id_tokens,
    stored_refresh_tokens,
)
from tests.support.webauth_arrangement import (
    SESSION_IDLE_SECONDS,
    FakeUser,
    an_http_scope,
    body_of,
    drive,
    seeded_session,
    session_cookie_header,
    starts,
)
from webauth.cookies import (
    sign_session_id,
)
from webauth.oidc import OidcRelyingParty
from webauth.ports import (
    AccountEventKind,
)

FORM_MEDIA_TYPE = "application/x-www-form-urlencoded"


FORM = {"content-type": FORM_MEDIA_TYPE}


def a_logout_token_of_the_issuer(
    *,
    claims: dict[str, object] | None = None,
    header: dict[str, object] | None = None,
    key_name: str = "issuer",
) -> str:
    return a_logout_token(
        issuer=BOUND_ISSUER,
        audience=CLIENT_ID,
        subject=SUBJECT,
        now=NOW,
        key_id="issuer-key",
        key_name=key_name,
        claims=claims,
        header=header,
    )


def a_form_of(logout_token: str, **other_fields: str) -> bytes:
    return urllib.parse.urlencode({"logout_token": logout_token, **other_fields}).encode()


def post_backchannel_logout(
    host: OidcHost,
    content: bytes | Iterator[bytes],
    headers: dict[str, str] = FORM,
) -> HttpxResponse:
    return host.client.post(BACKCHANNEL_LOGOUT_PATH, content=content, headers=headers)


def post_logout_token(host: OidcHost, logout_token: str, **other_fields: str) -> HttpxResponse:
    return post_backchannel_logout(host, a_form_of(logout_token, **other_fields))


def a_host_with_sessions(
    *,
    subject_sessions: int,
    other_sessions: int = 0,
    address_budget: int | None = None,
    max_sessions: int | None = None,
) -> OidcHost:
    host = an_oidc_host(
        FakeUser(id=SUBJECT, username="lena"),
        FakeUser(id=OTHER_SUBJECT, username="omar"),
        address_budget=address_budget,
        max_sessions=max_sessions,
    )
    open_sessions(host, SUBJECT, subject_sessions)
    open_sessions(host, OTHER_SUBJECT, other_sessions)
    return host


def open_sessions(host: OidcHost, user_id: str, count: int) -> None:
    first_created_at = datetime.now(UTC) - timedelta(minutes=30)
    for minute in range(count):
        created_at = first_created_at + timedelta(minutes=minute)
        seeded_session(
            host.sessions,
            host.lock.hold(),
            user_id,
            created_at,
            created_at + timedelta(seconds=SESSION_IDLE_SECONDS),
            SecretStr(f"{user_id}-refresh-token-{minute}"),
        )


def sessions_of(host: OidcHost, user_id: str) -> int:
    return len(host.sessions.sessions_of(user_id))


def test_a_valid_logout_token_ends_every_session_of_its_subject_and_keeps_anothers() -> None:
    """SIGNIN-55, APP-29: a valid logout token ends every session of its subject."""
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
    assert host.callback(host.sign_in_at_issuer()).status_code == 303


@pytest.mark.parametrize(
    ("ending", "ended"),
    [
        pytest.param(_logged_out_holding_the_second_session, {1}, id="logout-route"),
        pytest.param(_logged_out_by_the_issuer, {0, 1, 2}, id="back-channel-logout-route"),
        pytest.param(_logged_in_again_at_the_cap, {0}, id="login-at-the-session-cap"),
    ],
)
def test_after_a_session_ends_its_cookie_is_refused_and_every_other_sessions_cookie_still_works(
    ending: Callable[[OidcHost, list[str]], None],
    ended: set[int],
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
    """SIGNIN-54: a subject without an account is accepted and provisions nothing."""
    host = an_oidc_host(FakeUser(id=OTHER_SUBJECT, username="omar"))
    open_sessions(host, OTHER_SUBJECT, 1)

    response = post_logout_token(host, a_logout_token_of_the_issuer())

    assert response.status_code == 200
    assert [account.id for account in host.accounts.list()] == [OTHER_SUBJECT]
    assert sessions_of(host, OTHER_SUBJECT) == 1
    assert host.audit.account_events == []


def test_a_logout_for_a_subject_without_sessions_is_accepted_and_audits_nothing() -> None:
    """SIGNIN-56: no event is recorded when no session ended."""
    host = a_host_with_sessions(subject_sessions=0, other_sessions=1)

    response = post_logout_token(host, a_logout_token_of_the_issuer())

    assert (response.status_code, sessions_of(host, OTHER_SUBJECT)) == (200, 1)
    assert host.audit.account_events == []


def test_a_logout_that_ended_sessions_audits_one_event_for_the_account_and_no_actor() -> None:
    """SIGNIN-56: one `BACKCHANNEL_LOGOUT` event with no actor is recorded when sessions ended."""
    host = a_host_with_sessions(subject_sessions=3)

    post_logout_token(host, a_logout_token_of_the_issuer())

    assert [asdict(event) for event in host.audit.account_events] == [
        {
            "kind": AccountEventKind.BACKCHANNEL_LOGOUT,
            "actor_id": None,
            "subject_id": SUBJECT,
            "role": None,
            "previous_role": None,
        }
    ]


def test_an_accepted_logout_enters_the_transaction_once_and_calls_no_issuer_endpoint() -> None:
    """SIGNIN-58: an accepted logout calls no issuer endpoint."""
    host = a_host_with_sessions(subject_sessions=1)
    exchanges_before = len(host.issuer.requests)

    post_logout_token(host, a_logout_token_of_the_issuer())

    assert host.transaction.entries == 1
    assert len(host.issuer.requests) == exchanges_before


@pytest.mark.parametrize(
    "logout_token",
    [
        pytest.param(a_logout_token_of_the_issuer(key_name="forger"), id="forged-signature"),
        pytest.param("not-a-token", id="malformed"),
    ],
)
def test_a_logout_token_that_does_not_hold_is_refused_before_the_transaction_and_ends_nothing(
    logout_token: str,
) -> None:
    """SIGNIN-51: a token that does not verify gets an empty 400 before any transaction."""
    host = a_host_with_sessions(subject_sessions=2)

    response = post_logout_token(host, logout_token)

    assert (response.status_code, response.content) == (400, b"")
    assert sessions_of(host, SUBJECT) == 2
    assert host.transaction.entries == 0
    assert host.audit.account_events == []


def test_an_id_token_posted_as_a_logout_token_ends_nothing() -> None:
    host = a_host_with_sessions(subject_sessions=1)

    response = post_logout_token(host, an_id_token("nonce", host.wall_clock, [LOGIN_GROUP]))

    assert (response.status_code, sessions_of(host, SUBJECT)) == (400, 1)


@pytest.mark.parametrize(
    ("body", "content_type"),
    [
        pytest.param(b"", FORM_MEDIA_TYPE, id="empty-body"),
        pytest.param(b"other=1", FORM_MEDIA_TYPE, id="token-missing"),
        pytest.param(b"logout_token=", FORM_MEDIA_TYPE, id="token-empty"),
        pytest.param(b"logout_token", FORM_MEDIA_TYPE, id="field-without-a-value"),
        pytest.param(b"logout_token=%ff", FORM_MEDIA_TYPE, id="undecodable-token"),
        pytest.param(b"logout_token=a&logout_token=b", FORM_MEDIA_TYPE, id="token-twice"),
        pytest.param(b"\xff\xfe", FORM_MEDIA_TYPE, id="body-not-utf-8"),
        pytest.param(
            a_form_of(a_logout_token_of_the_issuer()),
            "application/json",
            id="json-media-type",
        ),
        pytest.param(a_form_of(a_logout_token_of_the_issuer()), "text/plain", id="text-media-type"),
        pytest.param(
            a_form_of(a_logout_token_of_the_issuer()),
            "multipart/form-data",
            id="multipart-media-type",
        ),
        pytest.param(a_form_of(a_logout_token_of_the_issuer()), None, id="no-media-type"),
    ],
)
def test_what_is_not_one_well_formed_logout_token_form_gets_an_empty_400_before_the_transaction(
    body: bytes,
    content_type: str | None,
) -> None:
    """SIGNIN-50: a request that is not one form with one non-empty `logout_token` gets an empty 400
    before any transaction."""
    host = a_host_with_sessions(subject_sessions=1)
    headers = {} if content_type is None else {"content-type": content_type}

    response = post_backchannel_logout(host, body, headers)

    assert (response.status_code, response.content) == (400, b"")
    assert (sessions_of(host, SUBJECT), host.transaction.entries) == (1, 0)


@pytest.mark.parametrize(
    "content_type",
    [
        pytest.param(f"{FORM_MEDIA_TYPE}; charset=UTF-8", id="media-type-with-parameter"),
        pytest.param(FORM_MEDIA_TYPE.upper(), id="media-type-in-capitals"),
    ],
)
def test_a_form_media_type_with_a_parameter_or_in_capitals_is_read(content_type: str) -> None:
    host = a_host_with_sessions(subject_sessions=1)

    response = post_backchannel_logout(
        host,
        a_form_of(a_logout_token_of_the_issuer()),
        {"content-type": content_type},
    )

    assert (response.status_code, sessions_of(host, SUBJECT)) == (200, 0)


def test_a_malformed_logout_token_form_gets_an_empty_400() -> None:
    host = a_host_with_sessions(subject_sessions=1)

    response = post_backchannel_logout(host, b"logout_token")

    assert (response.status_code, response.content) == (400, b"")


def test_two_logout_tokens_in_one_form_are_refused_even_when_one_is_valid() -> None:
    host = a_host_with_sessions(subject_sessions=1)
    form = urllib.parse.urlencode(
        [
            ("logout_token", a_logout_token_of_the_issuer()),
            ("logout_token", "another"),
        ]
    )

    response = post_backchannel_logout(host, form.encode())

    assert (response.status_code, sessions_of(host, SUBJECT)) == (400, 1)


def test_an_unknown_form_field_beside_a_valid_token_is_ignored_past_the_default_limit() -> None:
    host = a_host_with_sessions(subject_sessions=1)

    response = post_logout_token(
        host,
        a_logout_token_of_the_issuer(),
        unknown="x" * (2 * DEFAULT_MAX_BODY_BYTES),
    )

    assert (response.status_code, sessions_of(host, SUBJECT)) == (200, 0)


def an_oversized_streamed_body() -> Iterator[bytes]:
    for _ in range(BACKCHANNEL_LOGOUT_MAX_BODY_BYTES // 1024 + 1):
        yield b"x" * 1024


@pytest.mark.parametrize(
    "body",
    [
        pytest.param(b"x" * (BACKCHANNEL_LOGOUT_MAX_BODY_BYTES + 1), id="declared"),
        pytest.param(an_oversized_streamed_body(), id="streamed"),
    ],
)
def test_an_oversized_logout_body_is_refused_and_ends_nothing(
    body: bytes | Iterator[bytes],
) -> None:
    """SIGNIN-07, SIGNIN-49: a body over the derived bound gets 413, a streamed one before the form
    is read."""
    host = a_host_with_sessions(subject_sessions=1)

    response = post_backchannel_logout(host, body)

    assert (response.status_code, sessions_of(host, SUBJECT)) == (413, 1)


@pytest.mark.parametrize(
    "path",
    [
        pytest.param(f"{BACKCHANNEL_LOGOUT_PATH}/", id="trailing-slash"),
        pytest.param(f"{BACKCHANNEL_LOGOUT_PATH}-other", id="longer-name"),
        pytest.param(LOGOUT_PATH, id="the-browser-logout"),
    ],
)
def test_a_path_next_to_the_back_channel_stays_csrf_protected(path: str) -> None:
    """SIGNIN-43: the exact back-channel path is exempt from the origin check, and no other path is."""
    host = after_signing_in(an_oidc_host())

    response = host.client.post(path, headers=FORM, content=b"logout_token=x")
    sessions_after_the_neighbour = host.sessions.count_active()
    exact = host.client.post(
        BACKCHANNEL_LOGOUT_PATH, headers=FORM, content=a_form_of(a_logout_token_of_the_issuer())
    )

    assert (response.status_code, sessions_after_the_neighbour) == (403, 1)
    assert exact.status_code == 200


def _the_deletion_fails(host: OidcHost, monkeypatch: pytest.MonkeyPatch) -> None:
    failing(host.sessions, "delete_for_user", monkeypatch)


def _the_audit_sink_fails(host: OidcHost, monkeypatch: pytest.MonkeyPatch) -> None:
    failing(host.audit, "account_event", monkeypatch)


def _the_exit_fails(host: OidcHost, _monkeypatch: pytest.MonkeyPatch) -> None:
    host.transaction.exit_failure = ConnectionError("the commit failed")


@pytest.mark.parametrize(
    ("fail", "per_call_sessions", "per_call_events"),
    [
        pytest.param(_the_deletion_fails, 2, 0, id="deletion-fails"),
        pytest.param(_the_audit_sink_fails, 0, 0, id="audit-fails-after-deletion"),
        pytest.param(_the_exit_fails, 0, 1, id="exit-fails"),
    ],
)
@pytest.mark.parametrize("kind", list(TransactionKind), ids=lambda kind: kind.name.lower())
def test_a_store_audit_or_exit_failure_answers_400_and_keeps_only_what_the_host_keeps(
    fail: Callable[[OidcHost, pytest.MonkeyPatch], None],
    per_call_sessions: int,
    per_call_events: int,
    kind: TransactionKind,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    host = an_oidc_host(
        FakeUser(id=SUBJECT, username="lena"),
        transaction_kind=kind,
    )
    open_sessions(host, SUBJECT, 2)
    fail(host, monkeypatch)

    response = post_logout_token(host, a_logout_token_of_the_issuer())

    rolls_back = kind is TransactionKind.ROLLING_BACK
    assert (response.status_code, response.content, response.headers["cache-control"]) == (
        400,
        b"",
        "no-store",
    )
    assert sessions_of(host, SUBJECT) == (2 if rolls_back else per_call_sessions)
    assert len(host.audit.account_events) == (0 if rolls_back else per_call_events)


@pytest.mark.parametrize(
    ("other_keys", "status", "sessions_left"),
    [
        pytest.param(0, 200, 0, id="sole-key"),
        pytest.param(1, 400, 1, id="several-keys"),
    ],
)
def test_a_logout_token_without_kid_is_verified_only_against_a_sole_issuer_key(
    other_keys: int,
    status: int,
    sessions_left: int,
) -> None:
    host = a_host_with_sessions(subject_sessions=1)
    host.key_set.response = key_set_document(
        public_jwk(rsa_key("issuer"), "issuer-key", kid=ABSENT),
        *(public_jwk(rsa_key(f"other-{index}"), f"other-{index}") for index in range(other_keys)),
    )

    response = post_logout_token(host, a_logout_token_of_the_issuer(header={"kid": ABSENT}))

    assert (response.status_code, sessions_of(host, SUBJECT)) == (status, sessions_left)


def test_the_back_channel_bypasses_an_exhausted_address_budget() -> None:
    """SIGNIN-06: the derived `backchannel` rules exempt the back-channel from the rate limit."""
    host = a_host_with_sessions(subject_sessions=1, address_budget=1)
    host.client.get("/me")
    assert host.client.get("/me").status_code == 429

    response = post_logout_token(host, a_logout_token_of_the_issuer())

    assert (response.status_code, sessions_of(host, SUBJECT)) == (200, 0)


@pytest.mark.parametrize(
    ("body", "status"),
    [
        pytest.param(None, 200, id="accepted"),
        pytest.param(b"logout_token=x", 400, id="refused"),
        pytest.param(b"x" * (BACKCHANNEL_LOGOUT_MAX_BODY_BYTES + 1), 413, id="oversized"),
    ],
)
def test_every_answer_of_the_back_channel_carries_no_store(body: bytes | None, status: int) -> None:
    host = a_host_with_sessions(subject_sessions=1)
    content = a_form_of(a_logout_token_of_the_issuer()) if body is None else body

    response = post_backchannel_logout(host, content)

    assert (response.status_code, response.headers["cache-control"]) == (status, "no-store")


def test_the_back_channel_needs_neither_an_origin_nor_a_cookie() -> None:
    """SIGNIN-05: the back-channel needs neither an origin nor a cookie."""
    host = a_host_with_sessions(subject_sessions=1)
    assert not host.client.cookies

    response = post_logout_token(host, a_logout_token_of_the_issuer())

    assert (response.status_code, "origin" in response.request.headers) == (200, False)


def test_after_back_channel_logout_no_stored_row_holds_the_login_token() -> None:
    host = after_signing_in(an_oidc_host())

    post_logout_token(host, a_logout_token_of_the_issuer())

    assert host.issued_id_tokens[-1] not in stored_id_tokens(host)


def test_a_declared_oversized_body_gets_413_before_any_back_channel_dependency_runs() -> None:
    reached: list[str] = []

    def record() -> None:
        reached.append("dependency")

    host = an_oidc_host(backchannel_dependencies=[Depends(record)])

    response = post_backchannel_logout(host, b"x" * (BACKCHANNEL_LOGOUT_MAX_BODY_BYTES + 1))

    assert (response.status_code, reached) == (413, [])


class NotTheIssuerError(Exception):
    pass


def refuse_everyone() -> None:
    raise NotTheIssuerError


def _a_host_whose_dependency_refuses() -> OidcHost:
    host = an_oidc_host(
        FakeUser(id=SUBJECT, username="lena"),
        backchannel_dependencies=[Depends(refuse_everyone)],
    )
    app: FastAPI = host.client.app  # pyright: ignore[reportAssignmentType]
    app.add_exception_handler(
        NotTheIssuerError,
        lambda _request, _error: Response(status_code=404),
    )
    open_sessions(host, SUBJECT, 1)
    return host


def test_a_refusing_dependency_answers_the_hosts_empty_404_before_the_body_is_read() -> None:
    """SIGNIN-45: the dependencies run before the body is read."""
    host = _a_host_whose_dependency_refuses()

    response = post_backchannel_logout(host, an_oversized_streamed_body())

    assert (response.status_code, response.content) == (404, b"")
    assert (host.transaction.entries, sessions_of(host, SUBJECT)) == (0, 1)


@pytest.mark.parametrize(
    ("body", "status"),
    [
        pytest.param(b"x" * (BACKCHANNEL_LOGOUT_MAX_BODY_BYTES + 1), 413, id="declared"),
        pytest.param(an_oversized_streamed_body(), 404, id="streamed"),
    ],
)
def test_a_refusing_dependency_answers_after_the_declared_bound_and_before_the_streamed_one(
    body: bytes | Iterator[bytes],
    status: int,
) -> None:
    """SIGNIN-47, SIGNIN-48: a declared oversized body is refused before any dependency and a
    dependency answers before a streamed oversized body."""
    host = _a_host_whose_dependency_refuses()

    response = post_backchannel_logout(host, body)

    assert response.status_code == status


def _a_relying_party_that_raises(_request: Request) -> NoReturn:
    raise StoreDown


def test_a_relying_party_that_raises_answers_400_and_enters_no_transaction() -> None:
    host = a_host_with_sessions(subject_sessions=1)

    host.relying_party_of = _a_relying_party_that_raises

    response = post_logout_token(host, a_logout_token_of_the_issuer())

    assert (response.status_code, response.content) == (400, b"")
    assert (host.transaction.entries, sessions_of(host, SUBJECT)) == (0, 1)


def _the_relying_party_raises(host: OidcHost, _monkeypatch: pytest.MonkeyPatch) -> None:
    host.relying_party_of = _a_relying_party_that_raises


def _the_verification_raises(host: OidcHost, monkeypatch: pytest.MonkeyPatch) -> None:
    failing(host.relying_party, "verify_logout_token", monkeypatch)


@pytest.mark.parametrize(
    ("fail", "raised_type"),
    [
        pytest.param(_the_relying_party_raises, StoreDown, id="relying-party"),
        pytest.param(_the_verification_raises, StoreDown, id="verification"),
        pytest.param(_the_deletion_fails, StoreDown, id="store"),
        pytest.param(_the_audit_sink_fails, StoreDown, id="audit-sink"),
        pytest.param(_the_exit_fails, ConnectionError, id="exit"),
    ],
)
def test_a_back_channel_failure_is_raised_once_the_400_is_sent(
    fail: Callable[[OidcHost, pytest.MonkeyPatch], None],
    raised_type: type[Exception],
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """SIGNIN-53: an exception in the relying party, verification, store, audit sink or exit gets an
    empty 400, then is raised."""
    host = a_host_with_sessions(subject_sessions=1)
    fail(host, monkeypatch)
    app: FastAPI = host.client.app  # pyright: ignore[reportAssignmentType]
    scope = an_http_scope(
        app,
        BACKCHANNEL_LOGOUT_PATH,
        method="POST",
        headers=[(b"host", b"testserver"), (b"content-type", FORM_MEDIA_TYPE.encode())],
    )
    form = a_form_of(a_logout_token_of_the_issuer())

    messages, raised = anyio.run(lambda: drive(app, scope, body_chunks=[form]))

    assert [message["status"] for message in starts(messages)] == [400]  # pyright: ignore[reportArgumentType]
    assert body_of(messages) == b""
    assert type(raised) is raised_type


@pytest.mark.parametrize("strict_records", [False, True], ids=["plain", "strict"])
@pytest.mark.parametrize("kind", list(TransactionKind), ids=lambda kind: kind.name.lower())
def test_an_accepted_back_channel_logout_enters_the_transaction_once_and_reads_no_record_after_its_exit(  # noqa: E501
    kind: TransactionKind,
    *,
    strict_records: bool,
) -> None:
    host = an_oidc_host(
        FakeUser(id=SUBJECT, username="lena"),
        transaction_kind=kind,
        strict_records=strict_records,
    )
    open_sessions(host, SUBJECT, 2)

    response = post_logout_token(host, a_logout_token_of_the_issuer())

    assert (response.status_code, host.transaction.entries) == (200, 1)


@pytest.mark.parametrize("exit_failure", [None, ConnectionError("the commit failed")])
def test_the_back_channel_answers_200_only_after_the_exit_returned(
    exit_failure: Exception | None,
) -> None:
    """SIGNIN-52: the empty 200 follows the clean exit of one entry; a failing exit answers 400."""
    host = a_host_with_sessions(subject_sessions=1)
    host.transaction.exit_failure = exit_failure

    response = post_logout_token(host, a_logout_token_of_the_issuer())

    assert (response.status_code, response.content) == (200 if exit_failure is None else 400, b"")
    assert host.transaction.entries == 1


@pytest.mark.parametrize(
    "path",
    [
        pytest.param(f"{BACKCHANNEL_LOGOUT_PATH}/", id="trailing-slash"),
        pytest.param(f"{BACKCHANNEL_LOGOUT_PATH}-other", id="longer-name"),
        pytest.param(LOGOUT_PATH, id="the-browser-logout"),
    ],
)
def test_a_path_next_to_the_back_channel_spends_the_address_budget(path: str) -> None:
    """SIGNIN-44: the exact back-channel path is exempt from the rate limit, and no other path is."""
    host = a_host_with_sessions(subject_sessions=1, address_budget=1)
    host.client.get("/me")
    assert host.client.get("/me").status_code == 429

    response = host.client.post(path, headers=SAME_ORIGIN_FORM, content=b"logout_token=x")
    exact = post_logout_token(host, a_logout_token_of_the_issuer())

    assert response.status_code == 429
    assert exact.status_code == 200


@pytest.mark.parametrize(
    ("body", "status"),
    [
        pytest.param(None, 200, id="accepted"),
        pytest.param(b"logout_token=x", 400, id="refused"),
        pytest.param(b"x" * (BACKCHANNEL_LOGOUT_MAX_BODY_BYTES + 1), 413, id="oversized"),
    ],
)
def test_no_answer_of_the_back_channel_sets_or_clears_a_cookie(
    body: bytes | None,
    status: int,
) -> None:
    """SIGNIN-57: no answer of the back-channel sets or clears a cookie."""
    host = after_signing_in(an_oidc_host())
    content = a_form_of(a_logout_token_of_the_issuer()) if body is None else body

    response = post_backchannel_logout(host, content)

    assert (response.status_code, set_cookies(response)) == (status, {})


def test_the_relying_party_receives_the_back_channel_request_with_the_host_it_was_posted_to() -> (
    None
):
    """SIGNIN-59: the relying party receives the request with the Host it was posted to."""
    host = a_host_with_sessions(subject_sessions=1)
    hosts_seen: set[str] = set()

    def a_relying_party_noting_the_host(request: Request) -> OidcRelyingParty:
        hosts_seen.add(request.headers["host"])
        return host.relying_party

    host.relying_party_of = a_relying_party_noting_the_host
    internal_alias = "idp-callback.internal"

    response = post_backchannel_logout(
        host,
        a_form_of(a_logout_token_of_the_issuer()),
        {**FORM, "host": internal_alias},
    )

    assert (response.status_code, hosts_seen) == (200, {internal_alias})


def test_after_an_audit_failure_a_per_call_host_keeps_the_ended_sessions_and_a_retry_audits_nothing(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """SIGNIN-60: a per-call host keeps the sessions ended before the failure and no event is
    emitted again."""
    host = an_oidc_host(FakeUser(id=SUBJECT, username="lena"))
    open_sessions(host, SUBJECT, 2)
    with monkeypatch.context() as patch:
        failing(host.audit, "account_event", patch)
        failed = post_logout_token(host, a_logout_token_of_the_issuer())

    retried = post_logout_token(host, a_logout_token_of_the_issuer())

    assert (failed.status_code, retried.status_code) == (400, 200)
    assert sessions_of(host, SUBJECT) == 0
    assert host.audit.account_events == []
