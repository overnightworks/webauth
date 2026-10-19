"""What a WebSocket handshake proves, and how a later check closes the socket."""

from __future__ import annotations

from collections.abc import Callable, Sequence
from datetime import UTC, datetime, timedelta

import pytest
from fastapi import FastAPI
from starlette.requests import HTTPConnection, Request
from starlette.websockets import WebSocket, WebSocketDisconnect
from webauth_arrangement import (
    ALLOWED_ORIGIN,
    CLIENT_ADDRESS,
    CLIENT_USER_AGENT,
    MEMBER_ROLE,
    POLICY_VIOLATION_CLOSE_CODE,
    SESSION_COOKIE_NAME,
    SESSION_ID,
    WEBSOCKET_DEPENDENCY_PATH,
    AuthApp,
    FakeSessionRecord,
    FakeUser,
    SessionsAnsweringTouch,
    SessionsThatMustNotBeAsked,
    a_session,
    a_web_auth_config,
    an_auth_app,
    an_idle_auth_app,
    an_idle_session,
    session_cookie_header,
)

from webauth.config import (
    DEFAULT_MAX_USER_AGENT_CHARS,
    install_web_auth_config,
    web_auth_config,
)
from webauth.cookies import (
    MAX_SESSION_COOKIE_CHARS,
    cookie_pairs,
    cookie_values,
    session_reference,
    sign_session_id,
)
from webauth.dependencies import AuthenticatedUser, WebSocketRefusal, session_id_from_request
from webauth.ports import SessionIdentityChange, SessionIdentityChanged
from webauth.proxies import client_user_agent, resolve_client_ip
from webauth.session_ending import end_session

CONFIG = a_web_auth_config()
SIGNING_KEY = CONFIG.signing_key
ALICE = AuthenticatedUser(id="user-1", username="alice", role=MEMBER_ROLE, is_active=True)
NO_PATTERNS = {"allowed_hosts_patterns": ()}
LOCAL_DEVELOPMENT_HOSTS = {
    "allowed_hosts_exact": frozenset({"localhost", "127.0.0.1"}),
    **NO_PATTERNS,
}


@pytest.fixture
def auth_app() -> AuthApp:
    return an_auth_app(a_session())


def the_refusal_of(app: AuthApp, **handshake: object) -> WebSocketRefusal:
    """Drive a handshake that must close before accept, and say why the helper refused it."""
    with pytest.raises(WebSocketDisconnect) as closed, app.connect(**handshake):
        pass
    assert closed.value.code == POLICY_VIOLATION_CLOSE_CODE
    refusal = app.websocket_outcomes[-1]
    assert isinstance(refusal, WebSocketRefusal)
    return refusal


def test_the_refusals_keep_their_stable_values() -> None:
    values_by_name = {refusal.name: refusal.value for refusal in WebSocketRefusal}

    assert values_by_name == {
        "NO_SESSION": "no-session",
        "INVALID_SESSION": "invalid-session",
        "SESSION_ENDED_OR_EXPIRED": "session-ended-or-expired",
        "ACCOUNT_DISABLED": "account-disabled",
        "MISSING_ORIGIN": "missing-origin",
        "FOREIGN_ORIGIN": "foreign-origin",
    }


def test_a_live_session_with_an_allowed_origin_opens_as_its_account(auth_app: AuthApp) -> None:
    with auth_app.connect(cookie=auth_app.signed_cookie()) as socket:
        assert socket.receive_json()["username"] == "alice"

    assert auth_app.websocket_outcomes == [ALICE]


def test_the_session_the_handshake_proved_can_be_named_from_the_same_connection(
    auth_app: AuthApp,
) -> None:
    with auth_app.connect(cookie=auth_app.signed_cookie()) as socket:
        assert socket.receive_json()["session_id"] == SESSION_ID


def test_an_admitted_handshake_renews_its_session_in_place(auth_app: AuthApp) -> None:
    before = auth_app.sessions.record.expires_at

    with auth_app.connect(cookie=auth_app.signed_cookie()) as socket:
        socket.receive_json()

    assert auth_app.sessions.record.expires_at > before


def test_an_admitted_handshake_renews_an_idle_window_session() -> None:
    record = an_idle_session(seen_ago=timedelta(minutes=20))
    seen_before = record.last_seen
    app = an_idle_auth_app(record)

    with app.connect(cookie=app.signed_cookie(), origin="https://app.example") as socket:
        socket.receive_json()

    assert record.last_seen > seen_before


@pytest.mark.parametrize(
    ("origin", "config_overrides"),
    [
        pytest.param(ALLOWED_ORIGIN, NO_PATTERNS, id="an exact host"),
        pytest.param(f"{ALLOWED_ORIGIN}:8443", NO_PATTERNS, id="an exact host on any port"),
        pytest.param("https://app.example", {}, id="a host matching a pattern"),
        pytest.param("http://localhost:8000", LOCAL_DEVELOPMENT_HOSTS, id="localhost, listed"),
        pytest.param("http://127.0.0.1:5173", LOCAL_DEVELOPMENT_HOSTS, id="127.0.0.1, listed"),
    ],
)
def test_an_origin_from_the_configured_hosts_is_admitted(
    origin: str, config_overrides: dict[str, object],
) -> None:
    app = an_auth_app(a_session(), **config_overrides)

    with app.connect(cookie=app.signed_cookie(), origin=origin) as socket:
        assert socket.receive_json()["username"] == "alice"


def test_the_allowlist_decides_whatever_fetch_metadata_claims(auth_app: AuthApp) -> None:
    with auth_app.connect(
        cookie=auth_app.signed_cookie(), headers=[("sec-fetch-site", "cross-site")],
    ) as socket:
        assert socket.receive_json()["username"] == "alice"


@pytest.mark.parametrize(
    ("handshake", "refusal"),
    [
        pytest.param({}, WebSocketRefusal.NO_SESSION, id="no cookie"),
        pytest.param({"cookie": ""}, WebSocketRefusal.NO_SESSION, id="an empty cookie"),
        pytest.param(
            {"cookie": "x" * (MAX_SESSION_COOKIE_CHARS + 1)},
            WebSocketRefusal.NO_SESSION,
            id="an oversized cookie",
        ),
        pytest.param(
            {"cookie": "unsigned"}, WebSocketRefusal.INVALID_SESSION, id="an unsigned cookie",
        ),
        pytest.param(
            {"cookie": sign_session_id(SESSION_ID, b"another signing key entirely")},
            WebSocketRefusal.INVALID_SESSION,
            id="a cookie signed with another key",
        ),
        pytest.param(
            {
                "headers": [
                    (
                        "cookie",
                        session_cookie_header(
                            sign_session_id(SESSION_ID, SIGNING_KEY),
                            sign_session_id("session-2", SIGNING_KEY),
                        ),
                    ),
                ],
            },
            WebSocketRefusal.INVALID_SESSION,
            id="two session cookies",
        ),
    ],
)
def test_a_handshake_without_one_valid_session_cookie_is_refused(
    auth_app: AuthApp, handshake: dict[str, object], refusal: WebSocketRefusal,
) -> None:
    assert the_refusal_of(auth_app, **handshake) is refusal


@pytest.mark.parametrize(
    ("record", "refusal"),
    [
        pytest.param(
            None, WebSocketRefusal.SESSION_ENDED_OR_EXPIRED, id="a session the store does not know",
        ),
        pytest.param(
            a_session(remaining=-timedelta(seconds=1)),
            WebSocketRefusal.SESSION_ENDED_OR_EXPIRED,
            id="a session past its expiry",
        ),
        pytest.param(
            a_session(age=timedelta(days=2)),
            WebSocketRefusal.SESSION_ENDED_OR_EXPIRED,
            id="a session past the absolute limit",
        ),
        pytest.param(
            a_session(user=FakeUser(is_active=False)),
            WebSocketRefusal.ACCOUNT_DISABLED,
            id="a deactivated account",
        ),
    ],
)
def test_a_session_that_no_longer_stands_is_refused(
    record: FakeSessionRecord | None, refusal: WebSocketRefusal,
) -> None:
    app = an_auth_app(record)

    assert the_refusal_of(app, cookie=app.signed_cookie()) is refusal


@pytest.mark.parametrize(
    ("origin", "headers", "refusal"),
    [
        pytest.param(None, [], WebSocketRefusal.MISSING_ORIGIN, id="no Origin"),
        pytest.param(
            None,
            [("referer", f"{ALLOWED_ORIGIN}/room"), ("sec-fetch-site", "same-origin")],
            WebSocketRefusal.MISSING_ORIGIN,
            id="no Origin, an allowed Referer and same-origin metadata",
        ),
        pytest.param(
            "https://evil.test",
            [("sec-fetch-site", "same-origin")],
            WebSocketRefusal.FOREIGN_ORIGIN,
            id="a foreign Origin claiming same-origin metadata",
        ),
        pytest.param("null", [], WebSocketRefusal.FOREIGN_ORIGIN, id="the null Origin"),
        pytest.param("", [], WebSocketRefusal.FOREIGN_ORIGIN, id="an empty Origin"),
        pytest.param("http://[::1", [], WebSocketRefusal.FOREIGN_ORIGIN, id="an unparsable Origin"),
        pytest.param(
            "https://user@songmaker.example",
            [],
            WebSocketRefusal.FOREIGN_ORIGIN,
            id="an Origin carrying credentials",
        ),
        pytest.param(
            None,
            [("origin", ALLOWED_ORIGIN), ("origin", ALLOWED_ORIGIN)],
            WebSocketRefusal.FOREIGN_ORIGIN,
            id="two Origins, both allowed",
        ),
    ],
)
def test_a_handshake_without_exactly_one_allowed_origin_is_refused(
    auth_app: AuthApp,
    origin: str | None,
    headers: Sequence[tuple[str, str]],
    refusal: WebSocketRefusal,
) -> None:
    assert (
        the_refusal_of(auth_app, cookie=auth_app.signed_cookie(), origin=origin, headers=headers)
        is refusal
    )


def test_a_sibling_host_the_application_does_not_list_is_refused_even_as_same_site() -> None:
    app = an_auth_app(a_session(), allowed_hosts_patterns=())

    refusal = the_refusal_of(
        app,
        cookie=app.signed_cookie(),
        origin="https://sibling.songmaker.example",
        headers=[("sec-fetch-site", "same-site")],
    )

    assert refusal is WebSocketRefusal.FOREIGN_ORIGIN


def test_a_refused_origin_leaves_the_session_and_the_audit_untouched() -> None:
    record = a_session(ip_address="203.0.113.9")
    app = an_auth_app(record)
    stored = (record.expires_at, record.ip_address)

    the_refusal_of(app, cookie=app.signed_cookie(), origin="https://evil.test")

    after = (record.expires_at, record.ip_address)

    assert after == stored
    assert app.audit.events == []


@pytest.mark.parametrize(
    ("origin", "refusal"),
    [
        pytest.param(None, WebSocketRefusal.MISSING_ORIGIN, id="no Origin"),
        pytest.param("https://evil.test", WebSocketRefusal.FOREIGN_ORIGIN, id="a foreign Origin"),
    ],
)
def test_a_refused_origin_never_asks_the_store(
    origin: str | None, refusal: WebSocketRefusal,
) -> None:
    app = an_auth_app(None, sessions=SessionsThatMustNotBeAsked(a_session()))

    assert the_refusal_of(app, cookie=app.signed_cookie(), origin=origin) is refusal
    assert app.audit.events == []


def test_a_touch_reporting_no_row_refuses_the_handshake_without_audit() -> None:
    record = a_session(ip_address="203.0.113.9")
    app = an_auth_app(None, sessions=SessionsAnsweringTouch(record, False))

    refusal = the_refusal_of(app, cookie=app.signed_cookie())

    assert refusal is WebSocketRefusal.SESSION_ENDED_OR_EXPIRED
    assert app.audit.events == []


@pytest.mark.parametrize("answer", [None, 1], ids=["None", "an int"])
def test_a_touch_answering_anything_but_a_bool_is_never_accepted(answer: object) -> None:
    app = an_auth_app(None, sessions=SessionsAnsweringTouch(a_session(), answer))

    with (
        pytest.raises(TypeError, match="SessionRecordStore.touch"),
        app.connect(cookie=app.signed_cookie()),
    ):
        pass


def test_a_failing_transaction_never_accepts_the_socket(auth_app: AuthApp) -> None:
    auth_app.sessions.commit_failure = ConnectionError("database down")

    with (
        pytest.raises(ConnectionError, match="database down"),
        auth_app.connect(cookie=auth_app.signed_cookie()),
    ):
        pass


def test_a_handshake_from_a_new_address_and_agent_is_reported_once_each_by_reference() -> None:
    app = an_auth_app(a_session(ip_address="203.0.113.9", user_agent="OldBrowser/1.0"))

    with app.connect(cookie=app.signed_cookie()) as socket:
        socket.receive_json()

    assert app.audit.events == [
        SessionIdentityChanged(
            change=SessionIdentityChange.IP_ADDRESS,
            user_id="user-1",
            session_ref=session_reference(SESSION_ID),
            previous="203.0.113.9",
            current=CLIENT_ADDRESS,
        ),
        SessionIdentityChanged(
            change=SessionIdentityChange.USER_AGENT,
            user_id="user-1",
            session_ref=session_reference(SESSION_ID),
            previous="OldBrowser/1.0",
            current=CLIENT_USER_AGENT,
        ),
    ]


def test_a_forwarded_address_from_an_untrusted_peer_is_not_the_client_identity() -> None:
    app = an_auth_app(a_session(ip_address="203.0.113.9"))

    with app.connect(
        cookie=app.signed_cookie(), headers=[("x-forwarded-for", "198.51.100.77")],
    ) as socket:
        socket.receive_json()

    recorded = [event.current for event in app.audit.events]

    assert recorded == [CLIENT_ADDRESS]


def test_a_long_user_agent_is_reported_cut_to_the_recorded_length() -> None:
    app = an_auth_app(a_session())

    long_agent = "u" * 10 * DEFAULT_MAX_USER_AGENT_CHARS

    with app.connect(cookie=app.signed_cookie(), headers=[("user-agent", long_agent)]) as socket:
        socket.receive_json()

    recorded = [event.current for event in app.audit.events]

    assert recorded == ["u" * DEFAULT_MAX_USER_AGENT_CHARS]


def logged_out(app: AuthApp) -> None:
    end_session(app.sessions, session_id=SESSION_ID)


def expired(app: AuthApp) -> None:
    app.sessions.record.expires_at = datetime.now(UTC) - timedelta(seconds=1)


def deactivated(app: AuthApp) -> None:
    app.sessions.record.user.is_active = False


def past_the_absolute_limit(app: AuthApp) -> None:
    app.sessions.record.created_at = datetime.now(UTC) - timedelta(days=2)


@pytest.mark.parametrize(
    ("ends_the_session", "refusal"),
    [
        pytest.param(logged_out, WebSocketRefusal.SESSION_ENDED_OR_EXPIRED, id="a logout"),
        pytest.param(expired, WebSocketRefusal.SESSION_ENDED_OR_EXPIRED, id="an expiry"),
        pytest.param(deactivated, WebSocketRefusal.ACCOUNT_DISABLED, id="a deactivation"),
        pytest.param(
            past_the_absolute_limit,
            WebSocketRefusal.SESSION_ENDED_OR_EXPIRED,
            id="the absolute limit, however recently it was renewed",
        ),
    ],
)
def test_a_later_check_closes_a_socket_whose_session_has_ended(
    auth_app: AuthApp,
    ends_the_session: Callable[[AuthApp], None],
    refusal: WebSocketRefusal,
) -> None:
    with auth_app.connect(cookie=auth_app.signed_cookie()) as socket:
        socket.receive_json()
        ends_the_session(auth_app)
        socket.send_text("check again")
        with pytest.raises(WebSocketDisconnect) as closed:
            socket.receive_json()

    assert closed.value.code == POLICY_VIOLATION_CLOSE_CODE
    assert auth_app.websocket_outcomes[-1] is refusal


def test_a_later_check_after_expiry_renews_nothing(auth_app: AuthApp) -> None:
    with auth_app.connect(cookie=auth_app.signed_cookie()) as socket:
        socket.receive_json()
        expired(auth_app)
        expired_at = auth_app.sessions.record.expires_at
        socket.send_text("check again")
        with pytest.raises(WebSocketDisconnect):
            socket.receive_json()

    assert auth_app.sessions.record.expires_at == expired_at


def test_a_later_check_counts_as_activity_and_keeps_the_socket_open(auth_app: AuthApp) -> None:
    with auth_app.connect(cookie=auth_app.signed_cookie()) as socket:
        socket.receive_json()
        nearly_expired = datetime.now(UTC) + timedelta(seconds=30)
        auth_app.sessions.record.expires_at = nearly_expired
        socket.send_text("check again")

        assert socket.receive_json() == {"username": "alice"}

    assert auth_app.sessions.record.expires_at > nearly_expired


def test_a_host_dependency_around_the_helper_admits_a_live_session(auth_app: AuthApp) -> None:
    with auth_app.connect(WEBSOCKET_DEPENDENCY_PATH, cookie=auth_app.signed_cookie()) as socket:
        assert socket.receive_json() == {"username": "alice"}


def test_a_host_dependency_around_the_helper_refuses_as_the_plain_call_does(
    auth_app: AuthApp,
) -> None:
    assert the_refusal_of(auth_app, path=WEBSOCKET_DEPENDENCY_PATH) is WebSocketRefusal.NO_SESSION


async def no_message() -> dict[str, object]:
    return {}


async def discard_message(message: dict[str, object]) -> None:
    return None


def a_connection(connection_type: type[HTTPConnection], scope_type: str) -> HTTPConnection:
    app = FastAPI()
    install_web_auth_config(app, CONFIG)
    cookie = f"{SESSION_COOKIE_NAME}={sign_session_id(SESSION_ID, SIGNING_KEY)}"
    scope = {
        "type": scope_type,
        "app": app,
        "client": (CLIENT_ADDRESS, 50000),
        "headers": [
            (b"cookie", cookie.encode()),
            (b"user-agent", CLIENT_USER_AGENT.encode()),
        ],
    }
    if connection_type is WebSocket:
        return WebSocket(scope, no_message, discard_message)
    return connection_type(scope)


@pytest.mark.parametrize(
    "connection",
    [a_connection(Request, "http"), a_connection(WebSocket, "websocket")],
    ids=["an HTTP request", "a WebSocket connection"],
)
@pytest.mark.parametrize(
    ("function", "extra_arguments", "answer"),
    [
        pytest.param(web_auth_config, {}, CONFIG, id="web_auth_config"),
        pytest.param(
            cookie_pairs,
            {},
            [(SESSION_COOKIE_NAME, sign_session_id(SESSION_ID, SIGNING_KEY))],
            id="cookie_pairs",
        ),
        pytest.param(
            cookie_values,
            {"name": SESSION_COOKIE_NAME},
            [sign_session_id(SESSION_ID, SIGNING_KEY)],
            id="cookie_values",
        ),
        pytest.param(resolve_client_ip, {}, CLIENT_ADDRESS, id="resolve_client_ip"),
        pytest.param(client_user_agent, {}, CLIENT_USER_AGENT, id="client_user_agent"),
        pytest.param(
            session_id_from_request,
            {"config": CONFIG},
            SESSION_ID,
            id="session_id_from_request",
        ),
    ],
)
def test_a_widened_public_function_takes_its_connection_by_keyword_and_by_position(
    function: Callable[..., object],
    extra_arguments: dict[str, object],
    answer: object,
    connection: HTTPConnection,
) -> None:
    assert function(connection=connection, **extra_arguments) == answer
    assert function(connection, **extra_arguments) == answer
