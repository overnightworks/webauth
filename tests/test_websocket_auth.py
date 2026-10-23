"""What a WebSocket handshake proves, and how a later check closes the socket."""

from __future__ import annotations

from collections.abc import Callable, Sequence
from datetime import UTC, datetime, timedelta

import pytest
from fastapi import FastAPI
from starlette.requests import HTTPConnection, Request
from starlette.websockets import WebSocket, WebSocketDisconnect
from webauth_arrangement import (
    ALLOWED_HOST,
    ALLOWED_ORIGIN,
    CLIENT_ADDRESS,
    FIXED_INSTANT,
    FIXED_WALL_CLOCK,
    MEMBER_ROLE,
    POLICY_VIOLATION_CLOSE_CODE,
    SESSION_COOKIE_NAME,
    SESSION_ID,
    SESSION_IDLE_SECONDS,
    WEBSOCKET_DEPENDENCY_PATH,
    AuthApp,
    SessionsAnsweringTouch,
    SessionsThatMustNotBeAsked,
    a_session,
    a_web_auth_config,
    an_auth_app,
    session_cookie_header,
)

from webauth.config import (
    install_web_auth_config,
    web_auth_config,
)
from webauth.cookies import (
    MAX_SESSION_COOKIE_CHARS,
    _cookie_pairs,
    _cookie_values,
    sign_session_id,
)
from webauth.dependencies import ConnectionRefusal, session_id_from_request
from webauth.ports import AuthenticatedUser
from webauth.proxies import resolve_client_ip

CONFIG = a_web_auth_config()
SIGNING_KEY = CONFIG.signing_key
ALICE = AuthenticatedUser(id="user-1", username="alice", role=MEMBER_ROLE)
LOOPBACK_HOSTS = frozenset({"localhost", "127.0.0.1"})
PLAIN_HTTP_DEVELOPMENT = {"allowed_hosts_exact": LOOPBACK_HOSTS, "cookie_secure": False}
HTTPS_DEVELOPMENT = {"allowed_hosts_exact": LOOPBACK_HOSTS, "cookie_secure": True}


@pytest.fixture
def auth_app() -> AuthApp:
    return an_auth_app(a_session())


def the_refusal_of(app: AuthApp, **handshake: object) -> ConnectionRefusal:
    """Drive a handshake that must close before accept, and say why the helper refused it."""
    with pytest.raises(WebSocketDisconnect) as closed, app.connect(**handshake):
        pass
    assert closed.value.code == POLICY_VIOLATION_CLOSE_CODE
    refusal = app.websocket_outcomes[-1]
    assert isinstance(refusal, ConnectionRefusal)
    return refusal


def test_the_refusals_keep_their_stable_values() -> None:
    values_by_name = {refusal.name: refusal.value for refusal in ConnectionRefusal}

    assert values_by_name == {
        "NO_SESSION": "no-session",
        "INVALID_SESSION": "invalid-session",
        "SESSION_ENDED_OR_EXPIRED": "session-ended-or-expired",
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


def test_a_handshake_decides_at_the_configured_clock_like_a_request_does() -> None:
    expired = a_session(now=FIXED_INSTANT, remaining=timedelta(seconds=-1))
    expired_app = an_auth_app(expired, wall_clock=FIXED_WALL_CLOCK)
    admitted = a_session(now=FIXED_INSTANT, remaining=timedelta(seconds=1))
    admitted_app = an_auth_app(admitted, wall_clock=FIXED_WALL_CLOCK)

    with pytest.raises(WebSocketDisconnect), expired_app.connect(
        cookie=expired_app.signed_cookie(),
    ):
        pass
    with admitted_app.connect(cookie=admitted_app.signed_cookie()) as socket:
        socket.receive_json()

    assert expired_app.websocket_outcomes == [ConnectionRefusal.SESSION_ENDED_OR_EXPIRED]
    assert expired.expires_at == FIXED_INSTANT - timedelta(seconds=1)
    assert admitted.expires_at == FIXED_INSTANT + timedelta(seconds=SESSION_IDLE_SECONDS)


@pytest.mark.parametrize(
    ("origin", "config_overrides"),
    [
        pytest.param(ALLOWED_ORIGIN, {}, id="an exact host"),
        pytest.param(f"{ALLOWED_ORIGIN}:8443", {}, id="an exact host on any port"),
        pytest.param("http://localhost:8000", PLAIN_HTTP_DEVELOPMENT, id="localhost over http"),
        pytest.param("http://127.0.0.1:5173", PLAIN_HTTP_DEVELOPMENT, id="127.0.0.1 over http"),
        pytest.param("https://localhost:8000", HTTPS_DEVELOPMENT, id="localhost over https"),
        pytest.param("https://127.0.0.1:5173", HTTPS_DEVELOPMENT, id="127.0.0.1 over https"),
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
        pytest.param({}, ConnectionRefusal.NO_SESSION, id="no cookie"),
        pytest.param({"cookie": ""}, ConnectionRefusal.NO_SESSION, id="an empty cookie"),
        pytest.param(
            {"cookie": "x" * (MAX_SESSION_COOKIE_CHARS + 1)},
            ConnectionRefusal.NO_SESSION,
            id="an oversized cookie",
        ),
        pytest.param(
            {"cookie": "unsigned"}, ConnectionRefusal.INVALID_SESSION, id="an unsigned cookie",
        ),
        pytest.param(
            {"cookie": sign_session_id(SESSION_ID, b"another signing key entirely")},
            ConnectionRefusal.INVALID_SESSION,
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
            ConnectionRefusal.INVALID_SESSION,
            id="two session cookies",
        ),
    ],
)
def test_a_handshake_without_one_valid_session_cookie_is_refused(
    auth_app: AuthApp, handshake: dict[str, object], refusal: ConnectionRefusal,
) -> None:
    assert the_refusal_of(auth_app, **handshake) is refusal


@pytest.mark.parametrize(
    ("origin", "headers", "refusal"),
    [
        pytest.param(None, [], ConnectionRefusal.MISSING_ORIGIN, id="no Origin"),
        pytest.param(
            None,
            [("referer", f"{ALLOWED_ORIGIN}/room"), ("sec-fetch-site", "same-origin")],
            ConnectionRefusal.MISSING_ORIGIN,
            id="no Origin, an allowed Referer and same-origin metadata",
        ),
        pytest.param(
            "https://evil.test",
            [("sec-fetch-site", "same-origin")],
            ConnectionRefusal.FOREIGN_ORIGIN,
            id="a foreign Origin claiming same-origin metadata",
        ),
        pytest.param(
            "https://app.example", [], ConnectionRefusal.FOREIGN_ORIGIN, id="a former pattern host",
        ),
        pytest.param("null", [], ConnectionRefusal.FOREIGN_ORIGIN, id="the null Origin"),
        pytest.param("", [], ConnectionRefusal.FOREIGN_ORIGIN, id="an empty Origin"),
        pytest.param(
            "http://[::1", [], ConnectionRefusal.FOREIGN_ORIGIN, id="an unparsable Origin",
        ),
        pytest.param(
            f"https://user@{ALLOWED_HOST}",
            [],
            ConnectionRefusal.FOREIGN_ORIGIN,
            id="an Origin carrying credentials",
        ),
        pytest.param(
            None,
            [("origin", ALLOWED_ORIGIN), ("origin", ALLOWED_ORIGIN)],
            ConnectionRefusal.FOREIGN_ORIGIN,
            id="two Origins, both allowed",
        ),
    ],
)
def test_a_handshake_without_exactly_one_allowed_origin_is_refused(
    auth_app: AuthApp,
    origin: str | None,
    headers: Sequence[tuple[str, str]],
    refusal: ConnectionRefusal,
) -> None:
    assert (
        the_refusal_of(auth_app, cookie=auth_app.signed_cookie(), origin=origin, headers=headers)
        is refusal
    )


def test_a_sibling_host_the_application_does_not_list_is_refused_even_as_same_site() -> None:
    app = an_auth_app(a_session())

    refusal = the_refusal_of(
        app,
        cookie=app.signed_cookie(),
        origin=f"https://sibling.{ALLOWED_HOST}",
        headers=[("sec-fetch-site", "same-site")],
    )

    assert refusal is ConnectionRefusal.FOREIGN_ORIGIN


def test_a_refused_origin_leaves_the_session_untouched() -> None:
    record = a_session()
    app = an_auth_app(record)
    stored_expiry = record.expires_at

    the_refusal_of(app, cookie=app.signed_cookie(), origin="https://evil.test")

    assert record.expires_at == stored_expiry


@pytest.mark.parametrize(
    ("origin", "refusal"),
    [
        pytest.param(None, ConnectionRefusal.MISSING_ORIGIN, id="no Origin"),
        pytest.param("https://evil.test", ConnectionRefusal.FOREIGN_ORIGIN, id="a foreign Origin"),
    ],
)
def test_a_refused_origin_never_asks_the_store(
    origin: str | None, refusal: ConnectionRefusal,
) -> None:
    app = an_auth_app(None, sessions=SessionsThatMustNotBeAsked(a_session()))

    assert the_refusal_of(app, cookie=app.signed_cookie(), origin=origin) is refusal


@pytest.mark.parametrize("cookie_secure", [True, False], ids=["secure", "plain-http"])
@pytest.mark.parametrize(
    ("origin", "is_plain_http"),
    [
        pytest.param(f"http://{ALLOWED_HOST}", True, id="an http Origin"),
        pytest.param(f"HTTP://{ALLOWED_HOST}", True, id="an upper-case HTTP Origin"),
        pytest.param(ALLOWED_ORIGIN, False, id="an https Origin"),
    ],
)
def test_the_origin_scheme_is_compared_only_while_cookie_secure_is_on(
    origin: str, is_plain_http: bool, cookie_secure: bool,
) -> None:
    refused = cookie_secure and is_plain_http
    sessions = SessionsThatMustNotBeAsked(a_session()) if refused else None
    app = an_auth_app(a_session(), sessions=sessions, cookie_secure=cookie_secure)

    if refused:
        assert the_refusal_of(app, cookie=app.signed_cookie(), origin=origin) is (
            ConnectionRefusal.FOREIGN_ORIGIN
        )
    else:
        with app.connect(cookie=app.signed_cookie(), origin=origin) as socket:
            assert socket.receive_json()["username"] == "alice"


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


def logged_out(app: AuthApp) -> None:
    app.sessions.delete(SESSION_ID)


def expired(app: AuthApp) -> None:
    app.sessions.record.expires_at = datetime.now(UTC) - timedelta(seconds=1)


def past_the_absolute_limit(app: AuthApp) -> None:
    app.sessions.record.created_at = datetime.now(UTC) - timedelta(days=2)


@pytest.mark.parametrize(
    ("ends_the_session", "refusal"),
    [
        pytest.param(logged_out, ConnectionRefusal.SESSION_ENDED_OR_EXPIRED, id="a logout"),
        pytest.param(expired, ConnectionRefusal.SESSION_ENDED_OR_EXPIRED, id="an expiry"),
        pytest.param(
            past_the_absolute_limit,
            ConnectionRefusal.SESSION_ENDED_OR_EXPIRED,
            id="the absolute limit, however recently it was renewed",
        ),
    ],
)
def test_a_later_check_closes_a_socket_whose_session_has_ended(
    auth_app: AuthApp,
    ends_the_session: Callable[[AuthApp], None],
    refusal: ConnectionRefusal,
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
    assert the_refusal_of(auth_app, path=WEBSOCKET_DEPENDENCY_PATH) is ConnectionRefusal.NO_SESSION


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
        "headers": [(b"cookie", cookie.encode())],
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
            _cookie_pairs,
            {},
            [(SESSION_COOKIE_NAME, sign_session_id(SESSION_ID, SIGNING_KEY))],
            id="cookie_pairs",
        ),
        pytest.param(
            _cookie_values,
            {"name": SESSION_COOKIE_NAME},
            [sign_session_id(SESSION_ID, SIGNING_KEY)],
            id="cookie_values",
        ),
        pytest.param(resolve_client_ip, {}, CLIENT_ADDRESS, id="resolve_client_ip"),
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
