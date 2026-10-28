"""What a signed session cookie proves, and what the application hears about it."""

from __future__ import annotations

import asyncio
from datetime import timedelta
from urllib.parse import urlencode

import pytest
from fastapi import Depends, FastAPI, Request
from fastapi.testclient import TestClient
from starlette.types import Message

from tests.support.webauth_arrangement import (
    ADMIN_ROLE,
    FIXED_INSTANT,
    FIXED_WALL_CLOCK,
    HTTPS_TEST_SERVER,
    MEMBER_ROLE,
    SESSION_COOKIE_NAME,
    SESSION_ID,
    AuthApp,
    FakeSessionRecord,
    FakeUser,
    SessionRecordsInMemory,
    SessionsAnsweringTouch,
    a_session,
    a_web_auth_config,
    an_auth_app,
    session_cookie_header,
    signed_without_bound,
)
from webauth.config import install_web_auth_config
from webauth.cookies import (
    MAX_SESSION_COOKIE_CHARS,
    PLAIN_SESSION_COOKIE_NAME,
    sign_session_id,
)
from webauth.dependencies import (
    LoginRedirect,
    current_user_dependency,
    session_id_from_request,
)
from webauth.ports import AuthenticatedUser

ADMIN_REQUIRED_DETAIL = "Admin access required"
AUTHENTICATION_REQUIRED_DETAIL = "Authentication required"
INVALID_SESSION_DETAIL = "Invalid session"
SESSION_EXPIRED_DETAIL = "Session expired"

A_LOGIN_REDIRECT = LoginRedirect(path="/login", redirect_query_param="next")
A_CONFIGURED_LOGIN_REDIRECT = LoginRedirect(path="/login", redirect_query_param="return_to")


@pytest.fixture
def auth_app() -> AuthApp:
    return an_auth_app(a_session())


@pytest.mark.parametrize(
    "path",
    [
        pytest.param("login", id="no leading slash"),
        pytest.param("//evil.example/login", id="a scheme-relative address"),
        pytest.param("/\\evil.example/login", id="a slash then a backslash"),
        pytest.param("\\/evil.example/login", id="a backslash then a slash"),
        pytest.param("\\\\evil.example/login", id="two backslashes"),
        pytest.param("/\t/evil.example/login", id="a tab the browser strips"),
        pytest.param("/\r\n/evil.example/login", id="a CR and LF the browser strips"),
        pytest.param("https://evil.example/login", id="an absolute URL"),
        pytest.param("javascript:alert(1)", id="a non-http scheme"),
    ],
)
def test_a_login_redirect_refuses_a_path_that_is_not_same_origin(path: str) -> None:
    with pytest.raises(ValueError, match="same-origin"):
        LoginRedirect(path=path, redirect_query_param="next")


def test_a_signed_cookie_names_the_account_behind_the_request(auth_app: AuthApp) -> None:
    response = auth_app.get("/me", cookie=auth_app.signed_cookie())

    assert response.status_code == 200
    assert response.json() == {"username": "alice", "role": MEMBER_ROLE}


def test_the_application_is_told_which_account_authenticated(auth_app: AuthApp) -> None:
    auth_app.get("/me", cookie=auth_app.signed_cookie())

    assert auth_app.authenticated == [
        AuthenticatedUser(id="user-1", username="alice", role=MEMBER_ROLE),
    ]


@pytest.mark.parametrize(
    ("cookie", "detail"),
    [
        pytest.param(None, AUTHENTICATION_REQUIRED_DETAIL, id="no cookie at all"),
        pytest.param("", AUTHENTICATION_REQUIRED_DETAIL, id="an empty cookie"),
        pytest.param(
            "x" * (MAX_SESSION_COOKIE_CHARS + 1),
            AUTHENTICATION_REQUIRED_DETAIL,
            id="a cookie longer than the reader accepts",
        ),
        pytest.param("unsigned", INVALID_SESSION_DETAIL, id="a cookie without a signature"),
        pytest.param(
            r'"abc.\351"', INVALID_SESSION_DETAIL, id="a cookie with non-ASCII characters",
        ),
        pytest.param(
            sign_session_id(SESSION_ID, b"a different signing key entirely"),
            INVALID_SESSION_DETAIL,
            id="a cookie signed with another key",
        ),
    ],
)
def test_a_cookie_that_was_not_issued_here_authenticates_nobody(
    auth_app: AuthApp, cookie: str | None, detail: str,
) -> None:
    response = auth_app.get("/me", cookie=cookie)

    assert response.status_code == 401
    assert response.json()["detail"] == detail


SIGNING_KEY = a_web_auth_config().signing_key
STORED_SESSION_COOKIE = sign_session_id(SESSION_ID, SIGNING_KEY)
ANOTHER_SESSION_COOKIE = sign_session_id("another-session", SIGNING_KEY)
FORGED_COOKIE = sign_session_id(SESSION_ID, b"a different signing key entirely")


@pytest.mark.parametrize(
    "cookie_headers",
    [
        pytest.param(
            [session_cookie_header(STORED_SESSION_COOKIE, STORED_SESSION_COOKIE)],
            id="the same valid cookie twice",
        ),
        pytest.param(
            [session_cookie_header(STORED_SESSION_COOKIE, ANOTHER_SESSION_COOKIE)],
            id="the stored session before another signed one",
        ),
        pytest.param(
            [session_cookie_header(ANOTHER_SESSION_COOKIE, STORED_SESSION_COOKIE)],
            id="another signed session before the stored one",
        ),
        pytest.param(
            [session_cookie_header(STORED_SESSION_COOKIE, FORGED_COOKIE)],
            id="a valid cookie before a forged one",
        ),
        pytest.param(
            [session_cookie_header(FORGED_COOKIE, STORED_SESSION_COOKIE)],
            id="a forged cookie before a valid one",
        ),
        pytest.param(
            [session_cookie_header(FORGED_COOKIE, "unsigned")],
            id="two invalid cookies",
        ),
        pytest.param(
            [
                session_cookie_header(STORED_SESSION_COOKIE),
                session_cookie_header(ANOTHER_SESSION_COOKIE),
            ],
            id="one cookie in each of two Cookie headers",
        ),
    ],
)
@pytest.mark.parametrize("path", ["/me", "/admin", "/session-id"])
def test_a_request_carrying_more_than_one_session_cookie_authenticates_nobody(
    cookie_headers: list[str], path: str,
) -> None:
    """Whichever cookie a dict kept, the request could run in a tossed account."""
    app = an_auth_app(a_session(user=FakeUser(id="user-2", username="mallory")))

    response = app.client.get(
        path, headers=[("cookie", header) for header in cookie_headers],
    )

    assert response.status_code == 401
    assert response.json()["detail"] == INVALID_SESSION_DETAIL


OVERLONG_SIGNED_COOKIE = signed_without_bound("s" * MAX_SESSION_COOKIE_CHARS, SIGNING_KEY)


def a_bare_request(*cookie_headers: str) -> Request:
    headers = [(b"cookie", header.encode()) for header in cookie_headers]
    return Request({"type": "http", "method": "GET", "path": "/", "headers": headers})


@pytest.mark.parametrize(
    ("cookie_headers", "session_id"),
    [
        pytest.param(
            [session_cookie_header(STORED_SESSION_COOKIE)], SESSION_ID, id="one cookie",
        ),
        pytest.param([], None, id="no cookie"),
        pytest.param(
            [session_cookie_header(STORED_SESSION_COOKIE, STORED_SESSION_COOKIE)],
            None,
            id="the same cookie twice",
        ),
        pytest.param(
            [session_cookie_header(OVERLONG_SIGNED_COOKIE)],
            None,
            id="a correctly signed cookie longer than the reader accepts",
        ),
        pytest.param([session_cookie_header("unsigned")], None, id="an unsigned cookie"),
    ],
)
def test_the_session_cookie_reader_names_only_the_one_signed_session(
    cookie_headers: list[str], session_id: str | None,
) -> None:
    request = a_bare_request(*cookie_headers)

    assert session_id_from_request(request, a_web_auth_config()) == session_id


@pytest.mark.parametrize(
    "cookie_header",
    [
        pytest.param(
            f"x{SESSION_COOKIE_NAME}={ANOTHER_SESSION_COOKIE}; "
            f"{session_cookie_header(STORED_SESSION_COOKIE)}",
            id="a cookie whose name ends like the session cookie",
        ),
        pytest.param(
            f"{session_cookie_header(STORED_SESSION_COOKIE)}; "
            f"{SESSION_COOKIE_NAME}_old={ANOTHER_SESSION_COOKIE}",
            id="a cookie whose name starts like the session cookie",
        ),
        pytest.param(
            "theme=dark; " + session_cookie_header(f'"{STORED_SESSION_COOKIE}"'),
            id="a quoted session cookie",
        ),
    ],
)
def test_one_session_cookie_among_others_still_authenticates(
    auth_app: AuthApp, cookie_header: str,
) -> None:
    response = auth_app.client.get("/me", headers={"cookie": cookie_header})

    assert response.status_code == 200
    assert response.json() == {"username": "alice", "role": MEMBER_ROLE}


def test_a_signed_cookie_under_the_pre_upgrade_name_signs_nobody_in(auth_app: AuthApp) -> None:
    """Only the configured ``__Host-`` name is read; a sibling host can plant the plain one."""
    old_cookie = f"{PLAIN_SESSION_COOKIE_NAME}={auth_app.signed_cookie()}"

    response = auth_app.client.get("/me", headers={"cookie": old_cookie})

    assert response.status_code == 401
    assert response.json()["detail"] == AUTHENTICATION_REQUIRED_DETAIL


def test_a_served_request_renews_its_session_in_place(auth_app: AuthApp) -> None:
    before = auth_app.sessions.stored_record.expires_at

    auth_app.get("/me", cookie=auth_app.signed_cookie())

    assert auth_app.sessions.stored_record.expires_at > before


def test_a_session_one_second_past_the_configured_clock_is_refused_and_not_renewed() -> None:
    record = a_session(now=FIXED_INSTANT, remaining=timedelta(seconds=-1))
    app = an_auth_app(record, wall_clock=FIXED_WALL_CLOCK)

    response = app.get("/me", cookie=app.signed_cookie())

    assert response.status_code == 401
    assert response.json()["detail"] == SESSION_EXPIRED_DETAIL
    assert record.expires_at == FIXED_INSTANT - timedelta(seconds=1)


@pytest.mark.parametrize("answer", [None, 1], ids=["None", "an int"])
def test_a_touch_answering_anything_but_a_bool_is_refused(answer: object) -> None:
    sessions = SessionsAnsweringTouch(a_session(), answer)
    app = an_auth_app(None, sessions=sessions)
    cookie = app.signed_cookie()

    with pytest.raises(TypeError, match="SessionRecordStore.touch"):
        app.get("/me", cookie=cookie)


def test_a_touch_reporting_no_row_refuses_the_request_and_writes_nothing() -> None:
    record = a_session()
    stored_expiry = record.expires_at
    app = an_auth_app(None, sessions=SessionsAnsweringTouch(record, False))

    response = app.get("/me", cookie=app.signed_cookie())

    assert response.status_code == 401
    assert record.expires_at == stored_expiry
    assert app.authenticated == []


def test_the_admin_route_admits_the_configured_admin_role() -> None:
    app = an_auth_app(a_session(user=FakeUser(role=ADMIN_ROLE)))

    response = app.get("/admin", cookie=app.signed_cookie())

    assert response.status_code == 200
    assert response.json() == {"username": "alice"}


def test_the_admin_route_refuses_every_other_role(auth_app: AuthApp) -> None:
    response = auth_app.get("/admin", cookie=auth_app.signed_cookie())

    assert response.status_code == 403
    assert response.json()["detail"] == ADMIN_REQUIRED_DETAIL


def test_the_admin_route_refuses_the_same_cookie_the_protected_route_refuses(
    auth_app: AuthApp,
) -> None:
    response = auth_app.get("/admin")

    assert response.status_code == 401
    assert response.json()["detail"] == AUTHENTICATION_REQUIRED_DETAIL


def test_a_route_can_name_the_session_the_request_proved_it_holds(
    auth_app: AuthApp,
) -> None:
    response = auth_app.get("/session-id", cookie=auth_app.signed_cookie())

    assert response.status_code == 200
    assert response.json() == {"session_id": SESSION_ID}


@pytest.mark.parametrize(
    ("record", "cookie", "status", "detail"),
    [
        pytest.param(a_session(), None, 401, AUTHENTICATION_REQUIRED_DETAIL, id="no cookie"),
        pytest.param(
            a_session(remaining=-timedelta(seconds=1)),
            SESSION_ID,
            401,
            SESSION_EXPIRED_DETAIL,
            id="a session past its expiry",
        ),
    ],
)
def test_no_session_is_named_where_no_account_would_be_admitted(
    record: FakeSessionRecord, cookie: str | None, status: int, detail: str,
) -> None:
    app = an_auth_app(record)

    response = app.get(
        "/session-id", cookie=None if cookie is None else app.signed_cookie(),
    )

    assert response.status_code == status
    assert response.json()["detail"] == detail


@pytest.mark.parametrize(
    ("login_redirect", "accept", "status", "location"),
    [
        pytest.param(None, None, 401, None, id="an API client"),
        pytest.param(
            A_LOGIN_REDIRECT, "text/html", 302, "/login?next=%2Fsession-id", id="a browser",
        ),
    ],
)
def test_a_replaced_current_user_still_names_no_session_for_a_request_without_a_cookie(
    login_redirect: LoginRedirect | None,
    accept: str | None,
    status: int,
    location: str | None,
) -> None:
    dependencies = current_user_dependency(
        session_store=lambda: SessionRecordsInMemory(None),
        on_authenticated=lambda user: None,
        login_redirect=login_redirect,
    )
    app = FastAPI()
    install_web_auth_config(app, a_web_auth_config())

    @app.get("/session-id")
    def session_id(
        verified: str = Depends(dependencies.verified_session_id),
    ) -> dict[str, str]:
        return {"session_id": verified}

    app.dependency_overrides[dependencies.current_user] = lambda: FakeUser()
    client = TestClient(app, base_url=HTTPS_TEST_SERVER)

    response = client.get(
        "/session-id",
        headers={} if accept is None else {"accept": accept},
        follow_redirects=False,
    )

    assert response.status_code == status
    assert response.headers.get("location") == location
    if location is None:
        assert response.json()["detail"] == AUTHENTICATION_REQUIRED_DETAIL


def test_a_missing_cookie_401_stays_byte_identical_without_a_login_redirect(
    auth_app: AuthApp,
) -> None:
    response = auth_app.get("/me")

    assert response.status_code == 401
    assert response.headers["content-type"] == "application/json"
    assert "location" not in response.headers
    assert response.content == b'{"detail":"Authentication required"}'


def test_an_invalid_signature_401_stays_byte_identical_without_a_login_redirect(
    auth_app: AuthApp,
) -> None:
    response = auth_app.get("/me", cookie="unsigned")

    assert response.status_code == 401
    assert response.headers["content-type"] == "application/json"
    assert "location" not in response.headers
    assert response.content == b'{"detail":"Invalid session"}'


def test_an_expired_session_401_stays_byte_identical_without_a_login_redirect() -> None:
    app = an_auth_app(a_session(remaining=-timedelta(seconds=1)))

    response = app.get("/me", cookie=app.signed_cookie())

    assert response.status_code == 401
    assert response.headers["content-type"] == "application/json"
    assert "location" not in response.headers
    assert response.content == b'{"detail":"Session expired"}'


def test_a_browser_with_no_cookie_at_all_is_sent_to_the_login_page() -> None:
    """The redirect's own status, ``Location``, and body — pinned once here.

    A dependency cannot answer with anything but an ``HTTPException``, so the
    302 still carries FastAPI's JSON body; every other redirect test below
    checks only the status and ``Location`` this one already proves the body of.
    """
    app = an_auth_app(a_session(), login_redirect=A_LOGIN_REDIRECT)

    response = app.get("/me", accept="text/html")

    assert response.status_code == 302
    assert response.headers["location"] == "/login?next=%2Fme"
    assert response.headers["content-type"] == "application/json"
    assert response.content == b'{"detail":"Found"}'


def test_a_browser_with_an_invalid_signature_is_sent_to_the_login_page() -> None:
    app = an_auth_app(a_session(), login_redirect=A_LOGIN_REDIRECT)

    response = app.get("/me", cookie="unsigned", accept="text/html")

    assert response.status_code == 302
    assert response.headers["location"] == "/login?next=%2Fme"


def test_a_browser_whose_session_expired_is_sent_to_the_login_page() -> None:
    app = an_auth_app(
        a_session(remaining=-timedelta(seconds=1)), login_redirect=A_LOGIN_REDIRECT,
    )

    response = app.get("/me", cookie=app.signed_cookie(), accept="text/html")

    assert response.status_code == 302
    assert response.headers["location"] == "/login?next=%2Fme"


@pytest.mark.parametrize(
    ("login_redirect", "expected_location"),
    [
        (A_LOGIN_REDIRECT, "/login?next=%2Fme%3Ftab%3Doverview"),
        (A_CONFIGURED_LOGIN_REDIRECT, "/login?return_to=%2Fme%3Ftab%3Doverview"),
    ],
)
def test_the_redirect_keeps_the_asked_for_query_string_under_the_configured_key(
    login_redirect: LoginRedirect, expected_location: str,
) -> None:
    app = an_auth_app(None, login_redirect=login_redirect)

    response = app.get("/me?tab=overview", accept="text/html")

    assert response.status_code == 302
    assert response.headers["location"] == expected_location


def a_guarded_catch_all_app() -> FastAPI:
    app = FastAPI()
    install_web_auth_config(app, a_web_auth_config())
    guard = current_user_dependency(
        session_store=lambda: SessionRecordsInMemory(None),
        on_authenticated=lambda user: None,
        login_redirect=A_LOGIN_REDIRECT,
    ).current_user

    @app.get("/{anything:path}", dependencies=[Depends(guard)])
    def any_guarded_path() -> None: ...

    return app


@pytest.mark.parametrize(
    ("asked_for", "carried"),
    [
        pytest.param(
            "/%5Cevil.example/x", "/%5Cevil.example/x", id="an encoded backslash stays inert",
        ),
        pytest.param(
            "/%09/evil.example/x", "/%09/evil.example/x", id="an encoded tab stays inert",
        ),
        pytest.param(
            "/lieder/%C3%BC%3Fx?y=1", "/lieder/%C3%BC%3Fx?y=1", id="the raw path is not decoded",
        ),
        pytest.param("/songs/1?x=2", "/songs/1?x=2", id="an ordinary path keeps its query"),
    ],
)
def test_the_redirect_carries_the_raw_path_and_query_of_the_request(
    asked_for: str, carried: str,
) -> None:
    response = TestClient(a_guarded_catch_all_app(), base_url=HTTPS_TEST_SERVER).get(
        asked_for, headers={"accept": "text/html"}, follow_redirects=False,
    )

    assert response.status_code == 302
    assert response.headers["location"] == f"/login?{urlencode({'next': carried})}"


def test_the_redirect_falls_back_for_a_literal_backslash_in_the_raw_path() -> None:
    sent: list[Message] = []
    scope = {
        "type": "http", "asgi": {"version": "3.0"}, "http_version": "1.1", "method": "GET",
        "scheme": "https", "server": ("testserver", 443), "client": ("127.0.0.1", 1),
        "root_path": "", "path": "/\\evil.example/x", "raw_path": b"/\\evil.example/x",
        "query_string": b"", "headers": [(b"host", b"testserver"), (b"accept", b"text/html")],
    }

    async def receive() -> Message:
        return {"type": "http.request", "body": b"", "more_body": False}

    async def send(message: Message) -> None:
        sent.append(message)

    asyncio.run(a_guarded_catch_all_app()(scope, receive, send))

    start = next(message for message in sent if message["type"] == "http.response.start")
    assert start["status"] == 302
    assert dict(start["headers"])[b"location"].decode() == f"/login?{urlencode({'next': '/'})}"


def a_redirect_location(client: TestClient, asked_for: str) -> str:
    response = client.get(asked_for, headers={"accept": "text/html"}, follow_redirects=False)
    assert response.status_code == 302
    return response.headers["location"]


@pytest.mark.parametrize(
    ("root_path", "asked_for", "carried"),
    [
        pytest.param(
            "/app", "/app/albums/42", "/app/albums/42",
            id="a path the server left prefixed",
        ),
        pytest.param(
            "/app", "/albums/42", "/app/albums/42",
            id="a path a proxy stripped of the prefix",
        ),
        pytest.param("/app", "/app/%FF", "/app/%FF", id="invalid UTF-8 below the prefix"),
        pytest.param(
            "/app", "/app/app/x", "/app/app/x",
            id="a prefix repeated by the host's own route",
        ),
        pytest.param(
            "/app", "/application", "/app/application",
            id="a sibling of the prefix's name",
        ),
        pytest.param(
            "/café", "/caf%C3%A9/albums/42", "/",
            id="a non-ASCII root the server left prefixed falls back",
        ),
        pytest.param(
            "/café", "/albums/42", "/",
            id="a non-ASCII root a proxy stripped falls back",
        ),
        pytest.param(
            "/my-app", "/my-app/albums/42", "/my-app/albums/42",
            id="a hyphenated root the server left prefixed",
        ),
        pytest.param(
            "/my-app", "/albums/42", "/my-app/albums/42",
            id="a hyphenated root a proxy stripped",
        ),
    ],
)
def test_the_redirect_carries_the_path_below_the_root_path_prefixed_once(
    root_path: str, asked_for: str, carried: str,
) -> None:
    client = TestClient(a_guarded_catch_all_app(), base_url=HTTPS_TEST_SERVER, root_path=root_path)

    location = a_redirect_location(client, asked_for)

    assert location == f"/login?{urlencode({'next': carried})}"


def test_the_redirect_of_a_mounted_app_carries_the_mount_prefix() -> None:
    host = FastAPI()
    host.mount("/sub", a_guarded_catch_all_app())

    location = a_redirect_location(
        TestClient(host, base_url=HTTPS_TEST_SERVER), "/sub/albums/42",
    )

    assert location == f"/login?{urlencode({'next': '/sub/albums/42'})}"


@pytest.mark.parametrize(
    ("accept", "status"),
    [
        pytest.param("*/*", 401, id="a bare wildcard prefers html no more than json"),
        pytest.param("text/html;q=0", 401, id="html explicitly refused"),
        pytest.param(
            "application/json, text/html;q=0.1",
            401,
            id="json preferred over low-quality html",
        ),
        pytest.param(
            "text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8",
            302,
            id="a browser's default Accept header",
        ),
        pytest.param(
            "application/json;q=0.1,,text/html",
            302,
            id="an empty entry is skipped",
        ),
        pytest.param(
            "text/html;q=abc, application/json;q=0.5",
            302,
            id="an unparsable q counts as 1.0",
        ),
        pytest.param(
            "application/json;level=0.5, text/html",
            401,
            id="a parameter other than q leaves the quality at 1.0, a tie",
        ),
        pytest.param(
            "text/html;q=0.1;q=0.9, application/json;q=0.5",
            302,
            id="the last q within an entry wins",
        ),
        pytest.param(
            "text/html ;q=0.9, application/json;q=0.5",
            302,
            id="the media range is read up to the first semicolon, spaces stripped",
        ),
        pytest.param(
            "text/*;q=0.2, application/json;q=0.1",
            302,
            id="a type wildcard sets the floor for html",
        ),
        pytest.param(
            "text/*;q=0.1, */*;q=0.9, text/*;q=0.2, application/json;q=0.5",
            302,
            id="the highest of several wildcards wins, not the first or the last",
        ),
        pytest.param("Text/HTML", 302, id="a media range compares without regard to case"),
        pytest.param(
            "TEXT/HTML;Q=0.1, application/json;q=0.5",
            401,
            id="the q parameter name compares without regard to case",
        ),
    ],
)
def test_the_redirect_follows_accept_quality_negotiation(accept: str, status: int) -> None:
    app = an_auth_app(None, login_redirect=A_LOGIN_REDIRECT)

    response = app.get("/me", accept=accept)

    assert response.status_code == status


def test_a_request_that_does_not_prefer_html_stays_401_with_a_login_redirect() -> None:
    app = an_auth_app(None, login_redirect=A_LOGIN_REDIRECT)

    response = app.get("/me", accept="application/json")

    assert response.status_code == 401
    assert response.json()["detail"] == AUTHENTICATION_REQUIRED_DETAIL


def test_a_live_session_authenticates_regardless_of_a_configured_login_redirect() -> None:
    app = an_auth_app(a_session(), login_redirect=A_LOGIN_REDIRECT)

    response = app.get("/me", cookie=app.signed_cookie(), accept="text/html")

    assert response.status_code == 200
    assert response.json() == {"username": "alice", "role": MEMBER_ROLE}
