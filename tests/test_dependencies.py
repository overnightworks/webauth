"""What a signed session cookie proves, and what the application hears about it."""

from __future__ import annotations

from datetime import timedelta

import pytest
from webauth_arrangement import (
    ADMIN_ROLE,
    CLIENT_ADDRESS,
    CLIENT_USER_AGENT,
    IDLE_WINDOW_SECONDS,
    MEMBER_ROLE,
    SESSION_ID,
    UNAUTHENTICATED_RESPONSE_PATH,
    AuthApp,
    FakeSessionRecord,
    FakeUser,
    a_session,
    an_auth_app,
    an_idle_auth_app,
    an_idle_session,
)

from webauth.cookies import sign_session_id
from webauth.dependencies import (
    ACCOUNT_DISABLED_DETAIL,
    ADMIN_REQUIRED_DETAIL,
    AUTHENTICATION_REQUIRED_DETAIL,
    INVALID_SESSION_DETAIL,
    MAX_SESSION_COOKIE_CHARS,
    SESSION_EXPIRED_DETAIL,
    AuthenticatedUser,
    LoginRedirect,
)
from webauth.ports import SessionIdentityChange, SessionIdentityChanged

A_LOGIN_REDIRECT = LoginRedirect(path="/login", redirect_query_param="next")


@pytest.fixture
def auth_app() -> AuthApp:
    return an_auth_app(a_session())


@pytest.mark.parametrize(
    "path",
    [
        pytest.param("login", id="no leading slash"),
        pytest.param("//evil.example/login", id="a scheme-relative address"),
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
        AuthenticatedUser(id="user-1", username="alice", role=MEMBER_ROLE, is_active=True),
    ]


@pytest.mark.parametrize(
    ("cookie", "detail"),
    [
        pytest.param(None, AUTHENTICATION_REQUIRED_DETAIL, id="no cookie at all"),
        pytest.param("", AUTHENTICATION_REQUIRED_DETAIL, id="an empty cookie"),
        pytest.param(
            "x" * (MAX_SESSION_COOKIE_CHARS + 1),
            AUTHENTICATION_REQUIRED_DETAIL,
            id="a cookie longer than any this signs",
        ),
        pytest.param("unsigned", INVALID_SESSION_DETAIL, id="a cookie without a signature"),
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


@pytest.mark.parametrize(
    "record",
    [
        pytest.param(None, id="a session the store does not know"),
        pytest.param(a_session(remaining=-timedelta(seconds=1)), id="a session past its expiry"),
        pytest.param(a_session(age=timedelta(days=2)), id="a session past the absolute limit"),
    ],
)
def test_a_session_that_no_longer_stands_is_refused(record: FakeSessionRecord | None) -> None:
    app = an_auth_app(record)

    response = app.get("/me", cookie=app.signed_cookie())

    assert response.status_code == 401
    assert response.json()["detail"] == SESSION_EXPIRED_DETAIL


def test_a_deactivated_account_is_refused_its_own_live_session() -> None:
    app = an_auth_app(a_session(user=FakeUser(is_active=False)))

    response = app.get("/me", cookie=app.signed_cookie())

    assert response.status_code == 403
    assert response.json()["detail"] == ACCOUNT_DISABLED_DETAIL


def test_a_served_request_renews_its_session_in_place(auth_app: AuthApp) -> None:
    before = auth_app.sessions.record.expires_at

    auth_app.get("/me", cookie=auth_app.signed_cookie())

    assert auth_app.sessions.record.expires_at > before


def test_a_session_arriving_from_a_new_address_is_reported_once(auth_app: AuthApp) -> None:
    auth_app.sessions.record.ip_address = "203.0.113.9"

    auth_app.get("/me", cookie=auth_app.signed_cookie())

    assert auth_app.audit.events == [
        SessionIdentityChanged(
            change=SessionIdentityChange.IP_ADDRESS,
            user_id="user-1",
            session_id=SESSION_ID,
            previous="203.0.113.9",
            current=CLIENT_ADDRESS,
        ),
    ]


def test_a_session_arriving_from_a_new_agent_is_reported_once(auth_app: AuthApp) -> None:
    auth_app.sessions.record.user_agent = "OldBrowser/1.0"

    auth_app.get("/me", cookie=auth_app.signed_cookie())

    assert auth_app.audit.events == [
        SessionIdentityChanged(
            change=SessionIdentityChange.USER_AGENT,
            user_id="user-1",
            session_id=SESSION_ID,
            previous="OldBrowser/1.0",
            current=CLIENT_USER_AGENT,
        ),
    ]


def test_a_session_stored_without_an_origin_reports_no_change() -> None:
    app = an_auth_app(a_session(ip_address="", user_agent=""))

    app.get("/me", cookie=app.signed_cookie())

    assert app.audit.events == []


def test_an_unchanged_origin_reports_nothing(auth_app: AuthApp) -> None:
    auth_app.get("/me", cookie=auth_app.signed_cookie())

    assert auth_app.audit.events == []


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
        pytest.param(
            a_session(user=FakeUser(is_active=False)),
            SESSION_ID,
            403,
            ACCOUNT_DISABLED_DETAIL,
            id="a deactivated account",
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


def test_an_idle_window_host_authenticates_from_its_store() -> None:
    app = an_idle_auth_app(an_idle_session())

    response = app.get("/me", cookie=app.signed_cookie())

    assert response.status_code == 200
    assert response.json() == {"username": "alice", "role": MEMBER_ROLE}


def test_an_idle_window_host_refuses_a_session_past_its_window() -> None:
    app = an_idle_auth_app(
        an_idle_session(seen_ago=timedelta(seconds=IDLE_WINDOW_SECONDS + 1)),
    )

    response = app.get("/me", cookie=app.signed_cookie())

    assert response.status_code == 401
    assert response.json()["detail"] == SESSION_EXPIRED_DETAIL


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


def test_the_redirect_keeps_the_asked_for_query_string() -> None:
    app = an_auth_app(None, login_redirect=A_LOGIN_REDIRECT)

    response = app.get("/me?tab=1", accept="text/html")

    assert response.status_code == 302
    assert response.headers["location"] == "/login?next=%2Fme%3Ftab%3D1"


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


def test_a_deactivated_account_still_answers_403_not_a_redirect() -> None:
    app = an_auth_app(
        a_session(user=FakeUser(is_active=False)), login_redirect=A_LOGIN_REDIRECT,
    )

    response = app.get("/me", cookie=app.signed_cookie(), accept="text/html")

    assert response.status_code == 403
    assert response.json()["detail"] == ACCOUNT_DISABLED_DETAIL
    assert "location" not in response.headers


@pytest.mark.parametrize(
    ("login_redirect", "accept", "expected_status"),
    [
        pytest.param(None, None, 401, id="no login redirect configured"),
        pytest.param(A_LOGIN_REDIRECT, None, 401, id="login redirect but no accept header"),
        pytest.param(
            A_LOGIN_REDIRECT, "application/json", 401, id="login redirect but json preferred",
        ),
        pytest.param(A_LOGIN_REDIRECT, "text/html", 302, id="login redirect and html preferred"),
    ],
)
def test_the_public_function_answers_like_the_dependency_for_no_session(
    login_redirect: LoginRedirect | None, accept: str | None, expected_status: int,
) -> None:
    """``unauthenticated_response`` and the dependency-guarded route agree.

    Both are driven over the same client, so an identical request answers
    identically whether the answer comes from raising inside the dependency
    or from calling the public function directly. The redirect's ``next``
    value differs because the two routes live at different paths; the login
    page and query key it carries do not.
    """
    app = an_auth_app(None, login_redirect=login_redirect)

    via_dependency = app.get("/me", accept=accept)
    via_function = app.get(UNAUTHENTICATED_RESPONSE_PATH, accept=accept)

    assert via_dependency.status_code == expected_status
    assert via_function.status_code == expected_status
    assert via_function.json() == via_dependency.json()
    if expected_status == 302:
        assert login_redirect is not None
        assert via_function.headers["location"].split("?")[0] == login_redirect.path
        assert via_dependency.headers["location"].split("?")[0] == login_redirect.path
    else:
        assert "location" not in via_function.headers
        assert "location" not in via_dependency.headers
