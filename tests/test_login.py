"""What a login hands out, what it refuses, and what a logout takes back."""

from __future__ import annotations

from dataclasses import dataclass

import pytest
from fastapi import FastAPI, HTTPException, Request, Response
from fastapi.responses import RedirectResponse
from fastapi.testclient import TestClient
from httpx import Response as ClientResponse
from webauth_arrangement import a_cheap_argon2id_hasher, a_web_auth_config

from webauth.config import WebAuthConfig, install_web_auth_config
from webauth.cookies import verify_csrf_token, verify_session_cookie
from webauth.login import (
    ACCOUNT_LOCKED_DETAIL,
    INVALID_CREDENTIALS_DETAIL,
    RETRY_AFTER_HEADER,
    TOO_MANY_LOGIN_ATTEMPTS_DETAIL,
    LoginOutcome,
    LoginRefusal,
    clear_session_cookies,
    http_refusal,
    issue_session_cookies,
    judge_credentials,
    login_attempt_budget,
)
from webauth.middleware import SecurityHeadersMiddleware
from webauth.policies import SecurityHeadersPolicy, default_content_security_policy
from webauth.ports import PasswordHasher

SESSION_ID = "session-1"
CLIENT_ADDRESS = "203.0.113.7"
USERNAME = "alice"
PLAIN_HTTP = "http://songmaker.example"
OVER_HTTPS = "https://songmaker.example"
DEFAULT_SESSION_SET_COOKIE = (
    "__Host-session_id="
    "session-1.69aa4d225bc23dcce050c2be44156a8b099336a14cc6eb8fcebb4b350bc4f2ee; "
    "HttpOnly; Max-Age=3600; Path=/; SameSite=strict; Secure"
)
DEFAULT_CSRF_SET_COOKIE = (
    "__Host-csrf_token=c2c5cecdd7ae3886e360411f973c9aa43a9e31840585dad8625d47ce82059851; "
    "Max-Age=3600; Path=/; SameSite=strict; Secure"
)
CLEARED_SESSION_SET_COOKIE = (
    '__Host-session_id=""; HttpOnly; Max-Age=0; Path=/; SameSite=strict; Secure'
)
CLEARED_CSRF_SET_COOKIE = '__Host-csrf_token=""; Max-Age=0; Path=/; SameSite=strict; Secure'
CLEARED_SESSION_WITHOUT_SECURE = 'session_id=""; HttpOnly; Max-Age=0; Path=/; SameSite=strict'
CLEARED_CSRF_WITHOUT_SECURE = 'csrf_token=""; Max-Age=0; Path=/; SameSite=strict'
UNTRUSTED_PROXY_SAYS_HTTPS = {"x-forwarded-proto": "https"}
TRUSTED_PROXY_SAYS_HTTP = {"x-forwarded-proto": "http"}
UNTRUSTED_PEER = "testclient"
TRUSTED_PEER = "172.18.0.1"  # inside the arrangement's trusted proxy network
HSTS_HEADER = "strict-transport-security"
HSTS_PINNING_HTTPS_FOR_A_YEAR = "max-age=31536000; includeSubDomains"

A_CORRECT_PASSWORD = "the-correct-password"
A_WRONG_PASSWORD = "something-else-entirely"


@dataclass(frozen=True)
class CookieApp:
    """One route that issues the session cookies and one that clears them."""

    client: TestClient
    config: WebAuthConfig

    def issue(self, headers: dict[str, str] | None = None) -> ClientResponse:
        return self.client.post("/issue", headers=headers)

    def visit(self, path: str) -> ClientResponse:
        return self.client.get(path, follow_redirects=False)

    def signed_in_session(self) -> ClientResponse:
        return self.client.get("/session")

    def clear(self) -> ClientResponse:
        return self.client.delete("/session")

    def set_cookie_header(self, response: ClientResponse, name: str) -> str:
        return next(
            value
            for header, value in response.headers.multi_items()
            if header == "set-cookie" and value.startswith(f"{name}=")
        )

    def set_cookie_header_without_expires(self, response: ClientResponse, name: str) -> str:
        return "; ".join(
            part
            for part in self.set_cookie_header(response, name).split("; ")
            if not part.lower().startswith("expires=")
        )


def with_security_headers(app: FastAPI) -> None:
    app.add_middleware(
        SecurityHeadersMiddleware,
        policy=SecurityHeadersPolicy(default_content_security_policy([])),
    )


def a_cookie_app(
    *, base_url: str = OVER_HTTPS, peer: str = UNTRUSTED_PEER, **config_overrides: object,
) -> CookieApp:
    """The cookie routes behind the security headers a deployment installs.

    By default the test client's peer address is outside the configured
    trusted proxies, so a forwarded scheme it sends is the untrusted-proxy case.
    """
    config = a_web_auth_config(**config_overrides)
    app = FastAPI()
    install_web_auth_config(app, config)
    with_security_headers(app)

    @app.post("/issue")
    def issue(response: Response) -> dict[str, str]:
        issue_session_cookies(response, SESSION_ID, config)
        return {"status": "ok"}

    @app.get("/session")
    def signed_in_session(request: Request) -> dict[str, str | None]:
        cookie = request.cookies.get(config.session_cookie_name, "")
        return {"session_id": verify_session_cookie(cookie, config.signing_key)}

    @app.delete("/session")
    def clear(response: Response) -> dict[str, str]:
        clear_session_cookies(response, config)
        return {"status": "ok"}

    @app.get("/moved")
    def moved() -> RedirectResponse:
        return RedirectResponse("/session")

    @app.get("/forbidden")
    def forbidden() -> None:
        raise HTTPException(status_code=403)

    @app.get("/route-pins-https")
    def route_pins_https() -> Response:
        return Response(headers={"Strict-Transport-Security": "max-age=60"})

    return CookieApp(client=TestClient(app, base_url=base_url, client=(peer, 50000)), config=config)


@pytest.fixture
def cookie_app() -> CookieApp:
    return a_cookie_app()


def test_the_issued_cookie_carries_a_session_this_deployment_signed(
    cookie_app: CookieApp,
) -> None:
    response = cookie_app.issue()

    cookie = response.cookies[cookie_app.config.session_cookie_name]
    assert verify_session_cookie(cookie, cookie_app.config.signing_key) == SESSION_ID


def test_the_session_cookie_is_kept_from_scripts_and_from_other_sites(
    cookie_app: CookieApp,
) -> None:
    header = cookie_app.set_cookie_header(
        cookie_app.issue(), cookie_app.config.session_cookie_name,
    )

    assert "HttpOnly" in header
    assert "SameSite=strict" in header
    assert f"Max-Age={cookie_app.config.session_max_age_seconds}" in header
    assert "Path=/" in header


def test_a_host_that_configures_nothing_gets_host_only_set_cookie_bytes() -> None:
    """Exactly these bytes: ``__Host-``, ``Secure``, ``Path=/`` and no ``Domain``,
    so a sibling subdomain cannot set a cookie of the same name."""
    app = a_cookie_app()
    response = app.issue()

    session_header = app.set_cookie_header(response, app.config.session_cookie_name)
    csrf_header = app.set_cookie_header(response, app.config.csrf_cookie_name)
    assert session_header == DEFAULT_SESSION_SET_COOKIE
    assert csrf_header == DEFAULT_CSRF_SET_COOKIE


@pytest.mark.parametrize(("base_url", "config_overrides", "session_name", "csrf_name"), [
    pytest.param(
        OVER_HTTPS, {}, "__Host-session_id", "__Host-csrf_token", id="secure-default",
    ),
    pytest.param(
        PLAIN_HTTP, {"cookie_secure": False}, "session_id", "csrf_token",
        id="secure-off-falls-back-to-plain-names",
    ),
    pytest.param(
        OVER_HTTPS, {"session_cookie_name": "sid", "csrf_cookie_name": "xsrf"}, "sid", "xsrf",
        id="own-names-stay-when-secure",
    ),
    pytest.param(
        PLAIN_HTTP,
        {"cookie_secure": False, "session_cookie_name": "sid", "csrf_cookie_name": "xsrf"},
        "sid", "xsrf",
        id="own-names-stay-when-secure-off",
    ),
])
def test_both_cookies_are_issued_and_cleared_under_the_resolved_names(
    base_url: str, config_overrides: dict[str, object], session_name: str, csrf_name: str,
) -> None:
    app = a_cookie_app(base_url=base_url, **config_overrides)

    for response in (app.issue(), app.clear()):
        issued_names = {
            value.split("=", 1)[0]
            for header, value in response.headers.multi_items()
            if header == "set-cookie"
        }
        assert issued_names == {session_name, csrf_name}


def test_a_host_that_configures_lax_gets_lax_on_both_cookies_and_their_clearing() -> None:
    app = a_cookie_app(cookie_samesite="lax")

    issued = app.issue()
    for name in (app.config.session_cookie_name, app.config.csrf_cookie_name):
        header = app.set_cookie_header(issued, name)
        assert "SameSite=lax" in header
        assert "SameSite=strict" not in header

    cleared = app.clear()
    for name in (app.config.session_cookie_name, app.config.csrf_cookie_name):
        assert "SameSite=lax" in app.set_cookie_header(cleared, name)


@pytest.mark.parametrize(("base_url", "cookie_secure", "session_clearing", "csrf_clearing"), [
    pytest.param(
        OVER_HTTPS, True, CLEARED_SESSION_SET_COOKIE, CLEARED_CSRF_SET_COOKIE,
        id="secure-by-default",
    ),
    pytest.param(
        PLAIN_HTTP, False, CLEARED_SESSION_WITHOUT_SECURE, CLEARED_CSRF_WITHOUT_SECURE,
        id="switched-off-for-plain-http",
    ),
])
def test_clearing_repeats_the_attributes_each_cookie_was_set_with(
    base_url: str, cookie_secure: bool, session_clearing: str, csrf_clearing: str,
) -> None:
    app = a_cookie_app(base_url=base_url, cookie_secure=cookie_secure)

    cleared = app.clear()

    session_header = app.set_cookie_header_without_expires(cleared, app.config.session_cookie_name)
    csrf_header = app.set_cookie_header_without_expires(cleared, app.config.csrf_cookie_name)
    assert session_header == session_clearing
    assert csrf_header == csrf_clearing


def test_the_csrf_token_is_readable_by_the_client_and_bound_to_the_session(
    cookie_app: CookieApp,
) -> None:
    response = cookie_app.issue()

    header = cookie_app.set_cookie_header(response, cookie_app.config.csrf_cookie_name)
    assert "HttpOnly" not in header
    token = response.cookies[cookie_app.config.csrf_cookie_name]
    assert verify_csrf_token(token, SESSION_ID, cookie_app.config.signing_key)


@pytest.mark.parametrize(("base_url", "peer", "headers"), [
    pytest.param(OVER_HTTPS, UNTRUSTED_PEER, None, id="over-https"),
    pytest.param(
        PLAIN_HTTP, UNTRUSTED_PEER, UNTRUSTED_PROXY_SAYS_HTTPS,
        id="behind-an-untrusted-tls-proxy",
    ),
    pytest.param(PLAIN_HTTP, TRUSTED_PEER, TRUSTED_PROXY_SAYS_HTTP, id="trusted-proxy-says-http"),
    pytest.param(PLAIN_HTTP, UNTRUSTED_PEER, None, id="over-plain-http"),
])
def test_a_host_that_configures_nothing_gets_secure_cookies_and_hsts_however_reached(
    base_url: str, peer: str, headers: dict[str, str] | None,
) -> None:
    app = a_cookie_app(base_url=base_url, peer=peer)

    response = app.issue(headers)

    for name in (app.config.session_cookie_name, app.config.csrf_cookie_name):
        assert "Secure" in app.set_cookie_header(response, name).split("; ")
    assert response.headers[HSTS_HEADER] == HSTS_PINNING_HTTPS_FOR_A_YEAR


@pytest.mark.parametrize(("path", "status"), [
    pytest.param("/moved", 307, id="redirect"),
    pytest.param("/forbidden", 403, id="handled-error"),
    pytest.param("/route-pins-https", 200, id="route-sets-its-own-hsts"),
])
@pytest.mark.parametrize(("cookie_secure", "hsts"), [
    pytest.param(True, HSTS_PINNING_HTTPS_FOR_A_YEAR, id="secure"),
    pytest.param(False, None, id="secure-off"),
])
def test_every_answer_carries_exactly_the_hsts_cookie_secure_decides(
    path: str, status: int, cookie_secure: bool, hsts: str | None,
) -> None:
    app = a_cookie_app(cookie_secure=cookie_secure)

    response = app.visit(path)

    assert response.status_code == status
    assert response.headers.get(HSTS_HEADER) == hsts


def test_security_headers_without_a_configuration_stop_before_the_route_runs() -> None:
    route_ran: list[bool] = []
    app = FastAPI()
    with_security_headers(app)

    @app.post("/side-effect")
    def side_effect() -> None:
        route_ran.append(True)

    with (
        TestClient(app, base_url=OVER_HTTPS) as client,
        pytest.raises(RuntimeError, match="install_web_auth_config"),
    ):
        client.post("/side-effect")
    assert route_ran == []


def test_a_host_that_switches_cookie_secure_off_gets_neither_secure_nor_hsts() -> None:
    app = a_cookie_app(base_url=PLAIN_HTTP, cookie_secure=False)

    response = app.issue()

    for name in (app.config.session_cookie_name, app.config.csrf_cookie_name):
        assert "Secure" not in app.set_cookie_header(response, name).split("; ")
    assert HSTS_HEADER not in response.headers


def test_with_cookie_secure_off_a_plain_http_browser_signs_in_and_out() -> None:
    app = a_cookie_app(base_url=PLAIN_HTTP, cookie_secure=False)

    app.issue()
    assert app.signed_in_session().json() == {"session_id": SESSION_ID}

    app.clear()
    assert app.signed_in_session().json() == {"session_id": None}


def test_logging_out_takes_both_cookies_back(cookie_app: CookieApp) -> None:
    cookie_app.issue()

    cookie_app.clear()

    assert cookie_app.config.session_cookie_name not in cookie_app.client.cookies
    assert cookie_app.config.csrf_cookie_name not in cookie_app.client.cookies


@dataclass
class FailuresInMemory:
    """Recent failures, counted the way each budget asks for them."""

    lockout_window_seconds: int
    for_the_account_over_the_lockout_window: int = 0
    from_the_address: int = 0
    for_the_account: int = 0

    def count_recent_failures(
        self, *, ip_address: str, window_seconds: int, username: str | None = None,
    ) -> int:
        if window_seconds == self.lockout_window_seconds:
            return self.for_the_account_over_the_lockout_window
        return self.for_the_account if username else self.from_the_address


def a_login_limit(**failures: int) -> tuple[FailuresInMemory, WebAuthConfig]:
    config = a_web_auth_config(
        login_rate_limit=5, login_lockout_threshold=15,
        login_lockout_window_seconds=3600, login_rate_window_seconds=300,
    )
    return FailuresInMemory(config.login_lockout_window_seconds, **failures), config


def budget_for(attempts: FailuresInMemory, config: WebAuthConfig) -> LoginRefusal | None:
    return login_attempt_budget(
        attempts, ip_address=CLIENT_ADDRESS, username=USERNAME, config=config,
    )


def test_an_attempt_within_both_budgets_is_allowed_to_proceed() -> None:
    attempts, config = a_login_limit(
        for_the_account_over_the_lockout_window=14, from_the_address=4, for_the_account=4,
    )

    assert budget_for(attempts, config) is None


def test_an_account_that_kept_failing_is_locked_for_the_lockout_window() -> None:
    attempts, config = a_login_limit(for_the_account_over_the_lockout_window=15)

    assert budget_for(attempts, config) == LoginRefusal(
        LoginOutcome.ACCOUNT_LOCKED,
        retry_after_seconds=config.login_lockout_window_seconds,
    )


@pytest.mark.parametrize(
    "spent",
    [
        pytest.param({"from_the_address": 5}, id="an address that keeps guessing"),
        pytest.param({"for_the_account": 5}, id="one account guessed at repeatedly"),
    ],
)
def test_a_spent_rate_budget_is_refused_for_the_rate_window(spent: dict[str, int]) -> None:
    attempts, config = a_login_limit(**spent)

    assert budget_for(attempts, config) == LoginRefusal(
        LoginOutcome.RATE_LIMITED,
        retry_after_seconds=config.login_rate_window_seconds,
    )


def test_a_locked_account_hears_about_the_lockout_not_the_rate_limit() -> None:
    attempts, config = a_login_limit(
        for_the_account_over_the_lockout_window=15, from_the_address=5, for_the_account=5,
    )

    refusal = budget_for(attempts, config)

    assert refusal is not None
    assert refusal.outcome is LoginOutcome.ACCOUNT_LOCKED


def test_a_locked_refusal_maps_to_todays_429_and_retry_after() -> None:
    _, config = a_login_limit()
    refusal = LoginRefusal(
        LoginOutcome.ACCOUNT_LOCKED,
        retry_after_seconds=config.login_lockout_window_seconds,
    )

    error = http_refusal(refusal)

    assert error.status_code == 429
    assert error.detail == ACCOUNT_LOCKED_DETAIL
    assert error.headers[RETRY_AFTER_HEADER] == str(config.login_lockout_window_seconds)


def test_a_rate_limited_refusal_maps_to_todays_429_and_retry_after() -> None:
    _, config = a_login_limit()
    refusal = LoginRefusal(
        LoginOutcome.RATE_LIMITED,
        retry_after_seconds=config.login_rate_window_seconds,
    )

    error = http_refusal(refusal)

    assert error.status_code == 429
    assert error.detail == TOO_MANY_LOGIN_ATTEMPTS_DETAIL
    assert error.headers[RETRY_AFTER_HEADER] == str(config.login_rate_window_seconds)


@pytest.mark.parametrize(
    "outcome",
    [LoginOutcome.UNKNOWN_USER, LoginOutcome.WRONG_PASSWORD, LoginOutcome.DEACTIVATED],
    ids=["a username nobody holds", "a wrong password", "a deactivated account"],
)
def test_a_credential_refusal_maps_to_one_indistinguishable_401(
    outcome: LoginOutcome,
) -> None:
    error = http_refusal(LoginRefusal(outcome))

    assert error.status_code == 401
    assert error.detail == INVALID_CREDENTIALS_DETAIL
    assert error.headers is None


def test_an_admission_is_never_a_refusal() -> None:
    with pytest.raises(ValueError, match="admission"):
        LoginRefusal(LoginOutcome.ADMITTED)


@dataclass(frozen=True)
class StoredAccount:
    password_hash: str
    is_active: bool = True
    id: str = "user-1"
    username: str = USERNAME
    role: str = "user"


A_HASHER = a_cheap_argon2id_hasher()
AN_ACCOUNT = StoredAccount(password_hash=A_HASHER.hash(A_CORRECT_PASSWORD))
A_DEACTIVATED_ACCOUNT = StoredAccount(
    password_hash=AN_ACCOUNT.password_hash, is_active=False,
)
A_PASSWORD_SET_BEFORE_THE_LENGTH_RULE = "abc1234"
AN_ACCOUNT_WITH_A_SHORT_PASSWORD = StoredAccount(
    password_hash=A_HASHER.hash(A_PASSWORD_SET_BEFORE_THE_LENGTH_RULE),
)


@dataclass
class VerificationSpy:
    """A hasher that counts how many full verifications a decision runs."""

    delegate: PasswordHasher
    verify_calls: int = 0

    def hash(self, password: str) -> str:
        return self.delegate.hash(password)

    def verify(self, password: str, stored_hash: str | None) -> bool:
        self.verify_calls += 1
        return self.delegate.verify(password, stored_hash)


@pytest.mark.parametrize(
    ("password", "user", "outcome"),
    [
        pytest.param(
            A_CORRECT_PASSWORD, AN_ACCOUNT, LoginOutcome.ADMITTED,
            id="the account's own password",
        ),
        pytest.param(
            A_WRONG_PASSWORD, AN_ACCOUNT, LoginOutcome.WRONG_PASSWORD,
            id="a password that is not it",
        ),
        pytest.param(
            A_CORRECT_PASSWORD, None, LoginOutcome.UNKNOWN_USER,
            id="a username nobody holds",
        ),
        pytest.param(
            A_CORRECT_PASSWORD, A_DEACTIVATED_ACCOUNT, LoginOutcome.DEACTIVATED,
            id="a deactivated account and its right password",
        ),
        pytest.param(
            A_PASSWORD_SET_BEFORE_THE_LENGTH_RULE, AN_ACCOUNT_WITH_A_SHORT_PASSWORD,
            LoginOutcome.ADMITTED,
            id="a stored password shorter than today's minimum",
        ),
    ],
)
def test_judge_credentials_names_the_outcome_of_each_attempt(
    password: str, user: StoredAccount | None, outcome: LoginOutcome,
) -> None:
    assert judge_credentials(password, user, hasher=A_HASHER) is outcome


@pytest.mark.parametrize(
    ("password", "user"),
    [
        pytest.param(A_CORRECT_PASSWORD, None, id="a username nobody holds"),
        pytest.param(A_WRONG_PASSWORD, AN_ACCOUNT, id="a wrong password"),
    ],
)
def test_a_refused_credential_runs_exactly_one_full_verification(
    password: str, user: StoredAccount | None,
) -> None:
    spy = VerificationSpy(A_HASHER)

    judge_credentials(password, user, hasher=spy)

    assert spy.verify_calls == 1
