"""The signed session cookie and the CSRF token bound to it."""

from __future__ import annotations

import dataclasses
import hashlib
import secrets
from dataclasses import dataclass
from http.cookies import SimpleCookie

import pytest
from fastapi import FastAPI, HTTPException
from fastapi.responses import RedirectResponse
from fastapi.testclient import TestClient
from httpx import Response as ClientResponse
from starlette.requests import Request
from starlette.responses import Response
from webauth_arrangement import (
    SEVEN_DAYS_SECONDS,
    THIRTY_DAYS_SECONDS,
    a_web_auth_config,
    session_cookie_header,
    signed_like_release_0_14,
    signed_without_bound,
)

from webauth.config import WebAuthConfig, install_web_auth_config
from webauth.cookies import (
    DEFAULT_CSRF_HEADER_NAME,
    MAX_SESSION_COOKIE_CHARS,
    PendingLogin,
    clear_session_cookies,
    default_cookie_name,
    generate_csrf_token,
    is_valid_cookie_name,
    issue_session_cookies,
    pending_login_cookie_name,
    sign_pending_login,
    sign_session_id,
    verify_csrf_token,
    verify_pending_login,
    verify_session_cookie,
)
from webauth.dependencies import session_id_from_request
from webauth.liveness import IdleWindowLiveness
from webauth.middleware import SecurityHeadersMiddleware
from webauth.policies import SecurityHeadersPolicy, default_content_security_policy

_TEST_SECRET = b"a" * 64
_PENDING = PendingLogin(
    state=secrets.token_urlsafe(32),
    nonce=secrets.token_urlsafe(32),
    code_verifier=secrets.token_urlsafe(32),
    issued_at=1_800_000_000,
)


def test_the_csrf_header_name_is_the_one_clients_already_send() -> None:
    assert DEFAULT_CSRF_HEADER_NAME == "x-csrf-token"


@pytest.mark.parametrize(
    ("plain_name", "secure", "expected"),
    [
        ("session_id", True, "__Host-session_id"),
        ("csrf_token", True, "__Host-csrf_token"),
        ("custom", True, "__Host-custom"),
        ("session_id", False, "session_id"),
        ("custom", False, "custom"),
    ],
)
def test_default_cookie_name_prefixes_any_name_only_when_secure(
    plain_name: str,
    *,
    secure: bool,
    expected: str,
) -> None:
    assert default_cookie_name(plain_name, secure=secure) == expected


def test_sign_and_verify_session() -> None:
    signed = sign_session_id("my-session-token", _TEST_SECRET)
    assert "." in signed
    assert verify_session_cookie(signed, _TEST_SECRET) == "my-session-token"


LONGEST_SESSION_ID_THAT_FITS = "i" * (MAX_SESSION_COOKIE_CHARS - len(".") - 64)


def _session_id_read_back_after_issuing(session_id: str) -> str | None:
    config = a_web_auth_config()
    response = Response()
    issue_session_cookies(response, session_id, config)
    issued = SimpleCookie(response.headers.getlist("set-cookie")[0])
    cookie = issued[config.session_cookie_name].value
    request = Request({
        "type": "http",
        "method": "GET",
        "path": "/",
        "headers": [(b"cookie", session_cookie_header(cookie).encode())],
    })
    return session_id_from_request(request, config)


def test_the_longest_session_id_that_fits_is_issued_and_read_back() -> None:
    assert _session_id_read_back_after_issuing(LONGEST_SESSION_ID_THAT_FITS) == (
        LONGEST_SESSION_ID_THAT_FITS
    )


def test_a_session_id_whose_cookie_the_reader_would_refuse_is_not_issued() -> None:
    with pytest.raises(ValueError, match="session cookie"):
        _session_id_read_back_after_issuing(LONGEST_SESSION_ID_THAT_FITS + "i")


def test_an_empty_session_id_is_not_issued() -> None:
    with pytest.raises(ValueError, match="session id"):
        _session_id_read_back_after_issuing("")


def test_a_cookie_signed_without_the_length_bound_is_accepted_at_normal_length() -> None:
    cookie = signed_without_bound("my-session-token", _TEST_SECRET)

    assert verify_session_cookie(cookie, _TEST_SECRET) == "my-session-token"


def test_verify_rejects_tampered_signature() -> None:
    signed = sign_session_id("my-session-token", _TEST_SECRET)
    tampered = signed[:-4] + "XXXX"
    assert verify_session_cookie(tampered, _TEST_SECRET) is None


def test_verify_rejects_no_dot() -> None:
    assert verify_session_cookie("no-dot-here", _TEST_SECRET) is None


def test_verify_rejects_empty_parts() -> None:
    assert verify_session_cookie(".abc", _TEST_SECRET) is None
    assert verify_session_cookie("abc.", _TEST_SECRET) is None


def test_verify_rejects_another_secret() -> None:
    signed = sign_session_id("my-session-token", _TEST_SECRET)
    assert verify_session_cookie(signed, b"b" * 64) is None


@pytest.mark.parametrize(
    "borrowed_cookie",
    [
        pytest.param(
            f"csrf:my-session-token.{generate_csrf_token('my-session-token', _TEST_SECRET)}",
            id="a CSRF token appended to its signing input",
        ),
        pytest.param(
            f"oidc-pending:{sign_pending_login(_PENDING, _TEST_SECRET)}",
            id="a pending-login signature appended to its signing input",
        ),
        pytest.param(
            signed_like_release_0_14("my-session-token", _TEST_SECRET),
            id="a session cookie as 0.14.x signed it",
        ),
    ],
)
def test_a_signature_made_for_another_purpose_is_no_session_cookie(
    borrowed_cookie: str,
) -> None:
    assert verify_session_cookie(borrowed_cookie, _TEST_SECRET) is None


def test_generate_csrf_token_deterministic() -> None:
    t1 = generate_csrf_token("session-abc", _TEST_SECRET)
    t2 = generate_csrf_token("session-abc", _TEST_SECRET)
    assert t1 == t2


def test_generate_csrf_token_differs_per_session() -> None:
    t1 = generate_csrf_token("session-1", _TEST_SECRET)
    t2 = generate_csrf_token("session-2", _TEST_SECRET)
    assert t1 != t2


def test_verify_csrf_token_valid() -> None:
    token = generate_csrf_token("my-session", _TEST_SECRET)
    assert verify_csrf_token(token, "my-session", _TEST_SECRET) is True


def test_verify_csrf_token_wrong_session() -> None:
    token = generate_csrf_token("session-a", _TEST_SECRET)
    assert verify_csrf_token(token, "session-b", _TEST_SECRET) is False


def test_verify_csrf_token_forged() -> None:
    assert verify_csrf_token("forged-token", "session-a", _TEST_SECRET) is False


@pytest.mark.parametrize(
    ("secure", "prefix"), [(True, "__Host-oidc_pending_"), (False, "oidc_pending_")]
)
def test_a_pending_login_cookie_is_named_after_a_digest_of_its_state(
    *, secure: bool, prefix: str
) -> None:
    digest = hashlib.sha256(_PENDING.state.encode()).hexdigest()[:16]

    assert pending_login_cookie_name(_PENDING.state, secure=secure) == f"{prefix}{digest}"


def test_a_signed_pending_login_verifies_to_the_same_pending_login() -> None:
    signed = sign_pending_login(_PENDING, _TEST_SECRET)

    assert signed.startswith("v1.")
    assert verify_pending_login(signed, _TEST_SECRET) == _PENDING


_MINTED_SECRET = _PENDING.state


@pytest.mark.parametrize(
    "changes",
    [
        pytest.param({"state": "short"}, id="state-not-minted"),
        pytest.param({"state": _MINTED_SECRET + "A"}, id="state-overlong"),
        pytest.param({"state": "+" + _MINTED_SECRET[1:]}, id="state-outside-base64url"),
        pytest.param({"nonce": ""}, id="nonce-empty"),
        pytest.param({"nonce": _MINTED_SECRET + "A"}, id="nonce-overlong"),
        pytest.param({"nonce": "=" + _MINTED_SECRET[1:]}, id="nonce-outside-base64url"),
        pytest.param({"code_verifier": _MINTED_SECRET[1:]}, id="verifier-short"),
        pytest.param({"code_verifier": _MINTED_SECRET + "A"}, id="verifier-overlong"),
        pytest.param({"code_verifier": "/" + _MINTED_SECRET[1:]}, id="verifier-outside-base64url"),
        pytest.param({"issued_at": -1}, id="issued-before-the-epoch"),
        pytest.param({"issued_at": 10**12}, id="issued-at-beyond-twelve-digits"),
    ],
)
def test_a_pending_login_oidc_cannot_have_begun_is_refused_a_cookie(
    changes: dict[str, object],
) -> None:
    pending = dataclasses.replace(_PENDING, **changes)

    with pytest.raises(ValueError, match="does not fit"):
        sign_pending_login(pending, _TEST_SECRET)


SESSION_ID = "session-1"
PLAIN_HTTP = "http://songmaker.example"
OVER_HTTPS = "https://songmaker.example"
DEFAULT_SESSION_SET_COOKIE = (
    "__Host-session_id="
    "session-1.3052044bf3b276887bd8a25118374c1f96ff3567d5ab5568d6c393505b2e891d; "
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
    assert f"Max-Age={cookie_app.config.cookie_max_age_seconds}" in header
    assert "Path=/" in header


def test_a_cookie_lifetime_longer_than_the_idle_window_is_what_the_browser_keeps() -> None:
    """A 30-day cookie over a 7-day idle window: the cookie is issued once, so it
    must outlive the window for a session used every few days to stay signed in."""
    app = a_cookie_app(
        cookie_max_age_seconds=THIRTY_DAYS_SECONDS,
        session_liveness=IdleWindowLiveness(SEVEN_DAYS_SECONDS),
    )
    response = app.issue()

    for name in (app.config.session_cookie_name, app.config.csrf_cookie_name):
        assert f"Max-Age={THIRTY_DAYS_SECONDS};" in app.set_cookie_header(response, name)


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


@pytest.mark.parametrize(
    ("name", "valid"),
    [
        *[
            pytest.param(name, True, id=f"accepts-{name}")
            for name in (
                "__Host-session_id", "__Host-csrf_token", "session_id", "csrf_token",
                "sid", "a-b", "a_b", "a.b", "A9",
                *[f"a{char}b" for char in "!#$%&'*+^`|~"],
            )
        ],
        *[
            pytest.param(name, False, id=f"refuses-{name!r}")
            for name in (
                "", "a b", "a\tb", "a;b", "a=b", "a,b", 'a"b',
                "a\x01b", "a\x7fb", "a\n", "café",
                *[f"a{char}b" for char in "()<>@:\\/[]?{}"],
            )
        ],
    ],
)
def test_a_cookie_name_is_valid_only_when_it_is_an_rfc_6265_token(
    name: str, valid: bool,
) -> None:
    assert is_valid_cookie_name(name) is valid
