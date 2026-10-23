"""The signed session cookie."""

from __future__ import annotations

import base64
import dataclasses
import hashlib
import secrets
from dataclasses import dataclass
from http.cookies import SimpleCookie

import pytest
from fastapi import FastAPI
from fastapi.testclient import TestClient
from httpx import Response as ClientResponse
from starlette.requests import Request
from starlette.responses import Response
from webauth_arrangement import (
    ALLOWED_HOST,
    SEVEN_DAYS_SECONDS,
    THIRTY_DAYS_SECONDS,
    a_web_auth_config,
    session_cookie_header,
    signed_without_bound,
)

from webauth.config import SessionLifetime, WebAuthConfig, install_web_auth_config
from webauth.cookies import (
    MAX_SESSION_COOKIE_CHARS,
    PendingLogin,
    _default_cookie_name,
    _is_valid_cookie_name,
    _pending_login_cookie_name,
    _sign_pending_login,
    _verify_pending_login,
    _verify_session_cookie,
    clear_session_cookies,
    issue_session_cookies,
    sign_session_id,
)
from webauth.dependencies import session_id_from_request
from webauth.middleware import SecurityHeadersMiddleware
from webauth.policies import SecurityHeadersPolicy, default_content_security_policy

_TEST_SECRET = b"a" * 64
MAX_PENDING_LOGIN_COOKIE_CHARS = 896
_PENDING = PendingLogin(
    state=secrets.token_urlsafe(32),
    nonce=secrets.token_urlsafe(32),
    code_verifier=secrets.token_urlsafe(32),
    issued_at=1_800_000_000,
)


@pytest.mark.parametrize(
    ("plain_name", "secure", "expected"),
    [
        ("session_id", True, "__Host-session_id"),
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
    assert _default_cookie_name(plain_name, secure=secure) == expected


def test_sign_and_verify_session() -> None:
    signed = sign_session_id("my-session-token", _TEST_SECRET)
    assert "." in signed
    assert _verify_session_cookie(signed, _TEST_SECRET) == "my-session-token"


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

    assert _verify_session_cookie(cookie, _TEST_SECRET) == "my-session-token"


def test_verify_rejects_tampered_signature() -> None:
    signed = sign_session_id("my-session-token", _TEST_SECRET)
    tampered = signed[:-4] + "XXXX"
    assert _verify_session_cookie(tampered, _TEST_SECRET) is None


def test_verify_rejects_no_dot() -> None:
    assert _verify_session_cookie("no-dot-here", _TEST_SECRET) is None


def test_verify_rejects_empty_parts() -> None:
    assert _verify_session_cookie(".abc", _TEST_SECRET) is None
    assert _verify_session_cookie("abc.", _TEST_SECRET) is None


def test_verify_rejects_another_secret() -> None:
    signed = sign_session_id("my-session-token", _TEST_SECRET)
    assert _verify_session_cookie(signed, b"b" * 64) is None


@pytest.mark.parametrize(
    "borrowed_cookie",
    [
        pytest.param(
            f"oidc-pending:{_sign_pending_login(_PENDING, _TEST_SECRET)}",
            id="a pending-login signature appended to its signing input",
        ),
    ],
)
def test_a_signature_made_for_another_purpose_is_no_session_cookie(
    borrowed_cookie: str,
) -> None:
    assert _verify_session_cookie(borrowed_cookie, _TEST_SECRET) is None


@pytest.mark.parametrize(
    ("secure", "prefix"), [(True, "__Host-oidc_pending_"), (False, "oidc_pending_")]
)
def test_a_pending_login_cookie_is_named_after_a_digest_of_its_state(
    *, secure: bool, prefix: str
) -> None:
    digest = hashlib.sha256(_PENDING.state.encode()).hexdigest()[:16]

    assert _pending_login_cookie_name(_PENDING.state, secure=secure) == f"{prefix}{digest}"


def test_a_signed_pending_login_verifies_to_the_same_pending_login() -> None:
    signed = _sign_pending_login(_PENDING, _TEST_SECRET)

    assert signed.startswith("v2.")
    assert _verify_pending_login(signed, _TEST_SECRET) == _PENDING


@pytest.mark.parametrize("return_to", [
    pytest.param("/albums/42?x=1", id="a deep link"),
    pytest.param("/lieder/%C3%BC%3Fx?y=1", id="an encoded deep link"),
    pytest.param("/" + "a" * 511, id="the longest return path"),
])
def test_a_signed_pending_login_carries_its_return_path_within_the_cookie_cap(
    return_to: str,
) -> None:
    signed = _sign_pending_login(
        dataclasses.replace(_PENDING, return_to=return_to), _TEST_SECRET,
    )

    assert len(signed) <= MAX_PENDING_LOGIN_COOKIE_CHARS
    assert _verify_pending_login(signed, _TEST_SECRET) == dataclasses.replace(
        _PENDING, return_to=return_to,
    )


def test_a_pending_login_cookie_with_another_return_path_than_signed_does_not_verify() -> None:
    signed = _sign_pending_login(
        dataclasses.replace(_PENDING, return_to="/albums/42"), _TEST_SECRET,
    )
    *fields, return_path, signature = signed.split(".")
    other_path = base64.urlsafe_b64encode(b"/albums/43").decode().rstrip("=")

    assert return_path != other_path
    assert _verify_pending_login(".".join([*fields, other_path, signature]), _TEST_SECRET) is None


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
        pytest.param({"return_to": "/" + "a" * 512}, id="return-path-over-the-cap"),
    ],
)
def test_a_pending_login_oidc_cannot_have_begun_is_refused_a_cookie(
    changes: dict[str, object],
) -> None:
    pending = dataclasses.replace(_PENDING, **changes)

    with pytest.raises(ValueError, match="does not fit"):
        _sign_pending_login(pending, _TEST_SECRET)


SESSION_ID = "session-1"
PLAIN_HTTP = f"http://{ALLOWED_HOST}"
OVER_HTTPS = f"https://{ALLOWED_HOST}"
DEFAULT_SESSION_SET_COOKIE = (
    "__Host-session_id="
    "session-1.3052044bf3b276887bd8a25118374c1f96ff3567d5ab5568d6c393505b2e891d; "
    "HttpOnly; Max-Age=86400; Path=/; SameSite=strict; Secure"
)
CLEARED_SESSION_SET_COOKIE = (
    '__Host-session_id=""; HttpOnly; Max-Age=0; Path=/; SameSite=strict; Secure'
)
CLEARED_SESSION_WITHOUT_SECURE = 'session_id=""; HttpOnly; Max-Age=0; Path=/; SameSite=strict'
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
        return {"session_id": _verify_session_cookie(cookie, config.signing_key)}

    @app.delete("/session")
    def clear(response: Response) -> dict[str, str]:
        clear_session_cookies(response, config)
        return {"status": "ok"}

    return CookieApp(client=TestClient(app, base_url=base_url, client=(peer, 50000)), config=config)


@pytest.fixture
def cookie_app() -> CookieApp:
    return a_cookie_app()


def test_the_issued_cookie_carries_a_session_this_deployment_signed(
    cookie_app: CookieApp,
) -> None:
    response = cookie_app.issue()

    cookie = response.cookies[cookie_app.config.session_cookie_name]
    assert _verify_session_cookie(cookie, cookie_app.config.signing_key) == SESSION_ID


def test_the_session_cookie_is_kept_from_scripts_and_from_other_sites(
    cookie_app: CookieApp,
) -> None:
    header = cookie_app.set_cookie_header(
        cookie_app.issue(), cookie_app.config.session_cookie_name,
    )

    assert "HttpOnly" in header
    assert "SameSite=strict" in header
    assert f"Max-Age={cookie_app.config.session_lifetime.absolute_max_age_seconds}" in header
    assert "Path=/" in header


def test_a_seven_day_idle_window_with_a_thirty_day_cap_gives_a_thirty_day_cookie() -> None:
    """The cookie is issued once, so it must live as long as the cap for a session
    used every few days to stay signed in."""
    app = a_cookie_app(
        session_lifetime=SessionLifetime(SEVEN_DAYS_SECONDS, THIRTY_DAYS_SECONDS),
    )
    response = app.issue()

    header = app.set_cookie_header(response, app.config.session_cookie_name)
    assert f"Max-Age={THIRTY_DAYS_SECONDS};" in header


def test_a_host_that_configures_nothing_gets_host_only_set_cookie_bytes() -> None:
    """Exactly these bytes: ``__Host-``, ``Secure``, ``Path=/`` and no ``Domain``,
    so a sibling subdomain cannot set a cookie of the same name."""
    app = a_cookie_app()
    response = app.issue()

    session_header = app.set_cookie_header(response, app.config.session_cookie_name)
    assert session_header == DEFAULT_SESSION_SET_COOKIE


@pytest.mark.parametrize("samesite", ["strict", "lax"])
@pytest.mark.parametrize("cookie_secure", [True, False])
def test_issuing_sets_exactly_the_session_cookie_with_its_attributes(
    *, cookie_secure: bool, samesite: str,
) -> None:
    app = a_cookie_app(
        base_url=OVER_HTTPS if cookie_secure else PLAIN_HTTP,
        cookie_secure=cookie_secure,
        cookie_samesite=samesite,
    )

    response = app.issue()

    [header] = [value for name, value in response.headers.multi_items() if name == "set-cookie"]
    attributes = header.split("; ")
    assert header.split("=", 1)[0] == app.config.session_cookie_name
    assert "HttpOnly" in attributes
    assert f"SameSite={samesite}" in attributes
    assert ("Secure" in attributes) is cookie_secure


@pytest.mark.parametrize(("base_url", "config_overrides", "session_name"), [
    pytest.param(OVER_HTTPS, {}, "__Host-session_id", id="secure-default"),
    pytest.param(
        PLAIN_HTTP, {"cookie_secure": False}, "session_id",
        id="secure-off-falls-back-to-the-plain-name",
    ),
    pytest.param(
        OVER_HTTPS, {"session_cookie_name": "sid"}, "sid", id="own-name-stays-when-secure",
    ),
    pytest.param(
        PLAIN_HTTP, {"cookie_secure": False, "session_cookie_name": "sid"}, "sid",
        id="own-name-stays-when-secure-off",
    ),
])
def test_the_cookie_is_issued_and_cleared_under_the_resolved_name(
    base_url: str, config_overrides: dict[str, object], session_name: str,
) -> None:
    app = a_cookie_app(base_url=base_url, **config_overrides)

    for response in (app.issue(), app.clear()):
        [header] = [value for name, value in response.headers.multi_items() if name == "set-cookie"]
        assert header.split("=", 1)[0] == session_name


def test_a_host_that_configures_lax_gets_lax_on_the_cookie_and_its_clearing() -> None:
    app = a_cookie_app(cookie_samesite="lax")

    for response in (app.issue(), app.clear()):
        header = app.set_cookie_header(response, app.config.session_cookie_name)
        assert "SameSite=lax" in header
        assert "SameSite=strict" not in header


@pytest.mark.parametrize(("base_url", "cookie_secure", "session_clearing"), [
    pytest.param(OVER_HTTPS, True, CLEARED_SESSION_SET_COOKIE, id="secure-by-default"),
    pytest.param(
        PLAIN_HTTP, False, CLEARED_SESSION_WITHOUT_SECURE, id="switched-off-for-plain-http",
    ),
])
def test_clearing_repeats_the_attributes_the_cookie_was_set_with(
    base_url: str, cookie_secure: bool, session_clearing: str,
) -> None:
    app = a_cookie_app(base_url=base_url, cookie_secure=cookie_secure)

    cleared = app.clear()

    session_header = app.set_cookie_header_without_expires(cleared, app.config.session_cookie_name)
    assert session_header == session_clearing


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

    assert "Secure" in app.set_cookie_header(response, app.config.session_cookie_name).split("; ")
    assert response.headers[HSTS_HEADER] == HSTS_PINNING_HTTPS_FOR_A_YEAR


def test_a_host_that_switches_cookie_secure_off_gets_neither_secure_nor_hsts() -> None:
    app = a_cookie_app(base_url=PLAIN_HTTP, cookie_secure=False)

    response = app.issue()

    header = app.set_cookie_header(response, app.config.session_cookie_name)
    assert "Secure" not in header.split("; ")
    assert HSTS_HEADER not in response.headers


def test_with_cookie_secure_off_a_plain_http_browser_signs_in_and_out() -> None:
    app = a_cookie_app(base_url=PLAIN_HTTP, cookie_secure=False)

    app.issue()
    assert app.signed_in_session().json() == {"session_id": SESSION_ID}

    app.clear()
    assert app.signed_in_session().json() == {"session_id": None}


def test_logging_out_takes_the_cookie_back(cookie_app: CookieApp) -> None:
    cookie_app.issue()

    cookie_app.clear()

    assert cookie_app.config.session_cookie_name not in cookie_app.client.cookies


@pytest.mark.parametrize(
    ("name", "valid"),
    [
        *[
            pytest.param(name, True, id=f"accepts-{name}")
            for name in (
                "__Host-session_id", "session_id",
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
    assert _is_valid_cookie_name(name) is valid
