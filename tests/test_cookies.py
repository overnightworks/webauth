"""The signed session cookie and the CSRF token bound to it."""

from __future__ import annotations

import ast
import dataclasses
import hashlib
import re
import secrets
from dataclasses import dataclass
from http.cookies import SimpleCookie
from pathlib import Path

import pytest
from fastapi import FastAPI, HTTPException
from fastapi.responses import RedirectResponse
from fastapi.testclient import TestClient
from httpx import Response as ClientResponse
from starlette.requests import Request
from starlette.responses import Response
from webauth_arrangement import (
    ALLOWED_HOST,
    DOCUMENTED_ID_TOKEN_HINT_BOUND,
    SEVEN_DAYS_SECONDS,
    THIRTY_DAYS_SECONDS,
    a_web_auth_config,
    session_cookie_header,
    signed_like_release_0_14,
    signed_without_bound,
)

import webauth
from webauth.config import WebAuthConfig, install_web_auth_config
from webauth.cookies import (
    MAX_SESSION_COOKIE_CHARS,
    PendingLogin,
    _default_cookie_name,
    _generate_csrf_token,
    _is_valid_cookie_name,
    _issue_id_token_hint_cookie,
    _pending_login_cookie_name,
    _sign_pending_login,
    _verify_csrf_token,
    _verify_pending_login,
    _verify_session_cookie,
    clear_session_cookies,
    issue_session_cookies,
    session_reference,
    sign_session_id,
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


@pytest.mark.parametrize(("length", "kept"), [
    pytest.param(DOCUMENTED_ID_TOKEN_HINT_BOUND, True, id="exactly-the-bound-is-kept"),
    pytest.param(DOCUMENTED_ID_TOKEN_HINT_BOUND + 1, False, id="one-character-over-is-cleared"),
])
def test_an_id_token_hint_is_kept_up_to_the_bound_and_cleared_beyond_it(
    *, length: int, kept: bool,
) -> None:
    response = Response()

    _issue_id_token_hint_cookie(
        response, "A" * length, logout_path="/logout", config=a_web_auth_config(),
    )

    attributes = response.headers.getlist("set-cookie")[0].lower()
    assert ("max-age=0" not in attributes) is kept


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
            f"csrf:my-session-token.{_generate_csrf_token('my-session-token', _TEST_SECRET)}",
            id="a CSRF token appended to its signing input",
        ),
        pytest.param(
            f"oidc-pending:{_sign_pending_login(_PENDING, _TEST_SECRET)}",
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
    assert _verify_session_cookie(borrowed_cookie, _TEST_SECRET) is None


def test_generate_csrf_token_deterministic() -> None:
    t1 = _generate_csrf_token("session-abc", _TEST_SECRET)
    t2 = _generate_csrf_token("session-abc", _TEST_SECRET)
    assert t1 == t2


def test_generate_csrf_token_differs_per_session() -> None:
    t1 = _generate_csrf_token("session-1", _TEST_SECRET)
    t2 = _generate_csrf_token("session-2", _TEST_SECRET)
    assert t1 != t2


def test_verify_csrf_token_valid() -> None:
    token = _generate_csrf_token("my-session", _TEST_SECRET)
    assert _verify_csrf_token(token, "my-session", _TEST_SECRET) is True


def test_verify_csrf_token_wrong_session() -> None:
    token = _generate_csrf_token("session-a", _TEST_SECRET)
    assert _verify_csrf_token(token, "session-b", _TEST_SECRET) is False


def test_verify_csrf_token_forged() -> None:
    assert _verify_csrf_token("forged-token", "session-a", _TEST_SECRET) is False


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

    assert signed.startswith("v1.")
    assert _verify_pending_login(signed, _TEST_SECRET) == _PENDING


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
        _sign_pending_login(pending, _TEST_SECRET)


SESSION_ID = "session-1"
PLAIN_HTTP = f"http://{ALLOWED_HOST}"
OVER_HTTPS = f"https://{ALLOWED_HOST}"
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
        return {"session_id": _verify_session_cookie(cookie, config.signing_key)}

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
    assert _verify_session_cookie(cookie, cookie_app.config.signing_key) == SESSION_ID


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
    assert _verify_csrf_token(token, SESSION_ID, cookie_app.config.signing_key)


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
    assert _is_valid_cookie_name(name) is valid


SESSION_REFERENCE = "SessionReference"


def is_name(node: ast.AST, expected: str) -> bool:
    return isinstance(node, ast.Name) and node.id == expected


CODE_NODES = ast.Call | ast.Lambda | ast.NamedExpr


def is_mention(node: ast.AST, mention: re.Pattern[str]) -> bool:
    if isinstance(node, ast.Name):
        return bool(mention.fullmatch(node.id))
    if isinstance(node, ast.Attribute):
        return bool(mention.fullmatch(node.attr))
    return (
        isinstance(node, ast.Constant)
        and isinstance(node.value, str)
        and bool(mention.search(node.value))
    )


def quoted_expression_mentions_in_code(node: ast.Constant, mention: re.Pattern[str]) -> bool:
    if not isinstance(node.value, str):
        return False
    try:
        quoted = ast.parse(node.value, mode="eval")
    except SyntaxError:
        return False
    in_type_expression = {id(kept) for kept in nodes_without_code(quoted, mention)}
    return any(
        is_mention(inner, mention) and id(inner) not in in_type_expression
        for inner in ast.walk(quoted)
    )


def nodes_without_code(root: ast.AST, mention: re.Pattern[str]) -> list[ast.AST]:
    """The nodes of a type expression, leaving out every call, lambda, walrus and
    quoted expression that mentions the name inside one, since FastAPI and typing
    evaluate them."""
    pending, kept = [root], []
    while pending:
        node = pending.pop()
        quoted_code = isinstance(node, ast.Constant) and quoted_expression_mentions_in_code(
            node, mention
        )
        if isinstance(node, CODE_NODES) or quoted_code:
            continue
        kept.append(node)
        pending.extend(ast.iter_child_nodes(node))
    return kept


def nodes_of_the_function_itself(function: ast.FunctionDef) -> list[ast.AST]:
    pending, nodes = list(function.body), []
    while pending:
        node = pending.pop()
        nodes.append(node)
        if not isinstance(node, ast.FunctionDef | ast.AsyncFunctionDef | ast.Lambda | ast.ClassDef):
            pending.extend(ast.iter_child_nodes(node))
    return nodes


def newtype_definition_mentions(statement: ast.stmt) -> list[ast.AST]:
    if not (
        isinstance(statement, ast.Assign)
        and len(statement.targets) == 1
        and is_name(statement.targets[0], SESSION_REFERENCE)
        and isinstance(statement.value, ast.Call)
        and is_name(statement.value.func, "NewType")
    ):
        return []
    call = statement.value
    named = call.args[:1] or [keyword.value for keyword in call.keywords if keyword.arg == "name"]
    if not any(isinstance(arg, ast.Constant) and arg.value == SESSION_REFERENCE for arg in named):
        return []
    return [statement.targets[0], *named]


def dunder_all_entries(statement: ast.stmt) -> list[ast.AST]:
    targets = statement.targets if isinstance(statement, ast.Assign) else []
    if isinstance(statement, ast.AnnAssign):
        targets = [statement.target]
    if isinstance(statement, ast.AugAssign) and isinstance(statement.op, ast.Add):
        targets = [statement.target]
    value = getattr(statement, "value", None)
    if len(targets) != 1 or not is_name(targets[0], "__all__"):
        return []
    if not isinstance(value, ast.List | ast.Tuple):
        return []
    return [
        entry
        for entry in value.elts
        if isinstance(entry, ast.Constant) and isinstance(entry.value, str)
    ]


def maker_constructor_name(statement: ast.stmt) -> list[ast.AST]:
    if not (isinstance(statement, ast.FunctionDef) and statement.name == "session_reference"):
        return []
    constructions = [
        node.func
        for node in nodes_of_the_function_itself(statement)
        if isinstance(node, ast.Call) and is_name(node.func, SESSION_REFERENCE)
    ]
    return constructions if len(constructions) == 1 else []


def allowed_mentions(tree: ast.Module, module: str, mention: re.Pattern[str]) -> set[int]:
    """The ids of the nodes that may mention SessionReference: annotations without
    code, docstrings, string entries of a module ``__all__``, its NewType definition
    in ports.py and the one construction inside the maker in cookies.py."""
    allowed: list[ast.AST] = []
    for node in ast.walk(tree):
        if isinstance(node, ast.Module | ast.ClassDef | ast.FunctionDef | ast.AsyncFunctionDef):
            if ast.get_docstring(node, clean=False) is not None:
                allowed += ast.walk(node.body[0])
        if isinstance(node, ast.arg | ast.AnnAssign) and node.annotation:
            allowed += nodes_without_code(node.annotation, mention)
        if isinstance(node, ast.FunctionDef | ast.AsyncFunctionDef) and node.returns:
            allowed += nodes_without_code(node.returns, mention)
    for statement in tree.body:
        allowed += dunder_all_entries(statement)
        if module == "ports.py":
            allowed += newtype_definition_mentions(statement)
        if module == "cookies.py":
            allowed += maker_constructor_name(statement)
    return {id(node) for node in allowed}


def session_reference_mentions_outside_the_allowed_places(source: str, module: str) -> list[str]:
    tree = ast.parse(source)
    names = {SESSION_REFERENCE} | {
        alias.asname
        for node in ast.walk(tree)
        if isinstance(node, ast.Import | ast.ImportFrom)
        for alias in node.names
        if alias.asname and alias.name.split(".")[-1] == SESSION_REFERENCE
    }
    mention = re.compile(rf"\b({'|'.join(map(re.escape, names))})\b")
    excused = allowed_mentions(tree, module, mention)
    return sorted(
        f"{module}:{node.lineno}"
        for node in ast.walk(tree)
        if id(node) not in excused and is_mention(node, mention)
    )


IMPORT_IT = "from webauth.ports import SessionReference"
MAKER = [
    IMPORT_IT,
    "",
    "def session_reference(session_id: str) -> SessionReference:",
    "    return SessionReference(session_id)",
]


@pytest.mark.parametrize(
    ("module", "lines", "violations"),
    [
        ("a.py", ["def f(x):", "    return SessionReference(x)"], ["a.py:2"]),
        (
            "a.py",
            ["from typing import cast as typed", "typed(SessionReference, raw)"],
            ["a.py:2"],
        ),
        ("a.py", ["cast('SessionReference', raw)"], ["a.py:1"]),
        ("a.py", ["cast('ports.SessionReference', raw)"], ["a.py:1"]),
        ("a.py", ["from webauth import ports", "ports.SessionReference(raw)"], ["a.py:2"]),
        ("a.py", [IMPORT_IT + " as Ref", "Ref(raw)"], ["a.py:2"]),
        ("a.py", [IMPORT_IT + " as Ref", "cast('Ref', raw)"], ["a.py:2"]),
        ("a.py", ["Ref = SessionReference", "Ref(raw)"], ["a.py:1"]),
        (
            "a.py",
            ["from typing import NewType as NT", "Made = NT('Made', SessionReference)"],
            ["a.py:2"],
        ),
        ("a.py", ["Made = NewType('Made', SessionReference)"], ["a.py:1"]),
        ("a.py", ["x: int = SessionReference('x')"], ["a.py:1"]),
        ("a.py", ["def session_reference(x):", "    return SessionReference(x)"], ["a.py:2"]),
        (
            "cookies.py",
            [
                "class C:",
                "    def session_reference(self, x):",
                "        return SessionReference(x)",
            ],
            ["cookies.py:3"],
        ),
        (
            "cookies.py",
            [
                "def other():",
                "    def session_reference(x):",
                "        return SessionReference(x)",
            ],
            ["cookies.py:3"],
        ),
        ("cookies.py", ["def other(x):", "    return SessionReference(x)"], ["cookies.py:2"]),
        ("ports.py", ["SessionReference = NewType('Other', str)"], ["ports.py:1"]),
        ("a.py", ["def f(x):", "    x = 'SessionReference'", "    return x"], ["a.py:2"]),
        (
            "a.py",
            ["def f(x):", "    'SessionReference'", "    return 'SessionReference'"],
            ["a.py:3"],
        ),
        ("a.py", ["ref = __all__ = SessionReference(raw)"], ["a.py:1"]),
        (
            "a.py",
            ["def f(raw):", "    __all__ = SessionReference(raw)", "    return __all__"],
            ["a.py:2"],
        ),
        ("a.py", ["__all__ = [str(SessionReference(raw))]"], ["a.py:1"]),
        ("a.py", ["__all__: list[str] = [SessionReference(raw)]"], ["a.py:1"]),
        ("a.py", ["__all__ = build(SessionReference)"], ["a.py:1"]),
        ("a.py", ["def f(x: SessionReference('raw')): ..."], ["a.py:1"]),
        ("a.py", ["def f() -> cast(SessionReference, raw): ..."], ["a.py:1"]),
        ("a.py", ["x: SessionReference('raw')"], ["a.py:1"]),
        (
            "a.py",
            [
                "def endpoint(",
                "    ref: \"Annotated[str, Depends(lambda r: SessionReference(r))]\",",
                "): ...",
            ],
            ["a.py:2"],
        ),
        (
            "a.py",
            ["def f(x: \"Annotated[str, 'Depends(lambda r: SessionReference(r))']\"): ..."],
            ["a.py:1"],
        ),
        ("a.py", ["def f(x: (Ref := SessionReference)): ...", "Ref(raw)"], ["a.py:1"]),
        (
            "a.py",
            [
                "def endpoint(",
                "    ref: Annotated[str, Depends(lambda r: SessionReference(r.cookies['sid']))],",
                "): ...",
            ],
            ["a.py:2"],
        ),
        (
            "cookies.py",
            [
                "def session_reference(raw):",
                "    class C:",
                "        ref = SessionReference(raw)",
                "    return C.ref",
            ],
            ["cookies.py:3"],
        ),
        (
            "cookies.py",
            [
                "def session_reference(raw):",
                "    if raw:",
                "        return SessionReference(raw)",
                "    return SessionReference('')",
            ],
            ["cookies.py:3", "cookies.py:4"],
        ),
        (
            "ports.py",
            ["SessionReference = NewType('SessionReference', type(SessionReference('raw')))"],
            ["ports.py:1"],
        ),
        (
            "ports.py",
            ["SessionReference = NewType(name='SessionReference', tp=SessionReference)"],
            ["ports.py:1"],
        ),
        ("a.py", ["__all__ = []", "__all__ += [SessionReference(raw)]"], ["a.py:2"]),
        (
            "a.py",
            ["def f(x: \"Annotated[str, Depends(SessionReference('raw'))]\"): ..."],
            ["a.py:1"],
        ),
        ("a.py", ["def f(x):", "    return str(x)"], []),
        ("a.py", ["__all__ = []", "__all__ += ['SessionReference']"], []),
        ("a.py", ["__all__ = []", "__all__ += ('SessionReference',)"], []),
        (
            "a.py",
            ["def f(x: \"Annotated[SessionReference, Depends(provide_reference)]\"): ..."],
            [],
        ),
        (
            "a.py",
            ["def f(x: \"Annotated[SessionReference, Depends(lambda r: str(r))]\"): ..."],
            [],
        ),
        ("a.py", ["__all__ = ('SessionReference',)"], []),
        ("a.py", ["__all__: list[str] = ['SessionReference']"], []),
        ("a.py", ["def f(x: Annotated[str, 'SessionReference']): ..."], []),
        ("ports.py", ["SessionReference = NewType(name='SessionReference', tp=str)"], []),
        ("a.py", ["def f(x):", "    'Names SessionReference.'"], []),
        ("a.py", ["'Names SessionReference.'"], []),
        ("a.py", ["class C:", "    'Names SessionReference.'"], []),
        ("a.py", [IMPORT_IT, "def f(x: SessionReference) -> SessionReference | None: ..."], []),
        ("a.py", ["def f(x: 'SessionReference | None'): ..."], []),
        ("a.py", ["ref: SessionReference"], []),
        ("a.py", ["import webauth.ports as SessionReferenceAlias"], []),
        ("a.py", ["__all__ = [", "    'SessionReference',", "]"], []),
        ("ports.py", ["SessionReference = NewType('SessionReference', str)"], []),
        ("cookies.py", MAKER, []),
    ],
)
def test_the_session_reference_guard_flags_every_mention_outside_the_allowed_places(
    module: str, lines: list[str], violations: list[str]
) -> None:
    source = "\n".join(lines)

    assert session_reference_mentions_outside_the_allowed_places(source, module) == violations


def test_only_session_reference_constructs_a_session_reference_in_the_library() -> None:
    library = Path(webauth.__file__).parent
    violations = [
        violation
        for path in sorted(library.rglob("*.py"))
        for violation in session_reference_mentions_outside_the_allowed_places(
            path.read_text(), path.relative_to(library).as_posix()
        )
    ]

    assert violations == []


@pytest.mark.parametrize(("session_id", "reference"), [
    ("", "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"),
    ("abc", "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"),
    ("é", "4a99557e4033c3539de2eb65472017cad5f9557f7a0625a09f1c3f6e2ba69c4c"),
])
def test_session_references_are_the_sha256_hex_of_utf8_identifiers(
    session_id: str, reference: str,
) -> None:
    assert session_reference(session_id) == reference
