"""The signed session cookie and the CSRF token bound to it."""

from __future__ import annotations

import dataclasses
import hashlib
import secrets
from http.cookies import SimpleCookie

import pytest
from starlette.requests import Request
from starlette.responses import Response
from webauth_arrangement import (
    a_web_auth_config,
    session_cookie_header,
    signed_without_bound,
)

from webauth.cookies import (
    DEFAULT_CSRF_HEADER_NAME,
    MAX_SESSION_COOKIE_CHARS,
    PendingLogin,
    default_cookie_name,
    generate_csrf_token,
    pending_login_cookie_name,
    sign_pending_login,
    sign_session_id,
    verify_csrf_token,
    verify_pending_login,
    verify_session_cookie,
)
from webauth.dependencies import session_id_from_request
from webauth.login import issue_session_cookies

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
