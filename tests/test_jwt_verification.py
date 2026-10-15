"""RS256 verification of tokens signed by a remote issuer's published keys.

Every scenario drives `JwtVerifier.verify` with a raw token string, the way a
host's login or logout route will. The key-set endpoint and both clocks are
fakes, so the verifier's own refusals, cache and refresh rules are observed
offline and deterministically; only `fetch_key_set_over_https`, the real HTTPS
boundary, is driven against a loopback TLS server.
"""

from __future__ import annotations

import base64
import contextlib
import datetime
import gzip
import hashlib
import hmac
import ipaddress
import json
import logging
import socket
import ssl
import string
import threading
import time
import traceback
from collections.abc import Callable, Iterator
from concurrent.futures import ThreadPoolExecutor
from dataclasses import dataclass, field
from functools import cache
from http.server import BaseHTTPRequestHandler, HTTPServer
from pathlib import Path
from typing import Any, NoReturn

import jwt
import pytest
import urllib3
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec, padding, rsa
from cryptography.x509.oid import ExtendedKeyUsageOID, NameOID
from jwt.algorithms import ECAlgorithm, RSAAlgorithm

from webauth.jwt_verification import (
    KEY_SET_REFRESH_COOLDOWN_SECONDS,
    KEY_SET_TTL_SECONDS,
    MAX_JSON_NESTING_DEPTH,
    MAX_KEY_ID_CHARACTERS,
    MAX_KEY_SET_BYTES,
    MAX_KEY_SET_KEYS,
    MAX_TOKEN_CHARACTERS,
    JwtVerifier,
    KeySetFetchError,
    Rejected,
    RejectionReason,
    VerifiedClaims,
    fetch_key_set_over_https,
)

_ABSENT = object()
"""A claim or header change that removes the member instead of setting it."""


@cache
def _rsa_key(name: str, bits: int = 2048) -> rsa.RSAPrivateKey:
    """One generated key per name for the whole module: RSA generation is the
    slow part, and a key is immutable scenario data."""
    del name
    return rsa.generate_private_key(public_exponent=65537, key_size=bits)


def _segment(value: dict[str, Any] | str) -> str:
    """A base64url segment of a JSON object, or of raw JSON text when the
    scenario needs bytes `json.dumps` cannot produce (duplicate members)."""
    text = value if isinstance(value, str) else json.dumps(value)
    return base64.urlsafe_b64encode(text.encode()).rstrip(b"=").decode()


def _rs256(key: rsa.RSAPrivateKey) -> Callable[[bytes], bytes]:
    return lambda signing_input: key.sign(signing_input, padding.PKCS1v15(), hashes.SHA256())


def _hs256_with_public_key(key: rsa.RSAPrivateKey) -> Callable[[bytes], bytes]:
    """The RS/HS confusion attack: HMAC keyed with the published public key."""
    public_pem = key.public_key().public_bytes(
        serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo
    )
    return lambda signing_input: hmac.new(public_pem, signing_input, hashlib.sha256).digest()


def _jws(header: dict[str, Any] | str, claims: dict[str, Any] | str, sign: Callable) -> str:
    signing_input = f"{_segment(header)}.{_segment(claims)}"
    signature = base64.urlsafe_b64encode(sign(signing_input.encode())).rstrip(b"=").decode()
    return f"{signing_input}.{signature}"


_BASE64URL_ALPHABET = string.ascii_uppercase + string.ascii_lowercase + string.digits + "-_"


def _with_unused_signature_bits_set(token: str) -> str:
    """The same signature bytes spelled non-canonically. The last character
    of a 256-byte signature carries two signature bits and four unused zero
    bits, so the next alphabet character only sets an unused bit."""
    last = token[-1]
    return token[:-1] + _BASE64URL_ALPHABET[_BASE64URL_ALPHABET.index(last) + 1]


def _changed(base: dict[str, Any], changes: dict[str, Any]) -> dict[str, Any]:
    merged = {**base, **changes}
    return {name: value for name, value in merged.items() if value is not _ABSENT}


def _public_jwk(key: rsa.RSAPrivateKey, key_id: str, **changes: Any) -> dict[str, Any]:
    jwk = RSAAlgorithm.to_jwk(key.public_key(), as_dict=True)
    return _changed({**jwk, "kid": key_id, "alg": "RS256", "use": "sig"}, changes)


def _key_set_document(*jwks: object) -> bytes:
    return json.dumps({"keys": list(jwks)}).encode()


@dataclass
class FakeClock:
    now: float

    def __call__(self) -> float:
        return self.now


@dataclass
class FakeKeySetEndpoint:
    """Answers each fetch with `response`: a document, or the error to raise."""

    response: bytes | Exception
    fetched_urls: list[str] = field(default_factory=list)
    before_answer: Callable[[], None] = lambda: None

    def __call__(self, url: str) -> bytes:
        self.fetched_urls.append(url)
        self.before_answer()
        if isinstance(self.response, Exception):
            raise self.response
        return self.response


_ISSUER = "https://login.example.org/realms/workshop"
_AUDIENCE = "songmaker"
_JWKS_URL = f"{_ISSUER}/protocol/openid-connect/certs"
_URL_SECRET = "s3cr3t-in-the-url"
_LEEWAY_SECONDS = 30


@dataclass
class IssuerScenario:
    endpoint: FakeKeySetEndpoint
    wall_clock: FakeClock
    monotonic_clock: FakeClock
    verifier: JwtVerifier = field(init=False)
    key_id: str = "current-key"

    def __post_init__(self) -> None:
        self.verifier = self.verifier_with()

    def claims(self, changes: dict[str, Any] | None = None) -> dict[str, Any]:
        now = int(self.wall_clock.now)
        issued_claims = {
            "iss": _ISSUER,
            "aud": _AUDIENCE,
            "sub": "7335d417-61da-459d-899c-0a01c76a2f94",
            "exp": now + 300,
            "iat": now - 10,
            "nbf": now - 10,
            "sid": "4c2a9f0e-session",
            "preferred_username": "operator",
        }
        return _changed(issued_claims, changes or {})

    def token(
        self,
        claims: dict[str, Any] | None = None,
        header: dict[str, Any] | None = None,
        sign: Callable | None = None,
    ) -> str:
        return _jws(
            _changed({"alg": "RS256", "kid": self.key_id, "typ": "JWT"}, header or {}),
            self.claims(claims),
            sign or _rs256(_rsa_key("current")),
        )

    def verified(self, claims: dict[str, Any] | None = None) -> VerifiedClaims:
        issued = self.claims(claims)
        audience = issued["aud"]
        return VerifiedClaims(
            subject=issued.get("sub"),
            issuer=_ISSUER,
            audiences=(audience,) if isinstance(audience, str) else tuple(audience),
            expires_at=issued["exp"],
            issued_at=issued["iat"],
            claims=issued,
        )

    def serve(self, response: bytes | Exception) -> None:
        self.endpoint.response = response

    def after_cooldown(self) -> None:
        self.monotonic_clock.now += KEY_SET_REFRESH_COOLDOWN_SECONDS

    def verifier_with(self, **changes: Any) -> JwtVerifier:
        arguments = {
            "issuer": _ISSUER,
            "audiences": [_AUDIENCE],
            "jwks_url": _JWKS_URL,
            "leeway_seconds": _LEEWAY_SECONDS,
            "fetch_key_set": self.endpoint,
            "wall_clock": self.wall_clock,
            "monotonic_clock": self.monotonic_clock,
        }
        return JwtVerifier(**{**arguments, **changes})


@pytest.fixture
def issuer() -> IssuerScenario:
    endpoint = FakeKeySetEndpoint(
        _key_set_document(_public_jwk(_rsa_key("current"), "current-key"))
    )
    return IssuerScenario(endpoint, FakeClock(1_800_000_000.0), FakeClock(5_000.0))


@pytest.mark.parametrize(
    "claims",
    [
        pytest.param({}, id="audience-string"),
        pytest.param({"aud": [_AUDIENCE]}, id="audience-list"),
        pytest.param({"aud": ["another-app", _AUDIENCE]}, id="audience-among-others"),
        pytest.param({"nbf": _ABSENT}, id="without-nbf"),
        pytest.param({"sub": _ABSENT}, id="without-sub"),
        pytest.param(
            {"note": 'a quoted "[[[[[[[[[[" and a \\ backslash'},
            id="brackets-inside-a-string-are-no-nesting",
        ),
    ],
)
def test_a_token_signed_by_a_key_of_the_fake_key_set_verifies_as_its_claims(
    issuer: IssuerScenario, claims: dict[str, Any]
) -> None:
    assert issuer.verifier.verify(issuer.token(claims)) == issuer.verified(claims)
    assert issuer.endpoint.fetched_urls == [_JWKS_URL]


def test_a_token_for_any_one_of_the_accepted_audiences_verifies(
    issuer: IssuerScenario,
) -> None:
    verifier = issuer.verifier_with(audiences=["songmaker", "agent-board"])

    outcome = verifier.verify(issuer.token({"aud": "agent-board"}))

    assert outcome == issuer.verified({"aud": "agent-board"})


_DEEP_ARRAY = "[" * 2_000 + "]" * 2_000


@pytest.mark.parametrize(
    ("build_token", "reason"),
    [
        # Signature and algorithm
        pytest.param(
            lambda issuer: issuer.token(sign=_rs256(_rsa_key("forger"))),
            RejectionReason.INVALID_SIGNATURE,
            id="forged-signature",
        ),
        pytest.param(
            lambda issuer: issuer.token(header={"alg": "none"}, sign=lambda _: b""),
            RejectionReason.UNSUPPORTED_ALGORITHM,
            id="alg-none",
        ),
        pytest.param(
            lambda issuer: issuer.token(
                header={"alg": "HS256"}, sign=_hs256_with_public_key(_rsa_key("current"))
            ),
            RejectionReason.UNSUPPORTED_ALGORITHM,
            id="hs256-signed-with-the-public-key",
        ),
        pytest.param(
            lambda issuer: issuer.token(header={"alg": "RS512"}),
            RejectionReason.UNSUPPORTED_ALGORITHM,
            id="alg-rs512",
        ),
        # Claims
        pytest.param(
            lambda issuer: issuer.token({"aud": "another-app"}),
            RejectionReason.INVALID_AUDIENCE,
            id="foreign-audience-string",
        ),
        pytest.param(
            lambda issuer: issuer.token({"aud": ["another-app", "third-app"]}),
            RejectionReason.INVALID_AUDIENCE,
            id="foreign-audience-list",
        ),
        pytest.param(
            lambda issuer: issuer.token({"aud": [7]}),
            RejectionReason.INVALID_AUDIENCE,
            id="audience-list-of-non-strings",
        ),
        pytest.param(
            lambda issuer: issuer.token({"aud": []}),
            RejectionReason.INVALID_CLAIM,
            id="empty-audience-list",
        ),
        pytest.param(
            lambda issuer: issuer.token({"iss": "https://login.example.org/realms/other"}),
            RejectionReason.INVALID_ISSUER,
            id="foreign-issuer",
        ),
        pytest.param(
            lambda issuer: issuer.token({"iss": _ISSUER + "/"}),
            RejectionReason.INVALID_ISSUER,
            id="issuer-with-trailing-slash",
        ),
        pytest.param(
            lambda issuer: issuer.token({"iss": 7}),
            RejectionReason.INVALID_ISSUER,
            id="issuer-not-a-string",
        ),
        *(
            pytest.param(
                lambda issuer, claim=claim: issuer.token({claim: _ABSENT}),
                RejectionReason.INVALID_CLAIM,
                id=f"missing-{claim}",
            )
            for claim in ("aud", "iss", "exp", "iat")
        ),
        *(
            pytest.param(
                lambda issuer, claim=claim, value=value: issuer.token({claim: value}),
                RejectionReason.INVALID_CLAIM,
                id=f"{claim}-as-{type(value).__name__}-{value!r}",
            )
            for claim, value in (
                ("exp", "1800000600"),
                ("exp", 1_800_000_600.5),
                ("exp", True),
                ("iat", None),
                ("nbf", "1799999990"),
                ("sub", 7),
                ("sub", ""),
            )
        ),
        # Headers
        pytest.param(
            lambda issuer: issuer.token(header={"kid": _ABSENT}),
            RejectionReason.INVALID_KEY_ID,
            id="kid-missing",
        ),
        pytest.param(
            lambda issuer: issuer.token(header={"kid": 7}),
            RejectionReason.INVALID_KEY_ID,
            id="kid-not-a-string",
        ),
        pytest.param(
            lambda issuer: issuer.token(header={"kid": ""}),
            RejectionReason.INVALID_KEY_ID,
            id="kid-empty",
        ),
        pytest.param(
            lambda issuer: issuer.token(header={"kid": "k" * (MAX_KEY_ID_CHARACTERS + 1)}),
            RejectionReason.INVALID_KEY_ID,
            id="kid-oversized",
        ),
        pytest.param(
            lambda issuer: issuer.token(header={"kid": "retired-key"}),
            RejectionReason.UNKNOWN_KEY_ID,
            id="kid-unknown",
        ),
        pytest.param(
            lambda issuer: _jws(
                '{"alg": "RS256", "kid": "current-key", "alg": "HS256"}',
                issuer.claims(),
                _rs256(_rsa_key("current")),
            ),
            RejectionReason.DUPLICATE_MEMBER,
            id="duplicate-alg",
        ),
        pytest.param(
            lambda issuer: _jws(
                '{"alg": "RS256", "kid": "current-key", "kid": "retired-key"}',
                issuer.claims(),
                _rs256(_rsa_key("current")),
            ),
            RejectionReason.DUPLICATE_MEMBER,
            id="duplicate-kid",
        ),
        pytest.param(
            lambda issuer: _jws(
                {"alg": "RS256", "kid": "current-key"},
                '{"sub": "operator", "sub": "intruder"}',
                _rs256(_rsa_key("current")),
            ),
            RejectionReason.DUPLICATE_MEMBER,
            id="duplicate-claim",
        ),
        *(
            pytest.param(
                lambda issuer, member=member: issuer.token(header={member: "attacker-chosen"}),
                RejectionReason.FORBIDDEN_HEADER,
                id=f"header-{member}",
            )
            for member in ("crit", "jwk", "jku", "x5u", "x5c")
        ),
        pytest.param(
            lambda issuer: issuer.token(header={"b64": False}),
            RejectionReason.FORBIDDEN_HEADER,
            id="header-b64-false",
        ),
        pytest.param(
            lambda issuer: issuer.token({"padding": "x" * MAX_TOKEN_CHARACTERS}),
            RejectionReason.TOKEN_TOO_LONG,
            id="oversized-token",
        ),
        pytest.param(
            lambda issuer: _jws(
                {"alg": "RS256", "kid": "current-key"},
                f'{{"deep": {_DEEP_ARRAY}}}',
                _rs256(_rsa_key("current")),
            ),
            RejectionReason.NESTING_TOO_DEEP,
            id="nesting-past-the-recursion-limit",
        ),
        pytest.param(
            lambda issuer: issuer.token(
                {"deep": json.loads("[" * MAX_JSON_NESTING_DEPTH + "]" * MAX_JSON_NESTING_DEPTH)}
            ),
            RejectionReason.NESTING_TOO_DEEP,
            id="nesting-one-past-the-bound",
        ),
        *(
            pytest.param(lambda issuer, raw=raw: raw, RejectionReason.MALFORMED_TOKEN, id=name)
            for name, raw in (
                ("empty", ""),
                ("one-segment", "abc"),
                ("four-segments", "a.b.c.d"),
                ("non-base64url-characters", "e30.e30.sig+nature"),
                ("impossible-base64-length", "e30.e30.a"),
                ("header-not-json", f"{_segment('not json')}.e30.c2ln"),
                ("header-not-an-object", f"{_segment('[]')}.e30.c2ln"),
                ("header-not-utf8", "_w.e30.c2ln"),
                ("non-ascii-character", "e30.e30.sïg"),
            )
        ),
        pytest.param(
            lambda issuer: _jws({"alg": "RS256", "kid": "current-key"}, "[]", lambda _: b"s"),
            RejectionReason.MALFORMED_TOKEN,
            id="claims-not-an-object",
        ),
        pytest.param(
            lambda issuer: _with_unused_signature_bits_set(issuer.token()),
            RejectionReason.MALFORMED_TOKEN,
            id="non-canonical-base64url",
        ),
        pytest.param(
            lambda issuer: issuer.token({"score": float("-inf")}),
            RejectionReason.MALFORMED_TOKEN,
            id="claim-with-a-non-json-constant",
        ),
        pytest.param(
            lambda issuer: _jws(
                {"alg": "RS256", "kid": "current-key"},
                '{"score": -1e999999}',
                _rs256(_rsa_key("current")),
            ),
            RejectionReason.MALFORMED_TOKEN,
            id="claim-overflowing-to-infinity",
        ),
    ],
)
def test_a_hostile_token_is_refused_with_its_reason(
    issuer: IssuerScenario,
    build_token: Callable[[IssuerScenario], str],
    reason: RejectionReason,
) -> None:
    assert issuer.verifier.verify(build_token(issuer)) == Rejected(reason)


def test_a_token_pyjwt_cannot_decode_is_refused_as_malformed(
    issuer: IssuerScenario, monkeypatch: pytest.MonkeyPatch
) -> None:
    """The strict parse refuses every token PyJWT cannot decode today; should a
    later PyJWT read a segment differently, its DecodeError is still a rejection."""

    def decode_differently(*args: object, **kwargs: object) -> NoReturn:
        del args, kwargs
        raise jwt.DecodeError("this PyJWT reads the segment differently")

    monkeypatch.setattr(jwt, "decode", decode_differently)

    assert issuer.verifier.verify(issuer.token()) == Rejected(RejectionReason.MALFORMED_TOKEN)


@pytest.mark.parametrize(
    ("claim", "offset", "outcome"),
    [
        pytest.param("exp", -_LEEWAY_SECONDS + 1, None, id="exp-inside-the-leeway"),
        pytest.param("exp", -_LEEWAY_SECONDS, RejectionReason.EXPIRED, id="exp-at-the-leeway"),
        pytest.param("iat", _LEEWAY_SECONDS, None, id="iat-at-the-leeway"),
        pytest.param(
            "iat", _LEEWAY_SECONDS + 1, RejectionReason.ISSUED_IN_FUTURE, id="iat-past-the-leeway"
        ),
        pytest.param("nbf", _LEEWAY_SECONDS, None, id="nbf-at-the-leeway"),
        pytest.param(
            "nbf", _LEEWAY_SECONDS + 1, RejectionReason.NOT_YET_VALID, id="nbf-past-the-leeway"
        ),
    ],
)
def test_time_claims_hold_exactly_the_configured_leeway_on_the_wall_clock(
    issuer: IssuerScenario, claim: str, offset: int, outcome: RejectionReason | None
) -> None:
    changes = {claim: int(issuer.wall_clock.now) + offset}

    expected = issuer.verified(changes) if outcome is None else Rejected(outcome)
    assert issuer.verifier.verify(issuer.token(changes)) == expected


def _defective_key_sets() -> list[Any]:
    current = _rsa_key("current")
    valid_jwk = _public_jwk(current, "current-key")
    return [
        pytest.param(KeySetFetchError("timed out"), id="fetch-failure"),
        pytest.param(b" " * MAX_KEY_SET_BYTES + b"{}", id="oversized-response"),
        pytest.param(
            _key_set_document(
                valid_jwk,
                *(_public_jwk(current, f"spare-{index}") for index in range(MAX_KEY_SET_KEYS)),
            ),
            id="too-many-keys",
        ),
        pytest.param(
            _key_set_document(
                valid_jwk,
                *(
                    _public_jwk(current, f"encryption-{index}", use="enc")
                    for index in range(MAX_KEY_SET_KEYS)
                ),
            ),
            id="too-many-keys-counting-passed-over-ones",
        ),
        pytest.param(
            _key_set_document(valid_jwk, _public_jwk(_rsa_key("other"), "current-key")),
            id="duplicate-kid",
        ),
        pytest.param(
            _key_set_document(valid_jwk, {"kty": "oct", "kid": "shared", "k": "c2VjcmV0"}),
            id="symmetric-key",
        ),
        pytest.param(
            _key_set_document({**RSAAlgorithm.to_jwk(current, as_dict=True), "kid": "current-key"}),
            id="private-key",
        ),
        pytest.param(
            _key_set_document(valid_jwk, _public_jwk(_rsa_key("weak", 1024), "weak-key")),
            id="rsa-key-under-2048-bits",
        ),
        pytest.param(
            _key_set_document(_public_jwk(current, "current-key", alg="RS512")),
            id="only-an-rs512-key",
        ),
        pytest.param(
            _key_set_document(_public_jwk(current, "current-key", use="enc")),
            id="only-an-encryption-key",
        ),
        pytest.param(
            _key_set_document(_public_jwk(current, "current-key", key_ops=["encrypt"])),
            id="only-a-key-without-verify",
        ),
        pytest.param(
            _key_set_document(_public_jwk(current, "current-key", key_ops="verify")),
            id="only-a-key-whose-key-ops-is-no-list",
        ),
        pytest.param(
            _key_set_document(_public_jwk(current, "current-key", kid=7)), id="key-kid-not-a-string"
        ),
        pytest.param(
            _key_set_document(_public_jwk(current, "current-key", n=7)),
            id="key-modulus-not-a-string",
        ),
        pytest.param(
            _key_set_document(_public_jwk(current, "current-key", e="AAAA")), id="key-exponent-zero"
        ),
        pytest.param(_key_set_document("not a key"), id="key-not-an-object"),
        pytest.param(_key_set_document(), id="no-keys"),
        pytest.param(b'{"keys": {"current-key": {}}}', id="keys-not-a-list"),
        pytest.param(b'{"keys": [], "keys": []}', id="duplicate-member"),
        pytest.param(b'{"keys": [', id="malformed-json"),
        pytest.param(
            json.dumps({"keys": [valid_jwk], "extra": float("nan")}).encode(),
            id="non-json-constant",
        ),
        pytest.param(
            json.dumps({"keys": [valid_jwk]}).encode()[:-1] + b', "extra": 1e999999}',
            id="number-overflowing-to-infinity",
        ),
        pytest.param(gzip.compress(_key_set_document(valid_jwk)), id="compressed"),
    ]


@pytest.mark.parametrize("response", _defective_key_sets())
def test_a_defective_key_set_is_refused_as_a_whole(
    issuer: IssuerScenario, response: bytes | Exception
) -> None:
    issuer.serve(response)

    assert issuer.verifier.verify(issuer.token()) == Rejected(RejectionReason.KEY_SET_UNAVAILABLE)


def test_keys_published_for_other_purposes_beside_the_signing_key_are_passed_over(
    issuer: IssuerScenario,
) -> None:
    """The shape Keycloak serves: an RSA-OAEP encryption key, and an EC key
    once the realm adds one, beside the RS256 signing key."""
    current = _rsa_key("current")
    issuer.serve(
        _key_set_document(
            _public_jwk(current, "current-key"),
            _public_jwk(_rsa_key("encryption"), "encryption-key", alg="RSA-OAEP", use="enc"),
            {
                **ECAlgorithm.to_jwk(
                    ec.generate_private_key(ec.SECP256R1()).public_key(), as_dict=True
                ),
                "kid": "ec-key",
                "alg": "ES256",
                "use": "sig",
            },
        )
    )

    assert issuer.verifier.verify(issuer.token()) == issuer.verified()
    assert issuer.verifier.verify(issuer.token(header={"kid": "encryption-key"})) == Rejected(
        RejectionReason.UNKNOWN_KEY_ID
    )


def test_a_key_whose_key_ops_include_verify_is_accepted(issuer: IssuerScenario) -> None:
    issuer.serve(
        _key_set_document(_public_jwk(_rsa_key("current"), "current-key", key_ops=["verify"]))
    )

    assert issuer.verifier.verify(issuer.token()) == issuer.verified()


@pytest.mark.parametrize("response", _defective_key_sets())
def test_a_failed_refresh_keeps_the_last_valid_key_set_until_its_ttl(
    issuer: IssuerScenario, response: bytes | Exception
) -> None:
    assert issuer.verifier.verify(issuer.token()) == issuer.verified()
    issuer.serve(response)
    issuer.after_cooldown()

    refreshing = issuer.verifier.verify(issuer.token(header={"kid": "rotated-key"}))
    still_cached = issuer.verifier.verify(issuer.token())
    issuer.monotonic_clock.now += KEY_SET_TTL_SECONDS
    expired = issuer.verifier.verify(issuer.token())

    assert refreshing == Rejected(RejectionReason.UNKNOWN_KEY_ID)
    assert still_cached == issuer.verified()
    assert expired == Rejected(RejectionReason.KEY_SET_UNAVAILABLE)
    assert len(issuer.endpoint.fetched_urls) == 3


_SECRET_BEARING_JWKS_URL = f"https://login.example.org/certs/{_URL_SECRET}?signature={_URL_SECRET}"


@pytest.mark.parametrize(
    ("response", "logged_cause"),
    [
        pytest.param(
            KeySetFetchError(f"GET {_SECRET_BEARING_JWKS_URL} answered 503"),
            "fetch-failed",
            id="failed-fetch-quoting-its-url",
        ),
        pytest.param(b"[]", "not-strict-json", id="invalid-key-set"),
        pytest.param(
            _key_set_document(
                _public_jwk(_rsa_key("current"), _URL_SECRET),
                _public_jwk(_rsa_key("other"), _URL_SECRET),
            ),
            "duplicate-key-id",
            id="key-set-repeating-a-kid",
        ),
        pytest.param(
            _key_set_document(_public_jwk(_rsa_key("weak", 1024), _URL_SECRET)),
            "key-too-short",
            id="key-set-with-a-weak-key",
        ),
    ],
)
def test_a_failed_refresh_is_logged_by_its_cause_code_alone(
    issuer: IssuerScenario,
    caplog: pytest.LogCaptureFixture,
    response: bytes | Exception,
    logged_cause: str,
) -> None:
    verifier = issuer.verifier_with(jwks_url=_SECRET_BEARING_JWKS_URL)
    issuer.serve(response)

    with caplog.at_level(logging.WARNING, logger="webauth.jwt_verification"):
        verifier.verify(issuer.token())

    [warning] = caplog.records
    assert logged_cause in warning.getMessage()
    assert _ISSUER not in warning.getMessage()
    assert _URL_SECRET not in warning.getMessage()


def test_the_key_set_is_cached_on_the_monotonic_clock_until_its_ttl(
    issuer: IssuerScenario,
) -> None:
    issuer.verifier.verify(issuer.token())
    issuer.serve(_key_set_document(_public_jwk(_rsa_key("other"), "other-key")))

    issuer.monotonic_clock.now += KEY_SET_TTL_SECONDS - 1
    cached = issuer.verifier.verify(issuer.token())
    issuer.monotonic_clock.now += 1
    refetched = issuer.verifier.verify(issuer.token())

    assert cached == issuer.verified()
    assert refetched == Rejected(RejectionReason.UNKNOWN_KEY_ID)


def test_an_unknown_kid_refreshes_at_most_once_per_cooldown(issuer: IssuerScenario) -> None:
    issuer.verifier.verify(issuer.token())
    issuer.after_cooldown()
    unknown = issuer.token(header={"kid": "rotated-key"})

    for _ in range(3):
        issuer.verifier.verify(unknown)
    fetches_within_cooldown = len(issuer.endpoint.fetched_urls)
    issuer.after_cooldown()
    issuer.verifier.verify(unknown)

    assert fetches_within_cooldown == 2
    assert len(issuer.endpoint.fetched_urls) == 3


def test_a_rotated_key_verifies_once_its_unknown_kid_refreshed_the_key_set(
    issuer: IssuerScenario,
) -> None:
    issuer.verifier.verify(issuer.token())
    issuer.serve(
        _key_set_document(
            _public_jwk(_rsa_key("current"), "current-key"),
            _public_jwk(_rsa_key("other"), "rotated-key"),
        )
    )
    issuer.after_cooldown()

    rotated = issuer.token(header={"kid": "rotated-key"}, sign=_rs256(_rsa_key("other")))

    assert issuer.verifier.verify(rotated) == issuer.verified()


def test_parallel_unknown_kids_share_one_fetch_and_each_fails_closed(
    issuer: IssuerScenario,
) -> None:
    issuer.verifier.verify(issuer.token())
    issuer.after_cooldown()
    fetch_started, release_fetch = threading.Event(), threading.Event()

    def hold_the_fetch() -> None:
        fetch_started.set()
        assert release_fetch.wait(timeout=10)

    issuer.endpoint.before_answer = hold_the_fetch
    unknown = issuer.token(header={"kid": "rotated-key"})
    with ThreadPoolExecutor(max_workers=8) as pool:
        refreshing = pool.submit(issuer.verifier.verify, unknown)
        assert fetch_started.wait(timeout=10)
        while_refreshing = [
            outcome.result(timeout=10)
            for outcome in [pool.submit(issuer.verifier.verify, unknown) for _ in range(7)]
        ]
        release_fetch.set()
        outcomes = [refreshing.result(timeout=10), *while_refreshing]

    assert outcomes == [Rejected(RejectionReason.UNKNOWN_KEY_ID)] * 8
    assert len(issuer.endpoint.fetched_urls) == 2


@pytest.mark.parametrize(
    ("changes", "refused"),
    [
        pytest.param({"issuer": ""}, "issuer", id="empty-issuer"),
        pytest.param(
            {"issuer": [_ISSUER, "https://other.example.org"]}, "issuer", id="issuer-list"
        ),
        pytest.param({"audiences": []}, "audiences", id="no-audience"),
        pytest.param({"audiences": [""]}, "audiences", id="empty-audience"),
        pytest.param({"audiences": "songmaker"}, "audiences", id="audience-as-one-string"),
        pytest.param({"jwks_url": "http://login.example.org/certs"}, "https", id="http-key-set"),
        pytest.param({"jwks_url": "https:///certs"}, "https", id="key-set-without-host"),
        pytest.param({"jwks_url": "https://["}, "https", id="unparseable-key-set-url"),
        pytest.param(
            {"jwks_url": "https://login.example.org:99999/certs"},
            "https",
            id="key-set-url-with-bad-port",
        ),
        pytest.param(
            {"jwks_url": "https://login.example.org:abc/certs"},
            "https",
            id="key-set-url-with-non-numeric-port",
        ),
        pytest.param(
            {"jwks_url": "https://operator:password@login.example.org/certs"},
            "https",
            id="key-set-url-with-credentials",
        ),
        pytest.param({"leeway_seconds": -1}, "negative", id="negative-leeway"),
        pytest.param({"leeway_seconds": 1.5}, "whole", id="fractional-leeway"),
        pytest.param({"leeway_seconds": True}, "whole", id="boolean-leeway"),
    ],
)
def test_a_verifier_refuses_a_configuration_it_cannot_verify_against(
    issuer: IssuerScenario, changes: dict[str, Any], refused: str
) -> None:
    with pytest.raises(ValueError, match=refused):
        issuer.verifier_with(**changes)


# The real HTTPS boundary, served from loopback under a self-signed certificate.


_SILENT_HOLD_SECONDS = 10
_TRANSPORT_FAILURE = (
    "fetching the key set failed: the origin could not be reached,"
    " or the TLS handshake or HTTP exchange failed"
)
"""How long `/silent` keeps a request unanswered unless the test releases it."""


@dataclass
class HttpsKeySetServer:
    base_url: str
    requested_paths: list[str]
    silent_request_arrived: threading.Event
    release_silent_request: threading.Event


def _served_key_set() -> bytes:
    return _key_set_document(_public_jwk(_rsa_key("current"), "current-key"))


def _self_signed_loopback_certificate(directory: Path) -> tuple[Path, Path]:
    key = _rsa_key("loopback-tls")
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "127.0.0.1")])
    now = datetime.datetime.now(datetime.UTC)
    certificate = (
        x509.CertificateBuilder()
        .subject_name(name)
        .issuer_name(name)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - datetime.timedelta(hours=1))
        .not_valid_after(now + datetime.timedelta(hours=1))
        .add_extension(
            x509.SubjectAlternativeName([x509.IPAddress(ipaddress.ip_address("127.0.0.1"))]),
            critical=False,
        )
        .add_extension(x509.BasicConstraints(ca=True, path_length=None), critical=True)
        .add_extension(x509.SubjectKeyIdentifier.from_public_key(key.public_key()), critical=False)
        .add_extension(
            x509.AuthorityKeyIdentifier.from_issuer_public_key(key.public_key()), critical=False
        )
        .add_extension(x509.ExtendedKeyUsage([ExtendedKeyUsageOID.SERVER_AUTH]), critical=False)
        .sign(key, hashes.SHA256())
    )
    certificate_path, key_path = directory / "cert.pem", directory / "key.pem"
    certificate_path.write_bytes(certificate.public_bytes(serialization.Encoding.PEM))
    key_path.write_bytes(
        key.private_bytes(
            serialization.Encoding.PEM,
            serialization.PrivateFormat.PKCS8,
            serialization.NoEncryption(),
        )
    )
    return certificate_path, key_path


@pytest.fixture
def https_key_set_server(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> Iterator[HttpsKeySetServer]:
    certificate_path, key_path = _self_signed_loopback_certificate(tmp_path)
    monkeypatch.setenv("SSL_CERT_FILE", str(certificate_path))
    requested_paths: list[str] = []
    silent_request_arrived, release_silent_request = threading.Event(), threading.Event()

    class KeySetHandler(BaseHTTPRequestHandler):
        def do_GET(self) -> None:
            requested_paths.append(self.path)
            if self.path == "/silent":
                silent_request_arrived.set()
                release_silent_request.wait(timeout=_SILENT_HOLD_SECONDS)
            elif self.path == "/moved":
                self._send_head(302, {"Location": "/certs", "Content-Length": "0"})
            elif self.path == "/missing":
                self._send_head(404, {"Content-Length": "0"})
            elif self.path == "/oversized":
                self._answer(b" " * (2 * MAX_KEY_SET_BYTES))
            elif self.path == "/compressed":
                self._answer(gzip.compress(_served_key_set()), content_encoding="gzip")
            else:
                self._answer(_served_key_set())

        def _answer(self, body: bytes, content_encoding: str | None = None) -> None:
            headers = {"Content-Length": str(len(body))}
            if content_encoding is not None:
                headers["Content-Encoding"] = content_encoding
            self._send_head(200, headers)
            # The fetch may hang up once it read its limit.
            with contextlib.suppress(OSError):
                self.wfile.write(body)

        def _send_head(self, status: int, headers: dict[str, str]) -> None:
            # The fetch may already have hung up, refusing the certificate or
            # the answer.
            with contextlib.suppress(OSError):
                self.send_response(status)
                for name, value in headers.items():
                    self.send_header(name, value)
                self.end_headers()

        def log_message(self, format: str, *args: Any) -> None:
            del format, args

    tls = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    tls.load_cert_chain(certificate_path, key_path)
    server = HTTPServer(("127.0.0.1", 0), KeySetHandler)
    server.socket = tls.wrap_socket(server.socket, server_side=True)
    serving = threading.Thread(target=server.serve_forever, daemon=True)
    serving.start()
    try:
        yield HttpsKeySetServer(
            f"https://127.0.0.1:{server.server_port}",
            requested_paths,
            silent_request_arrived,
            release_silent_request,
        )
    finally:
        release_silent_request.set()
        server.shutdown()
        server.server_close()
        serving.join(timeout=10)


def test_https_fetch_returns_the_served_key_set(https_key_set_server: HttpsKeySetServer) -> None:
    document = fetch_key_set_over_https(f"{https_key_set_server.base_url}/certs")

    assert json.loads(document)["keys"][0]["kid"] == "current-key"


def test_a_verifier_on_the_https_fetch_verifies_a_token_of_the_served_key_set(
    https_key_set_server: HttpsKeySetServer, issuer: IssuerScenario
) -> None:
    verifier = issuer.verifier_with(
        jwks_url=f"{https_key_set_server.base_url}/certs", fetch_key_set=fetch_key_set_over_https
    )

    assert verifier.verify(issuer.token()) == issuer.verified()


def test_https_fetch_gives_up_on_an_origin_silent_past_the_read_timeout(
    https_key_set_server: HttpsKeySetServer,
) -> None:
    started = time.monotonic()
    with pytest.raises(KeySetFetchError, match=_TRANSPORT_FAILURE):
        fetch_key_set_over_https(f"{https_key_set_server.base_url}/silent", timeout_seconds=0.2)

    assert time.monotonic() - started < _SILENT_HOLD_SECONDS / 2


def test_a_request_during_a_stalled_key_set_fetch_is_refused_without_waiting(
    https_key_set_server: HttpsKeySetServer, issuer: IssuerScenario
) -> None:
    verifier = issuer.verifier_with(
        jwks_url=f"{https_key_set_server.base_url}/silent", fetch_key_set=fetch_key_set_over_https
    )
    token = issuer.token()
    with ThreadPoolExecutor(max_workers=1) as pool:
        refreshing = pool.submit(verifier.verify, token)
        assert https_key_set_server.silent_request_arrived.wait(timeout=10)

        assert verifier.verify(token) == Rejected(RejectionReason.KEY_SET_UNAVAILABLE)
        assert not refreshing.done()

        https_key_set_server.release_silent_request.set()
        assert refreshing.result(timeout=10) == Rejected(RejectionReason.KEY_SET_UNAVAILABLE)


def test_https_fetch_reads_at_most_one_byte_past_the_key_set_limit(
    https_key_set_server: HttpsKeySetServer,
) -> None:
    document = fetch_key_set_over_https(f"{https_key_set_server.base_url}/oversized")

    assert len(document) == MAX_KEY_SET_BYTES + 1


def test_https_fetch_hands_back_a_compressed_answer_still_compressed(
    https_key_set_server: HttpsKeySetServer,
) -> None:
    document = fetch_key_set_over_https(f"{https_key_set_server.base_url}/compressed")

    assert json.loads(gzip.decompress(document))["keys"][0]["kid"] == "current-key"


def test_https_fetch_refuses_a_certificate_the_system_does_not_trust(
    https_key_set_server: HttpsKeySetServer, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.delenv("SSL_CERT_FILE")

    with pytest.raises(KeySetFetchError, match=_TRANSPORT_FAILURE):
        fetch_key_set_over_https(f"{https_key_set_server.base_url}/certs")


def test_https_fetch_names_an_origin_nobody_listens_on_as_unreachable() -> None:
    with socket.socket() as probe:
        probe.bind(("127.0.0.1", 0))
        closed_port = probe.getsockname()[1]

    with pytest.raises(KeySetFetchError, match=_TRANSPORT_FAILURE):
        fetch_key_set_over_https(f"https://127.0.0.1:{closed_port}/certs")


def test_https_fetch_refuses_an_answer_other_than_200(
    https_key_set_server: HttpsKeySetServer,
) -> None:
    with pytest.raises(KeySetFetchError):
        fetch_key_set_over_https(f"{https_key_set_server.base_url}/missing")


def test_https_fetch_never_follows_a_redirect(https_key_set_server: HttpsKeySetServer) -> None:
    with pytest.raises(KeySetFetchError):
        fetch_key_set_over_https(f"{https_key_set_server.base_url}/moved")

    assert https_key_set_server.requested_paths == ["/moved"]


@pytest.mark.parametrize(
    "url",
    [
        pytest.param("http://127.0.0.1:9/certs", id="http"),
        pytest.param("file:///etc/hostname", id="file"),
        pytest.param("https://[", id="unparseable-host"),
        pytest.param("https://127.0.0.1:99999/certs", id="port-out-of-range"),
    ],
)
def test_fetch_refuses_every_url_but_a_well_formed_https_one(url: str) -> None:
    with pytest.raises(KeySetFetchError):
        fetch_key_set_over_https(url)


def test_a_refused_key_set_url_is_not_repeated_in_the_configuration_error(
    issuer: IssuerScenario,
) -> None:
    with pytest.raises(ValueError) as refusal:
        issuer.verifier_with(jwks_url=f"https://operator:{_URL_SECRET}@login.example.org/certs")

    assert _URL_SECRET not in "".join(traceback.format_exception(refusal.value))


@pytest.mark.parametrize(
    "url_template",
    [
        pytest.param("https://operator:{secret}@{authority}/certs", id="credentials"),
        pytest.param("https://{authority}/certs/{secret}", id="path-of-a-failed-fetch"),
        pytest.param("https://{authority}/certs?signature={secret}", id="query-of-a-failed-fetch"),
        pytest.param("https://key set.example/certs?signature={secret}", id="query-of-a-bad-host"),
        pytest.param("https://127.0.0.1:99999/certs?signature={secret}", id="query-of-a-bad-port"),
    ],
)
def test_a_failed_fetch_never_repeats_a_secret_its_url_carries(
    https_key_set_server: HttpsKeySetServer, monkeypatch: pytest.MonkeyPatch, url_template: str
) -> None:
    monkeypatch.delenv("SSL_CERT_FILE")
    authority = https_key_set_server.base_url.removeprefix("https://")
    url = url_template.format(secret=_URL_SECRET, authority=authority)

    with pytest.raises(KeySetFetchError) as refusal:
        fetch_key_set_over_https(url)

    assert _URL_SECRET not in repr(refusal.value)
    # urllib3's own error may hold the URL in an attribute no repr shows.
    assert refusal.value.__cause__ is None
    assert refusal.value.__context__ is None


@pytest.mark.parametrize(
    "url_template",
    [
        pytest.param("https://{authority}/certs", id="untrusted-certificate"),
        pytest.param("https://key set.example/certs", id="unparseable-host"),
    ],
)
def test_a_failed_fetch_speaks_none_of_urllib3s_error_vocabulary(
    https_key_set_server: HttpsKeySetServer, monkeypatch: pytest.MonkeyPatch, url_template: str
) -> None:
    monkeypatch.delenv("SSL_CERT_FILE")
    authority = https_key_set_server.base_url.removeprefix("https://")

    with pytest.raises(KeySetFetchError) as refusal:
        fetch_key_set_over_https(url_template.format(authority=authority))

    urllib3_error_names = {
        name for name, value in vars(urllib3.exceptions).items() if isinstance(value, type)
    }
    assert not any(name in str(refusal.value) for name in urllib3_error_names)
