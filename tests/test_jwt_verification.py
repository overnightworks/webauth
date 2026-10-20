"""RS256 verification of tokens signed by a remote issuer's published keys.

Every scenario drives `JwtVerifier.verify` with a raw token string, the way a
host's login or logout route will. The key-set endpoint and both clocks are
fakes, so the verifier's own refusals, cache and refresh rules are observed
offline and deterministically; only `fetch_key_set_over_https`, the real HTTPS
boundary, is driven against a loopback TLS server.
"""

from __future__ import annotations

import gzip
import hashlib
import hmac
import json
import logging
import string
import threading
import traceback
from collections.abc import Callable, Iterator
from concurrent.futures import ThreadPoolExecutor
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, NoReturn

import jwt
import pytest
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ec, rsa
from jwt.algorithms import ECAlgorithm, RSAAlgorithm
from oidc_arrangement import (
    ABSENT,
    FakeClock,
    FakeKeySetEndpoint,
    LoopbackHttpsServer,
    changed,
    jws,
    key_set_document,
    loopback_https_server,
    public_jwk,
    rs256,
    rsa_key,
    segment,
    weak_public_jwk,
)

from webauth.https_client import (
    MAX_KEY_SET_BYTES,
    KeySetFetchError,
    fetch_key_set_over_https,
)
from webauth.jwt_verification import (
    KEY_SET_REFRESH_COOLDOWN_SECONDS,
    MAX_KEY_SET_KEYS,
    MAX_TOKEN_CHARACTERS,
    JwtVerifier,
    Rejected,
    RejectionReason,
    VerifiedClaims,
)

KEY_SET_TTL_SECONDS = 60 * 60
MAX_JSON_NESTING_DEPTH = 8
MAX_KEY_ID_CHARACTERS = 128


def _hs256_with_public_key(key: rsa.RSAPrivateKey) -> Callable[[bytes], bytes]:
    """The RS/HS confusion attack: HMAC keyed with the published public key."""
    public_pem = key.public_key().public_bytes(
        serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo
    )
    return lambda signing_input: hmac.new(public_pem, signing_input, hashlib.sha256).digest()


_BASE64URL_ALPHABET = string.ascii_uppercase + string.ascii_lowercase + string.digits + "-_"


def _with_unused_signature_bits_set(token: str) -> str:
    """The same signature bytes spelled non-canonically. The last character
    of a 256-byte signature carries two signature bits and four unused zero
    bits, so the next alphabet character only sets an unused bit."""
    last = token[-1]
    return token[:-1] + _BASE64URL_ALPHABET[_BASE64URL_ALPHABET.index(last) + 1]


_ISSUER = "https://login.example.org/realms/workshop"
_AUDIENCE = "notes-app"
_JWKS_URL = f"{_ISSUER}/protocol/openid-connect/certs"
# Canary whose recognisable text is the point
_URL_SECRET = "s3cr3t-in-the-url"  # noqa: S105
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
        return changed(issued_claims, changes or {})

    def token(
        self,
        claims: dict[str, Any] | None = None,
        header: dict[str, Any] | None = None,
        sign: Callable | None = None,
    ) -> str:
        return jws(
            changed({"alg": "RS256", "kid": self.key_id, "typ": "JWT"}, header or {}),
            self.claims(claims),
            sign or rs256(rsa_key("current")),
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
        key_set_document(public_jwk(rsa_key("current"), "current-key"))
    )
    return IssuerScenario(endpoint, FakeClock(1_800_000_000.0), FakeClock(5_000.0))


@pytest.mark.parametrize(
    "claims",
    [
        pytest.param({}, id="audience-string"),
        pytest.param({"aud": [_AUDIENCE]}, id="audience-list"),
        pytest.param({"aud": ["another-app", _AUDIENCE]}, id="audience-among-others"),
        pytest.param({"nbf": ABSENT}, id="without-nbf"),
        pytest.param({"sub": ABSENT}, id="without-sub"),
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
    verifier = issuer.verifier_with(audiences=["notes-app", "notes-api"])

    outcome = verifier.verify(issuer.token({"aud": "notes-api"}))

    assert outcome == issuer.verified({"aud": "notes-api"})


@pytest.mark.parametrize(
    ("header", "expected_type", "accepted"),
    [
        pytest.param({"typ": "logout+jwt"}, "logout+jwt", True, id="type-equals-expected"),
        pytest.param({"typ": ABSENT}, "logout+jwt", False, id="type-missing"),
        pytest.param({"typ": "JWT"}, "logout+jwt", False, id="type-another"),
        pytest.param({"typ": "LOGOUT+JWT"}, "logout+jwt", False, id="type-in-another-case"),
        pytest.param({"typ": ["logout+jwt"]}, "logout+jwt", False, id="type-not-a-string"),
        pytest.param({"typ": None}, "logout+jwt", False, id="type-null"),
        pytest.param({"typ": ABSENT}, None, True, id="no-type-asked-for-none-sent"),
        pytest.param({"typ": "logout+jwt"}, None, True, id="no-type-asked-for-one-sent"),
        pytest.param({"typ": 7}, None, True, id="no-type-asked-for-not-a-string"),
    ],
)
def test_a_tokens_type_header_is_judged_against_the_expected_type_only_when_one_is_asked_for(
    issuer: IssuerScenario, header: dict[str, Any], expected_type: str | None, accepted: bool
) -> None:
    outcome = issuer.verifier.verify(issuer.token(header=header), expected_type=expected_type)

    assert outcome == (
        issuer.verified() if accepted else Rejected(RejectionReason.INVALID_TOKEN_TYPE)
    )


_DEEP_ARRAY = "[" * 2_000 + "]" * 2_000


@pytest.mark.parametrize(
    ("build_token", "reason"),
    [
        # Signature and algorithm
        pytest.param(
            lambda issuer: issuer.token(sign=rs256(rsa_key("forger"))),
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
                header={"alg": "HS256"}, sign=_hs256_with_public_key(rsa_key("current"))
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
                lambda issuer, claim=claim: issuer.token({claim: ABSENT}),
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
            lambda issuer: issuer.token(header={"kid": None}),
            RejectionReason.INVALID_KEY_ID,
            id="kid-null",
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
            lambda issuer: jws(
                '{"alg": "RS256", "kid": "current-key", "alg": "HS256"}',
                issuer.claims(),
                rs256(rsa_key("current")),
            ),
            RejectionReason.DUPLICATE_MEMBER,
            id="duplicate-alg",
        ),
        pytest.param(
            lambda issuer: jws(
                '{"alg": "RS256", "kid": "current-key", "kid": "retired-key"}',
                issuer.claims(),
                rs256(rsa_key("current")),
            ),
            RejectionReason.DUPLICATE_MEMBER,
            id="duplicate-kid",
        ),
        pytest.param(
            lambda issuer: jws(
                {"alg": "RS256", "kid": "current-key"},
                '{"sub": "operator", "sub": "intruder"}',
                rs256(rsa_key("current")),
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
            lambda issuer: jws(
                {"alg": "RS256", "kid": "current-key"},
                f'{{"deep": {_DEEP_ARRAY}}}',
                rs256(rsa_key("current")),
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
                ("header-not-json", f"{segment('not json')}.e30.c2ln"),
                ("header-not-an-object", f"{segment('[]')}.e30.c2ln"),
                ("header-not-utf8", "_w.e30.c2ln"),
                ("non-ascii-character", "e30.e30.sïg"),
            )
        ),
        pytest.param(
            lambda issuer: jws({"alg": "RS256", "kid": "current-key"}, "[]", lambda _: b"s"),
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
            lambda issuer: jws(
                {"alg": "RS256", "kid": "current-key"},
                '{"score": -1e999999}',
                rs256(rsa_key("current")),
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


def _signing_keys(count: int) -> list[dict[str, Any]]:
    current = rsa_key("current")
    return [public_jwk(current, "current-key")] + [
        public_jwk(current, f"spare-{index}") for index in range(count - 1)
    ]


def _kidless_keys(count: int) -> list[dict[str, Any]]:
    return [public_jwk(rsa_key(f"kidless-{index}"), "unused", kid=ABSENT) for index in range(count)]


def _mixed_keys(count: int) -> list[dict[str, Any]]:
    keys = _kidless_keys(count)
    keys[::2] = [public_jwk(rsa_key("current"), "current-key")] + [
        public_jwk(rsa_key("current"), f"named-{index}") for index in range(len(keys[::2]) - 1)
    ]
    return keys


def _passed_over_keys(count: int) -> list[dict[str, Any]]:
    """What the OpenID Foundation suite's OP publishes beside its two RS256
    keys: other signing algorithms, encryption keys, and entries no verifier
    can use."""
    p256 = ec.generate_private_key(ec.SECP256R1()).public_key()
    secp256k1 = ec.generate_private_key(ec.SECP256K1()).public_key()
    kinds = [
        {**ECAlgorithm.to_jwk(p256, as_dict=True), "use": "sig"},
        {**ECAlgorithm.to_jwk(p256, as_dict=True), "alg": "ES256"},
        {**ECAlgorithm.to_jwk(secp256k1, as_dict=True), "alg": "ES256K"},
        {"kty": "OKP", "crv": "Ed25519", "x": "A" * 43, "alg": "EdDSA"},
        public_jwk(rsa_key("encryption"), "unused", alg="RSA-OAEP", use="enc"),
        {**ECAlgorithm.to_jwk(p256, as_dict=True), "alg": "ECDH-ES", "use": "enc"},
        {"kty": "AKP", "alg": "ML-DSA-9999", "pub": "AAAA"},
        {"kty": "UNKNOWN"},
        public_jwk(rsa_key("encryption"), "unused", alg="RS9999"),
        {**ECAlgorithm.to_jwk(p256, as_dict=True), "alg": "ES9999"},
        {**ECAlgorithm.to_jwk(p256, as_dict=True), "crv": "P-9999"},
    ]
    return [{**kinds[index % len(kinds)], "kid": f"passed-over-{index}"} for index in range(count)]


def _defective_key_sets() -> list[Any]:
    current = rsa_key("current")
    valid_jwk = public_jwk(current, "current-key")
    return [
        pytest.param(KeySetFetchError("timed out"), "fetch-failed", id="fetch-failure"),
        pytest.param(b" " * MAX_KEY_SET_BYTES + b"{}", "too-large", id="oversized-response"),
        pytest.param(
            key_set_document(
                valid_jwk,
                *(public_jwk(current, f"spare-{index}") for index in range(MAX_KEY_SET_KEYS)),
            ),
            "key-count-out-of-range",
            id="too-many-keys",
        ),
        pytest.param(
            key_set_document(
                *_signing_keys(MAX_KEY_SET_KEYS),
                public_jwk(current, "eleventh", n=7),
            ),
            "key-count-out-of-range",
            id="eleventh-signing-key-malformed-is-counted-before-it-is-built",
        ),
        pytest.param(
            key_set_document(
                *_signing_keys(MAX_KEY_SET_KEYS),
                public_jwk(current, "encryption-key", use="enc", d="AQAB"),
            ),
            "secret-key-published",
            id="passed-over-key-carrying-a-private-member",
        ),
        pytest.param(
            key_set_document(valid_jwk, public_jwk(rsa_key("other"), "current-key")),
            "duplicate-key-id",
            id="duplicate-kid",
        ),
        pytest.param(
            key_set_document(valid_jwk, {"kty": "oct", "kid": "shared", "k": "c2VjcmV0"}),
            "secret-key-published",
            id="symmetric-key",
        ),
        pytest.param(
            key_set_document({**RSAAlgorithm.to_jwk(current, as_dict=True), "kid": "current-key"}),
            "secret-key-published",
            id="private-key",
        ),
        pytest.param(
            key_set_document(valid_jwk, weak_public_jwk("weak-key")),
            "key-too-short",
            id="rsa-key-under-2048-bits",
        ),
        pytest.param(
            key_set_document(public_jwk(current, "current-key", alg="RS512")),
            "no-rs256-signing-key",
            id="only-an-rs512-key",
        ),
        pytest.param(
            key_set_document(public_jwk(current, "current-key", use="enc")),
            "no-rs256-signing-key",
            id="only-an-encryption-key",
        ),
        pytest.param(
            key_set_document(public_jwk(current, "current-key", key_ops=["encrypt"])),
            "no-rs256-signing-key",
            id="only-a-key-without-verify",
        ),
        pytest.param(
            key_set_document(public_jwk(current, "current-key", key_ops="verify")),
            "no-rs256-signing-key",
            id="only-a-key-whose-key-ops-is-no-list",
        ),
        pytest.param(
            key_set_document(public_jwk(current, "current-key", kid=7)),
            "malformed-key",
            id="key-kid-not-a-string",
        ),
        pytest.param(
            key_set_document(public_jwk(current, "current-key", kid=None)),
            "malformed-key",
            id="sole-key-kid-null",
        ),
        pytest.param(
            key_set_document(valid_jwk, public_jwk(current, "other-key", kid=None)),
            "malformed-key",
            id="kid-null-beside-another-signing-key",
        ),
        pytest.param(
            key_set_document(*_kidless_keys(MAX_KEY_SET_KEYS + 1)),
            "key-count-out-of-range",
            id="too-many-kidless-keys",
        ),
        pytest.param(
            key_set_document(*_mixed_keys(MAX_KEY_SET_KEYS + 1)),
            "key-count-out-of-range",
            id="too-many-named-and-kidless-keys",
        ),
        pytest.param(
            key_set_document(public_jwk(current, "current-key", n=7)),
            "malformed-key",
            id="key-modulus-not-a-string",
        ),
        pytest.param(
            key_set_document(public_jwk(current, "current-key", e="AAAA")),
            "invalid-rsa-key",
            id="key-exponent-zero",
        ),
        pytest.param(key_set_document("not a key"), "key-not-an-object", id="key-not-an-object"),
        pytest.param(key_set_document(), "key-count-out-of-range", id="no-keys"),
        pytest.param(
            b'{"keys": {"current-key": {}}}', "key-count-out-of-range", id="keys-not-a-list"
        ),
        pytest.param(
            b'{"keys": ' + json.dumps([valid_jwk]).encode() + b', "keys": []}',
            "key-count-out-of-range",
            id="duplicate-member-keeps-the-last",
        ),
        pytest.param(b'{"keys": [', "not-json", id="malformed-json"),
        pytest.param(b"[" * MAX_KEY_SET_BYTES, "not-json", id="nested-past-the-recursion-limit"),
        pytest.param(
            gzip.compress(key_set_document(valid_jwk)), "not-json", id="compressed"
        ),
    ]


def _logged_refresh_failures(caplog: pytest.LogCaptureFixture) -> list[str]:
    return [
        record.getMessage()
        for record in caplog.records
        if record.name == "webauth.jwt_verification" and record.levelno == logging.WARNING
    ]


@pytest.mark.parametrize(("response", "failure"), _defective_key_sets())
def test_a_defective_key_set_is_refused_as_a_whole(
    issuer: IssuerScenario,
    caplog: pytest.LogCaptureFixture,
    response: bytes | Exception,
    failure: str,
) -> None:
    issuer.serve(response)

    with caplog.at_level(logging.WARNING, logger="webauth.jwt_verification"):
        refused = issuer.verifier.verify(issuer.token())

    assert refused == Rejected(RejectionReason.KEY_SET_UNAVAILABLE)
    [logged] = _logged_refresh_failures(caplog)
    assert logged.endswith(failure)


def test_keys_passed_over_do_not_count_toward_the_key_bound(issuer: IssuerScenario) -> None:
    published = _signing_keys(MAX_KEY_SET_KEYS)
    issuer.serve(key_set_document(*published, *_passed_over_keys(20)))

    verified = [
        issuer.verifier.verify(issuer.token(header={"kid": jwk["kid"]}))
        for jwk in (published[0], published[-1])
    ]

    assert verified == [issuer.verified()] * 2


@pytest.mark.parametrize(
    "published",
    [
        pytest.param(_kidless_keys(MAX_KEY_SET_KEYS), id="all-kidless"),
        pytest.param(_mixed_keys(MAX_KEY_SET_KEYS), id="named-and-kidless"),
    ],
)
def test_the_key_bound_admits_that_many_eligible_keys_named_or_not(
    issuer: IssuerScenario, published: list[dict[str, Any]]
) -> None:
    issuer.serve(key_set_document(*published))
    kidless = issuer.verifier.verify(_kidless(issuer))
    issuer.after_cooldown()

    unfamiliar = issuer.verifier.verify(issuer.token(header={"kid": "x"}))

    assert kidless == Rejected(RejectionReason.INVALID_KEY_ID)
    assert unfamiliar == Rejected(RejectionReason.UNKNOWN_KEY_ID)


@pytest.mark.parametrize(
    "refused",
    [
        pytest.param(
            key_set_document(
                public_jwk(rsa_key("current"), "current-key"),
                public_jwk(rsa_key("other"), "current-key"),
            ),
            id="duplicate-named-kid",
        ),
        pytest.param(key_set_document(*_kidless_keys(MAX_KEY_SET_KEYS + 1)), id="too-many-keys"),
    ],
)
def test_a_refused_key_set_keeps_the_last_good_snapshot(
    issuer: IssuerScenario, refused: bytes
) -> None:
    issuer.verifier.verify(issuer.token())
    issuer.serve(refused)
    issuer.after_cooldown()

    unfamiliar = issuer.verifier.verify(issuer.token(header={"kid": "rotated-key"}))
    known = issuer.verifier.verify(issuer.token())

    assert unfamiliar == Rejected(RejectionReason.KEY_SET_UNAVAILABLE)
    assert known == issuer.verified()


def test_the_measured_key_set_of_two_unlabelled_signing_keys_among_thirteen_verifies_each_key(
    issuer: IssuerScenario,
) -> None:
    issuer.serve(
        key_set_document(
            public_jwk(rsa_key("current"), "current-key", alg=ABSENT),
            public_jwk(rsa_key("other"), "other-key", alg=ABSENT),
            *_passed_over_keys(11),
        )
    )
    other_signature = rs256(rsa_key("other"))

    assert issuer.verifier.verify(issuer.token()) == issuer.verified()
    assert (
        issuer.verifier.verify(issuer.token(header={"kid": "other-key"}, sign=other_signature))
        == issuer.verified()
    )
    assert issuer.verifier.verify(issuer.token(sign=other_signature)) == Rejected(
        RejectionReason.INVALID_SIGNATURE
    )


def test_one_signing_key_among_the_most_encryption_keys_is_accepted(
    issuer: IssuerScenario,
) -> None:
    current = rsa_key("current")
    issuer.serve(
        key_set_document(
            public_jwk(current, "current-key"),
            *(
                public_jwk(current, f"encryption-{index}", use="enc")
                for index in range(MAX_KEY_SET_KEYS)
            ),
        )
    )

    assert issuer.verifier.verify(issuer.token()) == issuer.verified()


def test_keys_published_for_other_purposes_beside_the_signing_key_are_passed_over(
    issuer: IssuerScenario,
) -> None:
    """The shape Keycloak serves: an RSA-OAEP encryption key, and an EC key
    once the realm adds one, beside the RS256 signing key."""
    current = rsa_key("current")
    issuer.serve(
        key_set_document(
            public_jwk(current, "current-key"),
            public_jwk(rsa_key("encryption"), "encryption-key", alg="RSA-OAEP", use="enc"),
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
        key_set_document(public_jwk(rsa_key("current"), "current-key", key_ops=["verify"]))
    )

    assert issuer.verifier.verify(issuer.token()) == issuer.verified()


def test_a_key_set_naming_keys_twice_is_read_by_its_last_value(issuer: IssuerScenario) -> None:
    valid_jwk = public_jwk(rsa_key("current"), "current-key")
    issuer.serve(b'{"keys": [], "keys": ' + json.dumps([valid_jwk]).encode() + b"}")

    assert issuer.verifier.verify(issuer.token()) == issuer.verified()


@pytest.mark.parametrize(("response", "failure"), _defective_key_sets())
def test_a_failed_refresh_keeps_the_last_valid_key_set_until_its_ttl(
    issuer: IssuerScenario,
    caplog: pytest.LogCaptureFixture,
    response: bytes | Exception,
    failure: str,
) -> None:
    assert issuer.verifier.verify(issuer.token()) == issuer.verified()
    issuer.serve(response)
    issuer.after_cooldown()

    with caplog.at_level(logging.WARNING, logger="webauth.jwt_verification"):
        refreshing = issuer.verifier.verify(issuer.token(header={"kid": "rotated-key"}))
    assert [message.endswith(failure) for message in _logged_refresh_failures(caplog)] == [True]
    cooling_down = issuer.verifier.verify(issuer.token(header={"kid": "rotated-key"}))
    still_cached = issuer.verifier.verify(issuer.token())
    issuer.monotonic_clock.now += KEY_SET_TTL_SECONDS
    expired = issuer.verifier.verify(issuer.token())

    assert refreshing == Rejected(RejectionReason.KEY_SET_UNAVAILABLE)
    assert cooling_down == Rejected(RejectionReason.KEY_SET_UNAVAILABLE)
    assert still_cached == issuer.verified()
    assert expired == Rejected(RejectionReason.KEY_SET_UNAVAILABLE)
    assert len(issuer.endpoint.fetched_urls) == 3


def test_an_unknown_kid_is_forged_again_once_a_refresh_succeeds_after_a_failed_one(
    issuer: IssuerScenario,
) -> None:
    assert issuer.verifier.verify(issuer.token()) == issuer.verified()
    issuer.serve(KeySetFetchError("GET answered 503"))
    issuer.after_cooldown()
    during_outage = issuer.verifier.verify(issuer.token(header={"kid": "rotated-key"}))
    issuer.serve(key_set_document(public_jwk(rsa_key("current"), "current-key")))
    issuer.after_cooldown()

    after_recovery = issuer.verifier.verify(issuer.token(header={"kid": "rotated-key"}))
    cooling_down = issuer.verifier.verify(issuer.token(header={"kid": "rotated-key"}))

    assert during_outage == Rejected(RejectionReason.KEY_SET_UNAVAILABLE)
    assert after_recovery == Rejected(RejectionReason.UNKNOWN_KEY_ID)
    assert cooling_down == Rejected(RejectionReason.UNKNOWN_KEY_ID)


def _kidless(issuer: IssuerScenario, sign: Callable | None = None) -> str:
    return issuer.token(header={"kid": ABSENT}, sign=sign)


def _serve_sole_key(issuer: IssuerScenario, name: str, **changes: Any) -> None:
    issuer.serve(key_set_document(public_jwk(rsa_key(name), f"{name}-key", **changes)))


def _serve_two_keys(issuer: IssuerScenario) -> None:
    issuer.serve(
        key_set_document(
            public_jwk(rsa_key("current"), "current-key"), public_jwk(rsa_key("other"), "other-key")
        )
    )


def _after_the_ttl(issuer: IssuerScenario) -> None:
    issuer.monotonic_clock.now += KEY_SET_TTL_SECONDS


@pytest.mark.parametrize(
    "published",
    [
        pytest.param(
            [public_jwk(rsa_key("current"), "current-key", kid=ABSENT), *_passed_over_keys(5)],
            id="the-measured-kidless-key-among-passed-over-keys",
        ),
        pytest.param([public_jwk(rsa_key("current"), "current-key")], id="the-only-key-has-a-kid"),
    ],
)
def test_a_token_without_kid_verifies_against_the_only_signing_key(
    issuer: IssuerScenario, published: list[dict[str, Any]]
) -> None:
    issuer.serve(key_set_document(*published))

    assert issuer.verifier.verify(_kidless(issuer)) == issuer.verified()


def test_a_token_without_kid_is_refused_without_a_fetch_when_the_key_set_holds_several_keys(
    issuer: IssuerScenario,
) -> None:
    _serve_two_keys(issuer)
    issuer.verifier.verify(issuer.token())
    issuer.after_cooldown()

    refused = issuer.verifier.verify(_kidless(issuer))

    assert refused == Rejected(RejectionReason.INVALID_KEY_ID)
    assert len(issuer.endpoint.fetched_urls) == 1


@pytest.mark.parametrize("kidless_first", [True, False], ids=["kidless-first", "named-first"])
def test_a_kidless_key_beside_a_named_one_is_admitted_but_verifies_nothing(
    issuer: IssuerScenario, kidless_first: bool
) -> None:
    named = public_jwk(rsa_key("current"), "current-key")
    kidless = public_jwk(rsa_key("other"), "other-key", kid=ABSENT)
    issuer.serve(key_set_document(*([kidless, named] if kidless_first else [named, kidless])))
    signed_by_kidless_key = rs256(rsa_key("other"))

    assert issuer.verifier.verify(issuer.token()) == issuer.verified()
    assert issuer.verifier.verify(_kidless(issuer)) == Rejected(RejectionReason.INVALID_KEY_ID)
    assert issuer.verifier.verify(
        _kidless(issuer, sign=signed_by_kidless_key)
    ) == Rejected(RejectionReason.INVALID_KEY_ID)
    assert issuer.verifier.verify(issuer.token(sign=signed_by_kidless_key)) == Rejected(
        RejectionReason.INVALID_SIGNATURE
    )


def test_several_kidless_keys_are_admitted_and_answer_every_token_as_ambiguous(
    issuer: IssuerScenario,
) -> None:
    issuer.serve(key_set_document(*_kidless_keys(3)))
    kidless = issuer.verifier.verify(_kidless(issuer))
    issuer.after_cooldown()

    named = issuer.verifier.verify(issuer.token(header={"kid": "x"}))

    assert kidless == Rejected(RejectionReason.INVALID_KEY_ID)
    assert named == Rejected(RejectionReason.UNKNOWN_KEY_ID)


def test_a_named_kid_unmatched_by_a_kidless_sole_key_is_unknown_once_the_refresh_succeeds(
    issuer: IssuerScenario,
) -> None:
    _serve_sole_key(issuer, "current", kid=ABSENT)
    issuer.verifier.verify(_kidless(issuer))
    issuer.after_cooldown()

    named = issuer.verifier.verify(issuer.token(header={"kid": "x"}))

    assert named == Rejected(RejectionReason.UNKNOWN_KEY_ID)


def test_a_named_kid_is_unavailable_when_the_refresh_fails_and_while_it_cools_down(
    issuer: IssuerScenario,
) -> None:
    _serve_sole_key(issuer, "current", kid=ABSENT)
    issuer.verifier.verify(_kidless(issuer))
    issuer.serve(KeySetFetchError("GET answered 503"))
    issuer.after_cooldown()
    named = issuer.token(header={"kid": "x"})

    assert issuer.verifier.verify(named) == Rejected(RejectionReason.KEY_SET_UNAVAILABLE)
    assert issuer.verifier.verify(named) == Rejected(RejectionReason.KEY_SET_UNAVAILABLE)


def test_a_signature_failure_without_kid_does_not_refresh_the_key_set(
    issuer: IssuerScenario,
) -> None:
    issuer.verifier.verify(issuer.token())
    issuer.after_cooldown()

    refused = issuer.verifier.verify(_kidless(issuer, sign=rs256(rsa_key("other"))))

    assert refused == Rejected(RejectionReason.INVALID_SIGNATURE)
    assert len(issuer.endpoint.fetched_urls) == 1


def test_a_token_without_kid_is_unavailable_when_no_key_set_can_be_fetched(
    issuer: IssuerScenario,
) -> None:
    issuer.serve(KeySetFetchError("GET answered 503"))

    assert issuer.verifier.verify(_kidless(issuer)) == Rejected(
        RejectionReason.KEY_SET_UNAVAILABLE
    )


def test_tokens_without_kid_inside_the_ttl_never_refresh_the_key_set(
    issuer: IssuerScenario,
) -> None:
    before_cooldown = issuer.verifier.verify(_kidless(issuer))
    issuer.after_cooldown()
    after_cooldown = issuer.verifier.verify(_kidless(issuer))

    assert before_cooldown == issuer.verified()
    assert after_cooldown == issuer.verified()
    assert len(issuer.endpoint.fetched_urls) == 1


def test_rotation_from_two_keys_to_one_is_seen_by_a_token_without_kid_after_the_ttl(
    issuer: IssuerScenario,
) -> None:
    _serve_two_keys(issuer)
    issuer.verifier.verify(issuer.token())
    _serve_sole_key(issuer, "current", kid=ABSENT)
    issuer.after_cooldown()
    before_ttl = issuer.verifier.verify(_kidless(issuer))
    _after_the_ttl(issuer)

    after_ttl = issuer.verifier.verify(_kidless(issuer))

    assert before_ttl == Rejected(RejectionReason.INVALID_KEY_ID)
    assert after_ttl == issuer.verified()


def test_rotation_from_one_sole_key_to_another_is_seen_by_a_token_without_kid_after_the_ttl(
    issuer: IssuerScenario,
) -> None:
    issuer.verifier.verify(_kidless(issuer))
    _serve_sole_key(issuer, "other", kid=ABSENT)
    issuer.after_cooldown()
    new_key_token = _kidless(issuer, sign=rs256(rsa_key("other")))
    before_ttl = issuer.verifier.verify(new_key_token)
    _after_the_ttl(issuer)

    after_ttl = issuer.verifier.verify(new_key_token)
    retired_key = issuer.verifier.verify(_kidless(issuer))

    assert before_ttl == Rejected(RejectionReason.INVALID_SIGNATURE)
    assert after_ttl == issuer.verified()
    assert retired_key == Rejected(RejectionReason.INVALID_SIGNATURE)


def test_rotation_from_one_key_to_two_is_seen_by_a_token_without_kid_after_the_ttl(
    issuer: IssuerScenario,
) -> None:
    issuer.verifier.verify(_kidless(issuer))
    _serve_two_keys(issuer)
    issuer.after_cooldown()
    before_ttl = issuer.verifier.verify(_kidless(issuer))
    _after_the_ttl(issuer)

    after_ttl = issuer.verifier.verify(_kidless(issuer))

    assert before_ttl == issuer.verified()
    assert after_ttl == Rejected(RejectionReason.INVALID_KEY_ID)


def test_a_token_without_kid_verifies_again_once_an_expiry_refresh_has_failed_and_recovered(
    issuer: IssuerScenario,
) -> None:
    issuer.verifier.verify(_kidless(issuer))
    issuer.serve(KeySetFetchError("GET answered 503"))
    _after_the_ttl(issuer)
    during_outage = issuer.verifier.verify(_kidless(issuer))
    _serve_sole_key(issuer, "current")
    issuer.after_cooldown()

    after_recovery = issuer.verifier.verify(_kidless(issuer))

    assert during_outage == Rejected(RejectionReason.KEY_SET_UNAVAILABLE)
    assert after_recovery == issuer.verified()


_SECRET_BEARING_JWKS_URL = f"https://login.example.org/certs/{_URL_SECRET}?signature={_URL_SECRET}"


@pytest.mark.parametrize(
    ("response", "logged_cause"),
    [
        pytest.param(
            KeySetFetchError(f"GET {_SECRET_BEARING_JWKS_URL} answered 503"),
            "fetch-failed",
            id="failed-fetch-quoting-its-url",
        ),
        pytest.param(b"[]", "not-json", id="invalid-key-set"),
        pytest.param(
            key_set_document(
                public_jwk(rsa_key("current"), _URL_SECRET),
                public_jwk(rsa_key("other"), _URL_SECRET),
            ),
            "duplicate-key-id",
            id="key-set-repeating-a-kid",
        ),
        pytest.param(
            key_set_document(weak_public_jwk(_URL_SECRET)),
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
    issuer.serve(key_set_document(public_jwk(rsa_key("other"), "other-key")))

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
        key_set_document(
            public_jwk(rsa_key("current"), "current-key"),
            public_jwk(rsa_key("other"), "rotated-key"),
        )
    )
    issuer.after_cooldown()

    rotated = issuer.token(header={"kid": "rotated-key"}, sign=rs256(rsa_key("other")))

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
        pytest.param({"audiences": "notes-app"}, "audiences", id="audience-as-one-string"),
        pytest.param({"jwks_url": "http://login.example.org/certs"}, "https", id="http-key-set"),
        pytest.param({"jwks_url": None}, "https", id="key-set-url-not-a-string"),
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
        pytest.param(
            {"jwks_url": "https://login.exa\nmple.org/certs"},
            "https",
            id="key-set-url-with-a-control-character",
        ),
        pytest.param({"leeway_seconds": -1}, "from 0 up", id="negative-leeway"),
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


@pytest.fixture
def https_key_set_server(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> Iterator[LoopbackHttpsServer]:
    with loopback_https_server(tmp_path, monkeypatch) as server:
        yield server


def test_a_verifier_on_the_https_fetch_verifies_a_token_of_the_served_key_set(
    https_key_set_server: LoopbackHttpsServer, issuer: IssuerScenario
) -> None:
    verifier = issuer.verifier_with(
        jwks_url=f"{https_key_set_server.base_url}/certs", fetch_key_set=fetch_key_set_over_https
    )

    assert verifier.verify(issuer.token()) == issuer.verified()


def test_a_request_during_a_stalled_key_set_fetch_is_refused_without_waiting(
    https_key_set_server: LoopbackHttpsServer, issuer: IssuerScenario
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


def test_a_refused_key_set_url_is_not_repeated_in_the_configuration_error(
    issuer: IssuerScenario,
) -> None:
    with pytest.raises(ValueError) as refusal:
        issuer.verifier_with(jwks_url=f"https://operator:{_URL_SECRET}@login.example.org/certs")

    assert _URL_SECRET not in "".join(traceback.format_exception(refusal.value))
