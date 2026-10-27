"""Token checks of `JwtVerifier.verify`: audience, type, hostile tokens, header bounds, leeway.

Every scenario hands the verifier a raw token string, the way a host's login or
logout route will, against a fake key-set endpoint and fake clocks.
"""

from __future__ import annotations

import hashlib
import hmac
import string
import threading
from collections.abc import Callable
from typing import Any

import pytest
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa

from tests.support.jwt_issuer import (
    AUDIENCE,
    ISSUER,
    JWKS_URL,
    LEEWAY_SECONDS,
    IssuerScenario,
)
from tests.support.oidc_arrangement import (
    ABSENT,
    jws,
    rs256,
    rsa_key,
    segment,
)
from webauth.jwt_verification import (
    MAX_TOKEN_CHARACTERS,
    Rejected,
    RejectionReason,
)

MAX_HEADER_SEGMENT_CHARACTERS = 512
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


@pytest.mark.parametrize(
    "claims",
    [
        pytest.param({}, id="audience-string"),
        pytest.param({"aud": [AUDIENCE]}, id="audience-list"),
        pytest.param({"aud": ["another-app", AUDIENCE]}, id="audience-among-others"),
        pytest.param({"nbf": ABSENT}, id="without-nbf"),
        pytest.param({"sub": ABSENT}, id="without-sub"),
    ],
)
def test_a_token_signed_by_a_key_of_the_fake_key_set_verifies_as_its_claims(
    issuer: IssuerScenario, claims: dict[str, Any]
) -> None:
    assert issuer.verifier.verify(issuer.token(claims)) == issuer.verified(claims)
    assert issuer.endpoint.fetched_urls == [JWKS_URL]


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
            lambda issuer: issuer.token({"iss": ISSUER + "/"}),
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
            RejectionReason.MALFORMED_TOKEN,
            id="kid-null",
        ),
        pytest.param(
            lambda issuer: issuer.token(header={"kid": 7}),
            RejectionReason.MALFORMED_TOKEN,
            id="kid-not-a-string",
        ),
        pytest.param(
            lambda issuer: issuer.token(header={"alg": "RS512", "kid": 7}),
            RejectionReason.MALFORMED_TOKEN,
            id="kid-not-a-string-beside-a-wrong-alg",
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
            RejectionReason.UNSUPPORTED_ALGORITHM,
            id="duplicate-alg",
        ),
        pytest.param(
            lambda issuer: jws(
                '{"alg": "RS256", "kid": "current-key", "kid": "retired-key"}',
                issuer.claims(),
                rs256(rsa_key("current")),
            ),
            RejectionReason.UNKNOWN_KEY_ID,
            id="duplicate-kid",
        ),
        pytest.param(
            lambda issuer: issuer.token(header={"crit": ["exp"]}),
            RejectionReason.MALFORMED_TOKEN,
            id="header-crit",
        ),
        pytest.param(
            lambda issuer: issuer.token(header={"b64": False}),
            RejectionReason.MALFORMED_TOKEN,
            id="header-b64-false",
        ),
        pytest.param(
            lambda issuer: issuer.token({"padding": "x" * MAX_TOKEN_CHARACTERS}),
            RejectionReason.TOKEN_TOO_LONG,
            id="oversized-token",
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
                ("lone-surrogate", "e30.e30.s\ud800g"),
            )
        ),
        pytest.param(
            lambda issuer: jws(
                {"alg": "RS256", "kid": "current-key"}, "[]", rs256(rsa_key("current"))
            ),
            RejectionReason.MALFORMED_TOKEN,
            id="claims-not-an-object",
        ),
        pytest.param(
            lambda issuer: _with_unused_signature_bits_set(issuer.token()),
            RejectionReason.MALFORMED_TOKEN,
            id="non-canonical-base64url",
        ),
    ],
)
def test_a_hostile_token_is_refused_with_its_reason(
    issuer: IssuerScenario,
    build_token: Callable[[IssuerScenario], str],
    reason: RejectionReason,
) -> None:
    assert issuer.verifier.verify(build_token(issuer)) == Rejected(reason)


def _token_with_header_of_bytes(issuer: IssuerScenario, header_bytes: int) -> str:
    header = '{"alg": "RS256", "kid": "current-key"}'
    return jws(
        header + " " * (header_bytes - len(header)), issuer.claims(), rs256(rsa_key("current"))
    )


@pytest.mark.parametrize(
    ("header_bytes", "outcome"),
    [
        pytest.param(MAX_HEADER_SEGMENT_CHARACTERS * 3 // 4, None, id="at-the-bound"),
        pytest.param(
            MAX_HEADER_SEGMENT_CHARACTERS * 3 // 4 + 1,
            RejectionReason.MALFORMED_TOKEN,
            id="one-byte-over-the-bound",
        ),
    ],
)
def test_a_header_segment_over_the_bound_is_refused_before_it_is_parsed(
    issuer: IssuerScenario, header_bytes: int, outcome: RejectionReason | None
) -> None:
    token = _token_with_header_of_bytes(issuer, header_bytes)

    expected = issuer.verified() if outcome is None else Rejected(outcome)
    assert issuer.verifier.verify(token) == expected


def test_the_deepest_header_the_bound_allows_does_not_crash_a_small_stack_thread(
    issuer: IssuerScenario,
) -> None:
    """CPython 3.12 and 3.13 segfault in `json.loads` of deeply nested input on
    a 128 KiB stack, the size of musl's thread default; a crash ends the test
    run, which is the intended failure."""
    header = "[" * (MAX_HEADER_SEGMENT_CHARACTERS * 3 // 4)
    token = jws(header, issuer.claims(), rs256(rsa_key("current")))
    outcomes: list[object] = []
    worker = threading.Thread(target=lambda: outcomes.append(issuer.verifier.verify(token)))
    previous_stack_size = threading.stack_size(128 * 1024)
    try:
        worker.start()
    finally:
        threading.stack_size(previous_stack_size)
    worker.join()

    assert outcomes == [Rejected(RejectionReason.MALFORMED_TOKEN)]


@pytest.mark.parametrize("member", ["jwk", "jku", "x5u", "x5c"])
def test_a_header_member_naming_a_key_is_ignored_and_only_the_configured_key_set_is_read(
    issuer: IssuerScenario, member: str
) -> None:
    token = issuer.token(header={member: "attacker-chosen"})

    assert issuer.verifier.verify(token) == issuer.verified()
    assert issuer.endpoint.fetched_urls == [JWKS_URL]


@pytest.mark.parametrize(
    ("claim", "offset", "outcome"),
    [
        pytest.param("exp", -LEEWAY_SECONDS + 1, None, id="exp-inside-the-leeway"),
        pytest.param("exp", -LEEWAY_SECONDS, RejectionReason.EXPIRED, id="exp-at-the-leeway"),
        pytest.param("iat", LEEWAY_SECONDS, None, id="iat-at-the-leeway"),
        pytest.param(
            "iat", LEEWAY_SECONDS + 1, RejectionReason.ISSUED_IN_FUTURE, id="iat-past-the-leeway"
        ),
        pytest.param("nbf", LEEWAY_SECONDS, None, id="nbf-at-the-leeway"),
        pytest.param(
            "nbf", LEEWAY_SECONDS + 1, RejectionReason.NOT_YET_VALID, id="nbf-past-the-leeway"
        ),
    ],
)
def test_time_claims_hold_exactly_the_configured_leeway_on_the_wall_clock(
    issuer: IssuerScenario, claim: str, offset: int, outcome: RejectionReason | None
) -> None:
    changes = {claim: int(issuer.wall_clock.now) + offset}

    expected = issuer.verified(changes) if outcome is None else Rejected(outcome)
    assert issuer.verifier.verify(issuer.token(changes)) == expected
