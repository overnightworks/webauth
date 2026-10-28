"""How `JwtVerifier` reads a published key set: defective sets, the key bound, key purposes,
`key_ops`, duplicate members and the last good snapshot.
"""

from __future__ import annotations

import gzip
import json
import logging
import string
from typing import Any

import pytest
from cryptography.hazmat.primitives.asymmetric import ec, rsa
from jwt.algorithms import ECAlgorithm, RSAAlgorithm

from tests.support.jwt_issuer import (
    KEY_SET_TTL_SECONDS,
    IssuerScenario,
    kidless_keys,
    passed_over_keys,
    token_without_kid,
)
from tests.support.oidc_arrangement import (
    ABSENT,
    key_set_document,
    public_jwk,
    rs256,
    rsa_key,
    weak_public_jwk,
)
from webauth.https_client import MAX_KEY_SET_BYTES, KeySetFetchError
from webauth.jwt_verification import (
    MAX_KEY_SET_KEYS,
    Rejected,
    RejectionReason,
)


def _signing_keys(count: int) -> list[dict[str, Any]]:
    current = rsa_key("current")
    return [public_jwk(current, "current-key")] + [
        public_jwk(current, f"spare-{index}") for index in range(count - 1)
    ]


def _mixed_keys(count: int) -> list[dict[str, Any]]:
    keys = kidless_keys(count)
    keys[::2] = [public_jwk(rsa_key("current"), "current-key")] + [
        public_jwk(rsa_key("current"), f"named-{index}") for index in range(len(keys[::2]) - 1)
    ]
    return keys


def _undeliverable_key_sets() -> list[Any]:
    return [
        pytest.param(KeySetFetchError("timed out"), "fetch-failed", id="fetch-failure"),
        pytest.param(b" " * MAX_KEY_SET_BYTES + b"{}", "too-large", id="oversized-response"),
    ]


def _key_sets_over_the_key_bound(
    current: rsa.RSAPrivateKey, valid_jwk: dict[str, Any]
) -> list[Any]:
    return [
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
    ]


def _unsafe_key_sets(current: rsa.RSAPrivateKey, valid_jwk: dict[str, Any]) -> list[Any]:
    return [
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
    ]


def _key_sets_without_a_signing_key(current: rsa.RSAPrivateKey) -> list[Any]:
    return [
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
    ]


def _key_sets_with_a_malformed_kid(
    current: rsa.RSAPrivateKey, valid_jwk: dict[str, Any]
) -> list[Any]:
    return [
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
    ]


def _key_sets_of_too_many_kidless_keys() -> list[Any]:
    return [
        pytest.param(
            key_set_document(*kidless_keys(MAX_KEY_SET_KEYS + 1)),
            "key-count-out-of-range",
            id="too-many-kidless-keys",
        ),
        pytest.param(
            key_set_document(*_mixed_keys(MAX_KEY_SET_KEYS + 1)),
            "key-count-out-of-range",
            id="too-many-named-and-kidless-keys",
        ),
    ]


def _key_sets_with_a_malformed_key(current: rsa.RSAPrivateKey) -> list[Any]:
    modulus = public_jwk(current, "current-key")["n"]
    # A 2048-bit modulus leaves four zero bits after its last sextet's data, so flipping the
    # low bit of that sextet stays inside the alphabet and sets a trailing bit.
    alphabet = string.ascii_uppercase + string.ascii_lowercase + string.digits + "-_"
    flipped_last_sextet = alphabet[alphabet.index(modulus[-1]) ^ 1]
    return [
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
        pytest.param(
            key_set_document(public_jwk(current, "current-key", n="+" + modulus[1:])),
            "invalid-rsa-key",
            id="key-modulus-not-base64url",
        ),
        pytest.param(
            key_set_document(public_jwk(current, "current-key", n=modulus + "=")),
            "invalid-rsa-key",
            id="key-modulus-padded",
        ),
        pytest.param(
            key_set_document(
                public_jwk(current, "current-key", n=modulus[:-1] + flipped_last_sextet)
            ),
            "invalid-rsa-key",
            id="key-modulus-with-nonzero-trailing-bits",
        ),
        pytest.param(key_set_document("not a key"), "key-not-an-object", id="key-not-an-object"),
    ]


def _malformed_key_set_documents(valid_jwk: dict[str, Any]) -> list[Any]:
    return [
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
        pytest.param(gzip.compress(key_set_document(valid_jwk)), "not-json", id="compressed"),
    ]


def _defective_key_sets() -> list[Any]:
    current = rsa_key("current")
    valid_jwk = public_jwk(current, "current-key")
    return [
        *_undeliverable_key_sets(),
        *_key_sets_over_the_key_bound(current, valid_jwk),
        *_unsafe_key_sets(current, valid_jwk),
        *_key_sets_without_a_signing_key(current),
        *_key_sets_with_a_malformed_kid(current, valid_jwk),
        *_key_sets_of_too_many_kidless_keys(),
        *_key_sets_with_a_malformed_key(current),
        *_malformed_key_set_documents(valid_jwk),
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
    issuer.serve(key_set_document(*published, *passed_over_keys(20)))

    verified = [
        issuer.verifier.verify(issuer.token(header={"kid": jwk["kid"]}))
        for jwk in (published[0], published[-1])
    ]

    assert verified == [issuer.verified()] * 2


@pytest.mark.parametrize(
    "published",
    [
        pytest.param(kidless_keys(MAX_KEY_SET_KEYS), id="all-kidless"),
        pytest.param(_mixed_keys(MAX_KEY_SET_KEYS), id="named-and-kidless"),
    ],
)
def test_the_key_bound_admits_that_many_eligible_keys_named_or_not(
    issuer: IssuerScenario, published: list[dict[str, Any]]
) -> None:
    issuer.serve(key_set_document(*published))
    kidless = issuer.verifier.verify(token_without_kid(issuer))
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
        pytest.param(key_set_document(*kidless_keys(MAX_KEY_SET_KEYS + 1)), id="too-many-keys"),
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
            *passed_over_keys(11),
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
