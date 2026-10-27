"""Tokens without `kid`, and key rotation as they see it."""

from __future__ import annotations

from typing import Any

import pytest

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
)
from webauth.https_client import KeySetFetchError
from webauth.jwt_verification import (
    Rejected,
    RejectionReason,
)


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
            [public_jwk(rsa_key("current"), "current-key", kid=ABSENT), *passed_over_keys(5)],
            id="the-measured-kidless-key-among-passed-over-keys",
        ),
        pytest.param([public_jwk(rsa_key("current"), "current-key")], id="the-only-key-has-a-kid"),
    ],
)
def test_a_token_without_kid_verifies_against_the_only_signing_key(
    issuer: IssuerScenario, published: list[dict[str, Any]]
) -> None:
    issuer.serve(key_set_document(*published))

    assert issuer.verifier.verify(token_without_kid(issuer)) == issuer.verified()


def test_a_token_without_kid_is_refused_without_a_fetch_when_the_key_set_holds_several_keys(
    issuer: IssuerScenario,
) -> None:
    _serve_two_keys(issuer)
    issuer.verifier.verify(issuer.token())
    issuer.after_cooldown()

    refused = issuer.verifier.verify(token_without_kid(issuer))

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
    assert issuer.verifier.verify(token_without_kid(issuer)) == Rejected(
        RejectionReason.INVALID_KEY_ID
    )
    assert issuer.verifier.verify(
        token_without_kid(issuer, sign=signed_by_kidless_key)
    ) == Rejected(RejectionReason.INVALID_KEY_ID)
    assert issuer.verifier.verify(issuer.token(sign=signed_by_kidless_key)) == Rejected(
        RejectionReason.INVALID_SIGNATURE
    )


def test_several_kidless_keys_are_admitted_and_answer_every_token_as_ambiguous(
    issuer: IssuerScenario,
) -> None:
    issuer.serve(key_set_document(*kidless_keys(3)))
    kidless = issuer.verifier.verify(token_without_kid(issuer))
    issuer.after_cooldown()

    named = issuer.verifier.verify(issuer.token(header={"kid": "x"}))

    assert kidless == Rejected(RejectionReason.INVALID_KEY_ID)
    assert named == Rejected(RejectionReason.UNKNOWN_KEY_ID)


def test_a_named_kid_unmatched_by_a_kidless_sole_key_is_unknown_once_the_refresh_succeeds(
    issuer: IssuerScenario,
) -> None:
    _serve_sole_key(issuer, "current", kid=ABSENT)
    issuer.verifier.verify(token_without_kid(issuer))
    issuer.after_cooldown()

    named = issuer.verifier.verify(issuer.token(header={"kid": "x"}))

    assert named == Rejected(RejectionReason.UNKNOWN_KEY_ID)


def test_a_named_kid_is_unavailable_when_the_refresh_fails_and_while_it_cools_down(
    issuer: IssuerScenario,
) -> None:
    _serve_sole_key(issuer, "current", kid=ABSENT)
    issuer.verifier.verify(token_without_kid(issuer))
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

    refused = issuer.verifier.verify(token_without_kid(issuer, sign=rs256(rsa_key("other"))))

    assert refused == Rejected(RejectionReason.INVALID_SIGNATURE)
    assert len(issuer.endpoint.fetched_urls) == 1


def test_a_token_without_kid_is_unavailable_when_no_key_set_can_be_fetched(
    issuer: IssuerScenario,
) -> None:
    issuer.serve(KeySetFetchError("GET answered 503"))

    assert issuer.verifier.verify(token_without_kid(issuer)) == Rejected(
        RejectionReason.KEY_SET_UNAVAILABLE
    )


def test_tokens_without_kid_inside_the_ttl_never_refresh_the_key_set(
    issuer: IssuerScenario,
) -> None:
    before_cooldown = issuer.verifier.verify(token_without_kid(issuer))
    issuer.after_cooldown()
    after_cooldown = issuer.verifier.verify(token_without_kid(issuer))

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
    before_ttl = issuer.verifier.verify(token_without_kid(issuer))
    _after_the_ttl(issuer)

    after_ttl = issuer.verifier.verify(token_without_kid(issuer))

    assert before_ttl == Rejected(RejectionReason.INVALID_KEY_ID)
    assert after_ttl == issuer.verified()


def test_rotation_from_one_sole_key_to_another_is_seen_by_a_token_without_kid_after_the_ttl(
    issuer: IssuerScenario,
) -> None:
    issuer.verifier.verify(token_without_kid(issuer))
    _serve_sole_key(issuer, "other", kid=ABSENT)
    issuer.after_cooldown()
    new_key_token = token_without_kid(issuer, sign=rs256(rsa_key("other")))
    before_ttl = issuer.verifier.verify(new_key_token)
    _after_the_ttl(issuer)

    after_ttl = issuer.verifier.verify(new_key_token)
    retired_key = issuer.verifier.verify(token_without_kid(issuer))

    assert before_ttl == Rejected(RejectionReason.INVALID_SIGNATURE)
    assert after_ttl == issuer.verified()
    assert retired_key == Rejected(RejectionReason.INVALID_SIGNATURE)


def test_rotation_from_one_key_to_two_is_seen_by_a_token_without_kid_after_the_ttl(
    issuer: IssuerScenario,
) -> None:
    issuer.verifier.verify(token_without_kid(issuer))
    _serve_two_keys(issuer)
    issuer.after_cooldown()
    before_ttl = issuer.verifier.verify(token_without_kid(issuer))
    _after_the_ttl(issuer)

    after_ttl = issuer.verifier.verify(token_without_kid(issuer))

    assert before_ttl == issuer.verified()
    assert after_ttl == Rejected(RejectionReason.INVALID_KEY_ID)


def test_a_token_without_kid_verifies_again_once_an_expiry_refresh_has_failed_and_recovered(
    issuer: IssuerScenario,
) -> None:
    issuer.verifier.verify(token_without_kid(issuer))
    issuer.serve(KeySetFetchError("GET answered 503"))
    _after_the_ttl(issuer)
    during_outage = issuer.verifier.verify(token_without_kid(issuer))
    _serve_sole_key(issuer, "current")
    issuer.after_cooldown()

    after_recovery = issuer.verifier.verify(token_without_kid(issuer))

    assert during_outage == Rejected(RejectionReason.KEY_SET_UNAVAILABLE)
    assert after_recovery == issuer.verified()
