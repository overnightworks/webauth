"""The key-set cache, the refresh cooldown, parallel unknown kids and refused configuration."""

from __future__ import annotations

import logging
import threading
import traceback
from concurrent.futures import ThreadPoolExecutor
from typing import Any

import pytest

from tests.support.jwt_issuer import (
    ISSUER,
    KEY_SET_TTL_SECONDS,
    IssuerScenario,
)
from tests.support.oidc_arrangement import (
    key_set_document,
    public_jwk,
    rs256,
    rsa_key,
    weak_public_jwk,
)
from webauth.https_client import KeySetFetchError
from webauth.jwt_verification import (
    Rejected,
    RejectionReason,
)

# Canary whose recognisable text is the point
_URL_SECRET = "s3cr3t-in-the-url"  # noqa: S105
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
    assert ISSUER not in warning.getMessage()
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
        pytest.param({"issuer": [ISSUER, "https://other.example.org"]}, "issuer", id="issuer-list"),
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


def test_a_refused_key_set_url_is_not_repeated_in_the_configuration_error(
    issuer: IssuerScenario,
) -> None:
    with pytest.raises(ValueError) as refusal:
        issuer.verifier_with(jwks_url=f"https://operator:{_URL_SECRET}@login.example.org/certs")

    assert _URL_SECRET not in "".join(traceback.format_exception(refusal.value))
