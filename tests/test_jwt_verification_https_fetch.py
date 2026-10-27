"""The verifier on `fetch_key_set_over_https`, the real HTTPS boundary, served from loopback
under a self-signed certificate.
"""

from __future__ import annotations

from collections.abc import Iterator
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path

import pytest

from tests.support.jwt_issuer import (
    IssuerScenario,
)
from tests.support.oidc_arrangement import (
    LoopbackHttpsServer,
    loopback_https_server,
)
from webauth.https_client import fetch_key_set_over_https
from webauth.jwt_verification import (
    Rejected,
    RejectionReason,
)


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
