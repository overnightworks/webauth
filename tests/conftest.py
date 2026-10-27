from __future__ import annotations

from typing import TYPE_CHECKING

import pytest

if TYPE_CHECKING:
    from tests.support.jwt_issuer import IssuerScenario

pytest.register_assert_rewrite("tests.support")


@pytest.fixture
def anyio_backend() -> str:
    return "asyncio"


@pytest.fixture
def issuer() -> IssuerScenario:
    # Inline: a top-level import of tests.support would load it before register_assert_rewrite
    # and lose assertion rewriting.
    from tests.support.jwt_issuer import IssuerScenario
    from tests.support.oidc_arrangement import (
        ACCESS_TOKEN_NOW,
        FakeClock,
        FakeKeySetEndpoint,
        key_set_document,
        public_jwk,
        rsa_key,
    )

    endpoint = FakeKeySetEndpoint(key_set_document(public_jwk(rsa_key("current"), "current-key")))
    return IssuerScenario(endpoint, FakeClock(float(ACCESS_TOKEN_NOW)), FakeClock(5_000.0))
