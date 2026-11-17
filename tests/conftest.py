from __future__ import annotations

import logging
from typing import TYPE_CHECKING

import pytest

if TYPE_CHECKING:
    from collections.abc import Iterator
    from pathlib import Path

    from tests.support.jwt_issuer import IssuerScenario
    from tests.support.oidc_arrangement import LoopbackHttpsServer

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
        served_key_set,
    )

    endpoint = FakeKeySetEndpoint(served_key_set())
    return IssuerScenario(endpoint, FakeClock(float(ACCESS_TOKEN_NOW)), FakeClock(5_000.0))


@pytest.fixture
def token_server(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Iterator[LoopbackHttpsServer]:
    from tests.support.oidc_arrangement import loopback_https_server

    with loopback_https_server(tmp_path, monkeypatch) as server:
        yield server


@pytest.fixture
def closed_port() -> Iterator[int]:
    from tests.support.oidc_arrangement import closed_loopback_port

    with closed_loopback_port() as port:
        yield port


@pytest.fixture
def every_log_record(caplog: pytest.LogCaptureFixture) -> None:
    caplog.set_level(logging.DEBUG)
