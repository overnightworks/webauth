"""The request line of a host that installs logline's middleware outside webauth's stack."""

from __future__ import annotations

import json
from contextlib import contextmanager
from typing import TYPE_CHECKING, Any

from fastapi.testclient import TestClient
from logline import REQUEST_EVENT, RequestLineMiddleware
from logline.testing import configured

from tests.support.webauth_arrangement import HTTPS_TEST_SERVER

if TYPE_CHECKING:
    from collections.abc import Iterator

    from fastapi import FastAPI
    from pytest import CaptureFixture

TRUSTED_PEER = "172.16.0.9"
FORWARDED_CLIENT = "203.0.113.7"


def logging_request_lines(app: FastAPI) -> None:
    """Install logline's middleware as its README asks a host: after every other, so outermost."""
    app.add_middleware(RequestLineMiddleware)


@contextmanager
def request_lines_written(capsys: CaptureFixture[str]) -> Iterator[list[dict[str, Any]]]:
    """The request lines the block's requests write, in order; filled when the block ends.

    `configure` binds the stdout of the moment, so it runs inside the test, after `capsys`; what
    was written before the block is dropped.
    """
    lines: list[dict[str, Any]] = []
    capsys.readouterr()
    with configured("webauth-tests"):
        yield lines
    records = (json.loads(line) for line in capsys.readouterr().out.splitlines())
    lines.extend(record for record in records if record["event"] == REQUEST_EVENT)


def a_client_behind_the_proxy(app: FastAPI, *, peer: str = TRUSTED_PEER) -> TestClient:
    """A client of `app` connecting from `peer`, by default a proxy the configuration trusts."""
    return TestClient(app, base_url=HTTPS_TEST_SERVER, client=(peer, 55000), follow_redirects=False)
