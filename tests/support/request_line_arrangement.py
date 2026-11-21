"""Reading the request line the composition call's front writes."""

from __future__ import annotations

import json
from contextlib import contextmanager
from typing import TYPE_CHECKING, Any

from fastapi.testclient import TestClient
from logline import REQUEST_EVENT
from logline.testing import configured

from tests.support.webauth_arrangement import HTTPS_TEST_SERVER

if TYPE_CHECKING:
    from collections.abc import Iterator

    import pytest
    from fastapi import FastAPI

WEBSOCKET_EVENT = "websocket.ended"
TRUSTED_PEER = "172.16.0.9"
FORWARDED_CLIENT = "203.0.113.7"


@contextmanager
def request_lines_written(
    capsys: pytest.CaptureFixture[str], *, event: str = REQUEST_EVENT
) -> Iterator[list[dict[str, Any]]]:
    """The lines of `event` the block's requests write, in order; filled when the block ends.

    `configure` binds the stdout of the moment, so it runs inside the test, after `capsys`; what
    was written before the block is dropped.
    """
    lines: list[dict[str, Any]] = []
    capsys.readouterr()
    with configured("webauth-tests"):
        yield lines
    records = (json.loads(line) for line in capsys.readouterr().out.splitlines())
    lines.extend(record for record in records if record["event"] == event)


def a_client_behind_the_proxy(app: FastAPI, *, peer: str = TRUSTED_PEER) -> TestClient:
    """A client of `app` connecting from `peer`, by default a proxy the configuration trusts."""
    return TestClient(app, base_url=HTTPS_TEST_SERVER, client=(peer, 55000), follow_redirects=False)
