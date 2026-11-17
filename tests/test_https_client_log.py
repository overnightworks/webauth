"""The one `.ended` line each HTTPS exchange writes, read from a loopback TLS server.

`post_token_request_over_https` and `fetch_key_set_over_https` run through
`webauth.https_client`; their scenarios read the line's level, outcome, status
and reason, and that the URL's query secret never reaches the log.
"""

from __future__ import annotations

import logging
from collections.abc import Callable

import pytest

from tests.support.log_records import fields_of
from tests.support.oidc_arrangement import (
    LoopbackHttpsServer,
)
from tests.support.token_request_canaries import (
    CANARY_URL_QUERY,
    a_canary_token_request,
    assert_no_canary_in,
    post_canary_token_form,
)
from webauth.https_client import KeySetFetchError, _HttpsExchangeError, fetch_key_set_over_https
from webauth.oidc_transport import post_token_request_over_https

pytestmark = pytest.mark.usefixtures("every_log_record")


def _ended_lines(caplog: pytest.LogCaptureFixture) -> list[logging.LogRecord]:
    return [record for record in caplog.records if record.name == "webauth.https_client"]


def _fields_besides_the_duration(line: logging.LogRecord) -> dict[str, object]:
    fields = fields_of(line)
    assert isinstance(fields.pop("duration_ms"), int | float)
    return fields


def test_a_token_request_writes_one_ended_line_with_the_status(
    token_server: LoopbackHttpsServer, caplog: pytest.LogCaptureFixture
) -> None:
    """LOG-05: the token request's one line carries its duration, outcome and status."""
    post_token_request_over_https(
        a_canary_token_request(f"{token_server.base_url}/token?{CANARY_URL_QUERY}")
    )

    [line] = _ended_lines(caplog)
    assert (line.levelno, line.getMessage()) == (logging.INFO, "token_request.ended")
    assert _fields_besides_the_duration(line) == {"outcome": "ok", "status": 200}
    assert_no_canary_in(caplog.text)


def test_a_key_set_fetch_writes_one_ended_line_with_the_status(
    token_server: LoopbackHttpsServer, caplog: pytest.LogCaptureFixture
) -> None:
    """LOG-05: the key-set fetch's one line carries its duration, outcome and status."""
    fetch_key_set_over_https(f"{token_server.base_url}/certs")

    [line] = _ended_lines(caplog)
    assert (line.levelno, line.getMessage()) == (logging.INFO, "key_set_fetch.ended")
    assert _fields_besides_the_duration(line) == {"outcome": "ok", "status": 200}


def test_a_key_set_answered_with_another_status_ends_refused_with_that_status(
    token_server: LoopbackHttpsServer, caplog: pytest.LogCaptureFixture
) -> None:
    with pytest.raises(KeySetFetchError):
        fetch_key_set_over_https(f"{token_server.base_url}/moved")

    [line] = _ended_lines(caplog)
    assert (line.levelno, line.getMessage()) == (logging.INFO, "key_set_fetch.ended")
    assert _fields_besides_the_duration(line) == {
        "outcome": "refused",
        "reason": "status-not-accepted",
        "status": 302,
    }


@pytest.mark.parametrize(
    ("event", "exchange", "level"),
    [
        pytest.param(
            "key_set_fetch.ended", fetch_key_set_over_https, logging.WARNING, id="key-set"
        ),
        pytest.param(
            "token_request.ended", post_canary_token_form, logging.ERROR, id="token-request"
        ),
    ],
)
def test_an_unreachable_origin_ends_failed_with_a_reason_and_the_error_class_only(
    closed_port: int,
    caplog: pytest.LogCaptureFixture,
    event: str,
    exchange: Callable[..., object],
    level: int,
) -> None:
    with pytest.raises((KeySetFetchError, _HttpsExchangeError)):
        exchange(f"https://127.0.0.1:{closed_port}/path?{CANARY_URL_QUERY}")

    [line] = _ended_lines(caplog)
    assert (line.levelno, line.getMessage()) == (level, event)
    assert _fields_besides_the_duration(line) == {
        "outcome": "failed",
        "reason": "unreachable",
        "error_type": "NewConnectionError",
    }
    assert line.exc_info is None
    assert_no_canary_in(caplog.text)


@pytest.mark.parametrize("path", ["/oversized", "/token-past-limit"], ids=["far", "one-byte"])
def test_a_token_answer_past_the_size_limit_ends_failed_as_too_large(
    token_server: LoopbackHttpsServer,
    caplog: pytest.LogCaptureFixture,
    path: str,
) -> None:
    """LOG-05: an answer the caller then refuses for its size is no `ok` line."""
    with pytest.raises(_HttpsExchangeError):
        post_canary_token_form(f"{token_server.base_url}{path}")

    [line] = _ended_lines(caplog)
    assert (line.levelno, line.getMessage()) == (logging.ERROR, "token_request.ended")
    assert _fields_besides_the_duration(line) == {
        "outcome": "failed",
        "reason": "too-large",
        "status": 200,
    }
