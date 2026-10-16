"""A body over the limit never earns a second response start."""

from __future__ import annotations

from typing import TYPE_CHECKING

import anyio
import anyio.lowlevel
import pytest
from fastapi import FastAPI, Request
from starlette.datastructures import Headers
from starlette.responses import StreamingResponse
from webauth_arrangement import (
    StartSend,
    a_web_auth_config,
    an_http_scope,
    assert_carries_policy_headers,
    body_of,
    completed,
    drive,
    starts,
)

from webauth.config import install_web_auth_config
from webauth.middleware import install_web_auth_middleware
from webauth.policies import BodySizePolicy, SecurityHeadersPolicy, default_content_security_policy

if TYPE_CHECKING:
    from collections.abc import AsyncIterator

    from starlette.types import Message

pytestmark = pytest.mark.anyio

LIMIT = 100
HEADERS_POLICY = SecurityHeadersPolicy(default_content_security_policy([]))
TWO_CHUNKS_UNDER_THE_LIMIT_EACH = (b"x" * 60, b"x" * 60)
ONE_CHUNK_OVER_THE_LIMIT = (b"x" * 120,)
TOO_LARGE_BODY = b'{"detail":"Request body too large"}'
SPEC_WITH_CONCURRENT_READER = "2.3"
SPEC_WITHOUT_CONCURRENT_READER = "2.4"


def a_body_limited_app() -> FastAPI:
    app = FastAPI()
    install_web_auth_config(app, a_web_auth_config())

    @app.post("/reads-after-first-chunk")
    async def reads_after_first_chunk(request: Request) -> StreamingResponse:
        async def stream() -> AsyncIterator[bytes]:
            yield b"first"
            yield str(len(await request.body())).encode()

        return StreamingResponse(stream())

    @app.post("/never-reads")
    async def never_reads() -> StreamingResponse:
        async def stream() -> AsyncIterator[bytes]:
            yield b"first"
            await anyio.lowlevel.checkpoint()
            yield b"second"

        return StreamingResponse(stream())

    @app.post("/never-reads-without-await")
    async def never_reads_without_await() -> StreamingResponse:
        async def stream() -> AsyncIterator[bytes]:
            yield b"first"
            yield b"second"

        return StreamingResponse(stream())

    @app.post("/reads")
    async def reads(request: Request) -> dict[str, int]:
        return {"length": len(await request.body())}

    install_web_auth_middleware(
        app, security_headers=HEADERS_POLICY, body_size=BodySizePolicy(default_max_bytes=LIMIT)
    )
    return app


async def drive_post(
    path: str,
    spec_version: str,
    body_chunks: tuple[bytes, ...],
    start_send: StartSend = StartSend.PLAIN,
) -> tuple[list[Message], BaseException | None]:
    app = a_body_limited_app()
    scope = an_http_scope(app, path, method="POST", spec_version=spec_version)
    return await drive(app, scope, body_chunks=body_chunks, start_send=start_send)


@pytest.mark.parametrize(
    ("path", "spec_version"),
    [
        pytest.param("/reads-after-first-chunk", SPEC_WITH_CONCURRENT_READER, id="reader-2.3"),
        pytest.param("/reads-after-first-chunk", SPEC_WITHOUT_CONCURRENT_READER, id="reader-2.4"),
        pytest.param("/never-reads", SPEC_WITH_CONCURRENT_READER, id="listener-2.3"),
    ],
)
async def test_a_response_started_before_the_body_overflowed_is_cut_off_without_a_second_start(
    path: str, spec_version: str
) -> None:
    sent, raised = await drive_post(path, spec_version, TWO_CHUNKS_UNDER_THE_LIMIT_EACH)

    assert [start["status"] for start in starts(sent)] == [200]
    assert not completed(sent)
    assert raised is not None


@pytest.mark.parametrize(
    "start_send",
    [StartSend.SUSPENDED_BEFORE_ACCEPTING, StartSend.SUSPENDED_AFTER_ACCEPTING],
)
async def test_a_start_still_in_its_send_when_the_body_overflows_stays_the_only_start(
    start_send: StartSend,
) -> None:
    sent, raised = await drive_post(
        "/never-reads", SPEC_WITH_CONCURRENT_READER, ONE_CHUNK_OVER_THE_LIMIT, start_send
    )

    assert [start["status"] for start in starts(sent)] == [200]
    assert not completed(sent)
    assert raised is not None


async def test_a_response_finished_before_the_overflow_is_noticed_stays_complete_and_the_error_reaches_the_server() -> None:  # noqa: E501
    sent, raised = await drive_post(
        "/never-reads-without-await", SPEC_WITH_CONCURRENT_READER, TWO_CHUNKS_UNDER_THE_LIMIT_EACH
    )

    assert [start["status"] for start in starts(sent)] == [200]
    assert completed(sent)
    assert body_of(sent) == b"firstsecond"
    assert raised is not None


@pytest.mark.parametrize(
    "spec_version", [SPEC_WITH_CONCURRENT_READER, SPEC_WITHOUT_CONCURRENT_READER]
)
async def test_a_streamed_body_over_the_limit_read_before_the_response_starts_answers_413_with_the_headers(  # noqa: E501
    spec_version: str,
) -> None:
    sent, raised = await drive_post("/reads", spec_version, TWO_CHUNKS_UNDER_THE_LIMIT_EACH)

    (start,) = starts(sent)
    assert start["status"] == 413
    assert body_of(sent) == TOO_LARGE_BODY
    assert raised is None
    assert_carries_policy_headers(Headers(raw=start["headers"]), HEADERS_POLICY, hsts=True)

