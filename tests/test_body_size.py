"""A body over the limit never earns a second response start."""

from __future__ import annotations

from typing import TYPE_CHECKING

import anyio
import anyio.lowlevel
import pytest
from fastapi import FastAPI, Request
from starlette.datastructures import Headers
from starlette.responses import JSONResponse, StreamingResponse
from webauth_arrangement import (
    SPEC_WITH_CONCURRENT_READER,
    SPEC_WITHOUT_CONCURRENT_READER,
    StartSend,
    a_signed_in_same_origin_request,
    a_web_auth_config,
    an_http_scope,
    assert_carries_policy_headers,
    body_of,
    completed,
    drive,
    starts,
)

from webauth import WebAuthError
from webauth.config import install_web_auth_config
from webauth.middleware import RequestBodyTooLarge, install_web_auth_middleware
from webauth.policies import (
    BodySizePolicy,
    CsrfPolicy,
    RateLimitBudget,
    RateLimitPolicy,
    SecurityHeadersPolicy,
    default_content_security_policy,
)

if TYPE_CHECKING:
    from collections.abc import AsyncIterator

    from starlette.types import Message

pytestmark = pytest.mark.anyio

LIMIT = 100
HEADERS_POLICY = SecurityHeadersPolicy(default_content_security_policy([]))
TWO_CHUNKS_UNDER_THE_LIMIT_EACH = (b"x" * 60, b"x" * 60)
ONE_CHUNK_OVER_THE_LIMIT = (b"x" * 120,)
A_CONFIG = a_web_auth_config()
SAME_ORIGIN = ((b"sec-fetch-site", b"same-origin"),)
TOO_LARGE_BODY = b'{"detail":"Request body too large"}'


START_SEND_BOUND_SECONDS = 0.05


def a_body_limited_app(
    *, full_stack: bool = False, policy: BodySizePolicy | None = None
) -> FastAPI:
    app = FastAPI()
    install_web_auth_config(app, A_CONFIG)

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

    @app.post("/reads-stream")
    async def reads_stream(request: Request) -> dict[str, int]:
        return {"length": sum([len(chunk) async for chunk in request.stream()])}

    body_size = policy or BodySizePolicy(default_max_bytes=LIMIT)
    if full_stack:
        install_web_auth_middleware(
            app,
            security_headers=HEADERS_POLICY,
            body_size=body_size,
            rate_limit=RateLimitPolicy(default=RateLimitBudget("api", 100, 60)),
            csrf_origin=CsrfPolicy(),
        )
    else:
        install_web_auth_middleware(
            app, security_headers=HEADERS_POLICY, body_size=body_size, csrf_origin=CsrfPolicy(),
        )
    return app


async def drive_post(
    path: str,
    spec_version: str,
    body_chunks: tuple[bytes, ...],
    start_send: StartSend = StartSend.PLAIN,
    *,
    app: FastAPI | None = None,
    headers: tuple[tuple[bytes, bytes], ...] = SAME_ORIGIN,
) -> tuple[list[Message], BaseException | None]:
    app = app or a_body_limited_app()
    scope = an_http_scope(app, path, method="POST", headers=headers, spec_version=spec_version)
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
    assert isinstance(raised, RequestBodyTooLarge)


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
    assert isinstance(raised, RequestBodyTooLarge)


async def test_a_response_finished_before_the_overflow_is_noticed_stays_complete_and_the_error_reaches_the_server() -> None:  # noqa: E501
    sent, raised = await drive_post(
        "/never-reads-without-await", SPEC_WITH_CONCURRENT_READER, TWO_CHUNKS_UNDER_THE_LIMIT_EACH
    )

    assert [start["status"] for start in starts(sent)] == [200]
    assert completed(sent)
    assert body_of(sent) == b"firstsecond"
    assert isinstance(raised, RequestBodyTooLarge)


@pytest.mark.parametrize("path", ["/reads", "/reads-stream"])
@pytest.mark.parametrize(
    "spec_version", [SPEC_WITH_CONCURRENT_READER, SPEC_WITHOUT_CONCURRENT_READER]
)
async def test_a_streamed_body_over_the_limit_read_before_the_response_starts_answers_413_with_the_headers(  # noqa: E501
    path: str,
    spec_version: str,
) -> None:
    sent, raised = await drive_post(path, spec_version, TWO_CHUNKS_UNDER_THE_LIMIT_EACH)

    (start,) = starts(sent)
    assert start["status"] == 413
    assert body_of(sent) == TOO_LARGE_BODY
    assert raised is None
    assert_carries_policy_headers(Headers(raw=start["headers"]), HEADERS_POLICY, hsts=True)



async def test_a_web_auth_error_handler_does_not_answer_in_place_of_the_413() -> None:
    app = a_body_limited_app()

    @app.exception_handler(WebAuthError)
    async def answer_502(request: Request, error: WebAuthError) -> JSONResponse:
        return JSONResponse({"detail": "handled"}, status_code=502)

    sent, raised = await drive_post(
        "/reads", SPEC_WITH_CONCURRENT_READER, TWO_CHUNKS_UNDER_THE_LIMIT_EACH, app=app
    )

    (start,) = starts(sent)
    assert start["status"] == 413
    assert raised is None


async def test_a_start_send_held_past_the_deadline_fails_after_the_policy_bound_without_a_second_start() -> None:  # noqa: E501
    app = a_body_limited_app(
        policy=BodySizePolicy(default_max_bytes=LIMIT, start_send_seconds=START_SEND_BOUND_SECONDS)
    )

    sent, raised = await drive_post(
        "/never-reads",
        SPEC_WITH_CONCURRENT_READER,
        ONE_CHUNK_OVER_THE_LIMIT,
        StartSend.HELD_PAST_THE_DEADLINE,
        app=app,
    )

    assert isinstance(raised, BaseExceptionGroup)
    assert raised.subgroup(TimeoutError) is not None
    assert [start["status"] for start in starts(sent)] == []


@pytest.mark.parametrize(
    "declared_lengths",
    [
        pytest.param((b"0", b"120"), id="over-last"),
        pytest.param((b"120", b"0"), id="over-first"),
        pytest.param((b"120",), id="only"),
    ],
)
async def test_any_content_length_over_the_limit_is_refused_before_the_route(
    declared_lengths: tuple[bytes, ...],
) -> None:
    headers = tuple((b"content-length", length) for length in declared_lengths)

    sent, raised = await drive_post(
        "/reads", SPEC_WITHOUT_CONCURRENT_READER, (), headers=SAME_ORIGIN + headers
    )

    (start,) = starts(sent)
    assert start["status"] == 413
    assert body_of(sent) == TOO_LARGE_BODY
    assert raised is None
    assert_carries_policy_headers(Headers(raw=start["headers"]), HEADERS_POLICY, hsts=True)


@pytest.mark.parametrize(
    "spec_version",
    [
        pytest.param(SPEC_WITH_CONCURRENT_READER, id="spec-2.3"),
        pytest.param(SPEC_WITHOUT_CONCURRENT_READER, id="spec-2.4"),
    ],
)
async def test_a_response_started_before_the_body_overflowed_is_cut_off_under_the_full_stack(  # noqa: E501
    spec_version: str,
) -> None:
    app = a_body_limited_app(full_stack=True)

    sent, raised = await drive_post(
        "/reads-after-first-chunk",
        spec_version,
        TWO_CHUNKS_UNDER_THE_LIMIT_EACH,
        app=app,
        headers=tuple(a_signed_in_same_origin_request(A_CONFIG)),
    )

    assert [start["status"] for start in starts(sent)] == [200]
    assert not completed(sent)
    assert isinstance(raised, RequestBodyTooLarge)
