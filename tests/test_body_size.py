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
from webauth.cookies import generate_csrf_token, sign_session_id
from webauth.middleware import install_web_auth_middleware
from webauth.policies import (
    BodySizePolicy,
    CsrfPolicy,
    RateLimitBudget,
    RateLimitClass,
    RateLimitPolicy,
    SecurityHeadersPolicy,
    default_content_security_policy,
)

if TYPE_CHECKING:
    from collections.abc import AsyncIterator

    from starlette.types import Message

    from webauth.config import WebAuthConfig

pytestmark = pytest.mark.anyio

LIMIT = 100
HEADERS_POLICY = SecurityHeadersPolicy(default_content_security_policy([]))
TWO_CHUNKS_UNDER_THE_LIMIT_EACH = (b"x" * 60, b"x" * 60)
ONE_CHUNK_OVER_THE_LIMIT = (b"x" * 120,)
A_CONFIG = a_web_auth_config()
TOO_LARGE_BODY = b'{"detail":"Request body too large"}'
SPEC_WITH_CONCURRENT_READER = "2.3"
SPEC_WITHOUT_CONCURRENT_READER = "2.4"


SESSION_ID = "sid-1"
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

    body_size = policy or BodySizePolicy(default_max_bytes=LIMIT)
    if full_stack:
        budget = RateLimitBudget(100, 60)
        install_web_auth_middleware(
            app,
            security_headers=HEADERS_POLICY,
            body_size=body_size,
            rate_limit=RateLimitPolicy(budgets=dict.fromkeys(RateLimitClass, budget)),
            csrf_origin=CsrfPolicy(),
            csrf_token=CsrfPolicy(),
        )
    else:
        install_web_auth_middleware(app, security_headers=HEADERS_POLICY, body_size=body_size)
    return app


def a_csrf_passing_request_headers(config: WebAuthConfig) -> list[tuple[bytes, bytes]]:
    cookie = f"{config.session_cookie_name}={sign_session_id(SESSION_ID, config.signing_key)}"
    token = generate_csrf_token(SESSION_ID, config.signing_key)
    return [
        (b"sec-fetch-site", b"same-origin"),
        (b"cookie", cookie.encode()),
        (config.csrf_header_name.encode(), token.encode()),
    ]


async def drive_post(
    path: str,
    spec_version: str,
    body_chunks: tuple[bytes, ...],
    start_send: StartSend = StartSend.PLAIN,
    *,
    app: FastAPI | None = None,
    headers: tuple[tuple[bytes, bytes], ...] = (),
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
        "/reads", SPEC_WITHOUT_CONCURRENT_READER, (), headers=headers
    )

    (start,) = starts(sent)
    assert start["status"] == 413
    assert body_of(sent) == TOO_LARGE_BODY
    assert raised is None
    assert_carries_policy_headers(Headers(raw=start["headers"]), HEADERS_POLICY, hsts=True)


async def test_behind_a_base_http_middleware_an_overflowing_started_response_is_cut_to_what_was_read_until_119() -> None:  # noqa: E501
    app = a_body_limited_app(full_stack=True)

    sent, raised = await drive_post(
        "/reads-after-first-chunk",
        SPEC_WITH_CONCURRENT_READER,
        TWO_CHUNKS_UNDER_THE_LIMIT_EACH,
        app=app,
        headers=tuple(a_csrf_passing_request_headers(A_CONFIG)),
    )

    assert [start["status"] for start in starts(sent)] == [200]
    assert completed(sent)
    assert body_of(sent) == b"first"
    assert raised is not None
