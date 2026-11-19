"""The full stack over a small app: the routes it answers and the install every stack test uses."""

from __future__ import annotations

from collections.abc import AsyncIterator
from contextvars import ContextVar
from dataclasses import replace

from fastapi import BackgroundTasks, FastAPI, Request
from pydantic import BaseModel
from starlette.responses import StreamingResponse

from tests.support.client_address_arrangement import add_the_client_address_writer
from tests.support.gated_stack_arrangement import GATED_SIGN_IN_PATHS
from tests.support.webauth_arrangement import API_PATH, a_web_auth_config
from webauth.config import install_web_auth_config
from webauth.middleware import BearerGate, SessionGate, install_web_auth_middleware
from webauth.policies import (
    BodySizePolicy,
    CsrfPolicy,
    RateLimitBudget,
    RateLimitPolicy,
    SecurityHeadersPolicy,
)
from webauth.ports import RateLimitBackend

BODY_LIMIT_BYTES = 100
RAISING_PATH = "/boom"
WEBHOOK_PREFIX = "/webhook/"
WEBHOOK_PATH = f"{WEBHOOK_PREFIX}event"
HEADERS_POLICY = SecurityHeadersPolicy(content_security_policy="default-src 'self'")
READING_PATH = "/reads-body"
TYPED_PATH = "/typed"
FAILING_STREAM_PATH = "/fails-mid-stream"
BACKGROUND_PATH = "/with-background"
CONTEXT_SETTING_PATH = "/sets-context"


class TypedBody(BaseModel):
    text: str


class RouteFailure(RuntimeError):
    pass


ROUTE_FAILURE = RouteFailure("mid-stream")
DOWNSTREAM_MARK: ContextVar[str] = ContextVar("downstream_mark", default="unset")


def a_rate_limit_policy(max_requests: int) -> RateLimitPolicy:
    return RateLimitPolicy(default=RateLimitBudget("api", max_requests, 60))


def a_fresh_app(
    *,
    rate_limits: RateLimitBackend | None = None,
    cookie_secure: bool = True,
) -> FastAPI:
    app = an_app_without_config()
    config = a_web_auth_config(cookie_secure=cookie_secure)
    if rate_limits is not None:
        config = replace(config, rate_limits=rate_limits)
    install_web_auth_config(app, config)
    return app


def an_app_without_config() -> FastAPI:
    app = FastAPI()
    app.state.background_ran = []
    for path in (API_PATH, WEBHOOK_PATH):
        app.add_api_route(path, lambda: {"status": "ok"}, methods=["GET", "POST"])

    @app.get(RAISING_PATH)
    def raising() -> None:
        raise RuntimeError("route failed")

    @app.post(READING_PATH)
    async def reading(request: Request) -> dict[str, int]:
        return {"length": len(await request.body())}

    @app.post(TYPED_PATH)
    async def typed(body: TypedBody) -> dict[str, int]:
        return {"length": len(body.text)}

    @app.get(FAILING_STREAM_PATH)
    async def failing_stream() -> StreamingResponse:
        async def stream() -> AsyncIterator[bytes]:
            yield b"first"
            raise ROUTE_FAILURE

        return StreamingResponse(stream())

    @app.get(CONTEXT_SETTING_PATH)
    async def context_setting() -> dict[str, bool]:
        DOWNSTREAM_MARK.set("set-by-the-route")
        return {"ok": True}

    @app.get(BACKGROUND_PATH)
    async def with_background(tasks: BackgroundTasks) -> dict[str, bool]:
        tasks.add_task(app.state.background_ran.append, BACKGROUND_PATH)
        return {"ok": True}

    return app


def install_full_stack(
    app: FastAPI,
    *,
    max_requests: int = 100,
    session_gate: SessionGate | None = None,
    bearer_gate: BearerGate | None = None,
    client_address_writer: bool = True,
) -> None:
    install_web_auth_middleware(
        app,
        sign_in_paths=GATED_SIGN_IN_PATHS,
        security_headers=HEADERS_POLICY,
        body_size=BodySizePolicy(default_max_bytes=BODY_LIMIT_BYTES),
        rate_limit=a_rate_limit_policy(max_requests),
        csrf_origin=CsrfPolicy(),
        bearer_gate=bearer_gate,
        session_gate=session_gate,
    )
    if client_address_writer:
        add_the_client_address_writer(app)
