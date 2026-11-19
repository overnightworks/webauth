"""The client address webauth's writer records, and what a stack and a host read of it.

Each proof runs the real stack under logline's `RequestLineMiddleware` and reads the line the
request wrote; the writer sits immediately inside logline's middleware, the way the host contract
tells a host to wire it.
"""

from __future__ import annotations

import logging
from contextlib import asynccontextmanager
from typing import TYPE_CHECKING

import pytest
from fastapi import FastAPI, Request
from fastapi.testclient import TestClient
from starlette.applications import Starlette
from starlette.middleware.cors import CORSMiddleware
from starlette.responses import JSONResponse, PlainTextResponse
from starlette.routing import Mount, Route
from starlette.websockets import WebSocket

from tests.support.client_address_arrangement import (
    add_the_client_address_writer,
    behind_the_client_address_writer,
)
from tests.support.full_stack_arrangement import (
    HEADERS_POLICY,
    a_fresh_app,
    install_full_stack,
)
from tests.support.request_line_arrangement import (
    FORWARDED_CLIENT,
    TRUSTED_PEER,
    WEBSOCKET_EVENT,
    a_client_behind_the_proxy,
    logging_request_lines,
    request_line_around,
    request_lines_written,
)
from tests.support.security_headers_arrangement import assert_carries_policy_headers
from tests.support.webauth_arrangement import API_PATH, HTTPS_TEST_SERVER
from webauth import proxies
from webauth.middleware import IpRateLimitMiddleware
from webauth.policies import PathRules, RateLimitBudget, RateLimitPolicy

if TYPE_CHECKING:
    from collections.abc import AsyncIterator

    from starlette.types import ASGIApp

ORIGIN = "https://spa.example"
SOCKET_PATH = "/ws"
FORWARDED = {"x-forwarded-for": FORWARDED_CLIENT}
NOT_AN_ADDRESS = {"x-forwarded-for": "not-an-address"}


def a_host_serving_a_socket(lifespan_events: list[str] | None = None) -> FastAPI:
    """A fresh app with a plain route and a WebSocket route, behind no writer yet."""

    @asynccontextmanager
    async def lifespan(_app: FastAPI) -> AsyncIterator[None]:
        if lifespan_events is not None:
            lifespan_events.append("startup")
        yield

    app = a_fresh_app()
    app.router.lifespan_context = lifespan

    @app.websocket(SOCKET_PATH)
    async def socket(websocket: WebSocket) -> None:
        await websocket.accept()
        await websocket.close()

    return app


def an_inner_app_with_a_stack() -> FastAPI:
    app = a_fresh_app()
    install_full_stack(app, client_address_writer=False)
    return app


def an_outer_router_around(*inner_apps: ASGIApp) -> ASGIApp:
    """A host router that answers its own 404 and 405 and mounts each inner app under its prefix."""
    routes = [
        Route("/outer-only", lambda request: PlainTextResponse("outer"), methods=["GET"]),
        *(Mount(f"/app{number}", app=inner) for number, inner in enumerate(inner_apps)),
    ]
    return Starlette(routes=routes)


def test_a_proxied_cors_preflight_the_cors_layer_answers_names_the_client(
    capsys: pytest.CaptureFixture[str],
) -> None:
    app = a_host_serving_a_socket()
    install_full_stack(app, client_address_writer=False)
    app.add_middleware(CORSMiddleware, allow_origins=[ORIGIN], allow_methods=["GET"])
    add_the_client_address_writer(app)
    logging_request_lines(app)

    with request_lines_written(capsys) as lines, a_client_behind_the_proxy(app) as client:
        response = client.options(
            API_PATH,
            headers={
                **FORWARDED,
                "origin": ORIGIN,
                "access-control-request-method": "GET",
            },
        )

    (line,) = lines
    assert (response.status_code, line["ip"]) == (200, FORWARDED_CLIENT)


@pytest.mark.parametrize(
    ("method", "path", "status"),
    [
        pytest.param("GET", "/nowhere", 404, id="a-path-the-router-does-not-know"),
        pytest.param("POST", "/outer-only", 405, id="a-method-the-router-refuses"),
    ],
)
def test_an_answer_an_outer_router_gives_by_itself_names_the_client(
    capsys: pytest.CaptureFixture[str], method: str, path: str, status: int
) -> None:
    router = request_line_around(
        behind_the_client_address_writer(an_outer_router_around(an_inner_app_with_a_stack()))
    )

    with request_lines_written(capsys) as lines:
        client = TestClient(router, base_url=HTTPS_TEST_SERVER, client=(TRUSTED_PEER, 55000))
        response = client.request(method, path, headers=FORWARDED)

    (line,) = lines
    assert (response.status_code, line["ip"]) == (status, FORWARDED_CLIENT)


def test_two_stacks_a_request_passes_behind_one_writer_log_an_ignored_header_once(
    caplog: pytest.LogCaptureFixture,
) -> None:
    outer = a_fresh_app()
    outer.mount("/inner", an_inner_app_with_a_stack())
    install_full_stack(outer, client_address_writer=False)
    client = TestClient(
        behind_the_client_address_writer(outer),
        base_url=HTTPS_TEST_SERVER,
        client=(TRUSTED_PEER, 55000),
    )

    with caplog.at_level(logging.WARNING, logger="webauth.proxies"):
        response = client.get(f"/inner{API_PATH}", headers=NOT_AN_ADDRESS)

    assert response.status_code == 200
    assert [record.getMessage() for record in caplog.records] == ["forwarded_for.ignored"]


def test_a_websocket_line_names_the_client(capsys: pytest.CaptureFixture[str]) -> None:
    app = a_host_serving_a_socket()
    install_full_stack(app)
    logging_request_lines(app)

    with (
        request_lines_written(capsys, event=WEBSOCKET_EVENT) as lines,
        a_client_behind_the_proxy(app) as client,
        client.websocket_connect(SOCKET_PATH, headers=FORWARDED),
    ):
        pass

    (line,) = lines
    assert line["ip"] == FORWARDED_CLIENT


def test_a_lifespan_passes_the_writer_and_the_stack() -> None:
    events: list[str] = []
    app = a_host_serving_a_socket(events)
    install_full_stack(app)
    logging_request_lines(app)

    with TestClient(app):
        events_while_running = list(events)

    assert events_while_running == ["startup"]


class TestAStackWithoutTheWriter:
    """The stack reads what the writer recorded, so a host without it fails on the first request."""

    @staticmethod
    def a_host() -> FastAPI:
        app = a_host_serving_a_socket()
        install_full_stack(app, client_address_writer=False)
        return app

    @pytest.mark.parametrize(
        ("path", "headers"),
        [
            pytest.param(API_PATH, {}, id="a-plain-request"),
            pytest.param("/api/thing%0A", {}, id="a-request-the-path-refusal-answers"),
            pytest.param(API_PATH, {"content-length": "1000000"}, id="a-body-over-the-limit"),
        ],
    )
    def test_a_request_fails_loud_naming_the_writer(
        self, path: str, headers: dict[str, str]
    ) -> None:
        with (
            TestClient(self.a_host(), base_url=HTTPS_TEST_SERVER) as client,
            pytest.raises(RuntimeError, match="ClientAddressMiddleware"),
        ):
            client.get(path, headers=headers)

    def test_the_answer_a_missing_writer_causes_still_carries_the_security_headers(self) -> None:
        client = TestClient(
            self.a_host(), base_url=HTTPS_TEST_SERVER, raise_server_exceptions=False
        )

        response = client.get(API_PATH)

        assert response.status_code == 500
        assert_carries_policy_headers(response.headers, HEADERS_POLICY, hsts=True)

    def test_a_websocket_fails_loud_naming_the_writer(self) -> None:
        with (
            TestClient(self.a_host(), base_url=HTTPS_TEST_SERVER) as client,
            pytest.raises(RuntimeError, match="ClientAddressMiddleware"),
            client.websocket_connect(SOCKET_PATH),
        ):
            pass


def test_the_accessor_only_reads_what_the_writer_recorded(
    caplog: pytest.LogCaptureFixture,
) -> None:
    app = FastAPI()

    @app.get("/client")
    def client_of(request: Request) -> JSONResponse:
        return JSONResponse({"ip": proxies.client_address(request)})

    client = a_client_behind_the_proxy(app)

    with (
        caplog.at_level(logging.WARNING, logger="webauth.proxies"),
        client,
        pytest.raises(RuntimeError, match="ClientAddressMiddleware"),
    ):
        client.get("/client", headers=NOT_AN_ADDRESS)

    assert caplog.records == []


def test_the_rate_limiter_alone_reads_the_address_before_its_exemption_check() -> None:
    app = a_fresh_app()
    app.add_api_route("/exempt", lambda: {"ok": True}, methods=["GET"])
    app.add_middleware(
        IpRateLimitMiddleware,
        policy=RateLimitPolicy(
            default=RateLimitBudget("api", 100, 60), exempt=PathRules(exact=frozenset({"/exempt"}))
        ),
    )

    with pytest.raises(RuntimeError, match="ClientAddressMiddleware"):
        TestClient(app, base_url=HTTPS_TEST_SERVER).get("/exempt")


def test_a_writer_added_before_the_installer_is_refused_naming_its_position() -> None:
    app = a_fresh_app()
    add_the_client_address_writer(app)
    before = list(app.user_middleware)

    with pytest.raises(RuntimeError, match="after the call"):
        install_full_stack(app, client_address_writer=False)

    assert app.user_middleware == before
