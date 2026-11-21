"""What a stack and a host read of the client address the private writer recorded.

The proofs here wire the low-level stack by hand; the composition call and `web_auth_front`
place the writer in `tests/test_web_auth.py` and `tests/test_web_auth_front.py`.
"""

from __future__ import annotations

import logging

import pytest
from fastapi import FastAPI, Request
from fastapi.testclient import TestClient
from starlette.responses import JSONResponse
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
    a_client_behind_the_proxy,
)
from tests.support.security_headers_arrangement import assert_carries_policy_headers
from tests.support.webauth_arrangement import API_PATH, HTTPS_TEST_SERVER
from webauth import proxies
from webauth.middleware.rate_limit import _IpRateLimitMiddleware
from webauth.policies import PathRules, RateLimitBudget, RateLimitPolicy
from webauth.web_auth import ServedBehind

SOCKET_PATH = "/ws"
FORWARDED = {"x-forwarded-for": FORWARDED_CLIENT}
NOT_AN_ADDRESS = {"x-forwarded-for": "not-an-address"}


def a_host_serving_a_socket() -> FastAPI:
    """A fresh app with a plain route and a WebSocket route, behind no writer yet."""
    app = a_fresh_app()

    @app.websocket(SOCKET_PATH)
    async def socket(websocket: WebSocket) -> None:
        await websocket.accept()
        await websocket.close()

    return app


class TestAStackWithoutTheWriter:
    """The stack reads what the writer recorded, so a host without it fails on the first request."""

    @staticmethod
    def a_host() -> FastAPI:
        app = a_host_serving_a_socket()
        install_full_stack(app, front=ServedBehind.SHARED_FRONT)
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
            pytest.raises(RuntimeError, match="web_auth_front"),
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
            pytest.raises(RuntimeError, match="web_auth_front"),
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
        pytest.raises(RuntimeError, match="web_auth_front"),
    ):
        client.get("/client", headers=NOT_AN_ADDRESS)

    assert caplog.records == []


def test_a_secure_websocket_counts_as_https() -> None:
    seen: list[bool] = []
    app = a_fresh_app()

    @app.websocket(SOCKET_PATH)
    async def socket(websocket: WebSocket) -> None:
        seen.append(proxies.request_is_https(websocket))
        await websocket.accept()
        await websocket.close()

    with (
        TestClient(behind_the_client_address_writer(app)) as client,
        client.websocket_connect("wss://testserver" + SOCKET_PATH),
    ):
        pass

    assert seen == [True]


def test_the_writer_rewrites_neither_the_peer_nor_the_scheme() -> None:
    app = a_fresh_app()

    @app.get("/scope")
    def scope_of(request: Request) -> JSONResponse:
        return JSONResponse(
            {"client": list(request.scope["client"]), "scheme": request.scope["scheme"]}
        )

    client = TestClient(
        behind_the_client_address_writer(app),
        base_url="http://testserver",
        client=(TRUSTED_PEER, 55000),
    )

    response = client.get("/scope", headers={**FORWARDED, "x-forwarded-proto": "https"})

    assert response.json() == {"client": [TRUSTED_PEER, 55000], "scheme": "http"}


def test_the_rate_limiter_alone_reads_the_address_before_its_exemption_check() -> None:
    app = a_fresh_app()
    app.add_api_route("/exempt", lambda: {"ok": True}, methods=["GET"])
    app.add_middleware(
        _IpRateLimitMiddleware,
        policy=RateLimitPolicy(
            default=RateLimitBudget("api", 100, 60), exempt=PathRules(exact=frozenset({"/exempt"}))
        ),
    )

    client = TestClient(app, base_url=HTTPS_TEST_SERVER)

    with pytest.raises(RuntimeError, match="web_auth_front"):
        client.get("/exempt")


def test_a_writer_added_by_hand_is_refused_untouched() -> None:
    app = a_fresh_app()
    add_the_client_address_writer(app)
    before = list(app.user_middleware)

    with pytest.raises(RuntimeError, match="by hand"):
        install_full_stack(app)

    assert app.user_middleware == before
