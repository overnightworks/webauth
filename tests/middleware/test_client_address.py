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
    behind_the_client_address_writer,
)
from tests.support.full_stack_arrangement import (
    a_fresh_app,
    install_full_stack,
)
from tests.support.request_line_arrangement import (
    TRUSTED_PEER,
    a_client_behind_the_proxy,
)
from tests.support.web_auth_host_arrangement import forwarded_by_the_proxy
from tests.support.webauth_arrangement import API_PATH, HTTPS_TEST_SERVER
from webauth import proxies
from webauth.middleware.rate_limit import _IpRateLimitMiddleware
from webauth.policies import PathRules, RateLimitBudget, RateLimitPolicy
from webauth.web_auth import ServedBehind

SOCKET_PATH = "/ws"
NOT_AN_ADDRESS = {"x-forwarded-for": "not-an-address"}


class TestTheFrontGuardSitsOutsideTheStack:
    """PROXY-09 itself is proven through the composition call in `tests/test_web_auth_front.py`."""

    @pytest.mark.parametrize(
        ("path", "headers"),
        [
            pytest.param("/api/thing%0A", {}, id="outside-the-path-refusal"),
            pytest.param(API_PATH, {"content-length": "1000000"}, id="outside-the-body-limit"),
        ],
    )
    def test_a_request_the_stack_would_refuse_fails_loud_naming_the_writer(
        self, path: str, headers: dict[str, str]
    ) -> None:
        app = a_fresh_app()
        install_full_stack(app, front=ServedBehind.SHARED_FRONT)

        with (
            TestClient(app, base_url=HTTPS_TEST_SERVER) as client,
            pytest.raises(RuntimeError, match="web_auth_front"),
        ):
            client.get(path, headers=headers)


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

    response = client.get(
        "/scope", headers={**forwarded_by_the_proxy(), "x-forwarded-proto": "https"}
    )

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
