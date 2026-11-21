"""Several apps behind one `web_auth_front`: one writer and one request line for all of them.

Each test names the PROXY rule of `docs/host-contract.md` it proves.
"""

from __future__ import annotations

import logging

import pytest
from fastapi import FastAPI
from starlette.middleware import Middleware
from starlette.middleware.cors import CORSMiddleware

from tests.support.client_address_arrangement import TRUSTED_PROXIES
from tests.support.full_stack_arrangement import HEADERS_POLICY
from tests.support.oidc_login_host import SIGN_IN_PATHS
from tests.support.request_line_arrangement import (
    FORWARDED_CLIENT,
    WEBSOCKET_EVENT,
    request_lines_written,
)
from tests.support.security_headers_arrangement import assert_carries_policy_headers
from tests.support.web_auth_host_arrangement import (
    FIRST_HOST,
    ME_PATH,
    SECOND_HOST,
    SECOND_ORIGIN,
    SHARED_PATH,
    a_client_of,
    a_composed_host,
    a_composition,
    a_host_world,
    a_shared_front_host,
    an_unparseable_forward,
    forwarded_by_the_proxy,
    two_signed_in_worlds,
)
from tests.support.webauth_arrangement import ALLOWED_ORIGIN, API_PATH, WEBSOCKET_PATH
from webauth.web_auth import ServedBehind, WebAuthSettingError, web_auth_front


@pytest.mark.parametrize(
    ("method", "host", "path", "status"),
    [
        pytest.param("GET", "unknown.example", "/nowhere", 404, id="an-unknown-host"),
        pytest.param(
            "POST", "unknown.example", SHARED_PATH, 405, id="a-wrong-method-on-the-shared-route"
        ),
    ],
)
def test_proxy_07_the_router_answers_by_itself_and_names_the_forwarded_client(
    capsys: pytest.CaptureFixture[str], method: str, host: str, path: str, status: int
) -> None:
    """PROXY-07"""
    worlds = two_signed_in_worlds()
    shared = a_shared_front_host(worlds.first, worlds.second)

    with request_lines_written(capsys) as lines:
        response = shared.client_at(host).request(method, path, headers=forwarded_by_the_proxy())

    (line,) = lines
    assert (response.status_code, line["ip"], line["sub"]) == (status, FORWARDED_CLIENT, None)


def test_proxy_07_a_signed_in_request_writes_one_line_with_the_account_of_the_app_it_reached(
    capsys: pytest.CaptureFixture[str],
) -> None:
    """PROXY-07"""
    worlds = two_signed_in_worlds()
    shared = a_shared_front_host(worlds.first, worlds.second)

    with request_lines_written(capsys) as first_lines:
        first = shared.client_at(FIRST_HOST).get(
            ME_PATH, headers={**forwarded_by_the_proxy(), **worlds.first.signed_cookie()}
        )
    with request_lines_written(capsys) as second_lines:
        second = shared.client_at(SECOND_HOST).get(
            ME_PATH, headers={**forwarded_by_the_proxy(), **worlds.second.signed_cookie()}
        )

    ((first_line,), (second_line,)) = first_lines, second_lines
    assert (first.json(), first_line["ip"], first_line["sub"]) == (
        {"username": worlds.first_member.username},
        FORWARDED_CLIENT,
        worlds.first_member.id,
    )
    assert (second.json(), second_line["ip"], second_line["sub"]) == (
        {"username": worlds.second_member.username},
        FORWARDED_CLIENT,
        worlds.second_member.id,
    )


@pytest.mark.parametrize("host", [FIRST_HOST, SECOND_HOST])
def test_proxy_08_a_header_the_writer_ignores_is_logged_once_for_a_request_through_a_child(
    caplog: pytest.LogCaptureFixture, host: str
) -> None:
    """PROXY-08"""
    worlds = two_signed_in_worlds()
    shared = a_shared_front_host(worlds.first, worlds.second)

    with caplog.at_level(logging.WARNING, logger="webauth.proxies"):
        response = shared.client_at(host).get(API_PATH, headers=an_unparseable_forward())

    assert response.status_code == 200
    assert [record.getMessage() for record in caplog.records] == ["forwarded_for.ignored"]


def test_proxy_07_a_preflight_a_child_answers_names_the_forwarded_client(
    capsys: pytest.CaptureFixture[str],
) -> None:
    """PROXY-07"""
    worlds = two_signed_in_worlds()
    cors = Middleware(CORSMiddleware, allow_origins=[ALLOWED_ORIGIN], allow_methods=["GET"])
    shared = a_shared_front_host(
        worlds.first,
        worlds.second,
        first_composition=a_composition(
            worlds.first, front=ServedBehind.SHARED_FRONT, outside=(cors,)
        ),
    )
    preflight = {
        **forwarded_by_the_proxy(),
        "origin": ALLOWED_ORIGIN,
        "access-control-request-method": "GET",
    }

    with request_lines_written(capsys) as lines:
        response = shared.client_at(FIRST_HOST).options(API_PATH, headers=preflight)

    (line,) = lines
    assert response.headers["access-control-allow-origin"] == ALLOWED_ORIGIN
    assert line["ip"] == FORWARDED_CLIENT


def test_proxy_07_a_socket_of_each_child_writes_one_line_with_the_client_and_its_account(
    capsys: pytest.CaptureFixture[str],
) -> None:
    """PROXY-07"""
    worlds = two_signed_in_worlds()
    shared = a_shared_front_host(worlds.first, worlds.second)
    handshakes = [
        (
            FIRST_HOST,
            {**forwarded_by_the_proxy(), **worlds.first.signed_cookie(), "origin": ALLOWED_ORIGIN},
        ),
        (
            SECOND_HOST,
            {**forwarded_by_the_proxy(), **worlds.second.signed_cookie(), "origin": SECOND_ORIGIN},
        ),
    ]

    with request_lines_written(capsys, event=WEBSOCKET_EVENT) as lines:
        for host, headers in handshakes:
            with (
                shared.client_at(host) as client,
                client.websocket_connect(f"wss://{host}{WEBSOCKET_PATH}", headers=headers),
            ):
                pass

    assert [(line["ip"], line["sub"]) for line in lines] == [
        (FORWARDED_CLIENT, worlds.first_member.id),
        (FORWARDED_CLIENT, worlds.second_member.id),
    ]


def test_proxy_09_an_http_request_to_a_child_without_its_front_answers_the_library_500() -> None:
    """PROXY-09"""
    host = a_composed_host(
        a_host_world(), a_composition(a_host_world(), front=ServedBehind.SHARED_FRONT)
    )

    response = host.client.get(API_PATH)

    assert response.status_code == 500
    assert_carries_policy_headers(response.headers, HEADERS_POLICY, hsts=True)


def test_proxy_09_the_refusal_of_a_sign_in_path_without_its_front_is_not_stored() -> None:
    """PROXY-09"""
    host = a_composed_host(
        a_host_world(), a_composition(a_host_world(), front=ServedBehind.SHARED_FRONT)
    )

    response = host.client.get(SIGN_IN_PATHS.start)

    assert response.status_code == 500
    assert response.headers["cache-control"] == "no-store"


def test_proxy_09_a_preflight_to_a_child_without_its_front_answers_the_library_500() -> None:
    """PROXY-09"""
    world = a_host_world()
    cors = Middleware(CORSMiddleware, allow_origins=[ALLOWED_ORIGIN], allow_methods=["GET"])
    host = a_composed_host(
        world, a_composition(world, front=ServedBehind.SHARED_FRONT, outside=(cors,))
    )
    preflight = {"origin": ALLOWED_ORIGIN, "access-control-request-method": "GET"}

    response = host.client.options(API_PATH, headers=preflight)

    assert response.status_code == 500
    assert "access-control-allow-origin" not in response.headers
    assert_carries_policy_headers(response.headers, HEADERS_POLICY, hsts=True)


def test_proxy_09_a_websocket_to_a_child_without_its_front_raises_before_the_app_runs() -> None:
    """PROXY-09"""
    world = a_host_world()
    host = a_composed_host(world, a_composition(world, front=ServedBehind.SHARED_FRONT))
    client = a_client_of(host.app, raise_server_exceptions=True)

    with (
        pytest.raises(RuntimeError, match="web_auth_front"),
        client.websocket_connect(WEBSOCKET_PATH),
    ):
        pass

    assert world.socket_outcomes == []


def test_proxy_07_a_lifespan_passes_through_the_front_untouched() -> None:
    """PROXY-07"""
    events: list[str] = []
    worlds = two_signed_in_worlds()
    shared = a_shared_front_host(worlds.first, worlds.second, lifespan_events=events)

    with shared.client_at(FIRST_HOST):
        events_while_running = list(events)

    assert events_while_running == ["startup"]


def test_proxy_07_an_app_built_with_trusted_proxies_writes_its_own_line_with_the_client(
    capsys: pytest.CaptureFixture[str],
) -> None:
    """PROXY-07"""
    worlds = two_signed_in_worlds()
    world = worlds.first
    host = a_composed_host(world, a_composition(world, front=TRUSTED_PROXIES))

    with request_lines_written(capsys) as lines:
        host.client.get(ME_PATH, headers={**forwarded_by_the_proxy(), **world.signed_cookie()})

    (line,) = lines
    assert (line["ip"], line["sub"]) == (FORWARDED_CLIENT, worlds.first_member.id)


def test_proxy_07_a_front_refuses_proxies_that_are_not_trusted_proxies() -> None:
    """PROXY-07"""
    with pytest.raises(WebAuthSettingError, match="trusted_proxies"):
        web_auth_front(FastAPI(), trusted_proxies="10.0.0.0/8")  # pyright: ignore[reportArgumentType]
