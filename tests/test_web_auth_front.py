"""Several apps behind one `web_auth_front`: one writer and one request line for all of them.

Each test names the PROXY rule of `docs/host-contract.md` it proves.
"""

from __future__ import annotations

import logging

import pytest
from fastapi import FastAPI
from starlette.middleware import Middleware
from starlette.middleware.cors import CORSMiddleware

from tests.support.account_arrangement import FakeUser
from tests.support.client_address_arrangement import TRUSTED_PROXIES
from tests.support.full_stack_arrangement import HEADERS_POLICY
from tests.support.oidc_login_host import SUBJECT
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
    SHARED_PATH,
    HostWorld,
    a_client_of,
    a_composed_host,
    a_composition,
    a_host_world,
    a_second_world,
    a_shared_front_host,
    a_stored_session,
)
from tests.support.webauth_arrangement import ALLOWED_ORIGIN, API_PATH, WEBSOCKET_PATH
from webauth.web_auth import ServedBehind, WebAuthSettingError, web_auth_front

FORWARDED = {"x-forwarded-for": FORWARDED_CLIENT}
NOT_AN_ADDRESS = {"x-forwarded-for": "not-an-address"}
FIRST_MEMBER = FakeUser(id=SUBJECT, username="lena")
SECOND_MEMBER = FakeUser(id="a-subject-of-the-second-app", username="mara")
SECOND_ORIGIN = f"https://{SECOND_HOST}"


def two_signed_in_worlds() -> tuple[HostWorld, HostWorld]:
    return (
        a_host_world(FIRST_MEMBER, stored_session=a_stored_session(FIRST_MEMBER)),
        a_second_world(SECOND_MEMBER, stored_session=a_stored_session(SECOND_MEMBER)),
    )


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
    shared = a_shared_front_host(*two_signed_in_worlds())

    with request_lines_written(capsys) as lines:
        response = shared.client_at(host).request(method, path, headers=FORWARDED)

    (line,) = lines
    assert (response.status_code, line["ip"], line["sub"]) == (status, FORWARDED_CLIENT, None)


def test_proxy_07_a_signed_in_request_writes_one_line_with_the_account_of_the_app_it_reached(
    capsys: pytest.CaptureFixture[str],
) -> None:
    """PROXY-07"""
    first_world, second_world = two_signed_in_worlds()
    shared = a_shared_front_host(first_world, second_world)

    with request_lines_written(capsys) as first_lines:
        first = shared.client_at(FIRST_HOST).get(
            ME_PATH, headers={**FORWARDED, **first_world.signed_cookie()}
        )
    with request_lines_written(capsys) as second_lines:
        second = shared.client_at(SECOND_HOST).get(
            ME_PATH, headers={**FORWARDED, **second_world.signed_cookie()}
        )

    ((first_line,), (second_line,)) = first_lines, second_lines
    assert (first.json(), first_line["ip"], first_line["sub"]) == (
        {"username": FIRST_MEMBER.username},
        FORWARDED_CLIENT,
        FIRST_MEMBER.id,
    )
    assert (second.json(), second_line["ip"], second_line["sub"]) == (
        {"username": SECOND_MEMBER.username},
        FORWARDED_CLIENT,
        SECOND_MEMBER.id,
    )


@pytest.mark.parametrize("host", [FIRST_HOST, SECOND_HOST])
def test_proxy_08_a_header_the_writer_ignores_is_logged_once_for_a_request_through_a_child(
    caplog: pytest.LogCaptureFixture, host: str
) -> None:
    """PROXY-08"""
    shared = a_shared_front_host(*two_signed_in_worlds())

    with caplog.at_level(logging.WARNING, logger="webauth.proxies"):
        response = shared.client_at(host).get(API_PATH, headers=NOT_AN_ADDRESS)

    assert response.status_code == 200
    assert [record.getMessage() for record in caplog.records] == ["forwarded_for.ignored"]


def test_proxy_07_a_preflight_a_child_answers_names_the_forwarded_client(
    capsys: pytest.CaptureFixture[str],
) -> None:
    """PROXY-07"""
    first_world, second_world = two_signed_in_worlds()
    cors = Middleware(CORSMiddleware, allow_origins=[ALLOWED_ORIGIN], allow_methods=["GET"])
    shared = a_shared_front_host(
        first_world,
        second_world,
        first_composition=a_composition(
            first_world, front=ServedBehind.SHARED_FRONT, outside=(cors,)
        ),
    )
    preflight = {
        **FORWARDED,
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
    first_world, second_world = two_signed_in_worlds()
    shared = a_shared_front_host(first_world, second_world)
    handshakes = [
        (FIRST_HOST, {**FORWARDED, **first_world.signed_cookie(), "origin": ALLOWED_ORIGIN}),
        (SECOND_HOST, {**FORWARDED, **second_world.signed_cookie(), "origin": SECOND_ORIGIN}),
    ]

    with request_lines_written(capsys, event=WEBSOCKET_EVENT) as lines:
        for host, headers in handshakes:
            with (
                shared.client_at(host) as client,
                client.websocket_connect(f"wss://{host}{WEBSOCKET_PATH}", headers=headers),
            ):
                pass

    assert [(line["ip"], line["sub"]) for line in lines] == [
        (FORWARDED_CLIENT, FIRST_MEMBER.id),
        (FORWARDED_CLIENT, SECOND_MEMBER.id),
    ]


def test_proxy_09_an_http_request_to_a_child_without_its_front_answers_the_library_500() -> None:
    """PROXY-09"""
    host = a_composed_host(
        a_host_world(), a_composition(a_host_world(), front=ServedBehind.SHARED_FRONT)
    )

    response = host.client.get(API_PATH)

    assert response.status_code == 500
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
    shared = a_shared_front_host(*two_signed_in_worlds(), lifespan_events=events)

    with shared.client_at(FIRST_HOST):
        events_while_running = list(events)

    assert events_while_running == ["startup"]


def test_proxy_07_an_app_built_with_trusted_proxies_writes_its_own_line_with_the_client(
    capsys: pytest.CaptureFixture[str],
) -> None:
    """PROXY-07"""
    world = a_host_world(FIRST_MEMBER, stored_session=a_stored_session(FIRST_MEMBER))
    host = a_composed_host(world, a_composition(world, front=TRUSTED_PROXIES))

    with request_lines_written(capsys) as lines:
        host.client.get(ME_PATH, headers={**FORWARDED, **world.signed_cookie()})

    (line,) = lines
    assert (line["ip"], line["sub"]) == (FORWARDED_CLIENT, FIRST_MEMBER.id)


def test_proxy_07_a_front_refuses_proxies_that_are_not_trusted_proxies() -> None:
    """PROXY-07"""
    with pytest.raises(WebAuthSettingError, match="trusted_proxies"):
        web_auth_front(FastAPI(), trusted_proxies="10.0.0.0/8")  # pyright: ignore[reportArgumentType]
