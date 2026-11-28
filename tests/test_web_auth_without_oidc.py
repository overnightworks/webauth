"""The composition call without OpenID Connect: `oidc=None`, the host's own routes, the same stack.

Each test names the COMPOSE rule of `docs/host-contract.md` it proves. The readers do not depend on
OpenID Connect, so their full tables stay in `tests/test_dependencies_websocket_auth.py`.
"""

from __future__ import annotations

from dataclasses import replace
from typing import TYPE_CHECKING

import pytest

from tests.support.account_arrangement import FakeUser
from tests.support.full_stack_arrangement import HEADERS_POLICY
from tests.support.oidc_login_host import SIGN_IN_PATHS, StoreDown
from tests.support.security_headers_arrangement import assert_carries_policy_headers
from tests.support.web_auth_host_arrangement import (
    A_MEMBER,
    ADMIN_PATH,
    ME_PATH,
    a_composed_host,
    a_composition,
    a_host_world,
    a_resource_and_person_paths,
    a_stored_session,
    forwarded_by_the_proxy,
    the_app_as_it_stands,
)
from tests.support.webauth_arrangement import (
    ADMIN_ROLE,
    ALLOWED_ORIGIN,
    API_PATH,
    WEBSOCKET_PATH,
)
from webauth.dependencies import LoginRedirect
from webauth.middleware import SessionGate
from webauth.policies import RateLimitBudget, RateLimitPolicy
from webauth.ports import AuthenticatedUser, StoreUnavailableError
from webauth.web_auth import WebAuth, WebAuthSettingError

if TYPE_CHECKING:
    from tests.support.web_auth_host_arrangement import ComposedHost, HostWorld

A_LOGIN_REDIRECT = LoginRedirect(path="/login", redirect_query_param="next")
A_GATE = SessionGate(login_redirect=A_LOGIN_REDIRECT, public=())
FOREIGN_ORIGIN = {"origin": "https://elsewhere.example", "sec-fetch-site": "cross-site"}
AS_A_BROWSER_PAGE = {"accept": "text/html"}


def _a_host_without_oidc(world: HostWorld, **changes: object) -> ComposedHost:
    return a_composed_host(world, a_composition(world, oidc=None, **changes))


def _the_cookie_of_the_stored_session(world: HostWorld) -> dict[str, str]:
    return {**forwarded_by_the_proxy(), **world.signed_cookie()}


def test_compose_20_the_oidc_keyword_has_no_default() -> None:
    """COMPOSE-20"""
    composition = a_composition(a_host_world())

    with pytest.raises(TypeError, match="oidc"):
        WebAuth.build(  # type: ignore[call-arg]
            composition.settings, stores=composition.stores, front=composition.front
        )


def test_compose_21_the_install_without_oidc_registers_no_route() -> None:
    """COMPOSE-21"""
    world = a_host_world()
    host = a_composed_host(world, a_composition(world, oidc=None), installed=False)
    routes_of_the_host = [route.path for route in host.app.routes]  # pyright: ignore[reportAttributeAccessIssue]

    host.auth.install(host.app, bearer=None)

    assert [route.path for route in host.app.routes] == routes_of_the_host  # pyright: ignore[reportAttributeAccessIssue]


@pytest.mark.parametrize(
    ("headers", "status", "location_prefix"),
    [
        pytest.param({}, 401, None, id="a-request-the-gate-refuses"),
        pytest.param(AS_A_BROWSER_PAGE, 302, "/login", id="a-browser-page-the-gate-redirects"),
    ],
)
def test_compose_21_a_path_that_is_a_sign_in_path_elsewhere_is_gated_like_any_other(
    headers: dict[str, str], status: int, location_prefix: str | None
) -> None:
    """COMPOSE-21"""
    world = a_host_world()
    host = _a_host_without_oidc(world, gate=A_GATE)

    response = host.client.get(SIGN_IN_PATHS.start, headers={**forwarded_by_the_proxy(), **headers})

    assert response.status_code == status
    assert location_prefix is None or response.headers["location"].startswith(location_prefix)


def test_compose_22_a_bearer_is_refused_before_the_app_changes_naming_bearer() -> None:
    """COMPOSE-22"""
    world = a_host_world()
    host = a_composed_host(world, a_composition(world, oidc=None), installed=False)
    before = the_app_as_it_stands(host.app)

    with pytest.raises(WebAuthSettingError, match="bearer"):
        host.auth.install(host.app, bearer=a_resource_and_person_paths()(host.auth))

    assert the_app_as_it_stands(host.app) == before


@pytest.mark.parametrize("name", ["relying_party", "admission"])
def test_compose_20_what_only_the_provider_gives_raises_on_a_handle_without_oidc(
    name: str,
) -> None:
    """COMPOSE-20"""
    auth = a_composition(a_host_world(), oidc=None).build()

    with pytest.raises(RuntimeError, match="oidc"):
        getattr(auth, name)


@pytest.mark.parametrize(
    ("rate_limit", "earlier_gets", "method", "path", "headers", "status"),
    [
        pytest.param(None, 0, "GET", f"{API_PATH}%0A", {}, 400, id="the-path-refusal-answers-400"),
        pytest.param(
            None, 0, "POST", API_PATH, FOREIGN_ORIGIN, 403, id="the-csrf-origin-rule-answers-403"
        ),
        pytest.param(
            RateLimitPolicy(default=RateLimitBudget("api", 1, 60)),
            1,
            "GET",
            API_PATH,
            {},
            429,
            id="a-request-over-the-budget-answers-429",
        ),
    ],
)
def test_compose_21_the_stack_refuses_without_oidc_as_it_does_with_it(
    rate_limit: RateLimitPolicy | None,
    earlier_gets: int,
    method: str,
    path: str,
    headers: dict[str, str],
    status: int,
) -> None:
    """COMPOSE-21"""
    world = a_host_world()
    composition = a_composition(world, oidc=None)
    settings = replace(composition.settings, rate_limit=rate_limit)
    host = a_composed_host(world, replace(composition, settings=settings))
    for _ in range(earlier_gets):
        host.client.get(API_PATH, headers=forwarded_by_the_proxy())

    response = host.client.request(method, path, headers={**forwarded_by_the_proxy(), **headers})

    assert response.status_code == status
    assert_carries_policy_headers(response.headers, HEADERS_POLICY, hsts=True)


@pytest.mark.parametrize(
    ("failure", "status"),
    [
        pytest.param(StoreUnavailableError(), 503, id="an-unreachable-store-answers-503"),
        pytest.param(StoreDown(), 500, id="a-failing-store-answers-500"),
    ],
)
def test_compose_21_a_store_failure_at_the_gate_answers_as_it_does_with_oidc(
    failure: Exception, status: int
) -> None:
    """COMPOSE-21"""
    world = a_host_world(A_MEMBER, stored_session=a_stored_session(A_MEMBER))
    world.sessions.load_failure = failure
    host = _a_host_without_oidc(world, gate=A_GATE)

    response = host.client.get(ME_PATH, headers=_the_cookie_of_the_stored_session(world))

    assert response.status_code == status


def test_compose_21_the_readers_serve_a_request_and_a_socket_over_the_installed_handle() -> None:
    """COMPOSE-21"""
    world = a_host_world(A_MEMBER, stored_session=a_stored_session(A_MEMBER))
    host = _a_host_without_oidc(world, gate=A_GATE)
    handshake = {**_the_cookie_of_the_stored_session(world), "origin": ALLOWED_ORIGIN}

    page = host.client.get(ME_PATH, headers=_the_cookie_of_the_stored_session(world))
    with host.client, host.client.websocket_connect(WEBSOCKET_PATH, headers=handshake):
        pass

    assert (page.status_code, page.json()) == (200, {"username": A_MEMBER.username})
    (outcome,) = world.socket_outcomes
    assert isinstance(outcome, AuthenticatedUser)
    assert outcome.username == A_MEMBER.username


@pytest.mark.parametrize(
    ("role", "status"),
    [
        pytest.param(ADMIN_ROLE, 200, id="the-stored-role-admin"),
        pytest.param("user", 403, id="a-member"),
    ],
)
def test_compose_21_admin_user_passes_the_stored_role_admin(role: str, status: int) -> None:
    """COMPOSE-21"""
    admin = FakeUser(id=A_MEMBER.id, username=A_MEMBER.username, role=role)
    world = a_host_world(admin, stored_session=a_stored_session(admin))
    host = _a_host_without_oidc(world, gate=A_GATE)

    response = host.client.get(ADMIN_PATH, headers=_the_cookie_of_the_stored_session(world))

    assert response.status_code == status
