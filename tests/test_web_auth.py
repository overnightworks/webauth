"""The composition call: an app built only by `WebAuth.build` and `auth.install`.

Each test names the COMPOSE rule of `docs/host-contract.md` it proves.
"""

from __future__ import annotations

import os
from collections.abc import AsyncIterator
from contextlib import suppress
from contextvars import ContextVar
from dataclasses import replace
from pathlib import Path
from typing import TYPE_CHECKING

import pytest
from fastapi import Depends, FastAPI, Request
from logline import WEBSOCKET_EVENT
from starlette.middleware import Middleware
from starlette.middleware.cors import CORSMiddleware
from starlette.responses import StreamingResponse
from starlette.websockets import WebSocketDisconnect

import webauth
from tests.support.account_arrangement import FakeUser
from tests.support.environment_arrangement import ForbiddenEnvironment
from tests.support.full_stack_arrangement import HEADERS_POLICY, install_full_stack
from tests.support.gate_arrangement import HAL_ONLY, PERSON_PATHS, a_resource, bearing
from tests.support.oidc_arrangement import (
    LogoutPage,
    a_logout_token,
    an_access_token,
)
from tests.support.oidc_login_host import (
    ADMIN_GROUP,
    ADMISSION,
    BACKCHANNEL_LOGOUT_PATH,
    BOUND_ISSUER,
    CALLBACK_PATH,
    CLIENT_ID,
    LOGIN_GROUP,
    LOGOUT_PATH,
    NO_ADMINS,
    NOW,
    SAME_ORIGIN_FORM,
    SIGN_IN_PATHS,
    START_PATH,
    SUBJECT,
)
from tests.support.request_line_arrangement import (
    FORWARDED_CLIENT,
    request_lines_written,
)
from tests.support.security_headers_arrangement import assert_carries_policy_headers
from tests.support.web_auth_host_arrangement import (
    ADMIN_PATH,
    ME_PATH,
    THE_REFUSAL_BODY,
    Composition,
    a_client_of,
    a_composed_host,
    a_composition,
    a_host_world,
    a_stored_session,
    the_app_as_it_stands,
    the_routes_of,
)
from tests.support.webauth_arrangement import (
    ADMIN_ROLE,
    ALLOWED_ORIGIN,
    API_PATH,
    WEBSOCKET_PATH,
)
from webauth.dependencies import ConnectionRefusal, current_user
from webauth.middleware import BearerGate, MachinePaths, PersonPaths, SessionGate
from webauth.policies import PathRules, RateLimitBudget, RateLimitPolicy
from webauth.ports import AuthenticatedUser
from webauth.sign_in_routes import LogoutPageText, RefusalPage, SignInPaths
from webauth.web_auth import ServedBehind, WebAuth, WebAuthSettingError

if TYPE_CHECKING:
    from collections.abc import Callable

    from starlette.types import ASGIApp, Receive, Scope, Send

    from tests.support.web_auth_host_arrangement import HostWorld

FORWARDED = {"x-forwarded-for": FORWARDED_CLIENT}
A_MEMBER = FakeUser(id=SUBJECT, username="lena")
THE_MARK: ContextVar[str] = ContextVar("the_mark", default="unset")


class _Saw:
    """A pure ASGI middleware that records the paths that reach it and sets `THE_MARK`."""

    def __init__(self, app: ASGIApp, *, name: str, record: list[str]) -> None:
        self._app = app
        self._name = name
        self._record = record

    async def __call__(self, scope: Scope, receive: Receive, send: Send) -> None:
        if scope["type"] == "http":
            self._record.append(f"{self._name} {scope['path']}")
            THE_MARK.set(f"set by {self._name}")
        await self._app(scope, receive, send)


class _ReadsTheMarkAfterwards:
    """A pure ASGI middleware that records `THE_MARK` as it reads it once the call returned."""

    def __init__(self, app: ASGIApp, *, record: list[str]) -> None:
        self._app = app
        self._record = record

    async def __call__(self, scope: Scope, receive: Receive, send: Send) -> None:
        await self._app(scope, receive, send)
        if scope["type"] == "http":
            self._record.append(THE_MARK.get())


def a_signed_in_member() -> HostWorld:
    return a_host_world(A_MEMBER, stored_session=a_stored_session(A_MEMBER))


@pytest.mark.parametrize(
    ("method", "path", "status", "requests_before"),
    [
        pytest.param("GET", f"{API_PATH}%0A", 400, 0, id="a-path-refused-with-400"),
        pytest.param("POST", API_PATH, 403, 0, id="a-forgery-refused-with-403"),
        pytest.param("GET", API_PATH, 429, 1, id="a-request-over-the-budget-refused-with-429"),
    ],
)
def test_compose_01_a_request_the_stack_refuses_writes_one_line_with_the_forwarded_client(
    capsys: pytest.CaptureFixture[str], method: str, path: str, status: int, requests_before: int
) -> None:
    """COMPOSE-01"""
    world = a_host_world()
    settings = replace(
        a_composition(world).settings,
        rate_limit=RateLimitPolicy(default=RateLimitBudget("api", 1, 60)),
    )
    host = a_composed_host(world, a_composition(world, settings=settings))
    for _ in range(requests_before):
        host.client.get(API_PATH, headers=FORWARDED)

    with request_lines_written(capsys) as lines:
        response = host.client.request(method, path, headers=FORWARDED)

    (line,) = lines
    assert (response.status_code, line["ip"]) == (status, FORWARDED_CLIENT)
    assert_carries_policy_headers(response.headers, HEADERS_POLICY, hsts=True)


def test_compose_02_a_layer_outside_the_stack_answers_a_preflight_before_the_stack_sees_it(
    capsys: pytest.CaptureFixture[str],
) -> None:
    """COMPOSE-02"""
    world = a_host_world()
    cors = Middleware(CORSMiddleware, allow_origins=["https://spa.example"], allow_methods=["GET"])
    host = a_composed_host(world, a_composition(world, outside=(cors,)))
    preflight = {
        **FORWARDED,
        "origin": "https://spa.example",
        "access-control-request-method": "GET",
    }

    with request_lines_written(capsys) as lines:
        response = host.client.options(API_PATH, headers=preflight)

    (line,) = lines
    assert response.headers["access-control-allow-origin"] == "https://spa.example"
    assert "content-security-policy" not in response.headers
    assert line["ip"] == FORWARDED_CLIENT


def test_compose_03_an_inside_layer_sees_only_the_admitted_and_its_context_shows_outside() -> None:
    """COMPOSE-03"""
    world = a_host_world()
    saw: list[str] = []
    marks_afterwards: list[str] = []
    host = a_composed_host(
        world,
        a_composition(
            world,
            outside=(Middleware(_ReadsTheMarkAfterwards, record=marks_afterwards),),
            inside=(Middleware(_Saw, name="inside", record=saw),),
        ),
    )

    host.client.get(f"{API_PATH}%0A", headers=FORWARDED)
    host.client.get(API_PATH, headers=FORWARDED)

    assert saw == [f"inside {API_PATH}"]
    assert marks_afterwards == ["unset", "set by inside"]


def test_compose_04_a_socket_through_the_proxy_writes_one_line_with_the_client_and_the_person(
    capsys: pytest.CaptureFixture[str],
) -> None:
    """COMPOSE-04"""
    world = a_signed_in_member()
    host = a_composed_host(world)
    handshake = {**FORWARDED, **world.signed_cookie(), "origin": ALLOWED_ORIGIN}

    with (
        request_lines_written(capsys, event=WEBSOCKET_EVENT) as lines,
        host.client,
        host.client.websocket_connect(WEBSOCKET_PATH, headers=handshake),
    ):
        pass

    (line,) = lines
    assert (line["ip"], line["sub"]) == (FORWARDED_CLIENT, SUBJECT)


def test_compose_05_the_install_serves_the_four_sign_in_routes(
    capsys: pytest.CaptureFixture[str],
) -> None:
    """COMPOSE-05"""
    world = a_host_world()
    host = a_composed_host(world)
    token = a_logout_token(
        issuer=BOUND_ISSUER,
        audience=CLIENT_ID,
        subject=SUBJECT,
        now=NOW,
        key_id="issuer-key",
        key_name="issuer",
    )

    started = host.client.get(START_PATH, headers=FORWARDED)
    with request_lines_written(capsys) as lines:
        callback = host.sign_in(FORWARDED)
    logout = host.client.post(LOGOUT_PATH, headers={**SAME_ORIGIN_FORM, **FORWARDED})
    back_channel = host.client.post(
        BACKCHANNEL_LOGOUT_PATH, data={"logout_token": token}, headers=FORWARDED
    )

    assert started.status_code == 303
    assert started.headers["location"].startswith(BOUND_ISSUER)
    assert callback.status_code == 303
    assert lines[-1]["sub"] == SUBJECT
    assert LogoutPage(logout.text).attributes_of("form")
    assert (back_channel.status_code, back_channel.content) == (200, b"")


def test_compose_06_build_and_install_make_no_outbound_call_and_the_login_uses_the_injected_ones(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """COMPOSE-06"""
    world = a_host_world()
    composition = a_composition(world)
    app = FastAPI()

    with monkeypatch.context() as patch:
        patch.setattr(os, "environ", ForbiddenEnvironment(only_from=Path(webauth.__file__).parent))
        composition.build().install(app, bearer=None)

    assert (world.issuer.requests, world.key_set.fetched_urls) == ([], [])
    host = a_composed_host(world)
    host.sign_in(FORWARDED)
    assert world.issuer.requests
    assert world.key_set.fetched_urls


def test_compose_07_the_pages_are_the_hosts(capsys: pytest.CaptureFixture[str]) -> None:
    """COMPOSE-07"""
    world = a_host_world()
    base = a_composition(world)
    pages = replace(
        base.pages,
        logout_page_text=lambda _request: LogoutPageText(language="de", button_label="Abmelden"),
        ui_language=lambda _request: "de",
    )
    host = a_composed_host(world, replace(base, pages=pages))

    start = host.client.get(START_PATH, headers=FORWARDED)
    refused = host.client.get(f"{CALLBACK_PATH}?state=forged&code=x", headers=FORWARDED)
    logout = LogoutPage(
        host.client.post(LOGOUT_PATH, headers={**SAME_ORIGIN_FORM, **FORWARDED}).text
    )

    assert "ui_locales=de" in start.headers["location"]
    assert (refused.status_code, refused.text) == (403, THE_REFUSAL_BODY)
    assert logout.attributes_of("html")[0]["lang"] == "de"
    assert logout.texts["button"] == "Abmelden"


def _a_session_probe(world: HostWorld, seen: list[list[str]]) -> Callable[[FastAPI, WebAuth], None]:
    def add(app: FastAPI, auth: WebAuth) -> None:
        the_routes_of(world)(app, auth)

        @app.get("/probe")
        def probe(user: AuthenticatedUser = Depends(current_user)) -> dict[str, str]:
            seen.append(list(world.sessions.event_names))
            return {"username": user.username}

        @app.get("/fails")
        def fails(user: AuthenticatedUser = Depends(current_user)) -> None:
            raise RuntimeError("the endpoint failed")

        @app.get("/direct")
        def direct(request: Request) -> dict[str, str]:
            return {"username": current_user(request).username}

        @app.get("/stream")
        def stream(user: AuthenticatedUser = Depends(current_user)) -> StreamingResponse:
            async def chunks() -> AsyncIterator[bytes]:
                seen.append(list(world.sessions.event_names))
                yield b"first"

            return StreamingResponse(chunks())

    return add


THE_ONE_ENTRY = ["open", "load", "touch", "commit"]


@pytest.mark.parametrize(
    ("path", "seen_by_the_endpoint"),
    [
        pytest.param("/probe", [THE_ONE_ENTRY], id="on-a-route"),
        pytest.param("/direct", [], id="called-directly"),
        pytest.param("/stream", [THE_ONE_ENTRY], id="before-a-streams-first-byte"),
    ],
)
def test_compose_08_current_user_opens_and_closes_one_entry_before_the_endpoint_runs(
    path: str, seen_by_the_endpoint: list[list[str]]
) -> None:
    """COMPOSE-08"""
    world = a_signed_in_member()
    seen: list[list[str]] = []
    host = a_composed_host(world, routes=_a_session_probe(world, seen))
    before = world.sessions.stored_record.expires_at

    response = host.client.get(path, headers=world.signed_cookie())

    assert response.status_code == 200
    assert world.sessions.event_names == THE_ONE_ENTRY
    assert seen == seen_by_the_endpoint
    assert world.sessions.stored_record.expires_at > before


def test_compose_08_a_failing_exit_runs_no_endpoint() -> None:
    """COMPOSE-08"""
    world = a_signed_in_member()
    world.sessions.commit_failure = RuntimeError("the exit failed")
    host = a_composed_host(world)

    response = host.client.get(ME_PATH, headers=world.signed_cookie())

    assert (response.status_code, world.routes_ran) == (500, [])


def test_compose_08_an_endpoint_rollback_keeps_the_renewal() -> None:
    """COMPOSE-08"""
    world = a_signed_in_member()
    host = a_composed_host(world, routes=_a_session_probe(world, []))
    before = world.sessions.stored_record.expires_at

    response = host.client.get("/fails", headers=world.signed_cookie())

    assert response.status_code == 500
    assert world.sessions.stored_record.expires_at > before


@pytest.mark.parametrize(
    ("groups_claim", "role", "me_status", "admin_status"),
    [
        pytest.param((str(LOGIN_GROUP),), "user", 200, 403, id="a-member"),
        pytest.param((str(LOGIN_GROUP), str(ADMIN_GROUP)), ADMIN_ROLE, 200, 200, id="an-admin"),
        pytest.param(("/apps/elsewhere",), None, 401, 401, id="a-non-member"),
    ],
)
def test_compose_09_the_groups_decide_who_is_admitted_and_who_is_admin(
    groups_claim: tuple[str, ...], role: str | None, me_status: int, admin_status: int
) -> None:
    """COMPOSE-09"""
    world = a_host_world(groups_claim=groups_claim)
    host = a_composed_host(world)

    callback = host.sign_in(FORWARDED)

    assert (host.client.get(ME_PATH).status_code, host.client.get(ADMIN_PATH).status_code) == (
        me_status,
        admin_status,
    )
    if role is None:
        assert (callback.status_code, world.refusals[0].page) == (403, RefusalPage.NO_ACCESS)
    else:
        assert [user.role for user in world.accounts.list()] == [role]


def test_compose_10_the_hosts_order_of_its_slots_is_kept_outermost_first() -> None:
    """COMPOSE-10"""
    world = a_host_world()
    order: list[str] = []
    names = ("first outside", "second outside", "first inside", "second inside")
    outside, inside = (
        tuple(Middleware(_Saw, name=name, record=order) for name in names[:2]),
        tuple(Middleware(_Saw, name=name, record=order) for name in names[2:]),
    )
    host = a_composed_host(world, a_composition(world, outside=outside, inside=inside))

    host.client.get(f"{API_PATH}%0A", headers=FORWARDED)
    host.client.get(API_PATH, headers=FORWARDED)

    assert [entry.split(" /")[0] for entry in order] == [*names[:2], *names]


def a_resource_and_person_paths() -> Callable[[WebAuth], BearerGate]:
    def bearer_of(_auth: WebAuth) -> BearerGate:
        return BearerGate(
            person_paths=PersonPaths(PERSON_PATHS, HAL_ONLY),
            resource=a_resource(),
        )

    return bearer_of


def a_member_token() -> str:
    return an_access_token(
        issuer=BOUND_ISSUER,
        client_id=CLIENT_ID,
        key_id="issuer-key",
        key_name="issuer",
        subject=SUBJECT,
        claims={"groups": [str(LOGIN_GROUP)]},
    )


def test_compose_11_a_bearer_given_after_the_routes_is_served_and_admitted() -> None:
    """COMPOSE-11"""
    world = a_host_world(A_MEMBER)
    gate = SessionGate(login_redirect=None, public=())

    def routes(app: FastAPI, auth: WebAuth) -> None:
        the_routes_of(world)(app, auth)

        @app.get("/api/me")
        def person_me(user: AuthenticatedUser = Depends(current_user)) -> dict[str, str]:
            return {"username": user.username}

    host = a_composed_host(
        world,
        a_composition(world, gate=gate),
        routes=routes,
        bearer_of=a_resource_and_person_paths(),
    )
    resource = a_resource()
    token = a_member_token()

    metadata = host.client.get(
        f"/.well-known/oauth-protected-resource{resource.entry_point}", headers=FORWARDED
    )
    person = host.client.get("/api/me", headers={**FORWARDED, "authorization": bearing(token)[0]})

    assert (metadata.status_code, metadata.json()["authorization_servers"]) == (200, [BOUND_ISSUER])
    assert (person.status_code, person.json()) == (200, {"username": "lena"})


def test_compose_19_the_stores_given_once_serve_the_gate_and_the_person_paths() -> None:
    """COMPOSE-19"""
    world = a_host_world(A_MEMBER, stored_session=a_stored_session(A_MEMBER))
    gate = SessionGate(login_redirect=None, public=())

    def routes(app: FastAPI, auth: WebAuth) -> None:
        the_routes_of(world)(app, auth)

        @app.get("/api/me")
        def person_me(user: AuthenticatedUser = Depends(current_user)) -> dict[str, str]:
            return {"username": user.username}

    host = a_composed_host(
        world,
        a_composition(world, gate=gate),
        routes=routes,
        bearer_of=a_resource_and_person_paths(),
    )

    by_session = host.client.get(ME_PATH, headers={**FORWARDED, **world.signed_cookie()})
    entries_before_the_token = world.sign_in.entries
    by_token = host.client.get(
        "/api/me", headers={**FORWARDED, "authorization": bearing(a_member_token())[0]}
    )

    assert (by_session.status_code, by_session.json()) == (200, {"username": "lena"})
    assert "load" in world.sessions.event_names
    assert (by_token.status_code, by_token.json()) == (200, {"username": "lena"})
    assert world.sign_in.entries == entries_before_the_token + 1


def test_compose_11_the_install_serves_its_routes_ahead_of_a_catch_all_of_the_host() -> None:
    """COMPOSE-11"""
    world = a_host_world()

    def routes(app: FastAPI, auth: WebAuth) -> None:
        the_routes_of(world)(app, auth)

        @app.get("/{path:path}")
        def catch_all(path: str) -> dict[str, str]:
            return {"answered_by": "catch-all"}

    host = a_composed_host(world, routes=routes, bearer_of=a_resource_and_person_paths())
    resource = a_resource()

    start = host.client.get(START_PATH, headers=FORWARDED)
    metadata = host.client.get(
        f"/.well-known/oauth-protected-resource{resource.entry_point}", headers=FORWARDED
    )
    unknown = host.client.get("/nothing-here", headers=FORWARDED)

    assert start.status_code == 303
    assert metadata.json()["authorization_servers"] == [BOUND_ISSUER]
    assert unknown.json() == {"answered_by": "catch-all"}


def _settings_with(world: HostWorld, **changes: object) -> Composition:
    base = a_composition(world)
    return replace(base, settings=replace(base.settings, **changes))


@pytest.mark.parametrize(
    ("field", "composition_of", "value"),
    [
        pytest.param(
            "groups.bound_issuer",
            lambda world, value: a_composition(
                world, groups=replace(ADMISSION, bound_issuer=value)
            ),
            "https://elsewhere.example/realms/other",
            id="a-bound-issuer-that-is-not-the-clients",
        ),
        pytest.param(
            "settings.max_sessions",
            lambda world, value: _settings_with(world, max_sessions=value),
            -777,
            id="a-session-cap-below-one",
        ),
        pytest.param(
            "settings.keeps_id_token",
            lambda world, value: _settings_with(world, keeps_id_token=value),
            "maybe-sentinel",
            id="a-keeps-id-token-that-is-no-bool",
        ),
        pytest.param(
            "pages.logout_page_text",
            lambda world, value: _without_a_logout_path(world),
            None,
            id="a-logout-page-text-without-a-logout-path",
        ),
        pytest.param(
            "pages.logout_page_text",
            lambda world, value: replace(
                a_composition(world),
                pages=replace(a_composition(world).pages, logout_page_text=value),
            ),
            None,
            id="a-logout-path-without-a-logout-page-text",
        ),
        pytest.param(
            "front",
            lambda world, value: a_composition(world, front=value),
            "not-proxies-sentinel",
            id="a-front-that-is-no-trusted-proxies",
        ),
        pytest.param(
            "outside",
            lambda world, value: a_composition(world, outside=(value,)),
            "not-middleware-sentinel",
            id="an-outside-entry-that-is-no-middleware",
        ),
        pytest.param(
            "inside",
            lambda world, value: a_composition(world, inside=(value,)),
            "not-middleware-sentinel",
            id="an-inside-entry-that-is-no-middleware",
        ),
    ],
)
def test_compose_12_an_early_value_is_refused_at_build_naming_the_field_never_the_value(
    field: str, composition_of: Callable[[HostWorld, object], Composition], value: object
) -> None:
    """COMPOSE-12"""
    composition = composition_of(a_host_world(), value)

    with pytest.raises(WebAuthSettingError) as refusal:
        composition.build()

    assert isinstance(refusal.value, ValueError)
    assert field in str(refusal.value)
    assert str(value) not in str(refusal.value)


def _without_a_logout_path(world: HostWorld) -> Composition:
    paths = SignInPaths(start=SIGN_IN_PATHS.start, callback=SIGN_IN_PATHS.callback)
    return _settings_with(world, sign_in_paths=paths)


def test_compose_13_a_second_install_is_refused_and_leaves_the_app_as_it_was() -> None:
    """COMPOSE-13"""
    host = a_composed_host(a_host_world())
    before = the_app_as_it_stands(host.app)

    with pytest.raises(RuntimeError, match="install"):
        host.auth.install(host.app, bearer=None)

    assert the_app_as_it_stands(host.app) == before


def test_compose_13_a_handle_installed_on_one_app_is_refused_on_a_second_app() -> None:
    """COMPOSE-13"""
    host = a_composed_host(a_host_world())
    second_app = FastAPI()
    before = the_app_as_it_stands(second_app)

    with pytest.raises(RuntimeError, match="installed on an app"):
        host.auth.install(second_app, bearer=None)

    assert the_app_as_it_stands(second_app) == before


def test_compose_13_an_app_that_carries_the_stack_of_another_handle_is_refused_untouched() -> None:
    """COMPOSE-13"""
    world = a_host_world()
    app = FastAPI()
    install_full_stack(app, front=ServedBehind.SHARED_FRONT)
    before = the_app_as_it_stands(app)
    auth = a_composition(world).build()

    with pytest.raises(RuntimeError, match="another WebAuth"):
        auth.install(app, bearer=None)

    assert the_app_as_it_stands(app) == before


@pytest.mark.parametrize("not_a_gate", ["a secret-looking string", 7, object()])
def test_compose_14_a_bearer_that_is_no_bearer_gate_is_refused_before_the_app_changes(
    not_a_gate: object,
) -> None:
    """COMPOSE-14"""
    world = a_host_world()
    auth = a_composition(world, groups=NO_ADMINS).build()
    app = FastAPI()
    the_routes_of(world)(app, auth)
    before = the_app_as_it_stands(app)

    with pytest.raises(WebAuthSettingError, match=r"bearer") as refusal:
        auth.install(app, bearer=not_a_gate)  # type: ignore[arg-type]

    assert "secret-looking" not in str(refusal.value)
    assert the_app_as_it_stands(app) == before


def test_compose_14_machine_paths_without_admins_are_refused_before_the_app_changes() -> None:
    """COMPOSE-14"""
    world = a_host_world()
    auth = a_composition(world, groups=NO_ADMINS).build()
    app = FastAPI()
    the_routes_of(world)(app, auth)
    before = the_app_as_it_stands(app)
    machine_paths = MachinePaths(PathRules(prefixes=("/api/admin/",)), HAL_ONLY)

    with pytest.raises(WebAuthSettingError, match=r"bearer\.machine_paths"):
        auth.install(app, bearer=BearerGate(machine_paths=machine_paths))

    assert the_app_as_it_stands(app) == before


@pytest.mark.parametrize(
    ("role", "status"),
    [pytest.param(ADMIN_ROLE, 200, id="an-admin"), pytest.param("user", 403, id="a-member")],
)
def test_compose_15_admin_user_checks_the_identity_an_override_of_current_user_gives(
    role: str, status: int
) -> None:
    """COMPOSE-15"""
    world = a_host_world()
    host = a_composed_host(world)
    host.app.dependency_overrides[current_user] = lambda: AuthenticatedUser(
        id="fixed", username="fixed", role=role, agent=None
    )

    response = host.client.get(ADMIN_PATH)

    assert response.status_code == status
    assert world.sessions.event_names == []


def test_compose_16_a_socket_with_a_foreign_origin_is_refused_before_any_store_is_opened() -> None:
    """COMPOSE-16"""
    world = a_signed_in_member()
    host = a_composed_host(world)
    handshake = {**FORWARDED, **world.signed_cookie(), "origin": "https://evil.example"}

    with (
        host.client,
        suppress(WebSocketDisconnect),
        host.client.websocket_connect(WEBSOCKET_PATH, headers=handshake),
    ):
        pass

    assert world.socket_outcomes == [ConnectionRefusal.FOREIGN_ORIGIN]
    assert world.sessions.event_names == []


def test_compose_17_a_handle_that_was_never_installed_fails_on_its_first_request() -> None:
    """COMPOSE-17"""
    world = a_signed_in_member()
    host = a_composed_host(world, installed=False)
    client = a_client_of(host.app, raise_server_exceptions=True)
    cookie = world.signed_cookie()

    with pytest.raises(RuntimeError, match=r"auth\.install"):
        client.get(ME_PATH, headers=cookie)


def test_compose_17_a_socket_of_a_handle_that_was_never_installed_names_the_missing_install() -> (
    None
):
    """COMPOSE-17"""
    world = a_signed_in_member()
    host = a_composed_host(world, installed=False)
    client = a_client_of(host.app, raise_server_exceptions=True)
    handshake = {**FORWARDED, **world.signed_cookie(), "origin": ALLOWED_ORIGIN}

    with (
        pytest.raises(RuntimeError, match=r"auth\.install"),
        client.websocket_connect(WEBSOCKET_PATH, headers=handshake),
    ):
        pass


@pytest.mark.parametrize(
    "positional",
    [
        pytest.param((), id="without a positional"),
        pytest.param((object(),), id="with a positional"),
    ],
)
def test_compose_18_the_class_called_with_every_argument_of_a_build_is_refused(
    positional: tuple[object, ...],
) -> None:
    """COMPOSE-18"""
    composition = a_composition(a_host_world())
    built = composition.build()

    with pytest.raises(TypeError):
        WebAuth(  # type: ignore[call-arg]
            *positional,  # type: ignore[arg-type]
            settings=composition.settings,
            stores=composition.stores,
            groups=composition.groups,
            pages=composition.pages,
            front=composition.front,
            gate=None,
            outside=(),
            inside=(),
            relying_party=built.relying_party,
        )
