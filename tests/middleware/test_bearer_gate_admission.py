"""What a bearer admission changes for the cookie, CSRF and the session, and where it stops.

Each scenario runs the real stack of `a_bearer_app`; a recorded admission is
carried between requests by `relayed`, the way a host's outer middleware could.
"""

from __future__ import annotations

from dataclasses import asdict
from typing import TYPE_CHECKING, Any

import pytest
from fastapi import Depends, FastAPI
from fastapi.testclient import TestClient
from starlette.middleware import Middleware
from starlette.websockets import WebSocket

from tests.support.gate_arrangement import (
    A_TOKEN,
    ADMITTED_ADMIN_PATH,
    ADMITTED_ADMIN_PATHS,
    EXPORT_PATH,
    MACHINE_PATHS,
    MACHINE_SESSION_PATH,
    PERSON_ME_PATH,
    RAISING_PATH,
    REALM,
    REALM_INVALID_TOKEN,
    UNDECLARED_PATH,
    UNGATED_EXPORT_PATH,
    BearerApp,
    a_bearer_app,
    a_bearer_gate,
    a_token,
    assert_answers_no_store,
    bearing,
    relayed,
    the_accounts,
    the_transaction,
    with_admitted_admin_routes,
)
from tests.support.gated_stack_arrangement import GATED_SIGN_IN_PATHS
from tests.support.oidc_arrangement import (
    ACCESS_TOKEN_LEEWAY_SECONDS,
    ACCESS_TOKEN_LIFETIME_SECONDS,
    ACCESS_TOKEN_NOW,
    OPERATOR_SUBJECT,
    REALM_JWKS_URL,
)
from tests.support.person_paths_arrangement import (
    MEMBER_TOKEN,
    a_lena,
    a_person_app,
)
from tests.support.session_store_arrangement import SessionsThatMustNotBeAsked
from tests.support.webauth_arrangement import (
    ALL_DEPENDENCIES_PATH,
    HTTPS_TEST_SERVER,
    LOGIN_REDIRECT,
    a_web_auth_config,
    session_cookie_header,
)
from webauth.config import install_web_auth_config
from webauth.dependencies import current_user_dependency
from webauth.middleware import SessionGate, bearer_caller, install_web_auth_middleware
from webauth.policies import (
    BodySizePolicy,
    CacheControlRule,
    CsrfPolicy,
    PathRules,
    PublicRule,
    RateLimitBudget,
    RateLimitPolicy,
    SecurityHeadersPolicy,
)
from webauth.ports import BearerCaller

if TYPE_CHECKING:
    from collections.abc import Callable

    from starlette.types import ASGIApp, Receive, Scope, Send

EXPIRY = ACCESS_TOKEN_NOW + ACCESS_TOKEN_LIFETIME_SECONDS
HEALTH_PATH = "/health"
CALLER_PATH = "/api/admin/caller"
SOCKET_PATH = "/api/admin/socket"
NOT_ADMIN = a_token(groups=["/apps/x"])
SESSION_PATHS = ("/me", "/admin", *ADMITTED_ADMIN_PATHS)
FOREIGN_PAGE = {
    "origin": "https://evil.example.test",
    "sec-fetch-site": "cross-site",
}


def never_asked() -> Any:
    raise AssertionError("the session transaction was opened")


COOKIE_KINDS = pytest.mark.parametrize("cookie_kind", ["none", "own", "another-accounts"])


def cookies_of(app: BearerApp, kind: str) -> dict[str, str]:
    """The cookie header of a browser: none, the app's own session, or another account's."""
    if kind == "none":
        return {}
    if kind == "own":
        return {"cookie": app.cookie}
    return {"cookie": session_cookie_header(app.auth.signed_cookie("another-account"))}


@pytest.mark.parametrize(
    ("arrange", "path", "token"),
    [
        pytest.param(a_bearer_app, EXPORT_PATH, A_TOKEN, id="machine-path"),
        pytest.param(
            lambda: a_person_app(session_gate=True, known_accounts=(a_lena(),)),
            PERSON_ME_PATH,
            MEMBER_TOKEN,
            id="person-path",
        ),
    ],
)
def test_a_bearer_request_needs_no_csrf_origin_header_or_cookie(
    arrange: Callable[[], BearerApp],
    path: str,
    token: str,
) -> None:
    """CSRF-10, MACHINE-16: a verified bearer request passes without Origin or a cookie.

    The session gate, which refuses a request with no session, decides nothing for it.
    """
    app = arrange()

    response = app.ask(path, method="DELETE", authorization=bearing(token), headers=FOREIGN_PAGE)

    assert response.status_code == 200


def test_the_cookie_counts_for_nothing_beside_a_token() -> None:
    """MACHINE-04, MACHINE-05, MACHINE-16: a token beside another account's cookie asks no store.

    The caller is the token's subject, no session is opened and no cookie is set.
    """
    app = a_bearer_app(
        sessions=SessionsThatMustNotBeAsked(),
        session_transaction=never_asked,
    )
    other_accounts_cookie = session_cookie_header(app.auth.signed_cookie("another-account"))

    response = app.ask(
        method="DELETE",
        authorization=bearing(A_TOKEN),
        headers={"cookie": other_accounts_cookie},
    )

    assert (response.status_code, response.json()) == (200, {"subject": OPERATOR_SUBJECT})
    assert_answers_no_store(response)


@pytest.mark.parametrize("path", [EXPORT_PATH, UNDECLARED_PATH])
def test_an_admin_cookie_alone_opens_no_machine_path_even_without_a_declared_dependency(
    path: str,
) -> None:
    """MACHINE-14: an admin's session cookie alone opens no machine path."""
    app = a_bearer_app()

    response = app.ask(path, cookie=True)

    assert (response.status_code, response.headers["www-authenticate"]) == (401, REALM)
    assert_answers_no_store(response)
    assert app.auth.route_runs == []


@pytest.mark.parametrize("path", SESSION_PATHS)
@pytest.mark.parametrize("accept", ["text/html", "application/json"])
def test_a_session_dependency_on_a_bearer_admitted_request_is_a_host_mistake(
    path: str,
    accept: str,
) -> None:
    """MACHINE-23: `current_user`, `admin_user` and `admitted_admin` on a gated path answer 500."""
    app = a_bearer_app(
        paths=PathRules(exact=frozenset(SESSION_PATHS)),
        login_redirect=LOGIN_REDIRECT,
    )
    with_admitted_admin_routes(app.auth)

    response = app.ask(
        path,
        authorization=bearing(A_TOKEN),
        cookie=True,
        headers={"accept": accept},
    )

    assert response.status_code == 500
    assert_answers_no_store(response)


def test_the_admitted_admin_of_a_bearer_request_is_an_error_the_public_reader_raises() -> None:
    app = a_bearer_app(paths=PathRules(exact=frozenset({ADMITTED_ADMIN_PATH})))
    with_admitted_admin_routes(app.auth)
    client = TestClient(app.auth.app, base_url=HTTPS_TEST_SERVER, raise_server_exceptions=True)
    headers = {"authorization": bearing(A_TOKEN)[0]}

    with pytest.raises(RuntimeError):
        client.get(ADMITTED_ADMIN_PATH, headers=headers)


@COOKIE_KINDS
def test_the_admitted_user_of_a_bearer_request_is_nobody(cookie_kind: str) -> None:
    """MACHINE-19: `admitted_user` is `None` on a gated path whatever cookie comes with it."""
    app = a_bearer_app(paths=PathRules(exact=frozenset({HEALTH_PATH})))

    response = app.ask(
        HEALTH_PATH, authorization=bearing(A_TOKEN), headers=cookies_of(app, cookie_kind)
    )

    assert (response.status_code, response.json()) == (200, {"username": None})
    assert_answers_no_store(response)


@pytest.mark.parametrize(
    "opened",
    [
        pytest.param({"public": (PublicRule(MACHINE_PATHS),)}, id="public"),
        pytest.param({"optional": MACHINE_PATHS}, id="optional"),
    ],
)
class TestAMachinePrefixTheSessionGateAlsoOpens:
    def test_without_a_token_the_gate_still_refuses(self, opened: dict[str, Any]) -> None:
        app = a_bearer_app(**opened)

        response = app.ask()

        assert (response.status_code, response.headers["www-authenticate"]) == (401, REALM)
        assert_answers_no_store(response)

    def test_with_a_token_the_session_store_is_not_asked(self, opened: dict[str, Any]) -> None:
        app = a_bearer_app(**opened, sessions=SessionsThatMustNotBeAsked())

        response = app.ask(authorization=bearing(A_TOKEN))

        assert response.status_code == 200
        assert_answers_no_store(response)


def a_sub_app(auth: BearerApp, *, csrf: bool, session_gate: bool = False) -> FastAPI:
    inner = FastAPI()
    install_web_auth_config(inner, auth.auth.config)
    sessions = current_user_dependency(
        session_store=lambda: auth.auth.sessions,
        on_authenticated=lambda user: None,
    )
    if csrf or session_gate:
        install_web_auth_middleware(
            inner,
            sign_in_paths=GATED_SIGN_IN_PATHS,
            security_headers=SecurityHeadersPolicy(content_security_policy="default-src 'self'"),
            csrf_origin=CsrfPolicy(),
            session_gate=SessionGate(
                session_transaction=auth.auth.sessions.in_transaction,
                login_redirect=None,
                public=(),
            )
            if session_gate
            else None,
        )

    @inner.api_route(EXPORT_PATH, methods=["GET", "DELETE"])
    def machine_route(_caller: BearerCaller = Depends(bearer_caller)) -> dict[str, str]:
        return {"ran": "the sub-app's machine route"}

    @inner.api_route(ALL_DEPENDENCIES_PATH, methods=["DELETE"])
    def session_route(user: Any = Depends(sessions.current_user)) -> dict[str, str]:
        return {"ran": user.username}

    return inner


class TestASubAppBelowAGatedPathDoesNotOwnTheAdmission:
    def a_mounted_app(self, *, csrf: bool, session_gate: bool = False) -> BearerApp:
        app = a_bearer_app(paths=PathRules(prefixes=("/sub/",)))
        app.auth.app.mount("/sub", a_sub_app(app, csrf=csrf, session_gate=session_gate))
        return app

    def test_its_own_csrf_stack_still_applies(self) -> None:
        """MACHINE-28: a sub-app mounted below a gated path keeps its own CSRF check."""
        app = self.a_mounted_app(csrf=True)

        response = app.ask(f"/sub{EXPORT_PATH}", method="DELETE", authorization=bearing(A_TOKEN))

        assert (response.status_code, response.json()) == (
            403,
            {"detail": "Missing Origin header"},
        )
        assert_answers_no_store(response)

    def test_its_own_session_gate_still_applies(self) -> None:
        """MACHINE-29: a sub-app mounted below a gated path keeps its own session gate."""
        app = self.a_mounted_app(csrf=False, session_gate=True)

        response = app.ask(f"/sub{EXPORT_PATH}", authorization=bearing(A_TOKEN))

        assert (response.status_code, response.json()) == (
            401,
            {"detail": "Authentication required"},
        )
        assert_answers_no_store(response)

    @pytest.mark.parametrize(
        "path",
        [EXPORT_PATH, ALL_DEPENDENCIES_PATH],
        ids=["bearer_caller", "current_user"],
    )
    def test_its_routes_raise_when_they_ask_for_the_admission(self, path: str) -> None:
        """MACHINE-30: the `bearer_caller` of a route in a mounted sub-app raises."""
        app = self.a_mounted_app(csrf=False)

        response = app.ask(f"/sub{path}", method="DELETE", authorization=bearing(A_TOKEN))

        assert response.status_code == 500
        assert_answers_no_store(response)


class Relay:
    """An admitted request's scope entries that the gate wrote, ready to be planted in another."""

    def __init__(self, app: BearerApp) -> None:
        self.relay = relayed(app.auth)
        control = a_bearer_app(gated=False)
        control_relay = relayed(control.auth)
        app.ask(authorization=bearing(A_TOKEN))
        control.ask(authorization=bearing(A_TOKEN), cookie=True)
        app.auth.route_runs.clear()
        self.entries = {
            key: value for key, value in self.relay.added.items() if key not in control_relay.added
        }
        assert self.entries, "the gate wrote no scope entry for the admission"

    def plant(self, entries: dict[str, Any] | None = None) -> None:
        self.relay.replay = self.entries if entries is None else entries


class TestAnAdmissionBelongsToItsPathAppAndHeader:
    def test_it_is_not_honoured_on_another_path(self) -> None:
        app = a_bearer_app()
        Relay(app).plant()

        response = app.ask(UNGATED_EXPORT_PATH, method="DELETE", authorization=bearing(A_TOKEN))

        assert response.status_code == 403

    def test_it_is_not_honoured_when_the_key_holds_another_object(self) -> None:
        app = a_bearer_app()
        relay = Relay(app)
        relay.plant({key: object() for key in relay.entries})

        response = app.ask(UNGATED_EXPORT_PATH, method="DELETE", authorization=bearing(A_TOKEN))

        assert response.status_code == 403

    def test_it_is_not_a_bearer_caller_on_another_path(self) -> None:
        app = a_bearer_app()
        Relay(app).plant()

        response = app.ask(UNGATED_EXPORT_PATH, authorization=bearing(A_TOKEN), cookie=True)

        assert response.status_code == 500

    def test_a_replay_on_its_own_path_is_verified_again(self) -> None:
        app = a_bearer_app()
        Relay(app).plant()
        app.clock.now = float(EXPIRY + ACCESS_TOKEN_LEEWAY_SECONDS)

        response = app.ask(authorization=bearing(A_TOKEN))

        assert (response.status_code, response.headers["www-authenticate"]) == (
            401,
            REALM_INVALID_TOKEN,
        )
        assert_answers_no_store(response)
        assert app.auth.route_runs == []

    def test_a_replay_without_the_header_is_refused(self) -> None:
        app = a_bearer_app()
        Relay(app).plant()

        response = app.ask()

        assert (response.status_code, response.headers["www-authenticate"]) == (401, REALM)
        assert_answers_no_store(response)
        assert app.auth.route_runs == []


class Rewriting:
    """A host middleware inside the stack that rewrites the request's header lines."""

    def __init__(self, app: ASGIApp, rewrite: Callable[[list[tuple[bytes, bytes]]], list[Any]]):
        self._app = app
        self._rewrite = rewrite

    async def __call__(self, scope: Scope, receive: Receive, send: Send) -> None:
        if scope["type"] == "http":
            scope["headers"] = self._rewrite(list(scope["headers"]))
        await self._app(scope, receive, send)


def without_authorization(headers: list[tuple[bytes, bytes]]) -> list[tuple[bytes, bytes]]:
    return [(name, value) for name, value in headers if name != b"authorization"]


@pytest.mark.parametrize(
    "rewrite",
    [
        pytest.param(
            lambda headers: [*without_authorization(headers), (b"authorization", b"Bearer other")],
            id="M03a-replaces",
        ),
        pytest.param(without_authorization, id="M03b-removes"),
        pytest.param(
            lambda headers: [*headers, (b"authorization", b"Bearer second")],
            id="M03c-duplicates",
        ),
    ],
)
def test_a_header_changed_after_admission_voids_the_caller(
    rewrite: Callable[[list[tuple[bytes, bytes]]], list[Any]],
) -> None:
    app = a_bearer_app(inner_middleware=(Middleware(Rewriting, rewrite=rewrite),))

    response = app.ask(authorization=bearing(A_TOKEN))

    assert response.status_code == 500
    assert_answers_no_store(response)


class TestTheGateSitsInsideTheRateLimitAndBodyLimitAndBehindTheHeaders:
    def test_a_bearer_request_spends_the_same_rate_budget(self) -> None:
        budget = RateLimitPolicy(default=RateLimitBudget("api", 1, 60))
        app = a_bearer_app(policies={"rate_limit": budget})

        app.ask(authorization=bearing(A_TOKEN))
        second = app.ask(authorization=bearing(A_TOKEN))

        assert (second.status_code, "retry-after" in second.headers) == (429, True)
        assert_answers_no_store(second)

    def test_a_body_over_the_limit_is_refused_before_the_token_is_read(self) -> None:
        app = a_bearer_app(policies={"body_size": BodySizePolicy(default_max_bytes=100)})

        response = app.ask(method="DELETE", authorization=bearing(A_TOKEN), content=b"x" * 101)

        assert response.status_code == 413
        assert_answers_no_store(response)
        assert app.key_sets.fetched_urls == []

    def test_a_machine_route_that_raises_answers_the_library_500(self) -> None:
        app = a_bearer_app()

        response = app.ask("/api/admin/boom", authorization=bearing(A_TOKEN))

        assert response.status_code == 500
        assert_answers_no_store(response)

    def test_a_host_cache_rule_on_the_machine_prefix_loses_to_no_store(self) -> None:
        app = FastAPI()
        install_web_auth_config(app, a_web_auth_config())
        install_web_auth_middleware(
            app,
            sign_in_paths=GATED_SIGN_IN_PATHS,
            security_headers=SecurityHeadersPolicy(
                content_security_policy="default-src 'self'",
                cache_control_rules=(CacheControlRule(MACHINE_PATHS, "public, max-age=60"),),
            ),
            csrf_origin=CsrfPolicy(),
            bearer_gate=a_bearer_gate(),
        )
        app.add_api_route(EXPORT_PATH, lambda: {"ok": True}, methods=["GET"])
        client = TestClient(app, base_url=HTTPS_TEST_SERVER)

        response = client.get(EXPORT_PATH, headers={"authorization": f"Bearer {A_TOKEN}"})

        assert (response.status_code, response.headers["cache-control"]) == (200, "no-store")
        assert "set-cookie" not in response.headers


class TestAGatedPathAnswersAsDocumented:
    def test_the_caller_holds_the_subject_alone_and_no_account_appears(self) -> None:
        """MACHINE-02: the caller is the token's `sub` with no account and no role."""
        app = a_bearer_app()

        @app.auth.app.get(CALLER_PATH)
        def caller_of(caller: BearerCaller = Depends(bearer_caller)) -> dict[str, str]:
            return asdict(caller)

        accounts_before = the_accounts(app)

        response = app.ask(CALLER_PATH, authorization=bearing(A_TOKEN))

        assert (response.status_code, response.json()) == (200, {"subject": OPERATOR_SUBJECT})
        assert the_accounts(app) == accounts_before

    def test_an_admission_creates_nothing_and_emits_no_event(self) -> None:
        """MACHINE-04, MACHINE-12, MACHINE-13: an admission creates nothing and audits nothing."""
        app = a_bearer_app()
        accounts_before = the_accounts(app)
        session_before = asdict(app.auth.sessions.stored_record)

        response = app.ask(authorization=bearing(A_TOKEN))

        assert response.status_code == 200
        assert the_accounts(app) == accounts_before
        assert the_transaction(app).entries == 0
        assert asdict(app.auth.sessions.stored_record) == session_before
        assert app.audit.account_events == []

    @pytest.mark.parametrize(
        ("arrangement", "ask", "status"),
        [
            pytest.param(
                {}, lambda app: app.ask(authorization=bearing(A_TOKEN)), 200, id="admitted"
            ),
            pytest.param({}, lambda app: app.ask(), 401, id="no-credential"),
            pytest.param(
                {},
                lambda app: app.ask(authorization=(f"Bearer {A_TOKEN}", f"Bearer {A_TOKEN}")),
                401,
                id="malformed",
            ),
            pytest.param(
                {}, lambda app: app.ask(authorization=("Bearer abc!def",)), 401, id="invalid"
            ),
            pytest.param(
                {}, lambda app: app.ask(authorization=bearing(NOT_ADMIN)), 403, id="not-admin"
            ),
            pytest.param(
                {},
                lambda app: app.ask(RAISING_PATH, authorization=bearing(A_TOKEN)),
                500,
                id="route-raises",
            ),
            pytest.param(
                {},
                lambda app: app.ask(f"{EXPORT_PATH}/none", authorization=bearing(A_TOKEN)),
                404,
                id="no-such-route",
            ),
            pytest.param(
                {
                    "policies": {
                        "rate_limit": RateLimitPolicy(default=RateLimitBudget("api", 1, 60))
                    }
                },
                lambda app: [app.ask(authorization=bearing(A_TOKEN)) for _ in range(2)][-1],
                429,
                id="rate-limited",
            ),
            pytest.param(
                {"policies": {"body_size": BodySizePolicy(default_max_bytes=100)}},
                lambda app: app.ask(
                    method="DELETE", authorization=bearing(A_TOKEN), content=b"x" * 101
                ),
                413,
                id="body-too-large",
            ),
        ],
    )
    def test_every_answer_is_no_store_and_sets_no_cookie(
        self,
        arrangement: dict[str, Any],
        ask: Callable[[BearerApp], Any],
        status: int,
    ) -> None:
        """MACHINE-17, MACHINE-18: every answer on a gated path is `no-store` and sets no cookie."""
        app = a_bearer_app(**arrangement)

        response = ask(app)

        assert response.status_code == status
        assert_answers_no_store(response)

    @COOKIE_KINDS
    @pytest.mark.parametrize(
        ("authorization", "status"),
        [
            pytest.param(bearing(A_TOKEN), 200, id="admin-token"),
            pytest.param((), 401, id="no-token"),
            pytest.param(bearing(NOT_ADMIN), 403, id="not-an-admin-token"),
        ],
    )
    def test_the_cookie_decides_nothing_beside_any_credential(
        self,
        cookie_kind: str,
        authorization: tuple[str, ...],
        status: int,
    ) -> None:
        """MACHINE-14: the answer on a gated path is the same whatever cookie comes with it."""
        app = a_bearer_app()

        response = app.ask(authorization=authorization, headers=cookies_of(app, cookie_kind))

        assert response.status_code == status

    @pytest.mark.parametrize(
        ("authorization", "status"),
        [
            pytest.param(bearing(A_TOKEN), 200, id="admin-token"),
            pytest.param((), 401, id="no-token"),
            pytest.param(("Bearer abc!def",), 401, id="invalid-token"),
            pytest.param(bearing(NOT_ADMIN), 403, id="not-an-admin-token"),
        ],
    )
    def test_the_csrf_check_decides_nothing_for_a_forged_looking_request(
        self,
        authorization: tuple[str, ...],
        status: int,
    ) -> None:
        """MACHINE-15: a DELETE from a foreign page is answered by the bearer gate alone."""
        app = a_bearer_app()

        response = app.ask(method="DELETE", authorization=authorization, headers=FOREIGN_PAGE)

        assert response.status_code == status

    @COOKIE_KINDS
    def test_the_session_id_of_a_bearer_request_is_nobodys_whatever_cookie_it_carries(
        self,
        cookie_kind: str,
    ) -> None:
        """MACHINE-20: `session_id_from_request` answers `None` on a gated path."""
        app = a_bearer_app()

        response = app.ask(
            MACHINE_SESSION_PATH,
            authorization=bearing(A_TOKEN),
            headers=cookies_of(app, cookie_kind),
        )

        assert (response.status_code, response.json()) == (200, {"session": None})

    @pytest.mark.parametrize(
        ("authorization", "status"),
        [
            pytest.param(bearing(A_TOKEN), 200, id="admin-token"),
            pytest.param(("Bearer abc!def",), 401, id="invalid-token"),
        ],
    )
    @pytest.mark.parametrize(
        ("exempt", "covered"),
        [
            pytest.param(PathRules(), True, id="covered"),
            pytest.param(MACHINE_PATHS, False, id="exempt"),
        ],
    )
    def test_a_rate_policy_bounds_the_requests_it_covers_invalid_tokens_included(
        self,
        authorization: tuple[str, ...],
        status: int,
        exempt: PathRules,
        covered: bool,
    ) -> None:
        """MACHINE-21, MACHINE-22: a covering rate policy bounds valid and invalid tokens alike."""
        budget = RateLimitPolicy(default=RateLimitBudget("api", 2, 60), exempt=exempt)
        app = a_bearer_app(policies={"rate_limit": budget})

        answered = [app.ask(authorization=authorization).status_code for _ in range(4)]

        assert answered == ([status, status, 429, 429] if covered else [status] * 4)

    def test_a_bearer_request_and_a_browser_request_spend_one_budget(self) -> None:
        """MACHINE-06: bearer requests share the per-address budget of browser requests."""
        budget = RateLimitPolicy(default=RateLimitBudget("api", 1, 60))
        browser_first = a_bearer_app(policies={"rate_limit": budget})
        bearer_first = a_bearer_app(policies={"rate_limit": budget})

        browser_first.ask("/me", cookie=True)
        bearer_first.ask(authorization=bearing(A_TOKEN))

        assert browser_first.ask(authorization=bearing(A_TOKEN)).status_code == 429
        assert bearer_first.ask("/me", cookie=True).status_code == 429

    @pytest.mark.parametrize(
        ("seconds_past_expiry", "status"),
        [
            pytest.param(-1, 200, id="before-expiry"),
            pytest.param(0, 200, id="at-expiry"),
            pytest.param(ACCESS_TOKEN_LEEWAY_SECONDS - 1, 200, id="inside-the-leeway"),
            pytest.param(ACCESS_TOKEN_LEEWAY_SECONDS, 401, id="at-expiry-plus-leeway"),
        ],
    )
    def test_a_token_is_admitted_until_expiry_plus_leeway_and_the_issuer_is_asked_nothing_else(
        self,
        seconds_past_expiry: int,
        status: int,
    ) -> None:
        """MACHINE-24: the gate decides a token by its expiry and the key set, nothing the issuer
        has decided since."""
        app = a_bearer_app()
        app.clock.now = float(EXPIRY + seconds_past_expiry)

        response = app.ask(authorization=bearing(A_TOKEN))

        assert response.status_code == status
        assert set(app.key_sets.fetched_urls) == {REALM_JWKS_URL}


class TestAWebSocketIsNotGated:
    @pytest.mark.parametrize(
        "headers",
        [
            pytest.param({}, id="no-token"),
            pytest.param({"authorization": f"Bearer {A_TOKEN}"}, id="admin-token"),
            pytest.param({"authorization": "Bearer abc!def"}, id="invalid-token"),
        ],
    )
    def test_a_websocket_scope_on_a_gated_path_reaches_the_app_untouched(
        self,
        headers: dict[str, str],
    ) -> None:
        """MACHINE-31: a WebSocket scope on a gated path passes the bearer gate unread."""
        app = a_bearer_app()

        @app.auth.app.websocket(SOCKET_PATH)
        async def socket(websocket: WebSocket) -> None:
            await websocket.accept()
            await websocket.send_json({"reached": True})
            await websocket.close()

        with app.auth.client.websocket_connect(SOCKET_PATH, headers=headers) as connection:
            assert connection.receive_json() == {"reached": True}
        assert app.key_sets.fetched_urls == []
