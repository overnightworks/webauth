"""The session gate: every route needs a live session, except the host's public paths."""

from __future__ import annotations

from contextlib import nullcontext
from dataclasses import dataclass, field
from datetime import UTC, datetime, timedelta
from enum import Enum
from typing import TYPE_CHECKING, Any

import anyio
import pytest
from fastapi import FastAPI
from httpx import Response
from starlette.websockets import WebSocketDisconnect
from webauth_arrangement import (
    ADMIN_ROLE,
    ADMITTED_ADMIN_AFTER_CURRENT_USER_PATH,
    ADMITTED_ADMIN_DEPENDENCY_PATH,
    ADMITTED_ADMIN_PATH,
    ADMITTED_ADMIN_PATHS,
    ALL_DEPENDENCIES_PATH,
    ALLOWED_ORIGIN,
    GATED_APP_HEADERS_POLICY,
    LOGIN_REDIRECT,
    MEMBER_ROLE,
    WEBSOCKET_ADMITTED_ADMIN_PATH,
    WEBSOCKET_ADMITTED_PATH,
    WEBSOCKET_PATH,
    AuthApp,
    FakeUser,
    SessionRecordsInMemory,
    SessionsFailingToLoad,
    SessionsRecordingTheirTransaction,
    SessionsThatMustNotBeAsked,
    UsersInMemory,
    a_csrf_passing_request_headers,
    a_session,
    a_web_auth_config,
    an_auth_app,
    an_http_scope,
    assert_carries_policy_headers,
    drive,
    session_cookie_header,
    starts,
)

from webauth.dependencies import ConnectionRefusal
from webauth.policies import (
    BodySizePolicy,
    CsrfPolicy,
    PathRules,
    PublicRule,
    RateLimitBudget,
    RateLimitPolicy,
)
from webauth.ports import AuthenticatedUser, SessionTransaction

if TYPE_CHECKING:
    from collections.abc import Callable

    from starlette.types import ASGIApp, Receive, Scope, Send

LOGIN_PATH = "/login"
HTML = "text/html"
OUTSIDE_LIFETIME = timedelta(minutes=-5)
FOREIGN_ORIGIN = "https://evil.test"
BODY_LIMIT_BYTES = 100

ONLY_LOGIN_AND_HEALTH = (PublicRule(PathRules(exact=frozenset({LOGIN_PATH, "/health"}))),)


def a_gated_app(
    record: Any = None, *, public: tuple[PublicRule, ...] = (), **keywords: Any,
) -> AuthApp:
    """A gated application with a login redirect, whose server errors answer 500."""
    return an_auth_app(
        a_session() if record is None else record,
        gate=True,
        login_redirect=LOGIN_REDIRECT,
        public=public,
        raise_server_exceptions=False,
        **keywords,
    )


def a_plain_app(record: Any, **keywords: Any) -> AuthApp:
    """The same application guarded by the route dependency alone."""
    return an_auth_app(record, login_redirect=LOGIN_REDIRECT, **keywords)


def ask(
    app: AuthApp,
    path: str,
    *,
    method: str = "GET",
    cookie: str | None = None,
    accept: str | None = None,
    headers: dict[str, str] | None = None,
) -> Response:
    sent = dict(headers or {})
    if cookie is not None:
        sent["cookie"] = cookie
    if accept is not None:
        sent["accept"] = accept
    return app.client.request(method, path, headers=sent, follow_redirects=False)


def signed_in(app: AuthApp) -> str:
    return session_cookie_header(app.signed_cookie())


def assert_answers_alike(gated: Response, plain: Response) -> None:
    assert gated.status_code == plain.status_code
    assert gated.content == plain.content
    assert {name: gated.headers[name] for name in plain.headers} == dict(plain.headers)


def counted(sessions: SessionsRecordingTheirTransaction, name: str) -> int:
    return sessions.event_names.count(name)


class TestPublicPaths:
    @pytest.mark.parametrize("signed_in_session", [False, True], ids=["signed-out", "signed-in"])
    def test_a_public_path_passes_untouched_and_asks_no_store(
        self, signed_in_session: bool,
    ) -> None:
        app = a_gated_app(
            None, public=ONLY_LOGIN_AND_HEALTH, sessions=SessionsThatMustNotBeAsked(),
        )
        response = ask(app, "/health", cookie=signed_in(app) if signed_in_session else None)
        assert (response.status_code, response.json()) == (200, {"username": None})

    def test_a_method_rule_opens_only_the_methods_it_names(self) -> None:
        hooks = PublicRule(PathRules(prefixes=("/hooks/",)), methods=frozenset({"POST"}))
        app = a_gated_app(None, public=(hooks,), sessions=SessionsThatMustNotBeAsked())
        assert ask(app, "/hooks/x", method="POST").status_code == 200
        navigation = ask(app, "/hooks/x", accept=HTML)
        assert (navigation.status_code, navigation.headers["location"]) == (
            302, "/login?next=%2Fhooks%2Fx",
        )
        for method in ("HEAD", "OPTIONS"):
            assert ask(app, "/hooks/x", method=method).status_code == 401

    def test_a_rule_naming_head_opens_head(self) -> None:
        hooks = PublicRule(PathRules(prefixes=("/hooks/",)), methods=frozenset({"POST", "HEAD"}))
        app = a_gated_app(None, public=(hooks,), sessions=SessionsThatMustNotBeAsked())
        assert ask(app, "/hooks/x", method="HEAD").status_code == 200


class TestRefusalsAreTheDependencysBytes:
    def test_a_page_without_a_session_is_redirected_to_the_start_route_with_next(self) -> None:
        gated, plain = a_gated_app(), a_plain_app(a_session())
        response = ask(gated, "/me", accept=HTML)
        assert (response.status_code, response.headers["location"], response.json()) == (
            302, "/login?next=%2Fme", {"detail": "Found"},
        )
        assert_answers_alike(response, ask(plain, "/me", accept=HTML))
        assert_carries_policy_headers(response.headers, GATED_APP_HEADERS_POLICY, hsts=True)

    def test_an_api_call_without_a_session_gets_401_authentication_required(self) -> None:
        gated, plain = a_gated_app(), a_plain_app(a_session())
        response = ask(gated, "/me")
        assert (response.status_code, response.json()) == (
            401, {"detail": "Authentication required"},
        )
        assert_answers_alike(response, ask(plain, "/me"))
        assert_carries_policy_headers(response.headers, GATED_APP_HEADERS_POLICY, hsts=True)

    @pytest.mark.parametrize("accept", [None, HTML], ids=["fetch", "navigation"])
    @pytest.mark.parametrize(
        ("detail", "record", "cookie_of"),
        [
            pytest.param(
                "Invalid session", a_session, lambda app: session_cookie_header("forged.signature"),
                id="forged",
            ),
            pytest.param(
                "Invalid session", a_session,
                lambda app: session_cookie_header(app.signed_cookie(), app.signed_cookie()),
                id="doubled",
            ),
            pytest.param(
                "Session expired", lambda: a_session(remaining=OUTSIDE_LIFETIME), signed_in,
                id="outside-its-lifetime",
            ),
            pytest.param("Session expired", lambda: None, signed_in, id="deleted"),
        ],
    )
    def test_a_session_that_is_not_live_is_refused_as_the_dependency_refuses_it(
        self,
        detail: str,
        record: Callable[[], Any],
        cookie_of: Callable[[AuthApp], str],
        accept: str | None,
    ) -> None:
        gated = a_gated_app(sessions=SessionRecordsInMemory(record()))
        plain = a_plain_app(None, sessions=SessionRecordsInMemory(record()))
        response = ask(gated, "/me", cookie=cookie_of(gated), accept=accept)
        assert_answers_alike(response, ask(plain, "/me", cookie=cookie_of(plain), accept=accept))
        if accept is None:
            assert (response.status_code, response.json()) == (401, {"detail": detail})
        else:
            assert response.status_code == 302
        assert gated.route_runs == []


class TestAdmission:
    @pytest.mark.parametrize(
        "provider_of",
        [
            pytest.param(lambda sessions: sessions.in_transaction, id="transaction"),
            pytest.param(lambda sessions: (lambda: nullcontext(sessions)), id="nullcontext"),
        ],
    )
    def test_a_live_session_is_admitted_and_renewed_once_with_either_provider(
        self, provider_of: Callable[[SessionsRecordingTheirTransaction], SessionTransaction],
    ) -> None:
        record = a_session()
        before = record.expires_at
        sessions = SessionsRecordingTheirTransaction(record)
        app = a_gated_app(record, sessions=sessions, session_transaction=provider_of(sessions))
        response = ask(app, "/optional", cookie=signed_in(app))
        assert (response.status_code, response.json()) == (200, {"username": "alice"})
        assert (counted(sessions, "load"), counted(sessions, "touch")) == (1, 1)
        assert record.expires_at > before


class TestRouterPaths:
    def test_public_rules_are_written_as_the_routes_are_under_a_root_path(self) -> None:
        app = a_gated_app(None, public=ONLY_LOGIN_AND_HEALTH, root_path="/app")
        assert ask(app, "/app/login").status_code == 200
        assert ask(app, "/login").status_code == 200
        redirect = ask(app, "/app/me", accept=HTML)
        assert redirect.headers["location"] == "/login?next=%2Fapp%2Fme"
        assert ask(app, redirect.headers["location"]).status_code == 200
        assert ask(app, "/app").status_code == 401
        assert ask(app, "/appx/login").status_code == 401

    def test_a_mounted_app_is_judged_by_its_full_path_under_the_top_apps_gate(self) -> None:
        app = a_gated_app(
            None, public=(PublicRule(PathRules(exact=frozenset({"/sub/health"}))),),
        )
        sub = FastAPI()
        sub.add_api_route("/health", lambda: {"mounted": True})
        sub.add_api_route("/me", lambda: {"mounted": True})
        app.app.mount("/sub", sub)
        assert ask(app, "/sub/health").status_code == 200
        redirect = ask(app, "/sub/me", accept=HTML)
        assert (redirect.status_code, redirect.headers["location"]) == (
            302, "/login?next=%2Fsub%2Fme",
        )

    @pytest.mark.parametrize(
        ("raw_path", "path"),
        [
            pytest.param(b"/static/../me", "/static/../me", id="dot-dot"),
            pytest.param(b"/static/%2e%2e/me", "/static/../me", id="encoded-dot-dot"),
            pytest.param(b"/static/%2E/x.css", "/static/./x.css", id="encoded-dot"),
            pytest.param(b"/static%2F..%2Fme", "/static/../me", id="encoded-slashes"),
            pytest.param(
                b"/static/x%3f/%2e%2e/secret", "/static/x?/../secret", id="encoded-question-mark",
            ),
            pytest.param(
                b"/opt/x%3f/%2e%2e/secret", "/opt/x?/../secret",
                id="optional-encoded-question-mark",
            ),
            pytest.param(b"/health/", "/health/", id="trailing-slash"),
            pytest.param(b"//health", "//health", id="doubled-slash"),
            pytest.param(b"/opt/../me", "/opt/../me", id="optional-with-dot-segment"),
        ],
    )
    def test_a_path_that_is_not_the_one_a_rule_names_is_gated(
        self, raw_path: bytes, path: str,
    ) -> None:
        public = PublicRule(PathRules(prefixes=("/static/",), exact=frozenset({"/health"})))
        app = a_gated_app(None, public=(public,), optional=PathRules(prefixes=("/opt/",)))
        assert status_of(app, path, raw_path) == 401

    def test_the_path_the_router_routes_is_the_one_judged(self) -> None:
        public = PublicRule(PathRules(prefixes=("/static/",)))
        app = a_gated_app(None, public=(public,))
        assert status_of(app, "/static/x.css", b"/static%2Fx.css") == 200


def status_of(app: AuthApp, path: str, raw_path: bytes) -> int:
    scope = an_http_scope(app.app, path, raw_path=raw_path)
    messages, raised = anyio.run(drive, app.app, scope)
    assert raised is None
    return starts(messages)[0]["status"]


class TestWebSocket:
    def test_a_handshake_passes_the_gate_and_the_handshake_owner_decides_it(self) -> None:
        app = a_gated_app()
        with app.client, app.connect(WEBSOCKET_PATH, cookie=app.signed_cookie()) as socket:
            assert socket.receive_json()["username"] == "alice"
        with app.client, pytest.raises(WebSocketDisconnect), app.connect(WEBSOCKET_PATH):
            pass
        assert app.websocket_outcomes[-1] is ConnectionRefusal.NO_SESSION

    def test_the_admitted_user_of_a_websocket_is_an_error_behind_the_gate(self) -> None:
        app = a_gated_app()
        with pytest.raises(RuntimeError), app.connect(
            WEBSOCKET_ADMITTED_PATH, cookie=app.signed_cookie(),
        ):
            pass


class TestOptionalPaths:
    OPTIONAL = PathRules(exact=frozenset({"/optional"}))

    def test_without_a_session_the_route_runs_with_no_user_and_asks_no_store(self) -> None:
        app = a_gated_app(
            None, optional=self.OPTIONAL, sessions=SessionsThatMustNotBeAsked(),
        )
        assert ask(app, "/optional").json() == {"username": None}

    def test_with_a_live_session_the_route_gets_the_user_renewed_once(self) -> None:
        record = a_session()
        sessions = SessionsRecordingTheirTransaction(record)
        app = a_gated_app(record, optional=self.OPTIONAL, sessions=sessions)
        assert ask(app, "/optional", cookie=signed_in(app)).json() == {"username": "alice"}
        assert (counted(sessions, "load"), counted(sessions, "touch")) == (1, 1)

    def test_a_dead_session_passes_as_no_user_without_a_refusal(self) -> None:
        app = a_gated_app(a_session(remaining=OUTSIDE_LIFETIME), optional=self.OPTIONAL)
        assert ask(app, "/optional", cookie=signed_in(app)).json() == {"username": None}

    def test_a_failing_store_is_the_library_500_never_an_anonymous_pass(self) -> None:
        app = a_gated_app(
            a_session(), optional=self.OPTIONAL, sessions=SessionsFailingToLoad(a_session()),
        )
        response = ask(app, "/optional", cookie=signed_in(app))
        assert response.status_code == 500
        assert_carries_policy_headers(response.headers, GATED_APP_HEADERS_POLICY, hsts=True)
        assert app.route_runs == []


class TestTransaction:
    def test_a_failing_commit_answers_the_library_500_and_rolls_the_renewal_back(self) -> None:
        record = a_session()
        before = record.expires_at
        sessions = SessionsRecordingTheirTransaction(record)
        sessions.commit_failure = ConnectionError("commit failed")
        app = a_gated_app(record, sessions=sessions)
        response = ask(app, "/optional", cookie=signed_in(app))
        assert response.status_code == 500
        assert_carries_policy_headers(response.headers, GATED_APP_HEADERS_POLICY, hsts=True)
        assert app.route_runs == []
        assert sessions.record is not None
        assert sessions.record.expires_at == before

    def test_the_transaction_is_opened_used_and_committed_before_the_route_runs(self) -> None:
        sessions = SessionsRecordingTheirTransaction(a_session())
        app = a_gated_app(None, sessions=sessions)
        assert ask(app, "/optional", cookie=signed_in(app)).status_code == 200
        assert sessions.event_names == ["open", "load", "touch", "commit", "route"]

    def test_the_whole_transaction_runs_on_one_worker_thread_off_the_route_thread(self) -> None:
        sessions = SessionsRecordingTheirTransaction(a_session())
        app = a_gated_app(None, sessions=sessions)
        ask(app, "/optional", cookie=signed_in(app))
        worker_threads = {
            thread for name, thread in sessions.events if name != "route"
        }
        assert len(worker_threads) == 1
        assert worker_threads.isdisjoint(app.route_threads)


class TestAdmittedUser:
    def test_it_is_an_error_where_no_gate_is_installed(self) -> None:
        app = an_auth_app(a_session())
        cookie = signed_in(app)
        with pytest.raises(RuntimeError):
            ask(app, "/health", cookie=cookie)


AUTHENTICATION_REQUIRED = {"detail": "Authentication required"}
ADMIN_REQUIRED = {"detail": "Admin access required"}
OPERATOR_ROLE = "operator"


def a_gated_app_of(role: str, **keywords: Any) -> AuthApp:
    return a_gated_app(a_session(user=FakeUser(role=role)), **keywords)


class TestAdmittedAdmin:
    @pytest.mark.parametrize("path", ADMITTED_ADMIN_PATHS)
    def test_a_session_with_the_admin_role_gets_its_account(self, path: str) -> None:
        app = a_gated_app_of(ADMIN_ROLE)
        response = ask(app, path, cookie=signed_in(app))
        assert (response.status_code, response.json()) == (200, {"username": "alice"})

    @pytest.mark.parametrize("path", [*ADMITTED_ADMIN_PATHS, "/admin"])
    def test_a_session_with_another_role_is_refused_as_admin_user_refuses_it(
        self, path: str,
    ) -> None:
        app = a_gated_app_of(MEMBER_ROLE)
        response = ask(app, path, cookie=signed_in(app))
        assert (response.status_code, response.json()) == (403, ADMIN_REQUIRED)

    @pytest.mark.parametrize("path", ADMITTED_ADMIN_PATHS)
    @pytest.mark.parametrize(
        ("role", "expected_status"),
        [(OPERATOR_ROLE, 200), (ADMIN_ROLE, 403)],
        ids=["the-configured-role", "the-literal-admin"],
    )
    def test_the_configured_admin_role_is_the_one_judged(
        self, path: str, role: str, expected_status: int,
    ) -> None:
        config = a_web_auth_config(admin_role=OPERATOR_ROLE)
        app = a_gated_app_of(role, config=config)
        response = ask(app, path, cookie=signed_in(app))
        assert response.status_code == expected_status

    @pytest.mark.parametrize("path", ADMITTED_ADMIN_PATHS)
    @pytest.mark.parametrize(
        ("accept", "expected_status"), [(HTML, 302), (None, 401)], ids=["page", "fetch"],
    )
    def test_the_gate_refuses_a_signed_out_request_on_a_gated_path_before_the_route(
        self, path: str, accept: str | None, expected_status: int,
    ) -> None:
        app = a_gated_app()
        response = ask(app, path, accept=accept)
        assert response.status_code == expected_status
        assert app.route_runs == []

    @pytest.mark.parametrize("path", ADMITTED_ADMIN_PATHS)
    @pytest.mark.parametrize("accept", [HTML, None], ids=["page", "fetch"])
    def test_where_the_gate_admitted_no_account_it_answers_401_and_never_redirects(
        self, path: str, accept: str | None,
    ) -> None:
        app = a_gated_app(optional=PathRules(exact=frozenset(ADMITTED_ADMIN_PATHS)))
        response = ask(app, path, accept=accept)
        assert (response.status_code, response.json()) == (401, AUTHENTICATION_REQUIRED)
        assert "location" not in response.headers

    @pytest.mark.parametrize("path", ADMITTED_ADMIN_PATHS)
    @pytest.mark.parametrize("dead", ["expired", "deleted"])
    def test_a_dead_admin_session_on_an_optional_path_is_401_and_asked_once_by_the_gate(
        self, path: str, dead: str,
    ) -> None:
        record = a_session(
            user=FakeUser(role=ADMIN_ROLE),
            remaining=OUTSIDE_LIFETIME if dead == "expired" else timedelta(minutes=30),
        )
        sessions = SessionsRecordingTheirTransaction(None if dead == "deleted" else record)
        app = a_gated_app(
            optional=PathRules(exact=frozenset(ADMITTED_ADMIN_PATHS)), sessions=sessions,
        )
        response = ask(app, path, cookie=signed_in(app))
        assert (response.status_code, response.json()) == (401, AUTHENTICATION_REQUIRED)
        assert counted(sessions, "load") == 1

    def test_the_admission_a_dependency_makes_on_a_public_path_is_not_the_gates(self) -> None:
        public = PublicRule(PathRules(exact=frozenset({ADMITTED_ADMIN_AFTER_CURRENT_USER_PATH})))
        app = a_gated_app_of(ADMIN_ROLE, public=(public,))
        response = ask(app, ADMITTED_ADMIN_AFTER_CURRENT_USER_PATH, cookie=signed_in(app))
        assert [user.username for user in app.authenticated] == ["alice"]
        assert (response.status_code, response.json()) == (401, AUTHENTICATION_REQUIRED)

    def test_it_is_an_error_where_no_gate_is_installed(self) -> None:
        app = an_auth_app(a_session(user=FakeUser(role=ADMIN_ROLE)))
        cookie = signed_in(app)
        with pytest.raises(RuntimeError):
            ask(app, ADMITTED_ADMIN_PATH, cookie=cookie)

    def test_the_admitted_admin_of_a_websocket_is_an_error_behind_the_gate(self) -> None:
        app = a_gated_app_of(ADMIN_ROLE)
        with pytest.raises(RuntimeError), app.connect(
            WEBSOCKET_ADMITTED_ADMIN_PATH, cookie=app.signed_cookie(),
        ):
            pass


class Rule(Enum):
    GATED = "gated"
    OPTIONAL = "optional"
    PUBLIC = "public"


@dataclass(frozen=True)
class Reuse:
    path: str
    mode: Rule = Rule.GATED
    role: str = MEMBER_ROLE
    dead: bool = False
    expected_status: int = 200
    gate_counts: tuple[int, int] = (1, 1)
    authenticated: int = 1


class TestTheGatesAdmissionIsTheDependencys:
    @pytest.mark.parametrize(
        "case",
        [
            pytest.param(Reuse("/me"), id="current-user"),
            pytest.param(Reuse("/admin", role=ADMIN_ROLE), id="admin"),
            pytest.param(
                Reuse("/admin", expected_status=403, authenticated=1), id="non-admin",
            ),
            pytest.param(Reuse("/session-id"), id="verified-session-id"),
            pytest.param(Reuse(ALL_DEPENDENCIES_PATH, role=ADMIN_ROLE), id="all-three"),
            pytest.param(Reuse("/me", mode=Rule.OPTIONAL), id="optional-live"),
            pytest.param(
                Reuse(
                    "/me", mode=Rule.OPTIONAL, dead=True, expected_status=401,
                    gate_counts=(1, 0), authenticated=0,
                ),
                id="optional-dead",
            ),
            pytest.param(Reuse("/me", mode=Rule.PUBLIC), id="public-admits-by-itself"),
        ],
    )
    def test_a_route_costs_one_load_and_one_touch_and_answers_as_without_the_gate(
        self, case: Reuse,
    ) -> None:
        def fresh() -> tuple[Any, SessionsRecordingTheirTransaction]:
            record = a_session(
                user=FakeUser(role=case.role),
                remaining=OUTSIDE_LIFETIME if case.dead else timedelta(minutes=30),
            )
            return record, SessionsRecordingTheirTransaction(record)

        record, gated_sessions = fresh()
        path_rules = PathRules(exact=frozenset({case.path}))
        gated = a_gated_app(
            record,
            sessions=gated_sessions,
            optional=path_rules if case.mode is Rule.OPTIONAL else PathRules(),
            public=(PublicRule(path_rules),) if case.mode is Rule.PUBLIC else (),
        )
        plain_record, plain_sessions = fresh()
        plain = a_plain_app(plain_record, sessions=plain_sessions)

        answer = ask(gated, case.path, cookie=signed_in(gated))
        assert_answers_alike(answer, ask(plain, case.path, cookie=signed_in(plain)))
        assert answer.status_code == case.expected_status
        gate_counts = (counted(gated_sessions, "load"), counted(gated_sessions, "touch"))
        if case.mode is Rule.PUBLIC:
            assert gate_counts == (1, 1)
        else:
            assert gate_counts == case.gate_counts
        assert len(gated.authenticated) == case.authenticated


class TestOrder:
    def test_a_forged_state_changing_request_is_refused_before_a_session_lookup(self) -> None:
        def a_full_stack_app() -> AuthApp:
            return a_gated_app(
                None,
                sessions=SessionsThatMustNotBeAsked(),
                stack_policies={
                    "body_size": BodySizePolicy(default_max_bytes=BODY_LIMIT_BYTES),
                    "rate_limit": RateLimitPolicy(default=RateLimitBudget("api", 1, 60)),
                    "csrf_origin": CsrfPolicy(),
                    "csrf_token": CsrfPolicy(),
                },
            )

        def post(app: AuthApp, *, body: bytes = b"{}", **headers: str) -> Response:
            passing = dict(
                (name.decode(), value.decode())
                for name, value in a_csrf_passing_request_headers(app.config)
            )
            passing.update(headers)
            return app.client.post(
                "/optional", content=body, headers=passing, follow_redirects=False,
            )

        assert post(a_full_stack_app(), origin=FOREIGN_ORIGIN, **{"sec-fetch-site": "cross-site"}
                    ).status_code == 403
        same_origin = {"origin": ALLOWED_ORIGIN}
        app = a_full_stack_app()
        without_token = {
            name.decode(): value.decode()
            for name, value in a_csrf_passing_request_headers(app.config)
            if name.decode() != app.config.csrf_header_name
        }
        assert app.client.post(
            "/optional", content=b"{}", headers=without_token | same_origin,
        ).status_code == 403
        assert post(
            a_full_stack_app(), body=b"x" * (BODY_LIMIT_BYTES + 1), **same_origin,
        ).status_code == 413
        spent = a_full_stack_app()
        post(spent, **same_origin)
        assert post(spent, **same_origin).status_code == 429


@dataclass
class ScopeRelay:
    """What an outer host middleware saw the inner app add to the scope, and what it replays."""

    added: dict[str, Any] = field(default_factory=dict)
    replay: dict[str, Any] = field(default_factory=dict)


class RelayingScope:
    """Outer middleware: records the scope entries the inner app adds, and plants others."""

    def __init__(self, app: ASGIApp, relay: ScopeRelay) -> None:
        self._app = app
        self._relay = relay

    async def __call__(self, scope: Scope, receive: Receive, send: Send) -> None:
        if scope["type"] != "http":
            await self._app(scope, receive, send)
            return
        known = set(scope)
        scope.update(self._relay.replay)
        await self._app(scope, receive, send)
        self._relay.added = {key: scope[key] for key in set(scope) - known}


def relayed(app: AuthApp) -> ScopeRelay:
    relay = ScopeRelay()
    app.app.add_middleware(RelayingScope, relay=relay)
    return relay


class TestARecordedAdmissionBelongsToItsRequest:
    @dataclass
    class Arrangement:
        first: AuthApp
        first_relay: ScopeRelay
        gate_entries: dict[str, Any]
        users: UsersInMemory
        sessions: SessionsRecordingTheirTransaction
        second_cookie: str

    @pytest.fixture
    def arrangement(self) -> TestARecordedAdmissionBelongsToItsRequest.Arrangement:
        first_user, second_user = FakeUser("user-1", "alice"), FakeUser("user-2", "bruno")
        users = UsersInMemory(first_user, second_user)
        now = datetime.now(UTC)
        record = a_session(user=first_user, now=now)
        sessions = SessionsRecordingTheirTransaction(record, users=users)
        second = sessions.create(
            second_user.id, now=now, expires_at=now + timedelta(minutes=30), refresh_token=None,
        )
        first = a_gated_app(
            record, sessions=sessions, public=ONLY_LOGIN_AND_HEALTH,
        )
        relay = relayed(first)
        assert ask(first, "/me", cookie=signed_in(first)).json()["username"] == "alice"
        control = a_plain_app(a_session())
        control_relay = relayed(control)
        ask(control, "/me", cookie=signed_in(control))
        return self.Arrangement(
            first=first,
            first_relay=relay,
            gate_entries={
                key: value for key, value in relay.added.items()
                if key not in control_relay.added
            },
            users=users,
            sessions=sessions,
            second_cookie=session_cookie_header(first.signed_cookie(second.id)),
        )

    def test_a_replay_on_the_gated_app_is_decided_by_the_gate_itself(
        self, arrangement: Arrangement,
    ) -> None:
        assert arrangement.gate_entries
        arrangement.first_relay.replay = arrangement.gate_entries
        assert ask(arrangement.first, "/me").json() == {"detail": "Authentication required"}
        assert ask(arrangement.first, "/health").json() == {"username": None}

    @pytest.mark.parametrize("planted", ["replayed", "an-account-under-each-key"])
    def test_a_replay_on_an_app_with_its_own_config_is_ignored(
        self, arrangement: Arrangement, planted: str,
    ) -> None:
        other = an_auth_app(None, login_redirect=LOGIN_REDIRECT)
        relay = relayed(other)
        relay.replay = (
            arrangement.gate_entries if planted == "replayed" else {
                key: AuthenticatedUser(id="user-1", username="alice", role=MEMBER_ROLE)
                for key in arrangement.gate_entries
            }
        )
        cookie = signed_in(arrangement.first)
        assert ask(other, "/me", cookie=cookie).json() == {"detail": "Session expired"}
        with pytest.raises(RuntimeError):
            ask(other, "/health", cookie=cookie)
        with pytest.raises(RuntimeError):
            ask(other, ADMITTED_ADMIN_PATH, cookie=cookie)

    def test_a_replay_on_a_shared_config_is_ignored_for_another_sessions_cookie(
        self, arrangement: Arrangement,
    ) -> None:
        shared = an_auth_app(
            None, sessions=arrangement.sessions, config=arrangement.first.config,
            login_redirect=LOGIN_REDIRECT,
        )
        relay = relayed(shared)
        relay.replay = arrangement.gate_entries
        arrangement.sessions.events.clear()
        answer = ask(shared, "/me", cookie=arrangement.second_cookie)
        assert answer.json()["username"] == "bruno"
        assert (
            counted(arrangement.sessions, "load"), counted(arrangement.sessions, "touch"),
        ) == (1, 1)
        assert ask(shared, "/me").json() == {"detail": "Authentication required"}
        with pytest.raises(RuntimeError):
            ask(shared, "/health", cookie=arrangement.second_cookie)
        with pytest.raises(RuntimeError):
            ask(shared, ADMITTED_ADMIN_PATH, cookie=arrangement.second_cookie)
        with pytest.raises(RuntimeError):
            ask(shared, "/health")

    def test_a_replay_for_the_same_cookie_is_reused_without_a_store_read(
        self, arrangement: Arrangement,
    ) -> None:
        shared = an_auth_app(
            None, sessions=arrangement.sessions, config=arrangement.first.config,
            login_redirect=LOGIN_REDIRECT,
        )
        relay = relayed(shared)
        relay.replay = arrangement.gate_entries
        arrangement.sessions.events.clear()
        cookie = signed_in(arrangement.first)
        assert ask(shared, "/me", cookie=cookie).json()["username"] == "alice"
        assert ask(shared, "/health", cookie=cookie).json() == {"username": "alice"}
        assert (
            counted(arrangement.sessions, "load"), counted(arrangement.sessions, "touch"),
        ) == (0, 0)
