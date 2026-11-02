"""The builders the bearer gate's and the session gate's tests share."""

from __future__ import annotations

from collections.abc import Mapping
from dataclasses import dataclass, field, replace
from typing import TYPE_CHECKING, Any, NoReturn

from fastapi import Depends, Request, WebSocket
from httpx import Response
from starlette.middleware import Middleware

from tests.support.oidc_arrangement import (
    ACCESS_TOKEN_NOW,
    OPERATOR_SUBJECT,
    REALM_ISSUER,
    FakeClock,
    FakeKeySetEndpoint,
    a_relying_party,
    an_access_token,
    key_set_document,
    public_jwk,
    rsa_key,
)
from tests.support.oidc_login_host import (
    RecordingSignInTransaction,
    TransactionKind,
    UsersWithSnapshots,
)
from tests.support.webauth_arrangement import (
    ADMIN_ROLE,
    GATED_STACK_POLICIES,
    MEMBER_ROLE,
    AuthApp,
    FakeSessionRecord,
    FakeUser,
    RecordingAuditSink,
    SessionRecordsInMemory,
    WriteLockInMemory,
    a_session,
    an_auth_app,
    session_cookie_header,
)
from webauth.config import web_auth_config
from webauth.dependencies import (
    LoginRedirect,
    current_user_dependency,
    session_id_from_request,
)
from webauth.middleware import (
    BearerGate,
    MachinePaths,
    PersonPaths,
    ProtectedResource,
    admitted_admin,
    admitted_user,
    bearer_caller,
    install_resource_metadata,
    install_web_auth_middleware,
    resource_person,
)
from webauth.oidc_login import AdmissionConfig
from webauth.policies import AuthorizedParties, CsrfPolicy, PathRules, PublicRule
from webauth.ports import AuthenticatedUser, BearerCaller

if TYPE_CHECKING:
    from starlette.types import ASGIApp, Receive, Scope, Send

    from webauth.ports import SignInTransaction

MACHINE_PREFIX = "/api/admin/"
PERSON_PREFIX = "/api/"
PERSON_ME_PATH = "/api/me"
PERSON_ADMIN_ME_PATH = "/api/admin-me"
PERSON_ADMITTED_ME_PATH = "/api/admitted-me"
PERSON_ADMITTED_ADMIN_PATH = "/api/admitted-admin"
PERSON_CALLER_PATH = "/api/caller"
MACHINE_AS_PERSON_PATH = "/api/admin/as-person"
MACHINE_SESSION_PATH = "/api/admin/session"
FOREIGN_SECRET_PATH = "/hooks/fetch"  # noqa: S105 - a path, not a credential
EXPORT_PATH = "/api/admin/export"
UNDECLARED_PATH = "/api/admin/forgotten"
RAISING_PATH = "/api/admin/boom"
PEOPLE_PATH = "/api/admin/people/{subject}/export"
UNGATED_EXPORT_PATH = "/ungated-export"
REALM = 'Bearer realm="admin"'
REALM_INVALID_REQUEST = f'{REALM}, error="invalid_request"'
REALM_INVALID_TOKEN = f'{REALM}, error="invalid_token"'
REALM_INSUFFICIENT_SCOPE = f'{REALM}, error="insufficient_scope"'
ADMISSION = AdmissionConfig(
    bound_issuer=a_relying_party().issuer, login_group="/apps/x", admin_group="/apps/x/admin",
)
HAL_ONLY = AuthorizedParties(frozenset({"hal"}))
RESOURCE_URL = "https://app.example/mcp"
RESOURCE_SCOPE = "mcp:tools"
RESOURCE_GROUP = "/apps/x/mcp"
MACHINE_PATHS = PathRules(prefixes=(MACHINE_PREFIX,))
PERSON_PATHS = PathRules(prefixes=(PERSON_PREFIX,))
FOREIGN_SECRET_PATHS = PathRules(exact=frozenset({FOREIGN_SECRET_PATH}))
FOREIGN_SECRET_PUBLIC = PublicRule(FOREIGN_SECRET_PATHS)
PERSON_REALM = 'Bearer realm="api"'
PERSON_INVALID_REQUEST = 'Bearer error="invalid_request"'
PERSON_INVALID_TOKEN = 'Bearer error="invalid_token"'
PERSON_INSUFFICIENT_SCOPE = 'Bearer error="insufficient_scope"'


def a_token(**claims: Any) -> str:
    return an_access_token(claims=claims)


def an_unbound_transaction() -> NoReturn:
    raise AssertionError("a resource was used without an app to bind its transaction")


def a_resource(
    url: str = RESOURCE_URL,
    parties: AuthorizedParties = HAL_ONLY,
    required_group: str = RESOURCE_GROUP,
    transaction: SignInTransaction = an_unbound_transaction,
) -> ProtectedResource:
    """A resource whose transaction `a_bearer_app` binds to its own when none is given."""
    return ProtectedResource(url, RESOURCE_SCOPE, required_group, parties, transaction)


def a_known_person(role: str = MEMBER_ROLE) -> FakeUser:
    """The account behind the arrangement's token subject, as a host stored it."""
    return FakeUser(id=OPERATOR_SUBJECT, username="lena", role=role)


def a_resource_token(resource: ProtectedResource | None = None, **claims: Any) -> str:
    """A token hal holds for `resource` (default `a_resource()`): its audience and its scope."""
    held = resource or a_resource()
    return an_access_token(claims={"aud": held.url, "scope": held.scope, **claims})


def bearing(token: str) -> tuple[str, ...]:
    return (f"Bearer {token}",)


def a_bearer_gate(
    *,
    paths: PathRules = MACHINE_PATHS,
    key_sets: FakeKeySetEndpoint | None = None,
    clock: FakeClock | None = None,
    person_paths: PersonPaths | None = None,
    admission: AdmissionConfig = ADMISSION,
    machine_parties: AuthorizedParties = HAL_ONLY,
    resource: ProtectedResource | None = None,
) -> BearerGate:
    """A gate whose machine paths are `paths` (none when empty), admitting `machine_parties`."""
    return BearerGate(
        relying_party=a_relying_party(fetch_key_set=key_sets, wall_clock=clock),
        admission=admission,
        machine_paths=(
            None if paths == PathRules() else MachinePaths(paths, machine_parties)
        ),
        person_paths=person_paths,
        resource=resource,
    )


def a_key_set_answering(response: bytes | Exception | None = None) -> FakeKeySetEndpoint:
    document = key_set_document(public_jwk(rsa_key("current"), "current-key"))
    return FakeKeySetEndpoint(document if response is None else response)


@dataclass
class BearerApp:
    auth: AuthApp
    key_sets: FakeKeySetEndpoint
    clock: FakeClock
    cookie: str = field(default="")
    accounts: UsersWithSnapshots | None = None
    audit: RecordingAuditSink = field(default_factory=RecordingAuditSink)
    transaction: SignInTransaction | None = None

    def ask(
        self,
        path: str = EXPORT_PATH,
        *,
        method: str = "GET",
        authorization: tuple[str, ...] = (),
        cookie: bool = False,
        headers: dict[str, str] | None = None,
        **request: Any,
    ) -> Response:
        sent = [("authorization", value) for value in authorization]
        sent += list((headers or {}).items())
        if cookie:
            sent.append(("cookie", self.cookie))
        return self.auth.client.request(method, path, headers=sent, **request)


def add_machine_routes(auth: AuthApp) -> None:
    def ran(request: Request) -> None:
        auth.route_runs.append(request.scope["path"])

    @auth.app.api_route(EXPORT_PATH, methods=["GET", "DELETE"])
    def export(
        request: Request, caller: BearerCaller = Depends(bearer_caller),
    ) -> dict[str, str]:
        ran(request)
        return {"subject": caller.subject}

    @auth.app.api_route(UNDECLARED_PATH, methods=["GET", "DELETE"])
    def forgotten(request: Request) -> dict[str, str]:
        ran(request)
        return {"ran": "without bearer_caller"}

    @auth.app.api_route(PEOPLE_PATH, methods=["GET"])
    def person(request: Request, subject: str) -> dict[str, str]:
        ran(request)
        return {"subject": subject}

    @auth.app.api_route(UNGATED_EXPORT_PATH, methods=["GET", "DELETE"])
    def ungated_export(
        request: Request, caller: BearerCaller = Depends(bearer_caller),
    ) -> dict[str, str]:
        ran(request)
        return {"subject": caller.subject}

    @auth.app.get(MACHINE_SESSION_PATH)
    def machine_session(
        request: Request, _caller: BearerCaller = Depends(bearer_caller),
    ) -> dict[str, str | None]:
        return {"session": session_id_from_request(request, web_auth_config(request))}

    @auth.app.get(RAISING_PATH)
    def raising(_caller: BearerCaller = Depends(bearer_caller)) -> None:
        raise RuntimeError("the route failed")


def add_resource_routes(auth: AuthApp, resource: ProtectedResource) -> None:
    """The resource's metadata document and the host's routes at its entry point.

    `POST` and the other methods echo `resource_person`; `PATCH` reads `current_user` and
    `DELETE` reads `admin_user`, so a request a middleware turns into one of them is judged by
    the reader it reaches.
    """
    install_resource_metadata(auth.app, resource, issuer=REALM_ISSUER)
    dependencies = current_user_dependency(
        session_store=lambda: auth.sessions, on_authenticated=auth.authenticated.append,
    )

    def echo(request: Request, user: AuthenticatedUser) -> dict[str, str]:
        auth.route_runs.append(request.scope["path"])
        return {"id": user.id, "username": user.username, "role": user.role}

    @auth.app.api_route(resource.entry_point, methods=["GET", "POST", "PUT", "HEAD", "OPTIONS"])
    def entry_point(request: Request) -> dict[str, str]:
        return echo(request, resource_person(request))

    @auth.app.patch(resource.entry_point)
    def current(
        request: Request, user: AuthenticatedUser = Depends(dependencies.current_user),
    ) -> dict[str, str]:
        return echo(request, user)

    @auth.app.delete(resource.entry_point)
    def admin(
        request: Request, user: AuthenticatedUser = Depends(dependencies.admin_user),
    ) -> dict[str, str]:
        return echo(request, user)


def add_person_routes(auth: AuthApp, login_redirect: LoginRedirect | None = None) -> None:
    """The routes under `PERSON_PREFIX` that read the person, and the foreign-secret webhook."""
    dependencies = current_user_dependency(
        session_store=lambda: auth.sessions,
        on_authenticated=auth.authenticated.append,
        login_redirect=login_redirect,
    )

    def person(request: Request, user: AuthenticatedUser) -> dict[str, str | None]:
        auth.route_runs.append(request.scope["path"])
        return {
            "id": user.id,
            "username": user.username,
            "role": user.role,
            "session": session_id_from_request(request, web_auth_config(request)),
        }

    @auth.app.api_route(PERSON_ME_PATH, methods=["GET", "POST", "DELETE"])
    def me(
        request: Request, user: AuthenticatedUser = Depends(dependencies.current_user),
    ) -> dict[str, str | None]:
        return person(request, user)

    @auth.app.get(PERSON_ADMIN_ME_PATH)
    def admin_me(
        request: Request, user: AuthenticatedUser = Depends(dependencies.admin_user),
    ) -> dict[str, str | None]:
        return person(request, user)

    @auth.app.get(PERSON_ADMITTED_ME_PATH)
    def admitted_me(request: Request) -> dict[str, str | None]:
        auth.route_runs.append(request.scope["path"])
        user = admitted_user(request)
        return {"username": None if user is None else user.username}

    @auth.app.get(PERSON_ADMITTED_ADMIN_PATH)
    def admitted_admin_me(
        request: Request, user: AuthenticatedUser = Depends(admitted_admin),
    ) -> dict[str, str | None]:
        return person(request, user)

    @auth.app.get(PERSON_CALLER_PATH)
    def caller_of_a_person_path(
        _caller: BearerCaller = Depends(bearer_caller),
    ) -> dict[str, str]:
        return {"ran": "bearer_caller on a person path"}

    @auth.app.get(MACHINE_AS_PERSON_PATH)
    def person_of_a_machine_path(
        _user: AuthenticatedUser = Depends(dependencies.current_user),
    ) -> dict[str, str]:
        return {"ran": "current_user on a machine path"}

    @auth.app.api_route(FOREIGN_SECRET_PATH, methods=["GET", "POST"])
    def foreign_secret(request: Request) -> dict[str, str]:
        auth.route_runs.append(request.scope["path"])
        return {"authorization": request.headers.get("authorization", "")}


@dataclass
class _SignInSide:
    """The host's accounts, sessions, audit and sign-in transaction over one write lock."""

    record: FakeSessionRecord
    accounts: UsersWithSnapshots
    sessions: SessionRecordsInMemory
    audit: RecordingAuditSink
    transaction: RecordingSignInTransaction


def _a_sign_in_side(
    kind: TransactionKind,
    strict: bool,
    cookie_role: str,
    known_accounts: tuple[FakeUser, ...],
    sessions: SessionRecordsInMemory | None,
) -> _SignInSide:
    cookie_person = FakeUser(role=cookie_role)
    record = a_session(user=cookie_person)
    lock = WriteLockInMemory()
    accounts = UsersWithSnapshots(cookie_person, *known_accounts, lock=lock)
    sessions = sessions or SessionRecordsInMemory(record, users=accounts, lock=lock)
    audit = RecordingAuditSink()
    transaction = RecordingSignInTransaction(
        kind, accounts=accounts, sessions=sessions, audit=audit, lock=lock, strict=strict,
    )
    return _SignInSide(record, accounts, sessions, audit, transaction)


def _stack_policies(
    gate: BearerGate | None, with_person_paths: bool, policies: dict[str, Any] | None,
) -> dict[str, Any]:
    stack: dict[str, Any] = {} if gate is None else {"bearer_gate": gate}
    if with_person_paths:
        stack["csrf_origin"] = CsrfPolicy(exempt=FOREIGN_SECRET_PATHS)
    return {**stack, **(policies or {})}


def _a_gate_over(
    paths: PathRules, key_sets: FakeKeySetEndpoint, clock: FakeClock,
    machine_parties: AuthorizedParties, person_paths: PathRules | None,
    person_parties: AuthorizedParties, transaction: SignInTransaction,
    resource: ProtectedResource | None,
) -> tuple[PersonPaths | None, BearerGate]:
    person = PersonPaths(person_paths, person_parties, transaction) if person_paths else None
    gate = a_bearer_gate(
        paths=paths, key_sets=key_sets, clock=clock,
        person_paths=person, machine_parties=machine_parties,
        resource=_bound_to(resource, transaction),
    )
    return person, gate


def _add_routes(
    auth: AuthApp,
    person: PersonPaths | None,
    resource: ProtectedResource | None,
    login_redirect: LoginRedirect | None,
) -> None:
    add_machine_routes(auth)
    if person is not None:
        add_person_routes(auth, login_redirect)
    if resource is not None:
        add_resource_routes(auth, resource)


def _public_rules(
    given: tuple[PublicRule, ...], person: PersonPaths | None, resource: ProtectedResource | None,
) -> tuple[PublicRule, ...]:
    webhook = [FOREIGN_SECRET_PUBLIC] if person else []
    metadata = [resource.public_rule] if resource else []
    return (*given, *webhook, *metadata)


def _bound_to(
    resource: ProtectedResource | None, transaction: SignInTransaction,
) -> ProtectedResource | None:
    if resource is None or resource.transaction is not an_unbound_transaction:
        return resource
    return replace(resource, transaction=transaction)


def a_bearer_app(
    *,
    paths: PathRules = MACHINE_PATHS,
    person_paths: PathRules | None = None,
    machine_parties: AuthorizedParties = HAL_ONLY,
    person_parties: AuthorizedParties = HAL_ONLY,
    session_gate: bool = True,
    transaction_kind: TransactionKind = TransactionKind.PER_CALL,
    transaction: SignInTransaction | None = None,
    strict_records: bool = False,
    known_accounts: tuple[FakeUser, ...] = (),
    cookie_role: str = ADMIN_ROLE,
    key_sets: FakeKeySetEndpoint | None = None,
    gated: bool = True,
    policies: dict[str, Any] | None = None,
    inner_middleware: tuple[Middleware, ...] = (),
    resource: ProtectedResource | None = None,
    **auth_app_keywords: Any,
) -> BearerApp:
    """An app whose machine paths sit behind a bearer gate (or none, when `gated` is false).

    It serves `EXPORT_PATH` and `UNGATED_EXPORT_PATH` (read `bearer_caller`), `UNDECLARED_PATH`
    and `PEOPLE_PATH` (read nothing) and `RAISING_PATH`, besides the arrangement's own routes;
    the session store holds an admin's session, whose cookie is `BearerApp.cookie`.

    `person_paths` adds the gate's person paths over `transaction` (default: a recording one
    on the app's accounts), held, injected or not, by `BearerApp.transaction`, and the routes
    of `add_person_routes`; `session_gate` false installs the stack without the session gate.
    `resource` adds a protected resource, its public metadata and a host route at its entry point.
    """
    key_sets, clock = key_sets or a_key_set_answering(), FakeClock(float(ACCESS_TOKEN_NOW))
    side = _a_sign_in_side(
        transaction_kind, strict_records, cookie_role, known_accounts,
        auth_app_keywords.pop("sessions", None),
    )
    used_transaction = transaction or side.transaction
    person, gate = _a_gate_over(
        paths, key_sets, clock, machine_parties, person_paths, person_parties,
        used_transaction, resource,
    )
    public = _public_rules(auth_app_keywords.pop("public", ()), person, resource)
    stack_policies = _stack_policies(gate if gated else None, person is not None, policies)
    auth = an_auth_app(
        side.record,
        gate=session_gate,
        raise_server_exceptions=False,
        sessions=side.sessions,
        public=public,
        stack_policies=stack_policies,
        **auth_app_keywords,
    )
    if not session_gate:
        install_web_auth_middleware(auth.app, **{**GATED_STACK_POLICIES, **stack_policies})
    auth.app.user_middleware.extend(inner_middleware)
    _add_routes(auth, person, resource, auth_app_keywords.get("login_redirect"))
    return BearerApp(
        auth, key_sets, clock, cookie=session_cookie_header(auth.signed_cookie()),
        accounts=side.accounts, audit=side.audit, transaction=used_transaction,
    )


A_TOKEN = a_token()


def assert_no_store_and_no_cookie(headers: Mapping[str, str]) -> None:
    assert headers["cache-control"] == "no-store"
    assert "set-cookie" not in headers


def assert_answers_no_store(response: Response) -> None:
    assert_no_store_and_no_cookie(response.headers)


ADMITTED_ADMIN_PATH = "/admitted-admin"
ADMITTED_ADMIN_DEPENDENCY_PATH = "/admitted-admin-dependency"
ADMITTED_ADMIN_AFTER_CURRENT_USER_PATH = "/admitted-admin-after-current-user"
ADMITTED_ADMIN_PATHS = (ADMITTED_ADMIN_PATH, ADMITTED_ADMIN_DEPENDENCY_PATH)
WEBSOCKET_ADMITTED_ADMIN_PATH = "/ws-admitted-admin"


def with_admitted_admin_routes(app: AuthApp) -> AuthApp:
    """The routes that read ``admitted_admin``, added to an application of the arrangement."""
    dependencies = current_user_dependency(
        session_store=lambda: app.sessions, on_authenticated=app.authenticated.append,
    )

    @app.app.get(ADMITTED_ADMIN_PATH)
    def reading_admitted_admin(request: Request) -> dict[str, str]:
        app.route_runs.append(request.url.path)
        return {"username": admitted_admin(request).username}

    @app.app.get(ADMITTED_ADMIN_DEPENDENCY_PATH)
    def depending_on_admitted_admin(
        request: Request, admin: AuthenticatedUser = Depends(admitted_admin),
    ) -> dict[str, str]:
        app.route_runs.append(request.url.path)
        return {"username": admin.username}

    @app.app.get(ADMITTED_ADMIN_AFTER_CURRENT_USER_PATH)
    def reading_admitted_admin_after_current_user(
        request: Request, _account: AuthenticatedUser = Depends(dependencies.current_user),
    ) -> dict[str, str]:
        return {"username": admitted_admin(request).username}

    @app.app.websocket(WEBSOCKET_ADMITTED_ADMIN_PATH)
    async def reading_admitted_admin_of_a_websocket(websocket: WebSocket) -> None:
        admitted_admin(websocket)
        await websocket.accept()
        await websocket.close()

    return app


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

