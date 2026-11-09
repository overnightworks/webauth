"""The bearer gate's protected resource, admission: a token that holds is admitted as a person the
host's store already knows, capped at the role "user", and every failure of the store is the
library's 500.

The app is the real stack over `an_auth_app` behind the session gate, with the host's routes
of `a_bearer_app`; the tokens are real RS256 `at+jwt`s.
"""

from __future__ import annotations

from collections.abc import Callable
from dataclasses import asdict
from typing import NoReturn

import pytest
from fastapi import FastAPI, Request, WebSocket
from starlette.middleware import Middleware

from tests.support.agent_arrangement import AGENT_NAME, AGENT_OWNER, an_agent_group_token
from tests.support.gate_arrangement import (
    A_TOKEN,
    EVERY_METHOD,
    EXPORT_PATH,
    PERSON_ME_PATH,
    PERSON_PATHS,
    REFUSED_AS_RUNTIME_ERROR,
    RESOURCE_GROUP,
    BearerApp,
    RewritingTheRequest,
    a_bearer_app,
    a_known_person,
    a_resource,
    a_resource_token,
    an_interactive_agent_token,
    answering_a_runtime_error_with_418,
    assert_no_bearer_admission,
    bearing,
    between_the_bearer_gate_and_csrf,
    relayed,
    the_accounts,
    the_transaction,
)
from tests.support.oidc_arrangement import (
    OPERATOR_SUBJECT,
)
from tests.support.oidc_login_host import StoreDown, failing
from tests.support.person_paths_arrangement import DisabledUser
from tests.support.webauth_arrangement import ADMIN_ROLE, MEMBER_ROLE, FakeUser
from webauth.middleware import (
    MarkedRoute,
    ProtectedResource,
    admitted_user,
    is_resource_admission,
    resource_person,
)
from webauth.policies import PathRules, PublicRule
from webauth.ports import SignInStores


@pytest.fixture
def resource() -> ProtectedResource:
    return a_resource()


MARKED_ADMISSION_PROBE = MarkedRoute("POST", "/probe/marked-resource-admission")
MARKED_PERSON_ADMISSION_PROBE = MarkedRoute("POST", "/api/probe/marked-resource-admission")
ADMISSION_PROBE_PATH = "/probe/resource-admission"
PERSON_ADMISSION_PROBE_PATH = "/api/probe/resource-admission"
MACHINE_ADMISSION_PROBE_PATH = "/api/admin/probe/resource-admission"
WEBSOCKET_ADMISSION_PROBE_PATH = "/probe/ws-resource-admission"


def the_admission_answer(request: Request) -> dict[str, object]:
    """What `is_resource_admission` answers beside `resource_person` and the agent facts."""
    is_resource = is_resource_admission(request)
    user = admitted_user(request) if is_resource else None
    try:
        resource_person(request)
        person_returned = True
    except RuntimeError:
        person_returned = False
    return {
        "is_resource_admission": is_resource,
        "resource_person_returns": person_returned,
        "agent": None if user is None or user.agent is None else asdict(user.agent),
    }


def with_admission_probes(app: BearerApp, resource: ProtectedResource) -> BearerApp:
    """Routes that echo `is_resource_admission` on a marked route, an unmarked person path, a
    machine path, a path no gate marks and a WebSocket; the entry point answers it on `LINK`.
    They come before the arrangement's own routes, which read `current_user` on a marked route."""
    routes = app.auth.app.router.routes
    existing = len(routes)
    probe_paths = (
        ADMISSION_PROBE_PATH,
        PERSON_ADMISSION_PROBE_PATH,
        MACHINE_ADMISSION_PROBE_PATH,
        MARKED_ADMISSION_PROBE.template,
        MARKED_PERSON_ADMISSION_PROBE.template,
    )
    for path in probe_paths:
        app.auth.app.add_api_route(
            path, the_admission_answer, methods=list(EVERY_METHOD), include_in_schema=False
        )
    app.auth.app.add_api_route(
        resource.entry_point, the_admission_answer, methods=["LINK", "UNLINK"]
    )

    @app.auth.app.websocket(WEBSOCKET_ADMISSION_PROBE_PATH)
    async def websocket_probe(websocket: WebSocket) -> None:
        await websocket.accept()
        await websocket.send_json({"is_resource_admission": is_resource_admission(websocket)})
        await websocket.close()

    probes = routes[existing:]
    del routes[existing:]
    routes[:0] = probes
    return app


@pytest.fixture
def marked_resource() -> ProtectedResource:
    return a_resource(
        marked_routes=frozenset({MARKED_ADMISSION_PROBE, MARKED_PERSON_ADMISSION_PROBE})
    )


def the_account_of_the_token(app: BearerApp) -> FakeUser | None:
    return next((user for user in the_accounts(app) if user.id == OPERATOR_SUBJECT), None)


@pytest.mark.parametrize("method", ["GET", "POST", "PUT", "PATCH"])
@pytest.mark.parametrize(
    "groups",
    [["/apps/x/mcp"], ["/apps/x/mcp/sub"]],
    ids=["required-group", "subgroup"],
)
@pytest.mark.parametrize(
    "sent",
    [{}, {"origin": "https://evil.example"}],
    ids=["plain", "foreign-origin"],
)
def test_a_known_person_in_the_group_is_admitted_with_no_cookie_and_the_person_role(
    resource: ProtectedResource,
    method: str,
    groups: list[str],
    sent: dict[str, str],
) -> None:
    """RESOURCE-24, RESOURCE-65: a person holding the required group or one below it, besides
    the login group, passes with no cookie and no Origin, and `resource_person` and
    `current_user` return the person with the role "user"."""
    app = a_bearer_app(paths=PathRules(), resource=resource, known_accounts=(a_known_person(),))

    response = app.ask(
        resource.entry_point,
        method=method,
        authorization=bearing(an_interactive_agent_token(resource, *groups)),
        headers=sent,
    )

    assert response.status_code == 200
    assert response.json() == {"id": OPERATOR_SUBJECT, "username": "lena", "role": MEMBER_ROLE}
    assert response.headers["cache-control"] == "no-store"
    assert app.audit.account_events == []


@pytest.mark.parametrize(
    "groups",
    [["/apps/x/mcp/sub"], ["/apps/x/mcp", "/apps/x/admin"]],
    ids=["subgroup", "admin"],
)
def test_a_subgroup_of_the_required_group_counts_and_an_admin_group_adds_nothing(
    resource: ProtectedResource,
    groups: list[str],
) -> None:
    app = a_bearer_app(paths=PathRules(), resource=resource, known_accounts=(a_known_person(),))

    token = bearing(an_interactive_agent_token(resource, *groups))

    response = app.ask(resource.entry_point, authorization=token)

    assert (response.status_code, response.json()["role"]) == (200, MEMBER_ROLE)


def test_a_token_of_a_person_whose_stored_account_is_marked_disabled_is_still_admitted(
    resource: ProtectedResource,
) -> None:
    """APP-21: resource admission reads no local active-user flag."""
    app = a_bearer_app(
        paths=PathRules(),
        resource=resource,
        known_accounts=(DisabledUser(id=OPERATOR_SUBJECT, username="lena"),),
    )

    response = app.ask(
        resource.entry_point, authorization=bearing(an_interactive_agent_token(resource))
    )

    assert response.status_code == 200
    assert response.json() == {"id": OPERATOR_SUBJECT, "username": "lena", "role": MEMBER_ROLE}


def test_a_stored_admin_is_admitted_as_a_person_and_the_store_changes_nothing(
    resource: ProtectedResource,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """APP-13, RESOURCE-27, RESOURCE-28: resource admission rewrites no role and writes no audit
    event, admits a stored admin as `AuthenticatedUser(id, username, role)` with the role
    "user", and `admin_user` answers that person a 403 without `WWW-Authenticate`."""
    app = a_bearer_app(
        paths=PathRules(),
        resource=resource,
        known_accounts=(a_known_person(ADMIN_ROLE),),
    )
    assert app.accounts is not None
    failing(app.accounts, "set_role", monkeypatch)
    token = bearing(an_interactive_agent_token(resource, RESOURCE_GROUP, "/apps/x/admin"))

    posted = app.ask(resource.entry_point, method="POST", authorization=token)
    admin_only = app.ask(resource.entry_point, method="DELETE", authorization=token)

    assert posted.status_code == 200
    assert posted.json() == {"id": OPERATOR_SUBJECT, "username": "lena", "role": MEMBER_ROLE}
    [admitted] = app.auth.resource_persons
    assert type(admitted.role) is str
    assert admin_only.status_code == 403
    assert "www-authenticate" not in admin_only.headers
    stored = the_account_of_the_token(app)
    assert stored is not None
    assert stored.role == ADMIN_ROLE
    assert app.audit.account_events == []


@pytest.mark.parametrize(
    "groups",
    [[], ["/apps/x"], ["/apps/x/mcp2"], ["/apps/x/other"]],
    ids=["none", "login-group-only", "sibling-prefix", "sibling"],
)
def test_a_person_without_the_required_group_gets_the_plain_403_and_the_store_is_untouched(
    resource: ProtectedResource,
    groups: list[str],
) -> None:
    """RESOURCE-21: a person whose groups lack the required group, or one below it, gets the
    plain 403 without `WWW-Authenticate`, no route runs, and the store, the accounts and the
    audit stay as they were."""
    app = a_bearer_app(paths=PathRules(), resource=resource, known_accounts=(a_known_person(),))
    accounts_before = the_accounts(app)

    response = app.ask(
        resource.entry_point,
        method="POST",
        authorization=bearing(a_resource_token(resource, groups=groups)),
    )

    assert (response.status_code, response.json()) == (403, {"detail": "Access denied"})
    assert "www-authenticate" not in response.headers
    assert (the_transaction(app).entries, app.audit.account_events) == (0, [])
    assert the_accounts(app) == accounts_before
    assert app.auth.route_runs == []


def test_a_person_outside_the_login_group_gets_the_plain_403_with_the_group_held() -> None:
    """RESOURCE-22: a person outside the admission's login group gets the plain 403 without
    `WWW-Authenticate`, no route runs, and the store and the audit stay as they were."""
    resource = a_resource(required_group="/other/mcp")
    app = a_bearer_app(paths=PathRules(), resource=resource, known_accounts=(a_known_person(),))

    response = app.ask(
        resource.entry_point,
        authorization=bearing(an_interactive_agent_token(resource, "/other/mcp")),
    )

    assert (response.status_code, response.json()) == (403, {"detail": "Access denied"})
    assert "www-authenticate" not in response.headers
    assert (the_transaction(app).entries, app.audit.account_events) == (0, [])
    assert app.auth.route_runs == []


def test_an_unknown_subject_gets_the_plain_403_and_no_account_or_event_appears(
    resource: ProtectedResource,
) -> None:
    """RESOURCE-23: a subject no account has gets the plain 403 without `WWW-Authenticate`, no
    route runs, and no account and no event appear."""
    app = a_bearer_app(paths=PathRules(), resource=resource)

    response = app.ask(
        resource.entry_point,
        method="POST",
        authorization=bearing(an_interactive_agent_token(resource)),
    )

    assert (response.status_code, response.json()) == (403, {"detail": "Access denied"})
    assert "www-authenticate" not in response.headers
    assert (the_account_of_the_token(app), app.audit.account_events) == (None, [])
    assert app.auth.route_runs == []


def a_transaction_that_cannot_be_created() -> NoReturn:
    raise StoreDown


class ATransactionThatCannotBeEntered:
    def __enter__(self) -> SignInStores:
        raise StoreDown

    def __exit__(self, *_exception: object) -> None:
        return None


@pytest.mark.parametrize("failure", ["creation", "entry", "lookup", "exit"])
def test_a_store_failure_in_the_admission_is_the_library_500_and_admits_nothing(
    resource: ProtectedResource,
    failure: str,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """RESOURCE-29: a store or transaction exit failure in the admission is the library's 500,
    no route runs, and no admission is recorded."""
    broken_transactions = {
        "creation": a_transaction_that_cannot_be_created,
        "entry": ATransactionThatCannotBeEntered,
    }
    app = a_bearer_app(
        paths=PathRules(),
        resource=resource,
        known_accounts=(a_known_person(),),
        transaction=broken_transactions.get(failure),
    )
    assert app.accounts is not None
    if failure == "lookup":
        failing(app.accounts, "get", monkeypatch)
    if failure == "exit":
        the_transaction(app).exit_failure = StoreDown()
    token = bearing(an_interactive_agent_token(resource))
    relay = relayed(app.auth)

    response = app.ask(resource.entry_point, method="POST", authorization=token)

    assert response.status_code == 500
    assert app.auth.route_runs == []
    assert_no_bearer_admission(
        app,
        {**relay.added, "method": "POST"},
        resource.entry_point,
        token[0],
    )


def test_the_resource_person_enters_the_sign_in_transaction_once_per_request(
    resource: ProtectedResource,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """RESOURCE-26: the admission is one `accounts.get` in one entry of the transaction, and
    changes no account."""
    app = a_bearer_app(
        paths=PathRules(),
        resource=resource,
        known_accounts=(a_known_person(),),
        strict_records=True,
    )

    assert app.accounts is not None
    lookups: list[str] = []
    stored_get = app.accounts.get

    def counting(user_id: str) -> FakeUser | None:
        lookups.append(user_id)
        return stored_get(user_id)

    monkeypatch.setattr(app.accounts, "get", counting)
    accounts_before = the_accounts(app)

    response = app.ask(
        resource.entry_point, authorization=bearing(an_interactive_agent_token(resource))
    )

    assert (response.status_code, the_transaction(app).entries) == (200, 1)
    assert lookups == [OPERATOR_SUBJECT]
    assert the_accounts(app) == accounts_before


def a_resource_person_reader(app: BearerApp, path: str) -> None:
    @app.auth.app.api_route(path, methods=["GET", "POST"])
    def reading(request: Request) -> dict[str, str]:
        return {"id": resource_person(request).id}


def an_admitted_user_reader(app: BearerApp, resource: ProtectedResource) -> None:
    @app.auth.app.api_route(resource.entry_point, methods=["TRACE"])
    def reading(request: Request) -> dict[str, str | None]:
        user = admitted_user(request)
        return {"id": None if user is None else user.id}


@pytest.mark.parametrize(
    ("changes", "status"),
    [
        pytest.param({"method": "PATCH"}, REFUSED_AS_RUNTIME_ERROR, id="method-to-current-user"),
        pytest.param({"method": "GET"}, REFUSED_AS_RUNTIME_ERROR, id="method-to-another-reader"),
        pytest.param({"app": FastAPI()}, REFUSED_AS_RUNTIME_ERROR, id="sub-app"),
        pytest.param(
            {"headers": [(b"authorization", b"Bearer other")]},
            REFUSED_AS_RUNTIME_ERROR,
            id="header",
        ),
        pytest.param({}, 200, id="unchanged"),
    ],
)
def test_the_resource_person_and_current_user_refuse_a_request_changed_after_admission(
    resource: ProtectedResource,
    changes: dict[str, object],
    status: int,
) -> None:
    """RESOURCE-67, RESOURCE-69: at the entry point `resource_person` and `current_user` raise
    `RuntimeError` in a sub-app and after the `Authorization` header or the method changed."""
    app = a_bearer_app(
        paths=PathRules(),
        resource=resource,
        known_accounts=(a_known_person(),),
        inner_middleware=(Middleware(RewritingTheRequest, changes=changes),),
    )
    answering_a_runtime_error_with_418(app)

    response = app.ask(
        resource.entry_point,
        method="POST",
        authorization=bearing(an_interactive_agent_token(resource)),
    )

    assert response.status_code == status


@pytest.mark.parametrize(
    ("sent", "changes", "status"),
    [
        pytest.param("POST", {"method": "TRACE"}, REFUSED_AS_RUNTIME_ERROR, id="method-changed"),
        pytest.param("TRACE", {}, 200, id="unchanged"),
    ],
)
def test_admitted_user_reads_the_resource_person_and_refuses_a_method_changed_after_admission(
    resource: ProtectedResource,
    sent: str,
    changes: dict[str, object],
    status: int,
) -> None:
    app = a_bearer_app(
        paths=PathRules(),
        resource=resource,
        known_accounts=(a_known_person(),),
        inner_middleware=(Middleware(RewritingTheRequest, changes=changes),),
    )
    an_admitted_user_reader(app, resource)
    answering_a_runtime_error_with_418(app)

    response = app.ask(
        resource.entry_point,
        method=sent,
        authorization=bearing(an_interactive_agent_token(resource)),
    )

    assert response.status_code == status
    if status == 200:
        assert response.json() == {"id": OPERATOR_SUBJECT}


@pytest.mark.parametrize(
    ("changes", "status"),
    [pytest.param({"method": "POST"}, 403, id="method-changed"), pytest.param({}, 200, id="same")],
)
def test_csrf_refuses_a_request_made_mutating_after_admission(
    resource: ProtectedResource,
    changes: dict[str, object],
    status: int,
) -> None:
    """RESOURCE-25: CSRF reads the admission as it reads a person path's, so a request made
    mutating after admission is refused."""
    app = a_bearer_app(paths=PathRules(), resource=resource, known_accounts=(a_known_person(),))
    between_the_bearer_gate_and_csrf(app, Middleware(RewritingTheRequest, changes=changes))

    response = app.ask(
        resource.entry_point,
        method="GET",
        authorization=bearing(an_interactive_agent_token(resource)),
    )

    assert response.status_code == status
    assert (status == 200) == (app.auth.route_runs == [resource.entry_point])


@pytest.mark.parametrize(
    ("path", "asked"),
    [
        pytest.param("/plain", {"cookie": True}, id="session"),
        pytest.param(f"{PERSON_ME_PATH}-reader", {"authorization": bearing(A_TOKEN)}, id="person"),
        pytest.param(
            f"{EXPORT_PATH}-reader",
            {"authorization": bearing(A_TOKEN)},
            id="machine",
        ),
    ],
)
def test_the_resource_person_raises_on_a_session_person_and_machine_request(
    resource: ProtectedResource,
    path: str,
    asked: dict[str, object],
) -> None:
    """RESOURCE-66: `resource_person` raises `RuntimeError` on a session, person or machine
    request."""
    app = a_bearer_app(
        person_paths=PERSON_PATHS,
        resource=resource,
        known_accounts=(a_known_person(),),
    )
    a_resource_person_reader(app, path)
    answering_a_runtime_error_with_418(app)

    response = app.ask(path, **asked)  # type: ignore[arg-type]

    assert response.status_code == REFUSED_AS_RUNTIME_ERROR


@pytest.mark.parametrize(
    "group",
    ["", "apps/x/mcp", "/", "/apps//mcp", "/apps/x/mcp ", "/a\u200bb"],
)
def test_a_required_group_that_is_not_a_group_path_is_refused(group: str) -> None:
    """RESOURCE-05: a `required_group` that is not a group path is a `ValueError`."""
    with pytest.raises(ValueError, match="required_group"):
        a_resource(required_group=group)


@pytest.mark.parametrize(
    "group",
    ["", "agents", "/", "/agents//x", "/agents ", "/a\u200bb"],
)
def test_an_agent_group_that_is_not_a_group_path_is_refused(group: str) -> None:
    """RESOURCE-05: an `agent_group` that is not a group path is a `ValueError`, as a
    `required_group` is."""
    with pytest.raises(ValueError, match="agent_group"):
        a_resource(agent_group=group)


THE_PUBLIC_PROBE = PublicRule(PathRules(exact=frozenset({ADMISSION_PROBE_PATH})))


def asked_by_a_session(path: str) -> dict[str, object]:
    return {"path": path, "cookie": True}


def asked_with(path: str, token: str, method: str = "POST") -> dict[str, object]:
    return {"path": path, "method": method, "authorization": bearing(token)}


@pytest.mark.parametrize(
    ("asked", "is_resource", "agent"),
    [
        pytest.param(
            lambda r: asked_by_a_session(MARKED_ADMISSION_PROBE.template),
            False,
            None,
            id="session-on-a-marked-route",
        ),
        pytest.param(
            lambda r: asked_with(PERSON_ADMISSION_PROBE_PATH, A_TOKEN),
            False,
            None,
            id="person-token-on-a-person-path",
        ),
        pytest.param(
            lambda r: asked_with(MARKED_PERSON_ADMISSION_PROBE.template, A_TOKEN),
            False,
            None,
            id="person-token-of-another-audience-on-a-marked-route-below-a-person-path",
        ),
        pytest.param(
            lambda r: asked_with(r.entry_point, an_interactive_agent_token(r), "LINK"),
            True,
            None,
            id="own-agent-at-the-entry-point",
        ),
        pytest.param(
            lambda r: asked_with(MARKED_ADMISSION_PROBE.template, an_interactive_agent_token(r)),
            True,
            None,
            id="own-agent-on-a-marked-route",
        ),
        pytest.param(
            lambda r: asked_with(
                MARKED_ADMISSION_PROBE.template,
                an_agent_group_token(r, r.agent_group, r.required_group),
            ),
            True,
            {"owner": AGENT_OWNER, "name": AGENT_NAME},
            id="agent-group-on-a-marked-route",
        ),
        pytest.param(
            lambda r: asked_with(
                MARKED_PERSON_ADMISSION_PROBE.template, an_interactive_agent_token(r)
            ),
            True,
            None,
            id="resource-token-on-a-marked-route-below-a-person-path",
        ),
        pytest.param(
            lambda r: asked_with(MACHINE_ADMISSION_PROBE_PATH, A_TOKEN),
            False,
            None,
            id="machine-request",
        ),
        pytest.param(
            lambda r: {"path": ADMISSION_PROBE_PATH},
            False,
            None,
            id="no-credential-on-a-public-path",
        ),
    ],
)
def test_a_route_reads_whether_the_request_is_a_resource_admission(
    marked_resource: ProtectedResource,
    asked: Callable[[ProtectedResource], dict[str, object]],
    is_resource: bool,
    agent: dict[str, str] | None,
) -> None:
    """RESOURCE-81, RESOURCE-82: the predicate is true for a resource admission, with agent
    facts or without, and false for every other request; it agrees with `resource_person`."""
    app = with_admission_probes(
        a_bearer_app(
            person_paths=PERSON_PATHS,
            resource=marked_resource,
            known_accounts=(a_known_person(),),
            public=(THE_PUBLIC_PROBE,),
        ),
        marked_resource,
    )

    response = app.ask(**asked(marked_resource))  # type: ignore[arg-type]

    assert response.status_code == 200
    assert response.json() == {
        "is_resource_admission": is_resource,
        "resource_person_returns": is_resource,
        "agent": agent,
    }


def test_a_websocket_is_no_resource_admission(marked_resource: ProtectedResource) -> None:
    """RESOURCE-82: the predicate is false on a WebSocket."""
    app = with_admission_probes(
        a_bearer_app(person_paths=PERSON_PATHS, resource=marked_resource), marked_resource
    )

    with (
        app.auth.client,
        app.auth.connect(WEBSOCKET_ADMISSION_PROBE_PATH, cookie=app.auth.signed_cookie()) as socket,
    ):
        answer = socket.receive_json()

    assert answer == {"is_resource_admission": False}


def test_an_app_without_a_bearer_gate_has_no_resource_admission(
    marked_resource: ProtectedResource,
) -> None:
    """RESOURCE-82: the predicate is false in an app without a bearer gate."""
    app = with_admission_probes(
        a_bearer_app(gated=False, resource=marked_resource), marked_resource
    )

    response = app.ask(ADMISSION_PROBE_PATH, cookie=True)

    assert (response.status_code, response.json()["is_resource_admission"]) == (200, False)


@pytest.mark.parametrize("surface", ["entry-point", "marked-route"])
@pytest.mark.parametrize(
    ("changes", "status"),
    [
        pytest.param({"app": FastAPI()}, REFUSED_AS_RUNTIME_ERROR, id="sub-app"),
        pytest.param({"method": "another"}, REFUSED_AS_RUNTIME_ERROR, id="method-changed"),
        pytest.param(
            {"headers": [(b"authorization", b"Bearer other")]},
            REFUSED_AS_RUNTIME_ERROR,
            id="authorization-changed",
        ),
        pytest.param({}, 200, id="unchanged"),
    ],
)
def test_the_predicate_raises_for_an_admission_that_no_longer_holds(
    marked_resource: ProtectedResource,
    surface: str,
    changes: dict[str, object],
    status: int,
) -> None:
    """RESOURCE-83: the predicate raises `RuntimeError` in a sub-app and after the
    `Authorization` header or the method changed, and answers otherwise."""
    path, method = (
        (marked_resource.entry_point, "LINK")
        if surface == "entry-point"
        else (MARKED_ADMISSION_PROBE.template, "POST")
    )
    if "method" in changes:
        changes = {"method": "UNLINK" if surface == "entry-point" else "GET"}

    app = with_admission_probes(
        a_bearer_app(
            paths=PathRules(),
            resource=marked_resource,
            known_accounts=(a_known_person(),),
            inner_middleware=(Middleware(RewritingTheRequest, changes=changes),),
        ),
        marked_resource,
    )
    answering_a_runtime_error_with_418(app)
    response = app.ask(
        path, method=method, authorization=bearing(an_interactive_agent_token(marked_resource))
    )

    assert response.status_code == status
