"""The bearer gate's protected resource, admission: a token that holds is admitted as a person the
host's store already knows, capped at the person role, and every failure of the store is the
library's 500.

The app is the real stack over `an_auth_app` behind the session gate, with the host's routes
of `a_bearer_app`; the tokens are real RS256 `at+jwt`s.
"""

from __future__ import annotations

from typing import NoReturn

import pytest
from fastapi import FastAPI, Request
from starlette.middleware import Middleware
from starlette.responses import JSONResponse

from tests.support.gate_arrangement import (
    A_TOKEN,
    EXPORT_PATH,
    PERSON_ME_PATH,
    PERSON_PATHS,
    RESOURCE_GROUP,
    BearerApp,
    RewritingTheRequest,
    a_bearer_app,
    a_known_person,
    a_resource,
    a_resource_token,
    assert_no_bearer_admission,
    bearing,
    relayed,
    the_accounts,
)
from tests.support.oidc_arrangement import (
    OPERATOR_SUBJECT,
)
from tests.support.oidc_login_host import RecordingSignInTransaction, StoreDown, failing
from tests.support.webauth_arrangement import ADMIN_ROLE, MEMBER_ROLE, FakeUser
from webauth.middleware import (
    BearerGateMiddleware,
    ProtectedResource,
    admitted_user,
    resource_person,
)
from webauth.policies import PathRules
from webauth.ports import SignInStores


@pytest.fixture
def resource() -> ProtectedResource:
    return a_resource()


def an_agent_token(resource: ProtectedResource, *groups: str) -> str:
    return a_resource_token(resource, groups=list(groups) or [RESOURCE_GROUP])


def the_account_of_the_token(app: BearerApp) -> FakeUser | None:
    return next((user for user in the_accounts(app) if user.id == OPERATOR_SUBJECT), None)


def the_transaction(app: BearerApp) -> RecordingSignInTransaction:
    assert isinstance(app.transaction, RecordingSignInTransaction)
    return app.transaction


@pytest.mark.parametrize("method", ["GET", "POST", "PUT"])
@pytest.mark.parametrize(
    "sent", [{}, {"origin": "https://evil.example"}], ids=["plain", "foreign-origin"],
)
def test_a_known_person_in_the_group_is_admitted_with_no_cookie_and_the_person_role(
    resource: ProtectedResource, method: str, sent: dict[str, str],
) -> None:
    app = a_bearer_app(paths=PathRules(), resource=resource, known_accounts=(a_known_person(),))

    response = app.ask(
        resource.entry_point, method=method, authorization=bearing(an_agent_token(resource)),
        headers=sent,
    )

    assert response.status_code == 200
    assert response.json() == {"id": OPERATOR_SUBJECT, "username": "lena", "role": MEMBER_ROLE}
    assert response.headers["cache-control"] == "no-store"
    assert app.audit.account_events == []


@pytest.mark.parametrize(
    "groups", [["/apps/x/mcp/sub"], ["/apps/x/mcp", "/apps/x/admin"]], ids=["subgroup", "admin"],
)
def test_a_subgroup_of_the_required_group_counts_and_an_admin_group_adds_nothing(
    resource: ProtectedResource, groups: list[str],
) -> None:
    app = a_bearer_app(paths=PathRules(), resource=resource, known_accounts=(a_known_person(),))

    token = bearing(an_agent_token(resource, *groups))

    response = app.ask(resource.entry_point, authorization=token)

    assert (response.status_code, response.json()["role"]) == (200, MEMBER_ROLE)


def test_a_stored_admin_is_admitted_as_a_person_and_the_store_changes_nothing(
    resource: ProtectedResource, monkeypatch: pytest.MonkeyPatch,
) -> None:
    app = a_bearer_app(
        paths=PathRules(), resource=resource, known_accounts=(a_known_person(ADMIN_ROLE),),
    )
    assert app.accounts is not None
    failing(app.accounts, "set_role", monkeypatch)
    token = bearing(an_agent_token(resource, RESOURCE_GROUP, "/apps/x/admin"))

    posted = app.ask(resource.entry_point, method="POST", authorization=token)
    admin_only = app.ask(resource.entry_point, method="DELETE", authorization=token)

    assert (posted.status_code, posted.json()["role"]) == (200, MEMBER_ROLE)
    assert admin_only.status_code == 403
    stored = the_account_of_the_token(app)
    assert stored is not None
    assert stored.role == ADMIN_ROLE
    assert app.audit.account_events == []


@pytest.mark.parametrize(
    "groups", [[], ["/apps/x"], ["/apps/x/mcp2"], ["/apps/x/other"]],
    ids=["none", "login-group-only", "sibling-prefix", "sibling"],
)
def test_a_person_without_the_required_group_gets_the_plain_403_and_the_store_is_untouched(
    resource: ProtectedResource, groups: list[str],
) -> None:
    app = a_bearer_app(paths=PathRules(), resource=resource, known_accounts=(a_known_person(),))

    response = app.ask(
        resource.entry_point, method="POST",
        authorization=bearing(a_resource_token(resource, groups=groups)),
    )

    assert (response.status_code, response.json()) == (403, {"detail": "Access denied"})
    assert "www-authenticate" not in response.headers
    assert (the_transaction(app).entries, app.audit.account_events) == (0, [])
    assert app.auth.route_runs == []


def test_a_person_outside_the_login_group_gets_the_plain_403_with_the_group_held() -> None:
    resource = a_resource(required_group="/other/mcp")
    app = a_bearer_app(paths=PathRules(), resource=resource, known_accounts=(a_known_person(),))

    response = app.ask(
        resource.entry_point, authorization=bearing(an_agent_token(resource, "/other/mcp")),
    )

    assert (response.status_code, response.json()) == (403, {"detail": "Access denied"})
    assert (the_transaction(app).entries, app.audit.account_events) == (0, [])


def test_an_unknown_subject_gets_the_plain_403_and_no_account_or_event_appears(
    resource: ProtectedResource,
) -> None:
    app = a_bearer_app(paths=PathRules(), resource=resource)

    response = app.ask(
        resource.entry_point, method="POST", authorization=bearing(an_agent_token(resource)),
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
    resource: ProtectedResource, failure: str, monkeypatch: pytest.MonkeyPatch,
) -> None:
    broken_transactions = {
        "creation": a_transaction_that_cannot_be_created,
        "entry": ATransactionThatCannotBeEntered,
    }
    app = a_bearer_app(
        paths=PathRules(), resource=resource, known_accounts=(a_known_person(),),
        transaction=broken_transactions.get(failure),
    )
    assert app.accounts is not None
    if failure == "lookup":
        failing(app.accounts, "get", monkeypatch)
    if failure == "exit":
        the_transaction(app).exit_failure = StoreDown()
    token = bearing(an_agent_token(resource))
    relay = relayed(app.auth)

    response = app.ask(resource.entry_point, method="POST", authorization=token)

    assert response.status_code == 500
    assert app.auth.route_runs == []
    assert_no_bearer_admission(
        app, {**relay.added, "method": "POST"}, resource.entry_point, token[0],
    )


def test_the_resource_person_enters_the_sign_in_transaction_once_per_request(
    resource: ProtectedResource,
) -> None:
    app = a_bearer_app(
        paths=PathRules(), resource=resource, known_accounts=(a_known_person(),),
        strict_records=True,
    )

    response = app.ask(resource.entry_point, authorization=bearing(an_agent_token(resource)))

    assert (response.status_code, the_transaction(app).entries) == (200, 1)


REFUSED_AS_RUNTIME_ERROR = 418


def answering_a_runtime_error_with_418(app: BearerApp) -> None:
    """A reader that refuses with `RuntimeError` answers 418; any other failure stays the 500."""

    def answer(_request: Request, _error: Exception) -> JSONResponse:
        return JSONResponse({"detail": "refused"}, status_code=REFUSED_AS_RUNTIME_ERROR)

    app.auth.app.add_exception_handler(RuntimeError, answer)


def a_resource_person_reader(app: BearerApp, path: str) -> None:
    @app.auth.app.api_route(path, methods=["GET", "POST"])
    def reading(request: Request) -> dict[str, str]:
        return {"id": resource_person(request).id}


def an_admitted_user_reader(app: BearerApp, resource: ProtectedResource) -> None:
    @app.auth.app.api_route(resource.entry_point, methods=["TRACE"])
    def reading(request: Request) -> dict[str, str | None]:
        user = admitted_user(request)
        return {"id": None if user is None else user.id}


def between_the_bearer_gate_and_csrf(app: BearerApp, rewriting: Middleware) -> None:
    stack = app.auth.app.user_middleware
    gate = next(at for at, entry in enumerate(stack) if entry.cls is BearerGateMiddleware)
    stack.insert(gate + 1, rewriting)


@pytest.mark.parametrize(
    ("changes", "status"),
    [
        pytest.param({"method": "PATCH"}, REFUSED_AS_RUNTIME_ERROR, id="method-to-current-user"),
        pytest.param({"method": "GET"}, REFUSED_AS_RUNTIME_ERROR, id="method-to-another-reader"),
        pytest.param({"app": FastAPI()}, REFUSED_AS_RUNTIME_ERROR, id="sub-app"),
        pytest.param(
            {"headers": [(b"authorization", b"Bearer other")]}, REFUSED_AS_RUNTIME_ERROR,
            id="header",
        ),
        pytest.param({}, 200, id="unchanged"),
    ],
)
def test_the_resource_person_and_current_user_refuse_a_request_changed_after_admission(
    resource: ProtectedResource, changes: dict[str, object], status: int,
) -> None:
    app = a_bearer_app(
        paths=PathRules(), resource=resource, known_accounts=(a_known_person(),),
        inner_middleware=(Middleware(RewritingTheRequest, changes=changes),),
    )
    answering_a_runtime_error_with_418(app)

    response = app.ask(
        resource.entry_point, method="POST", authorization=bearing(an_agent_token(resource)),
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
    resource: ProtectedResource, sent: str, changes: dict[str, object], status: int,
) -> None:
    app = a_bearer_app(
        paths=PathRules(), resource=resource, known_accounts=(a_known_person(),),
        inner_middleware=(Middleware(RewritingTheRequest, changes=changes),),
    )
    an_admitted_user_reader(app, resource)
    answering_a_runtime_error_with_418(app)

    response = app.ask(
        resource.entry_point, method=sent, authorization=bearing(an_agent_token(resource)),
    )

    assert response.status_code == status
    if status == 200:
        assert response.json() == {"id": OPERATOR_SUBJECT}


@pytest.mark.parametrize(
    ("changes", "status"),
    [pytest.param({"method": "POST"}, 403, id="method-changed"), pytest.param({}, 200, id="same")],
)
def test_csrf_refuses_a_request_made_mutating_after_admission(
    resource: ProtectedResource, changes: dict[str, object], status: int,
) -> None:
    app = a_bearer_app(paths=PathRules(), resource=resource, known_accounts=(a_known_person(),))
    between_the_bearer_gate_and_csrf(app, Middleware(RewritingTheRequest, changes=changes))

    response = app.ask(
        resource.entry_point, method="GET", authorization=bearing(an_agent_token(resource)),
    )

    assert response.status_code == status
    assert (status == 200) == (app.auth.route_runs == [resource.entry_point])


@pytest.mark.parametrize(
    ("path", "asked"),
    [
        pytest.param("/plain", {"cookie": True}, id="session"),
        pytest.param(f"{PERSON_ME_PATH}-reader", {"authorization": bearing(A_TOKEN)}, id="person"),
        pytest.param(
            f"{EXPORT_PATH}-reader", {"authorization": bearing(A_TOKEN)}, id="machine",
        ),
    ],
)
def test_the_resource_person_raises_on_a_session_person_and_machine_request(
    resource: ProtectedResource, path: str, asked: dict[str, object],
) -> None:
    app = a_bearer_app(
        person_paths=PERSON_PATHS, resource=resource, known_accounts=(a_known_person(),),
    )
    a_resource_person_reader(app, path)
    answering_a_runtime_error_with_418(app)

    response = app.ask(path, **asked)  # type: ignore[arg-type]

    assert response.status_code == REFUSED_AS_RUNTIME_ERROR


@pytest.mark.parametrize(
    "group", ["", "apps/x/mcp", "/", "/apps//mcp", "/apps/x/mcp ", "/a\u200bb"],
)
def test_a_required_group_that_is_not_a_group_path_is_refused(group: str) -> None:
    with pytest.raises(ValueError, match="required_group"):
        a_resource(required_group=group)
