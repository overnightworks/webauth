"""The bearer gate's protected resource, agents: a token that holds the resource's agent group is
admitted as an agent from any client, its first admission creates its account, and a person's
account is set to the agent kind.

The app is the real stack over `an_auth_app` behind the session gate, with the host's routes
of `a_bearer_app`; the tokens are real RS256 `at+jwt`s.
"""

from __future__ import annotations

from concurrent.futures import ThreadPoolExecutor
from copy import deepcopy

import pytest
from fastapi import FastAPI
from starlette.middleware import Middleware

from tests.support.agent_arrangement import (
    AGENT_CLIENT,
    AGENT_NAME,
    AGENT_OWNER,
    an_agent_group_claims,
    an_agent_group_token,
)
from tests.support.gate_arrangement import (
    A_NOTE,
    EXPORT_PATH,
    MARKED_ADMITTED_USER,
    MARKED_NEW_NOTE,
    MARKED_RESOURCE_PERSON,
    MARKED_ROUTES,
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
    a_token,
    an_interactive_agent_token,
    answering_a_runtime_error_with_418,
    assert_no_bearer_admission,
    bearing,
    relayed,
    the_accounts,
    the_transaction,
)
from tests.support.oidc_arrangement import (
    ABSENT,
    ACCESS_TOKEN_NOW,
    OPERATOR_SUBJECT,
    an_access_token,
)
from tests.support.oidc_login_host import StoreDown, TransactionKind, failing
from tests.support.webauth_arrangement import ADMIN_ROLE, MEMBER_ROLE, FakeUser
from webauth.middleware import ProtectedResource
from webauth.policies import PathRules
from webauth.ports import AccountEvent, AccountEventKind, AccountKind, AgentFacts, AuthenticatedUser

BOTH_SURFACES = pytest.mark.parametrize("surface", ["entry-point", "marked-route"])
BOTH_TRANSACTIONS = pytest.mark.parametrize("kind", list(TransactionKind), ids=lambda k: k.name)

THE_AGENT = AgentFacts(AGENT_OWNER, AGENT_NAME)


@pytest.fixture
def resource() -> ProtectedResource:
    return a_resource(marked_routes=MARKED_ROUTES)


def an_app(resource: ProtectedResource, *accounts: FakeUser, **keywords: object) -> BearerApp:
    return a_bearer_app(
        paths=PathRules(),
        resource=resource,
        known_accounts=accounts,
        **keywords,  # type: ignore[arg-type]
    )


def ask(
    app: BearerApp,
    resource: ProtectedResource,
    surface: str,
    token: str,
    **sent: object,
) -> tuple[int, dict[str, str], dict[str, object]]:
    """The status, the headers and the body of a GET at the entry point or at a marked route."""
    path = resource.entry_point if surface == "entry-point" else A_NOTE
    response = app.ask(path, authorization=bearing(token), **sent)  # type: ignore[arg-type]
    is_json = response.headers.get("content-type", "").startswith("application/json")
    body = response.json() if is_json else {}
    return response.status_code, dict(response.headers), body


def the_agent_account(app: BearerApp) -> FakeUser | None:
    return next((user for user in the_accounts(app) if user.id == OPERATOR_SUBJECT), None)


def the_admitted_agent(username: str = OPERATOR_SUBJECT) -> AuthenticatedUser:
    return AuthenticatedUser(OPERATOR_SUBJECT, username, MEMBER_ROLE, THE_AGENT)


def assert_nothing_created(app: BearerApp) -> None:
    assert (the_transaction(app).entries, app.audit.account_events) == (0, [])
    assert the_agent_account(app) is None
    assert app.auth.route_runs == []


@BOTH_SURFACES
@pytest.mark.parametrize("azp", [AGENT_CLIENT, "stranger", "hal", ABSENT])
@pytest.mark.parametrize(
    "extra",
    [[], ["/apps/x/admin", "/other"]],
    ids=["group-and-resource", "beside-other-groups"],
)
def test_a_token_holding_the_agent_group_passes_the_party_check_whatever_its_azp(
    resource: ProtectedResource,
    surface: str,
    azp: object,
    extra: list[str],
) -> None:
    """RESOURCE-70, RESOURCE-75, RESOURCE-77: a validated `groups` list holding `agent_group`
    as one element passes the party check whatever its `azp`, other groups beside it change
    nothing, and the admitted agent is the person with the role "user" and its facts."""
    app = an_app(resource)
    token = an_agent_group_token(resource, resource.agent_group, RESOURCE_GROUP, *extra, azp=azp)

    status, _, _ = ask(app, resource, surface, token)

    assert status == 200
    assert app.auth.resource_persons == [the_admitted_agent()]


# Tokens signed by the test issuer, with the agent group, that the resource's check refuses.
WRONG_FOR_THE_RESOURCE = {
    "foreign-issuer": lambda resource: an_agent_group_token(resource, iss="https://evil.example/r"),
    "bad-signature": lambda resource: an_access_token(
        key_name="forged", claims=an_agent_group_claims(resource)
    ),
    "two-audiences": lambda resource: an_agent_group_token(
        resource, aud=[resource.url, "another-app"]
    ),
    "the-apps-client": lambda resource: an_agent_group_token(resource, aud="app-client"),
    "expired": lambda resource: an_agent_group_token(resource, exp=ACCESS_TOKEN_NOW - 1_000),
    "not-an-access-token": lambda resource: an_access_token(
        claims=an_agent_group_claims(resource), header={"typ": "JWT"}
    ),
}


@BOTH_SURFACES
@pytest.mark.parametrize("name", list(WRONG_FOR_THE_RESOURCE))
def test_an_agent_group_token_the_resource_check_refuses_is_an_invalid_token_and_creates_nothing(
    resource: ProtectedResource,
    surface: str,
    name: str,
) -> None:
    """RESOURCE-15, RESOURCE-16, RESOURCE-17, RESOURCE-18, RESOURCE-70: the group exempts only
    the party check, so a token of another issuer, a bad signature, two audiences or the app's
    client ID as audience is a 401 `invalid_token` and nothing is created."""
    app = an_app(resource)

    status, headers, _ = ask(app, resource, surface, WRONG_FOR_THE_RESOURCE[name](resource))

    if surface == "marked-route" and name == "the-apps-client":
        assert status == 401
    else:
        assert (status, headers["www-authenticate"].endswith('error="invalid_token"')) == (
            401,
            True,
        )
    assert_nothing_created(app)


@BOTH_SURFACES
@pytest.mark.parametrize(
    "claims",
    [
        {"scope": ABSENT},
        {"scope": "mcp:other"},
        {"scope": "mcp:tools-extra xmcp:tools"},
        {"scope": ["mcp:tools"]},
    ],
    ids=["absent", "other", "substring", "list"],
)
def test_an_agent_group_token_without_the_scope_is_an_insufficient_scope_and_creates_nothing(
    resource: ProtectedResource,
    surface: str,
    claims: dict[str, object],
) -> None:
    """RESOURCE-20, RESOURCE-70: a token with the agent group whose `scope` lacks the
    resource's is a 403 `insufficient_scope` and nothing is created."""
    app = an_app(resource)

    status, headers, _ = ask(app, resource, surface, an_agent_group_token(resource, **claims))

    assert (status, headers["www-authenticate"].endswith('error="insufficient_scope"')) == (
        403,
        True,
    )
    assert_nothing_created(app)


@BOTH_SURFACES
@pytest.mark.parametrize(
    ("groups", "azp"),
    [
        pytest.param(["/agents/x", RESOURCE_GROUP], "stranger", id="below-the-group"),
        pytest.param(["/agentsX", RESOURCE_GROUP], "stranger", id="only-starts-with-it"),
        pytest.param("/agents", "stranger", id="one-string-unlisted"),
        pytest.param(["/agents", 7], "stranger", id="a-number-unlisted"),
        pytest.param("/agents", "hal", id="one-string-listed"),
        pytest.param(["/agents", 7], "hal", id="a-number-listed"),
    ],
)
def test_a_path_below_or_beside_the_agent_group_or_a_malformed_list_is_refused_as_without_it(
    resource: ProtectedResource,
    surface: str,
    groups: object,
    azp: str,
) -> None:
    """RESOURCE-71: a path below the agent group, one that only starts with it and a malformed
    `groups` claim do not count as the group: the token is refused as 401 `invalid_token`
    without any `transaction` entry."""
    app = an_app(resource)
    token = an_agent_group_token(resource, azp=azp, groups=groups)

    status, headers, _ = ask(app, resource, surface, token)

    well_formed = isinstance(groups, list) and 7 not in groups
    listed = azp == "hal"
    if well_formed and listed:
        assert status == 200
    else:
        assert (status, headers["www-authenticate"].endswith('error="invalid_token"')) == (
            401,
            True,
        )
    assert the_transaction(app).entries == int(well_formed and listed)


def test_a_token_with_a_subgroup_of_the_agent_group_and_a_listed_azp_is_a_person() -> None:
    """RESOURCE-71, RESOURCE-74: below the agent group, a listed client's token is a person's:
    `agent` is `None`."""
    resource = a_resource()
    app = an_app(resource, a_known_person())

    status, _, _ = ask(
        app,
        resource,
        "entry-point",
        an_agent_group_token(resource, "/agents/x", RESOURCE_GROUP, azp="hal"),
    )

    assert status == 200
    [admitted] = app.auth.resource_persons
    assert (admitted.agent, admitted.kind) == (None, AccountKind.PERSON)


def test_the_agent_group_widens_no_other_paths_parties() -> None:
    """RESOURCE-72: an agent-group token of a client no path lists is refused on a person path
    and on a machine path, and creates no account."""
    resource = a_resource()
    app = a_bearer_app(person_paths=PERSON_PATHS, resource=resource)
    token = a_token(
        azp=AGENT_CLIENT,
        groups=[resource.agent_group, "/apps/x/admin"],
        agent_owner=AGENT_OWNER,
        agent_name=AGENT_NAME,
    )

    on_person_path = app.ask(PERSON_ME_PATH, authorization=bearing(token))
    on_machine_path = app.ask(EXPORT_PATH, authorization=bearing(token))

    assert (on_person_path.status_code, on_machine_path.status_code) == (401, 401)
    assert the_agent_account(app) is None
    assert app.audit.account_events == []


@BOTH_SURFACES
@pytest.mark.parametrize("azp", ["stranger", "hal"], ids=["unlisted-azp", "listed-azp"])
@pytest.mark.parametrize(
    "claims",
    [
        pytest.param({"agent_owner": ABSENT}, id="owner-missing"),
        pytest.param({"agent_owner": ""}, id="owner-empty"),
        pytest.param({"agent_owner": 7}, id="owner-not-a-string"),
        pytest.param({"agent_name": ABSENT}, id="name-missing"),
        pytest.param({"agent_name": ["Mozart"]}, id="name-not-a-string"),
        pytest.param({"agent_name": ""}, id="name-empty"),
        pytest.param({"agent_name": "x" * 65}, id="name-65-characters"),
        pytest.param({"agent_name": "Moz\nart"}, id="name-with-a-line-break"),
        pytest.param({"agent_name": "Moz\u0000art"}, id="name-with-a-control-character"),
    ],
)
@pytest.mark.parametrize(
    "also",
    [
        pytest.param({}, id="alone"),
        pytest.param({"scope": ABSENT}, id="without-the-scope"),
        pytest.param({"groups": ["/agents"]}, id="without-the-required-group"),
    ],
)
def test_an_agent_group_token_with_bad_agent_claims_is_an_invalid_token_before_anything_else(
    resource: ProtectedResource,
    surface: str,
    azp: str,
    claims: dict[str, object],
    also: dict[str, object],
) -> None:
    """RESOURCE-73: with the agent group, `agent_owner` must be a non-empty string and
    `agent_name` a printable string of 1 to 64 characters, else 401 `invalid_token`, decided
    before the scope and the group refusals, before any `transaction` entry, and also when the
    `azp` is among the resource's parties."""
    app = an_app(resource)

    status, headers, _ = ask(
        app, resource, surface, an_agent_group_token(resource, azp=azp, **claims, **also)
    )

    assert (status, headers["www-authenticate"].endswith('error="invalid_token"')) == (401, True)
    assert_nothing_created(app)


@pytest.mark.parametrize("name", ["x", "x" * 64, "Mözärt 7"])
def test_an_agent_name_of_one_to_sixty_four_printable_characters_is_admitted(
    resource: ProtectedResource,
    name: str,
) -> None:
    """RESOURCE-73: the name's bounds are inclusive and its characters need not be ASCII."""
    app = an_app(resource)

    status, _, _ = ask(
        app, resource, "entry-point", an_agent_group_token(resource, agent_name=name)
    )

    assert status == 200
    assert app.auth.resource_persons[0].agent == AgentFacts(AGENT_OWNER, name)


@pytest.mark.parametrize(
    "claims",
    [{}, {"agent_owner": "", "agent_name": ""}, {"agent_owner": 7, "agent_name": "x" * 99}],
    ids=["valid", "empty", "malformed"],
)
def test_the_agent_claims_of_a_token_without_the_agent_group_are_ignored(
    resource: ProtectedResource,
    claims: dict[str, object],
) -> None:
    """RESOURCE-74: without the agent group both claims are ignored and the token is a
    person's, with `agent` `None`."""
    app = an_app(resource, a_known_person())
    token = a_resource_token(
        resource,
        groups=[RESOURCE_GROUP],
        **{"agent_owner": AGENT_OWNER, "agent_name": AGENT_NAME, **claims},
    )

    status, _, _ = ask(app, resource, "entry-point", token)

    assert status == 200
    assert app.auth.resource_persons == [
        AuthenticatedUser(OPERATOR_SUBJECT, "lena", MEMBER_ROLE, None)
    ]


@BOTH_SURFACES
@pytest.mark.parametrize(
    "case",
    [
        pytest.param("lacking-the-required-group", id="required-group"),
        pytest.param("lacking-the-login-group", id="login-group"),
    ],
)
def test_an_agent_group_token_without_the_required_or_the_login_group_gets_the_plain_403(
    surface: str,
    case: str,
) -> None:
    """RESOURCE-21, RESOURCE-22, RESOURCE-58, RESOURCE-59: for a token with the agent group too
    the groups must hold `required_group` and the login group, else the plain 403 without
    `WWW-Authenticate`, and the store is not touched."""
    resource = a_resource(
        marked_routes=MARKED_ROUTES,
        required_group="/other/mcp" if case == "lacking-the-login-group" else RESOURCE_GROUP,
    )
    app = an_app(resource, a_known_person())
    accounts_before = deepcopy(the_accounts(app))
    groups = (
        [resource.agent_group, "/other/mcp"]
        if case == "lacking-the-login-group"
        else [resource.agent_group]
    )

    status, headers, body = ask(app, resource, surface, an_agent_group_token(resource, *groups))

    assert (status, body) == (403, {"detail": "Access denied"})
    assert "www-authenticate" not in headers
    assert (the_transaction(app).entries, app.audit.account_events) == (0, [])
    assert the_accounts(app) == accounts_before
    assert app.auth.route_runs == []


@BOTH_TRANSACTIONS
@BOTH_SURFACES
def test_the_first_admission_creates_an_agent_account_and_the_second_only_reads_it(
    resource: ProtectedResource,
    surface: str,
    kind: TransactionKind,
) -> None:
    """RESOURCE-75, RESOURCE-76: a subject no account has gets one account of the kind `AGENT`
    with the role "user", the username of its subject and one `USER_CREATED` without actor,
    in one `transaction` entry; the second admission only reads it."""
    app = an_app(resource, transaction_kind=kind)
    token = an_agent_group_token(resource)

    first, _, _ = ask(app, resource, surface, token)

    assert first == 200
    assert the_transaction(app).entries == 1
    created = the_agent_account(app)
    assert created is not None
    assert (created.username, created.role, created.kind) == (
        OPERATOR_SUBJECT,
        MEMBER_ROLE,
        AccountKind.AGENT,
    )
    created_event = AccountEvent(
        kind=AccountEventKind.USER_CREATED,
        actor_id=None,
        subject_id=OPERATOR_SUBJECT,
        role=MEMBER_ROLE,
    )
    assert app.audit.account_events == [created_event]

    second, _, _ = ask(app, resource, surface, token)

    assert second == 200
    assert the_transaction(app).entries == 2
    assert (the_agent_account(app), app.audit.account_events) == (created, [created_event])


def test_two_concurrent_first_admissions_through_a_serialized_transaction_create_one_account(
    resource: ProtectedResource,
) -> None:
    """RESOURCE-75: the account is created inside the host's serialized entry, so two first
    requests make one account and one event."""
    app = an_app(resource)
    token = an_agent_group_token(resource)

    with ThreadPoolExecutor(max_workers=2) as pool:
        statuses = list(pool.map(lambda _: ask(app, resource, "entry-point", token)[0], range(2)))

    assert statuses == [200, 200]
    assert [user.id for user in the_accounts(app)].count(OPERATOR_SUBJECT) == 1
    assert len(app.audit.account_events) == 1


@BOTH_TRANSACTIONS
@BOTH_SURFACES
def test_a_known_person_met_with_an_agent_token_is_set_to_the_agent_kind_once(
    resource: ProtectedResource,
    surface: str,
    kind: TransactionKind,
) -> None:
    """RESOURCE-76: an account of the kind `PERSON` is set to `AGENT` with one `KIND_CHANGED`
    carrying the new and the previous kind and no actor; its role and username stay, and the
    next admission only reads it."""
    app = an_app(resource, a_known_person(), transaction_kind=kind)
    token = an_agent_group_token(resource)

    first, _, _ = ask(app, resource, surface, token)
    second, _, _ = ask(app, resource, surface, token)

    assert (first, second) == (200, 200)
    account = the_agent_account(app)
    assert account is not None
    assert (account.username, account.role, account.kind) == (
        "lena",
        MEMBER_ROLE,
        AccountKind.AGENT,
    )
    assert app.audit.account_events == [
        AccountEvent(
            kind=AccountEventKind.KIND_CHANGED,
            actor_id=None,
            subject_id=OPERATOR_SUBJECT,
            account_kind=AccountKind.AGENT,
            previous_account_kind=AccountKind.PERSON,
        )
    ]
    assert app.auth.resource_persons[0] == the_admitted_agent("lena")


def test_an_agent_account_met_with_an_agent_token_is_only_read(
    resource: ProtectedResource,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """RESOURCE-76: an account of the kind `AGENT` is only read: no create, no `set_kind`, no
    event."""
    app = an_app(resource, FakeUser(OPERATOR_SUBJECT, "mozart", MEMBER_ROLE, AccountKind.AGENT))
    assert app.accounts is not None
    failing(app.accounts, "set_kind", monkeypatch)
    failing(app.accounts, "create_for_subject", monkeypatch)

    status, _, _ = ask(app, resource, "entry-point", an_agent_group_token(resource))

    assert status == 200
    assert app.audit.account_events == []
    assert app.auth.resource_persons == [the_admitted_agent("mozart")]


def test_a_stored_admin_is_admitted_as_an_agent_with_the_role_user_and_keeps_its_role(
    resource: ProtectedResource,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """RESOURCE-77: whatever role is stored, the agent is admitted with the role "user" and the
    stored role is not written."""
    app = an_app(resource, a_known_person(ADMIN_ROLE))
    assert app.accounts is not None
    failing(app.accounts, "set_role", monkeypatch)
    token = an_agent_group_token(resource, resource.agent_group, RESOURCE_GROUP, "/apps/x/admin")

    status, _, _ = ask(app, resource, "entry-point", token)

    assert status == 200
    assert app.auth.resource_persons == [the_admitted_agent("lena")]
    stored = the_agent_account(app)
    assert stored is not None
    assert stored.role == ADMIN_ROLE


@pytest.mark.parametrize(
    ("method", "path_of"),
    [
        pytest.param("POST", lambda r: r.entry_point, id="entry-point-resource-person"),
        pytest.param("PATCH", lambda r: r.entry_point, id="entry-point-current-user"),
        pytest.param("POST", lambda r: MARKED_NEW_NOTE.template, id="marked-current-user"),
        pytest.param(
            "POST", lambda r: MARKED_RESOURCE_PERSON.template, id="marked-resource-person"
        ),
        pytest.param("POST", lambda r: MARKED_ADMITTED_USER.template, id="marked-admitted-user"),
    ],
)
@pytest.mark.parametrize("sent", [{}, {"origin": "https://evil.example"}], ids=["plain", "origin"])
def test_an_admitted_agent_needs_no_cookie_or_origin_and_every_reader_returns_its_facts(
    resource: ProtectedResource,
    method: str,
    path_of: object,
    sent: dict[str, str],
) -> None:
    """RESOURCE-77: CSRF and the session gate step aside for the agent, and `current_user`,
    `admitted_user` and `resource_person` return it with its `AgentFacts` and the kind
    `AGENT`."""
    app = an_app(resource)

    response = app.ask(
        path_of(resource),  # type: ignore[operator]
        method=method,
        authorization=bearing(an_agent_group_token(resource)),
        headers=sent,
    )

    assert response.status_code == 200
    [admitted] = app.auth.resource_persons
    assert admitted == the_admitted_agent()
    assert admitted.kind is AccountKind.AGENT


@pytest.mark.parametrize(
    ("path_of", "method", "changes"),
    [
        pytest.param(lambda r: r.entry_point, "POST", {"method": "PATCH"}, id="entry-method"),
        pytest.param(
            lambda r: r.entry_point,
            "POST",
            {"headers": [(b"authorization", b"Bearer other")]},
            id="entry-header",
        ),
        pytest.param(
            lambda r: MARKED_RESOURCE_PERSON.template,
            "POST",
            {"method": "GET"},
            id="marked-method",
        ),
        pytest.param(
            lambda r: MARKED_RESOURCE_PERSON.template,
            "POST",
            {"headers": [(b"authorization", b"Bearer other")]},
            id="marked-header",
        ),
        pytest.param(
            lambda r: MARKED_RESOURCE_PERSON.template,
            "POST",
            {"app": FastAPI()},
            id="marked-sub-app",
        ),
    ],
)
def test_the_admission_of_an_agent_ends_when_the_method_or_the_header_changes(
    resource: ProtectedResource,
    path_of: object,
    method: str,
    changes: dict[str, object],
) -> None:
    """RESOURCE-77: a changed method or `Authorization` header, or a sub-app, ends the
    admission of an agent as it ends a person's (RESOURCE-67 to RESOURCE-69)."""
    app = an_app(resource, inner_middleware=(Middleware(RewritingTheRequest, changes=changes),))
    answering_a_runtime_error_with_418(app)

    response = app.ask(
        path_of(resource),  # type: ignore[operator]
        method=method,
        authorization=bearing(an_agent_group_token(resource)),
    )

    assert response.status_code == REFUSED_AS_RUNTIME_ERROR


FAILURES = ["create", "created-audit", "set-kind", "kind-audit", "exit"]


@BOTH_TRANSACTIONS
@BOTH_SURFACES
@pytest.mark.parametrize("failure", FAILURES)
def test_a_failure_in_the_agent_admission_is_the_library_500_and_admits_nothing(
    resource: ProtectedResource,
    surface: str,
    kind: TransactionKind,
    failure: str,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """RESOURCE-78: a failure of a store call, of an audit or of the exit is the library's
    500 and records no admission; a transaction that rolls back leaves nothing, and one that
    applies each call may keep the account or kind, which a later request reads as known."""
    stored = (a_known_person(),) if failure in {"set-kind", "kind-audit"} else ()
    app = an_app(resource, *stored, transaction_kind=kind)
    assert app.accounts is not None
    accounts_before = deepcopy(the_accounts(app))
    if failure == "create":
        failing(app.accounts, "create_for_subject", monkeypatch)
    if failure == "set-kind":
        failing(app.accounts, "set_kind", monkeypatch)
    if failure.endswith("audit"):
        failing(app.audit, "account_event", monkeypatch)
    if failure == "exit":
        the_transaction(app).exit_failure = StoreDown()
    token = an_agent_group_token(resource)
    relay = relayed(app.auth)
    path = resource.entry_point if surface == "entry-point" else A_NOTE

    status, _, _ = ask(app, resource, surface, token)

    assert status == 500
    assert app.auth.route_runs == []
    assert_no_bearer_admission(app, {**relay.added, "method": "GET"}, path, bearing(token)[0])
    if kind is TransactionKind.ROLLING_BACK:
        assert the_accounts(app) == accounts_before
        assert app.audit.account_events == []
    monkeypatch.undo()
    the_transaction(app).exit_failure = None
    events_before = len(app.audit.account_events)

    assert ask(app, resource, surface, token)[0] == 200
    assert len(app.audit.account_events) <= events_before + 1
    assert len(app.audit.account_events) <= 1


@BOTH_TRANSACTIONS
@BOTH_SURFACES
def test_a_username_the_store_refuses_is_the_plain_403_and_a_failing_cleanup_the_500(
    resource: ProtectedResource,
    surface: str,
    kind: TransactionKind,
) -> None:
    """RESOURCE-79: a username already taken at the agent's creation is a plain 403 without
    `WWW-Authenticate` after the transaction's cleanup, and a failing cleanup stays the 500."""
    app = an_app(resource, transaction_kind=kind)
    taken = an_agent_group_token(resource, preferred_username="alice")

    refused = ask(app, resource, surface, taken)

    assert refused[0] == 403
    assert "www-authenticate" not in refused[1]
    assert (the_agent_account(app), app.audit.account_events, app.auth.route_runs) == (None, [], [])

    the_transaction(app).cleanup_failure = StoreDown()

    assert ask(app, resource, surface, taken)[0] == 500


@pytest.mark.parametrize("kind", [AccountKind.AGENT, AccountKind.PERSON])
def test_a_token_without_the_agent_group_only_reads_whatever_kind_the_account_stores(
    resource: ProtectedResource,
    kind: AccountKind,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """RESOURCE-80: a token without the agent group, whose `azp` is listed, only reads the
    account: its stored kind stays, `agent` is `None` and the derived kind is `PERSON`."""
    app = an_app(resource, FakeUser(OPERATOR_SUBJECT, "lena", MEMBER_ROLE, kind))
    assert app.accounts is not None
    failing(app.accounts, "set_kind", monkeypatch)
    failing(app.accounts, "create_for_subject", monkeypatch)

    status, _, _ = ask(app, resource, "entry-point", an_interactive_agent_token(resource))

    assert status == 200
    [admitted] = app.auth.resource_persons
    assert (admitted.agent, admitted.kind) == (None, AccountKind.PERSON)
    stored = the_agent_account(app)
    assert stored is not None
    assert stored.kind is kind
    assert app.audit.account_events == []


def test_a_token_without_the_agent_group_and_an_unknown_subject_gets_the_plain_403(
    resource: ProtectedResource,
) -> None:
    """RESOURCE-80, RESOURCE-60: on a marked route a token without the agent group whose
    subject has no account is the plain 403, and no account appears."""
    app = an_app(resource)

    status, headers, body = ask(app, resource, "marked-route", an_interactive_agent_token(resource))

    assert (status, body) == (403, {"detail": "Access denied"})
    assert "www-authenticate" not in headers
    assert (the_agent_account(app), app.audit.account_events) == (None, [])
