"""The sign-in routes a host installs: the transaction they enter, the answers they send and the
installs they refuse.

Each case drives a FastAPI host through a `TestClient` whose cookie jar is the browser, against
a stateful fake issuer, over a host whose `SignInTransaction` either only serializes or also
rolls back.
"""

from __future__ import annotations

import dataclasses
import threading
from collections.abc import Callable, Iterator
from concurrent.futures import ThreadPoolExecutor
from copy import deepcopy
from dataclasses import dataclass
from datetime import timedelta

import anyio
import pytest
from fastapi import Depends, FastAPI, Request
from fastapi.responses import StreamingResponse
from fastapi.routing import APIRoute
from fastapi.testclient import TestClient
from httpx import Response as HttpxResponse
from starlette.responses import Response
from starlette.types import Receive, Scope, Send

from tests.support.oidc_login_host import (
    ADMISSION,
    BACKCHANNEL_LOGOUT_PATH,
    CALLBACK_PATH,
    LEGACY_ADMIN,
    LOGIN_GROUP,
    LOGOUT_PATH,
    OTHER_SUBJECT,
    SIGN_IN_PATHS,
    START_PATH,
    SUBJECT,
    OidcHost,
    StoreDown,
    TransactionKind,
    UsersWithSnapshots,
    UsersWithSnapshotsAndCaseInsensitiveUsernames,
    an_oidc_host,
    failing,
    is_cleared,
    set_cookies,
)
from tests.support.webauth_arrangement import (
    FIXED_INSTANT,
    FakeUser,
    an_http_scope,
    body_of,
    drive,
    seeded_session,
    session_cookie_header,
    starts,
)
from webauth.admission import AdmissionConfig, AdmissionRefusal
from webauth.cookies import sign_session_id
from webauth.oidc import OidcIdentity, OidcRefusal, OidcRefusalReason
from webauth.ports import AccountEventKind, AccountKind
from webauth.sign_in_routes import (
    LogoutPageText,
    RefusalPage,
    SignInPaths,
    SignInRefusal,
    install_sign_in_routes,
)

BYSTANDER = FakeUser(id=OTHER_SUBJECT, username="omar")
BOTH_KINDS = [
    pytest.param(TransactionKind.PER_CALL, id="per-call host"),
    pytest.param(TransactionKind.ROLLING_BACK, id="rolling-back host"),
]


class _AnswerFailingBeforeItsStart(Response):
    async def __call__(self, scope: Scope, receive: Receive, send: Send) -> None:
        raise StoreDown


def _raise_in_the_hook(_request: Request, _refusal: SignInRefusal) -> Response:
    raise StoreDown


def _answer_failing_before_its_start(_request: Request, _refusal: SignInRefusal) -> Response:
    return _AnswerFailingBeforeItsStart()


def _carrying_its_own_cookie(_request: Request, _refusal: SignInRefusal) -> Response:
    answer = Response(status_code=403)
    answer.set_cookie("flash", "refused")
    return answer


def _signed_in_holding_session_of_bystander(host: OidcHost) -> tuple[str, str]:
    """The query of a login at the issuer and the Cookie header of a browser that also holds
    the session of the bystander, which that login replaces."""
    now = FIXED_INSTANT
    replaced = seeded_session(
        host.sessions,
        host.lock.hold(),
        BYSTANDER.id,
        now,
        now + timedelta(hours=1),
    )
    query = host.sign_in_at_issuer()
    session_cookie = session_cookie_header(sign_session_id(replaced.id, host.config.signing_key))
    return query, f"{host.pending_cookie(query)}; {session_cookie}"


def _state_of(host: OidcHost) -> tuple[list[tuple[str, str]], list[str], list[AccountEventKind]]:
    return (
        sorted((user.id, user.role) for user in host.accounts.list()),
        [record.id for record in host.sessions.list_active()],
        [event.kind for event in host.audit.account_events],
    )


def _is_refused_and_leaves_no_session_cookie(
    response: HttpxResponse,
    host: OidcHost,
    query: str,
) -> bool:
    return (
        response.status_code == 500
        and is_cleared(response, host.pending_cookie_name(query))
        and host.config.session_cookie_name not in set_cookies(response)
    )


def test_a_start_enters_no_sign_in_transaction() -> None:
    host = an_oidc_host()

    response = host.client.get(START_PATH)

    assert (response.status_code, host.transaction.entries) == (303, 0)


@pytest.mark.parametrize(
    ("asked_for", "landing"),
    [
        pytest.param("/app/albums/42", "/app/albums/42", id="a deep link below the mount"),
        pytest.param("/albums/42", "/app/", id="a path outside the mount"),
        pytest.param(None, "/app/", id="no return path"),
    ],
)
def test_a_mounted_host_returns_below_its_root_path_and_otherwise_to_the_mount_root(
    asked_for: str | None,
    landing: str,
) -> None:
    """REFUSE-03, REFUSE-06, REFUSE-07: a mounted host returns to the explicit `next` as given."""
    host = an_oidc_host(root_path="/app")

    response = host.callback(host.sign_in_at_issuer(return_to=asked_for))

    assert (response.status_code, response.headers["location"]) == (303, landing)


@pytest.mark.parametrize("kind", BOTH_KINDS)
def test_an_admitted_callback_signs_in_with_one_entry_and_one_session_cookie(
    kind: TransactionKind,
) -> None:
    """SIGNIN-18, SIGNIN-21, SIGNIN-23, REFUSE-02: after signing in, the person lands on the
    page they were sent from, and a browser sign-in creates an account of kind PERSON."""
    host = an_oidc_host(transaction_kind=kind)

    response = host.callback(host.sign_in_at_issuer(return_to="/albums/42"))

    assert (response.status_code, response.headers["location"]) == (303, "/albums/42")
    assert host.config.session_cookie_name in set_cookies(response)
    assert (host.transaction.entries, host.sessions.count_active()) == (1, 1)
    assert [(account.id, account.kind) for account in host.accounts.list()] == [
        (SUBJECT, AccountKind.PERSON)
    ]


@pytest.mark.parametrize(
    ("groups_claim", "admission", "refusal"),
    [
        pytest.param((), ADMISSION, AdmissionRefusal.NOT_A_MEMBER, id="not a member"),
        pytest.param(
            (LOGIN_GROUP,),
            AdmissionConfig(
                bound_issuer="https://other.example/realms/lab",
                login_group=LOGIN_GROUP,
                admin_group=f"{LOGIN_GROUP}/admin",
            ),
            AdmissionRefusal.FOREIGN_ISSUER,
            id="a foreign issuer",
        ),
    ],
)
def test_an_identity_refused_before_admission_writes_nothing_and_enters_no_transaction(
    groups_claim: tuple[str, ...],
    admission: AdmissionConfig,
    refusal: AdmissionRefusal,
) -> None:
    host = an_oidc_host(BYSTANDER, groups_claim=groups_claim, admission=admission)
    query, cookie = _signed_in_holding_session_of_bystander(host)
    before = _state_of(host)

    response = host.callback(query, cookie=cookie)

    assert [attempt.cause for attempt in host.refusals] == [refusal]
    assert (response.status_code, host.transaction.entries) == (403, 0)
    assert _state_of(host) == before
    assert is_cleared(response, host.pending_cookie_name(query))


@pytest.mark.parametrize(
    "cause",
    [
        *(OidcRefusal(reason) for reason in OidcRefusalReason),
        *AdmissionRefusal,
    ],
    ids=lambda cause: str(cause.reason if isinstance(cause, OidcRefusal) else cause),
)
def test_a_refusal_shows_no_access_for_a_person_outside_the_app_and_login_failed_otherwise(
    cause: OidcRefusal | AdmissionRefusal,
) -> None:
    """REFUSE-24, REFUSE-25: no access for a person outside the app, login failed otherwise."""
    expected = (
        RefusalPage.NO_ACCESS
        if cause is AdmissionRefusal.NOT_A_MEMBER
        else RefusalPage.LOGIN_FAILED
    )

    assert SignInRefusal(cause).page is expected


_A_FOREIGN_ISSUERS_ADMISSION = AdmissionConfig(
    bound_issuer="https://other.example/realms/lab",
    login_group=LOGIN_GROUP,
    admin_group=f"{LOGIN_GROUP}/admin",
)


def _a_foreign_issuers_identity() -> OidcHost:
    return an_oidc_host(admission=_A_FOREIGN_ISSUERS_ADMISSION)


def _with_another_code(query: str) -> str:
    return query.replace("code=", "code=not-issued-")


def _without_a_state(query: str) -> str:
    return query.replace("state=", "other=")


@pytest.mark.parametrize(
    ("host", "returned_query", "cause", "page"),
    [
        pytest.param(
            lambda: an_oidc_host(groups_claim=()),
            str,
            AdmissionRefusal.NOT_A_MEMBER,
            RefusalPage.NO_ACCESS,
            id="not a member",
        ),
        pytest.param(
            _a_foreign_issuers_identity,
            str,
            AdmissionRefusal.FOREIGN_ISSUER,
            RefusalPage.LOGIN_FAILED,
            id="a foreign issuer",
        ),
        pytest.param(
            lambda: an_oidc_host(FakeUser(id="user-7", username="lena")),
            str,
            AdmissionRefusal.USERNAME_TAKEN,
            RefusalPage.LOGIN_FAILED,
            id="a taken username",
        ),
        pytest.param(
            an_oidc_host,
            _with_another_code,
            OidcRefusal(OidcRefusalReason.TOKEN_REQUEST_REFUSED, idp_error="invalid_grant"),
            RefusalPage.LOGIN_FAILED,
            id="an issuer that refuses the code",
        ),
    ],
)
def test_a_refusal_reaches_the_hook_as_its_cause_alone_with_its_page(
    host: Callable[[], OidcHost],
    returned_query: Callable[[str], str],
    cause: OidcRefusal | AdmissionRefusal,
    page: RefusalPage,
) -> None:
    """SIGNIN-28, REFUSE-26, REFUSE-27: both kinds of refusal reach the hook, no identity."""
    refused_host = host()

    refused_host.callback(returned_query(refused_host.sign_in_at_issuer()))

    [refusal] = refused_host.refusals
    assert (refusal, refusal.page) == (SignInRefusal(cause), page)


def test_a_refusal_holds_no_field_of_the_identity() -> None:
    """REFUSE-27: no public field of a refusal is a field of the person it refused."""
    identity_fields = {field.name for field in dataclasses.fields(OidcIdentity)} | {"username"}
    refusal_fields = {
        field.name
        for refusal_type in (SignInRefusal, OidcRefusal)
        for field in dataclasses.fields(refusal_type)
    }

    assert refusal_fields.isdisjoint(identity_fields)
    assert all(
        not [name for name in vars(member) if not name.startswith("_")]
        for member in AdmissionRefusal
    )


@pytest.mark.parametrize("kind", BOTH_KINDS)
@pytest.mark.parametrize(
    ("account_store", "stored_username"),
    [
        pytest.param(UsersWithSnapshots, "lena", id="an exact duplicate"),
        pytest.param(UsersWithSnapshotsAndCaseInsensitiveUsernames, "LENA", id="a differing case"),
    ],
)
def test_a_taken_username_refuses_through_the_hook_and_changes_nothing(
    kind: TransactionKind,
    account_store: type[UsersWithSnapshots],
    stored_username: str,
) -> None:
    """APP-22: a username the store refuses refuses the sign-in and writes nothing."""
    host = an_oidc_host(
        BYSTANDER,
        FakeUser(id="user-7", username=stored_username),
        transaction_kind=kind,
        account_store=account_store,
    )
    query, cookie = _signed_in_holding_session_of_bystander(host)
    before = _state_of(host)

    response = host.callback(query, cookie=cookie)

    assert [attempt.cause for attempt in host.refusals] == [AdmissionRefusal.USERNAME_TAKEN]
    assert (response.status_code, host.transaction.entries) == (403, 1)
    assert _state_of(host) == before
    assert is_cleared(response, host.pending_cookie_name(query))
    assert host.config.session_cookie_name not in set_cookies(response)


@dataclass(frozen=True)
class BlockFault:
    """A store or the audit sink failing inside the transaction's block, and what a per-call
    host keeps of the block's writes before it."""

    fail: Callable[[OidcHost, pytest.MonkeyPatch], None]
    stored_users: tuple[FakeUser, ...]
    per_call_residue: object


_BYSTANDER_ACCOUNT = (OTHER_SUBJECT, "user")
_NEW_ACCOUNT = (SUBJECT, "user")

_BLOCK_FAULTS = [
    pytest.param(
        BlockFault(
            lambda host, patch: failing(host.accounts, "create_for_subject", patch),
            (BYSTANDER,),
            ([_BYSTANDER_ACCOUNT], ["session-1"], []),
        ),
        id="create_for_subject raises: nothing was written",
    ),
    pytest.param(
        BlockFault(
            lambda host, patch: failing(host.accounts, "set_role", patch),
            (BYSTANDER, LEGACY_ADMIN),
            (sorted([_BYSTANDER_ACCOUNT, (SUBJECT, "admin")]), ["session-1"], []),
        ),
        id="set_role raises: the role stands",
    ),
    pytest.param(
        BlockFault(
            lambda host, patch: failing(host.sessions, "create", patch),
            (BYSTANDER,),
            (sorted([_BYSTANDER_ACCOUNT, _NEW_ACCOUNT]), [], [AccountEventKind.USER_CREATED]),
        ),
        id="sessions.create raises: the account stays and the replaced session stays ended",
    ),
    pytest.param(
        BlockFault(
            lambda host, patch: failing(host.audit, "account_event", patch),
            (BYSTANDER,),
            (sorted([_BYSTANDER_ACCOUNT, _NEW_ACCOUNT]), ["session-1"], []),
        ),
        id="the audit sink raises: the account stays without its event",
    ),
]


@pytest.mark.parametrize("fault", _BLOCK_FAULTS)
@pytest.mark.parametrize("kind", BOTH_KINDS)
def test_a_failure_in_the_block_answers_500_with_the_deletion_and_keeps_only_what_the_host_keeps(
    fault: BlockFault,
    kind: TransactionKind,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """SIGNIN-23, SIGNIN-24, SIGNIN-25: a failure in the block escapes through the exit; a
    rolling-back host keeps none of the writes and a per-call host keeps the account and the
    events before it."""
    host = an_oidc_host(*deepcopy(fault.stored_users), transaction_kind=kind)
    query, cookie = _signed_in_holding_session_of_bystander(host)
    before = _state_of(host)
    fault.fail(host, monkeypatch)

    response = host.callback(query, cookie=cookie)

    assert _is_refused_and_leaves_no_session_cookie(response, host, query)
    assert host.transaction.entries == 1
    expected = before if kind is TransactionKind.ROLLING_BACK else fault.per_call_residue
    assert _state_of(host) == expected


def test_a_failing_commit_answers_500_with_the_deletion_and_issues_no_session_cookie() -> None:
    """SIGNIN-22: the session cookie is issued only after the transaction's exit returned."""
    host = an_oidc_host(transaction_kind=TransactionKind.ROLLING_BACK)
    host.sessions.commit_failure = StoreDown()
    query = host.sign_in_at_issuer()

    response = host.callback(query)

    assert _is_refused_and_leaves_no_session_cookie(response, host, query)
    assert host.sessions.count_active() == 0


@pytest.mark.parametrize("behind_base_http_middleware", [False, True], ids=["plain", "base-http"])
def test_a_refusal_hook_that_raises_answers_500_with_the_deletion(
    *,
    behind_base_http_middleware: bool,
) -> None:
    host = an_oidc_host(groups_claim=(), behind_base_http_middleware=behind_base_http_middleware)
    host.answer_refusals = _raise_in_the_hook
    query = host.sign_in_at_issuer()

    response = host.callback(query)

    assert _is_refused_and_leaves_no_session_cookie(response, host, query)


@pytest.mark.parametrize("behind_base_http_middleware", [False, True], ids=["plain", "base-http"])
def test_a_refusal_answer_that_fails_before_start_answers_500_with_the_deletion(
    *,
    behind_base_http_middleware: bool,
) -> None:
    host = an_oidc_host(groups_claim=(), behind_base_http_middleware=behind_base_http_middleware)
    host.answer_refusals = _answer_failing_before_its_start
    query = host.sign_in_at_issuer()

    response = host.callback(query)

    assert _is_refused_and_leaves_no_session_cookie(response, host, query)


def test_a_refusal_hook_that_raises_before_the_pending_cookie_is_selected_answers_the_ordinary_500() -> (  # noqa: E501
    None
):
    host = an_oidc_host()
    host.answer_refusals = _raise_in_the_hook
    query = host.sign_in_at_issuer().replace("state=", "other=")

    response = host.callback(query)

    assert response.status_code == 500
    assert set_cookies(response) == {}


def test_a_refusal_answer_keeps_its_own_cookies_beside_the_pending_deletion() -> None:
    """SIGNIN-29: the hook's `Response` is the callback's answer."""
    host = an_oidc_host(groups_claim=())
    host.answer_refusals = _carrying_its_own_cookie
    query = host.sign_in_at_issuer()

    response = host.callback(query)

    assert response.status_code == 403
    assert set(set_cookies(response)) == {"flash", host.pending_cookie_name(query)}


def _drive_the_callback(host: OidcHost, query: str) -> tuple[list[dict[str, object]], object]:
    app: FastAPI = host.client.app  # pyright: ignore[reportAssignmentType]
    scope = an_http_scope(
        app,
        CALLBACK_PATH,
        headers=[
            (b"host", b"testserver"),
            (b"cookie", host.pending_cookie(query).encode()),
        ],
    )
    scope["query_string"] = query.encode()
    messages, raised = anyio.run(lambda: drive(app, scope, body_chunks=[]))
    return [dict(message) for message in messages], raised


@pytest.mark.parametrize(
    "answer",
    [_raise_in_the_hook, _answer_failing_before_its_start],
    ids=["the hook raises", "the answer fails before its start"],
)
def test_a_failure_before_the_start_is_raised_once_the_500_is_sent(
    answer: Callable[[Request, SignInRefusal], Response],
) -> None:
    """SIGNIN-31: a hook that raises or an answer that fails before its start gets a plain 500 with
    the deletion, then the failure is raised."""
    host = an_oidc_host(groups_claim=())
    host.answer_refusals = answer
    query = host.sign_in_at_issuer()

    messages, raised = _drive_the_callback(host, query)

    [start] = starts(messages)  # pyright: ignore[reportArgumentType]
    assert start["status"] == 500  # pyright: ignore[reportTypedDictNotRequiredAccess]
    assert body_of(messages) == b"Internal Server Error"  # pyright: ignore[reportArgumentType]
    assert [
        value
        for name, value in start["headers"]  # pyright: ignore[reportTypedDictNotRequiredAccess]
        if name == b"set-cookie"
        and value.startswith(host.pending_cookie_name(query).encode())
        and b"max-age=0" in value.lower()
    ]
    assert isinstance(raised, StoreDown)


def test_a_failure_after_the_answer_started_sends_no_second_response() -> None:
    host = an_oidc_host(groups_claim=())

    def chunks_then_down() -> Iterator[bytes]:
        yield b"partial"
        raise StoreDown

    host.answer_refusals = lambda _request, _refusal: StreamingResponse(chunks_then_down())
    query = host.sign_in_at_issuer()

    messages, raised = _drive_the_callback(host, query)

    assert [message["status"] for message in starts(messages)] == [200]  # pyright: ignore[reportArgumentType]
    assert isinstance(raised, StoreDown)


def test_two_concurrent_callbacks_exchange_outside_the_transaction_and_keep_the_cap() -> None:
    """SIGNIN-19: no issuer call runs inside the transaction."""
    host = an_oidc_host(max_sessions=1)
    first, second = host.sign_in_at_issuer(), host.sign_in_at_issuer()
    cookies = [host.pending_cookie(query) for query in (first, second)]
    host.issuer.before_exchange = threading.Barrier(2, timeout=10).wait

    with ThreadPoolExecutor(max_workers=2) as pool:
        responses = list(
            pool.map(
                lambda attempt: host.callback(attempt[0], cookie=attempt[1]),
                zip((first, second), cookies, strict=True),
            )
        )

    assert [response.status_code for response in responses] == [303, 303]
    assert host.transaction.entries == 2
    assert host.sessions.count_active() == 1


def test_each_login_the_start_route_begins_holds_a_signed_pending_cookie_of_its_own() -> None:
    """SIGNIN-17: every start sets one pending cookie under a name of its own, and a callback
    carrying that cookie tampered with is refused."""
    host = an_oidc_host()
    first, second = host.sign_in_at_issuer(), host.sign_in_at_issuer()
    pending = host.pending_cookie(first)
    tampered = pending[:-1] + ("0" if pending[-1] != "0" else "1")

    names = host.pending_cookie_names()

    refused = host.callback(first, cookie=tampered)

    assert names == {host.pending_cookie_name(first), host.pending_cookie_name(second)}
    assert len(host.refusals) == 1
    assert host.config.session_cookie_name not in set_cookies(refused)


def test_a_callback_enters_the_transaction_once_and_reads_no_record_after_its_exit() -> None:
    """SIGNIN-18: the callback enters the transaction once and reads no record after its exit."""
    host = an_oidc_host(BYSTANDER, strict_records=True)
    query, cookie = _signed_in_holding_session_of_bystander(host)

    response = host.callback(query, cookie=cookie)

    assert (response.status_code, host.transaction.entries) == (303, 1)


def test_installing_without_stating_whether_the_host_keeps_the_id_token_raises() -> None:
    """SIGNIN-61: install without `keeps_id_token` raises `TypeError` and registers no route."""
    app = FastAPI()
    arguments = _install_arguments()
    del arguments["keeps_id_token"]

    with pytest.raises(TypeError, match="keeps_id_token"):
        install_sign_in_routes(app, **arguments)  # type: ignore[arg-type]

    assert not _sign_in_routes_of(app)


@pytest.mark.parametrize(
    "max_sessions",
    [
        pytest.param(0, id="zero"),
        pytest.param(-1, id="negative"),
        pytest.param(True, id="bool"),
        pytest.param("2", id="text"),
        pytest.param(2.0, id="float"),
    ],
)
def test_a_cap_that_is_not_a_positive_whole_number_is_refused_before_any_route_is_registered(
    max_sessions: object,
) -> None:
    """SIGNIN-62: install validates `max_sessions` before it registers a route."""
    app = FastAPI()
    arguments = {**_install_arguments(), "max_sessions": max_sessions}

    with pytest.raises(ValueError, match="max_sessions"):
        install_sign_in_routes(app, **arguments)  # type: ignore[arg-type]

    assert not _sign_in_routes_of(app)


@pytest.mark.parametrize(
    ("logout", "page_text"),
    [
        pytest.param(LOGOUT_PATH, None, id="a logout path without page text"),
        pytest.param(
            None,
            lambda _request: LogoutPageText(language="en", button_label="Sign out"),
            id="page text without a logout path",
        ),
    ],
)
def test_a_logout_path_and_page_text_come_together_or_install_refuses_before_any_route(
    logout: str | None,
    page_text: Callable[[Request], LogoutPageText] | None,
) -> None:
    """SIGNIN-15: one of `paths.logout` and `logout_page_text` without the other refuses install
    before any route."""
    app = FastAPI()
    arguments = {
        **_install_arguments(),
        "paths": SignInPaths(start=START_PATH, callback=CALLBACK_PATH, logout=logout),
        "logout_page_text": page_text,
    }

    with pytest.raises(ValueError, match="logout"):
        install_sign_in_routes(app, **arguments)  # type: ignore[arg-type]

    assert not _sign_in_routes_of(app)


def test_a_host_without_a_logout_path_and_page_text_registers_no_logout_route() -> None:
    """SIGNIN-16: a host with neither registers no logout route."""
    app = FastAPI()
    arguments = {
        **_install_arguments(),
        "paths": SignInPaths(start=START_PATH, callback=CALLBACK_PATH),
        "logout_page_text": None,
    }

    install_sign_in_routes(app, **arguments)  # type: ignore[arg-type]

    assert _sign_in_routes_of(app) == [START_PATH, CALLBACK_PATH]


def _install_arguments() -> dict[str, object]:
    host = an_oidc_host()
    return {
        "paths": SIGN_IN_PATHS,
        "relying_party": lambda _request: host.relying_party,
        "admission": ADMISSION,
        "transaction": host.transaction,
        "refused": lambda _request, _refusal: Response(status_code=403),
        "keeps_id_token": True,
        "max_sessions": None,
        "logout_page_text": lambda _request: LogoutPageText(language="en", button_label="Sign out"),
        "backchannel_dependencies": (),
    }


def test_back_channel_dependencies_without_a_back_channel_path_refuse_install_before_any_route() -> (  # noqa: E501
    None
):
    """SIGNIN-46: dependencies without the back-channel path refuse install before any route."""
    app = FastAPI()
    arguments = {
        **_install_arguments(),
        "paths": SignInPaths(start=START_PATH, callback=CALLBACK_PATH, logout=LOGOUT_PATH),
        "backchannel_dependencies": [Depends(lambda: None)],
    }

    with pytest.raises(ValueError, match="backchannel"):
        install_sign_in_routes(app, **arguments)  # type: ignore[arg-type]

    assert not _sign_in_routes_of(app)


def _sign_in_routes_of(app: FastAPI) -> list[str]:
    paths = {
        SIGN_IN_PATHS.start,
        SIGN_IN_PATHS.callback,
        LOGOUT_PATH,
        BACKCHANNEL_LOGOUT_PATH,
    }
    routes = [route for route in app.routes if isinstance(route, APIRoute)]
    return [route.path for route in routes if route.path in paths]


@pytest.mark.parametrize(
    ("groups_claim", "admission", "returned_query"),
    [
        pytest.param((), ADMISSION, str, id="not a member"),
        pytest.param((LOGIN_GROUP,), _A_FOREIGN_ISSUERS_ADMISSION, str, id="a foreign issuer"),
        pytest.param((LOGIN_GROUP,), ADMISSION, _with_another_code, id="a code the issuer refuses"),
        pytest.param((LOGIN_GROUP,), ADMISSION, _without_a_state, id="a callback without a state"),
    ],
)
def test_a_refusal_before_the_admission_decision_enters_no_transaction(
    groups_claim: tuple[str, ...],
    admission: AdmissionConfig,
    returned_query: Callable[[str], str],
) -> None:
    """SIGNIN-20: a refusal before the admission decision enters no transaction."""
    host = an_oidc_host(groups_claim=groups_claim, admission=admission)

    response = host.callback(returned_query(host.sign_in_at_issuer()))

    assert (response.status_code, len(host.refusals), host.transaction.entries) == (403, 1, 0)


@pytest.mark.parametrize(
    ("groups_claim", "hook", "failing_call"),
    [
        pytest.param((LOGIN_GROUP,), None, None, id="an admitted login"),
        pytest.param((), None, None, id="a refusal"),
        pytest.param((LOGIN_GROUP,), None, "create_for_subject", id="a failure in the block"),
        pytest.param((), _raise_in_the_hook, None, id="a hook that raises"),
        pytest.param(
            (), _answer_failing_before_its_start, None, id="an answer that fails before its start"
        ),
    ],
)
def test_every_callback_answer_deletes_its_pending_cookie_and_leaves_the_other_tabs(
    groups_claim: tuple[str, ...],
    hook: Callable[[Request, SignInRefusal], Response] | None,
    failing_call: str | None,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """SIGNIN-30, SIGNIN-32: every callback answer deletes its pending cookie and leaves the other
    tabs' cookies."""
    host = an_oidc_host(groups_claim=groups_claim)
    if hook is not None:
        host.answer_refusals = hook
    if failing_call is not None:
        failing(host.accounts, failing_call, monkeypatch)
    other_tab = host.sign_in_at_issuer()
    query = host.sign_in_at_issuer()

    response = host.callback(query)

    assert is_cleared(response, host.pending_cookie_name(query))
    assert host.pending_cookie_names() == {host.pending_cookie_name(other_tab)}


@pytest.mark.parametrize("method", ["GET", "PUT", "PATCH", "DELETE"])
@pytest.mark.parametrize("path", [LOGOUT_PATH, BACKCHANNEL_LOGOUT_PATH])
def test_the_logout_and_back_channel_routes_serve_post_only(path: str, method: str) -> None:
    """SIGNIN-10, SIGNIN-41: the logout and the back-channel route serve `POST` only."""
    app = FastAPI()
    install_sign_in_routes(app, **_install_arguments())  # type: ignore[arg-type]

    response = TestClient(app).request(method, path)

    assert response.status_code == 405
    assert response.headers["allow"] == "POST"


def test_install_registers_the_start_callback_logout_and_back_channel_routes() -> None:
    """SIGNIN-01: install registers the four routes on the host's app."""
    app = FastAPI()

    install_sign_in_routes(app, **_install_arguments())  # type: ignore[arg-type]

    assert sorted(_sign_in_routes_of(app)) == sorted(
        [START_PATH, CALLBACK_PATH, LOGOUT_PATH, BACKCHANNEL_LOGOUT_PATH]
    )
