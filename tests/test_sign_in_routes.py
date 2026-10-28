"""The sign-in routes a host installs: the transaction they enter, the answers they send, the
policies they derive and the installs they refuse.

Each case drives a FastAPI host through a `TestClient` whose cookie jar is the browser, against
a stateful fake issuer, over a host whose `SignInTransaction` either only serializes or also
rolls back.
"""

from __future__ import annotations

import threading
from collections.abc import Callable, Iterator
from concurrent.futures import ThreadPoolExecutor
from contextlib import AbstractContextManager
from copy import deepcopy
from dataclasses import dataclass
from datetime import timedelta

import anyio
import pytest
from fastapi import FastAPI, Request
from fastapi.responses import StreamingResponse
from fastapi.routing import APIRoute
from fastapi.testclient import TestClient
from httpx import Response as HttpxResponse
from starlette.responses import Response
from starlette.types import Receive, Scope, Send

from tests.support.oidc_arrangement import FakeIssuer, a_relying_party
from tests.support.oidc_login_host import (
    ADMISSION,
    CALLBACK_PATH,
    LEGACY_ADMIN,
    LOGIN_GROUP,
    LOGOUT_PATH,
    OTHER_SUBJECT,
    SAME_ORIGIN_FORM,
    SIGN_IN_PATHS,
    START_PATH,
    SUBJECT,
    OidcHost,
    StoreDown,
    TransactionKind,
    an_oidc_host,
    failing,
    is_cleared,
    set_cookies,
)
from tests.support.webauth_arrangement import (
    FIXED_INSTANT,
    HTTPS_TEST_SERVER,
    FakeUser,
    SessionRecordsInMemory,
    a_web_auth_config,
    an_http_scope,
    drive,
    seeded_session,
    session_cookie_header,
    starts,
)
from webauth.config import install_web_auth_config
from webauth.cookies import sign_session_id
from webauth.middleware import SessionGate, install_web_auth_middleware
from webauth.oidc import OidcRefusal, OidcRefusalReason
from webauth.oidc_login import AdmissionConfig, AdmissionRefusal
from webauth.policies import (
    BodySizePolicy,
    CsrfPolicy,
    RateLimitBudget,
    RateLimitPolicy,
    RateLimitRule,
    SecurityHeadersPolicy,
)
from webauth.ports import AccountEventKind, SignInStores
from webauth.sign_in_routes import (
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
        host.sessions, host.lock.hold_uncounted(), BYSTANDER.id, now, now + timedelta(hours=1),
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
    response: HttpxResponse, host: OidcHost, query: str,
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


@pytest.mark.parametrize(("asked_for", "landing"), [
    pytest.param("/app/albums/42", "/app/albums/42", id="a deep link below the mount"),
    pytest.param("/albums/42", "/app/", id="a path outside the mount"),
    pytest.param(None, "/app/", id="no return path"),
])
def test_a_mounted_host_returns_below_its_root_path_and_otherwise_to_the_mount_root(
    asked_for: str | None, landing: str,
) -> None:
    host = an_oidc_host(root_path="/app")

    response = host.callback(host.sign_in_at_issuer(return_to=asked_for))

    assert (response.status_code, response.headers["location"]) == (303, landing)


@pytest.mark.parametrize("kind", BOTH_KINDS)
def test_an_admitted_callback_signs_in_with_one_entry_and_one_session_cookie(
    kind: TransactionKind,
) -> None:
    host = an_oidc_host(transaction_kind=kind)

    response = host.callback(host.sign_in_at_issuer(return_to="/albums/42"))

    assert (response.status_code, response.headers["location"]) == (303, "/albums/42")
    assert host.config.session_cookie_name in set_cookies(response)
    assert (host.transaction.entries, host.sessions.count_active()) == (1, 1)


@pytest.mark.parametrize(("groups_claim", "admission", "refusal"), [
    pytest.param((), ADMISSION, AdmissionRefusal.NOT_A_MEMBER, id="not a member"),
    pytest.param(
        (LOGIN_GROUP,),
        AdmissionConfig(
            bound_issuer="https://other.example/realms/lab", login_group=LOGIN_GROUP,
            admin_group=f"{LOGIN_GROUP}/admin",
        ),
        AdmissionRefusal.FOREIGN_ISSUER, id="a foreign issuer",
    ),
])
def test_an_identity_refused_before_admission_writes_nothing_and_enters_no_transaction(
    groups_claim: tuple[str, ...], admission: AdmissionConfig, refusal: AdmissionRefusal,
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
    expected = (
        RefusalPage.NO_ACCESS if cause is AdmissionRefusal.NOT_A_MEMBER
        else RefusalPage.LOGIN_FAILED
    )

    assert SignInRefusal(cause).page is expected


@pytest.mark.parametrize("kind", BOTH_KINDS)
def test_a_taken_username_refuses_through_the_hook_and_changes_nothing(
    kind: TransactionKind,
) -> None:
    host = an_oidc_host(
        BYSTANDER, FakeUser(id="user-7", username="lena"), transaction_kind=kind,
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
    fault: BlockFault, kind: TransactionKind, monkeypatch: pytest.MonkeyPatch,
) -> None:
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
    host = an_oidc_host(transaction_kind=TransactionKind.ROLLING_BACK)
    host.sessions.commit_failure = StoreDown()
    query = host.sign_in_at_issuer()

    response = host.callback(query)

    assert _is_refused_and_leaves_no_session_cookie(response, host, query)
    assert host.sessions.count_active() == 0


@pytest.mark.parametrize("behind_base_http_middleware", [False, True], ids=["plain", "base-http"])
def test_a_refusal_hook_that_raises_answers_500_with_the_deletion(
    *, behind_base_http_middleware: bool,
) -> None:
    host = an_oidc_host(groups_claim=(), behind_base_http_middleware=behind_base_http_middleware)
    host.answer_refusals = _raise_in_the_hook
    query = host.sign_in_at_issuer()

    response = host.callback(query)

    assert _is_refused_and_leaves_no_session_cookie(response, host, query)


@pytest.mark.parametrize("behind_base_http_middleware", [False, True], ids=["plain", "base-http"])
def test_a_refusal_answer_that_fails_before_start_answers_500_with_the_deletion(
    *, behind_base_http_middleware: bool,
) -> None:
    host = an_oidc_host(groups_claim=(), behind_base_http_middleware=behind_base_http_middleware)
    host.answer_refusals = _answer_failing_before_its_start
    query = host.sign_in_at_issuer()

    response = host.callback(query)

    assert _is_refused_and_leaves_no_session_cookie(response, host, query)


def test_a_refusal_hook_that_raises_before_the_pending_cookie_is_selected_answers_the_ordinary_500(
) -> None:
    host = an_oidc_host()
    host.answer_refusals = _raise_in_the_hook
    query = host.sign_in_at_issuer().replace("state=", "other=")

    response = host.callback(query)

    assert response.status_code == 500
    assert set_cookies(response) == {}


def test_a_refusal_answer_keeps_its_own_cookies_beside_the_pending_deletion() -> None:
    host = an_oidc_host(groups_claim=())
    host.answer_refusals = _carrying_its_own_cookie
    query = host.sign_in_at_issuer()

    response = host.callback(query)

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


def test_a_failure_before_the_start_is_raised_once_the_500_is_sent() -> None:
    host = an_oidc_host(groups_claim=())
    host.answer_refusals = _raise_in_the_hook
    query = host.sign_in_at_issuer()

    messages, raised = _drive_the_callback(host, query)

    assert [message["status"] for message in starts(messages)] == [500]  # pyright: ignore[reportArgumentType]
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
    host = an_oidc_host(max_sessions=1)
    first, second = host.sign_in_at_issuer(), host.sign_in_at_issuer()
    cookies = [host.pending_cookie(query) for query in (first, second)]
    host.issuer.before_exchange = threading.Barrier(2, timeout=10).wait

    with ThreadPoolExecutor(max_workers=2) as pool:
        responses = list(pool.map(
            lambda attempt: host.callback(attempt[0], cookie=attempt[1]),
            zip((first, second), cookies, strict=True),
        ))

    assert [response.status_code for response in responses] == [303, 303]
    assert host.transaction.entries == 2
    assert host.sessions.count_active() == 1


def test_a_callback_enters_the_transaction_once_and_reads_no_record_after_its_exit() -> None:
    host = an_oidc_host(BYSTANDER, strict_records=True)
    query, cookie = _signed_in_holding_session_of_bystander(host)

    response = host.callback(query, cookie=cookie)

    assert (response.status_code, host.transaction.entries) == (303, 1)


def test_installing_without_stating_whether_the_host_keeps_the_id_token_raises() -> None:
    app = FastAPI()
    arguments = _install_arguments()
    del arguments["keeps_id_token"]

    with pytest.raises(TypeError, match="keeps_id_token"):
        install_sign_in_routes(app, **arguments)  # type: ignore[arg-type]

    assert not _sign_in_routes_of(app)


@pytest.mark.parametrize("max_sessions", [
    pytest.param(0, id="zero"),
    pytest.param(-1, id="negative"),
    pytest.param(True, id="bool"),
    pytest.param("2", id="text"),
    pytest.param(2.0, id="float"),
])
def test_a_cap_that_is_not_a_positive_whole_number_is_refused_before_any_route_is_registered(
    max_sessions: object,
) -> None:
    app = FastAPI()
    arguments = {**_install_arguments(), "max_sessions": max_sessions}

    with pytest.raises(ValueError, match="max_sessions"):
        install_sign_in_routes(app, **arguments)  # type: ignore[arg-type]

    assert not _sign_in_routes_of(app)


@pytest.mark.parametrize(("start", "callback", "logout"), [
    pytest.param("login", "/callback", "/logout", id="a relative start"),
    pytest.param("/login", "callback", "/logout", id="a relative callback"),
    pytest.param("/login", "/callback", "logout", id="a relative logout"),
    pytest.param("//evil.example/login", "/callback", "/logout", id="a start another host serves"),
    pytest.param("/login", "/\\evil.example", "/logout", id="a callback another host serves"),
    pytest.param("/login", "/\t/evil.example", "/logout", id="a callback a browser strips"),
    pytest.param("/login", "/callback", "//evil.example/logout", id="a logout another host serves"),
    pytest.param("/a/../login", "/callback", "/logout", id="a dot segment in start"),
    pytest.param("/login", "/a/%2e%2e/callback", "/logout", id="an encoded dot segment"),
    pytest.param("/login", "/callback", "/a/../logout", id="a dot segment in logout"),
    pytest.param("/login?x=1", "/callback", "/logout", id="a query in start"),
    pytest.param("/login", "/callback#top", "/logout", id="a fragment in callback"),
    pytest.param("/login", "/callback", "/logout?x=1", id="a query in logout"),
    pytest.param("/auth", "/auth", "/logout", id="one path for start and callback"),
    pytest.param("/auth", "/callback", "/auth", id="one path for start and logout"),
    pytest.param("/login", "/auth", "/auth", id="one path for callback and logout"),
])
def test_a_path_that_is_not_an_absolute_distinct_path_of_this_app_is_refused_at_construction(
    start: str, callback: str, logout: str,
) -> None:
    with pytest.raises(ValueError, match="SignInPaths"):
        SignInPaths(start=start, callback=callback, logout=logout)


@pytest.mark.parametrize(("logout", "label"), [
    pytest.param(LOGOUT_PATH, None, id="a logout path without a label"),
    pytest.param(None, lambda _request: "Sign out", id="a label without a logout path"),
])
def test_a_logout_path_and_a_label_come_together_or_install_refuses_before_any_route(
    logout: str | None, label: Callable[[Request], str] | None,
) -> None:
    app = FastAPI()
    arguments = {
        **_install_arguments(),
        "paths": SignInPaths(start=START_PATH, callback=CALLBACK_PATH, logout=logout),
        "logout_button_label": label,
    }

    with pytest.raises(ValueError, match="logout"):
        install_sign_in_routes(app, **arguments)  # type: ignore[arg-type]

    assert not _sign_in_routes_of(app)


def test_a_host_without_a_logout_path_and_label_registers_no_logout_route() -> None:
    app = FastAPI()
    arguments = {
        **_install_arguments(),
        "paths": SignInPaths(start=START_PATH, callback=CALLBACK_PATH),
        "logout_button_label": None,
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
        "logout_button_label": lambda _request: "Sign out",
    }


def _sign_in_routes_of(app: FastAPI) -> list[str]:
    paths = {SIGN_IN_PATHS.start, SIGN_IN_PATHS.callback, LOGOUT_PATH}
    routes = [route for route in app.routes if isinstance(route, APIRoute)]
    return [route.path for route in routes if route.path in paths]


@dataclass
class GatedHost:
    client: TestClient
    issuer: FakeIssuer


def _a_gated_host(rate_budget: int | None = None) -> GatedHost:
    """A host whose gate, rate limit and cache rules are the ones the paths derive."""
    config = a_web_auth_config()
    sessions = SessionRecordsInMemory()
    issuer = FakeIssuer(mint_id_token=lambda _nonce: "unused")
    relying_party = a_relying_party(post_token_request=issuer)
    app = FastAPI()
    install_web_auth_config(app, config)
    install_web_auth_middleware(
        app,
        security_headers=SecurityHeadersPolicy(
            content_security_policy="default-src 'self'",
            cache_control_rules=(SIGN_IN_PATHS.cache_control_rule,),
        ),
        body_size=BodySizePolicy(default_max_bytes=1024),
        rate_limit=None if rate_budget is None else RateLimitPolicy(
            default=RateLimitBudget("host", 1000, 60),
            rules=(RateLimitRule(
                paths=SIGN_IN_PATHS.browser_paths,
                budget=RateLimitBudget("sign-in", rate_budget, 60),
            ),),
        ),
        csrf_origin=CsrfPolicy(),
        session_gate=SessionGate(
            session_transaction=sessions.in_transaction,
            login_redirect=SIGN_IN_PATHS.login_redirect,
            public=SIGN_IN_PATHS.public_rules,
        ),
    )
    install_sign_in_routes(
        app,
        paths=SIGN_IN_PATHS,
        relying_party=lambda _request: relying_party,
        admission=ADMISSION,
        transaction=_a_transaction_nobody_enters,
        refused=lambda _request, _refusal: Response(status_code=403),
        keeps_id_token=True,
        max_sessions=None,
        logout_button_label=lambda _request: "Sign out",
    )

    @app.get("/albums/{album_id}")
    def album(album_id: str) -> str:
        return album_id

    return GatedHost(
        TestClient(app, base_url=HTTPS_TEST_SERVER, follow_redirects=False), issuer,
    )


def _a_transaction_nobody_enters() -> AbstractContextManager[SignInStores]:
    raise AssertionError("the gated host never signs anyone in")


def test_the_derived_policies_open_the_sign_in_paths_and_send_a_signed_out_page_to_start() -> None:
    host = _a_gated_host()

    start = host.client.get(START_PATH)
    deep_link = host.client.get("/albums/42", headers={"accept": "text/html"})

    assert start.status_code == 303
    assert (deep_link.status_code, deep_link.headers["location"]) == (
        302, f"{START_PATH}?next=%2Falbums%2F42",
    )


def test_a_signed_out_logout_passes_the_gate_and_enters_no_transaction() -> None:
    host = _a_gated_host()

    response = host.client.post(LOGOUT_PATH, headers=SAME_ORIGIN_FORM)

    assert response.status_code == 200


def test_the_derived_cache_rule_marks_the_sign_in_answers_no_store() -> None:
    host = _a_gated_host()

    answers = [
        host.client.get(START_PATH),
        host.client.get(CALLBACK_PATH),
        host.client.post(LOGOUT_PATH, headers={"content-type": SAME_ORIGIN_FORM["content-type"]}),
    ]

    assert [answer.status_code for answer in answers[-1:]] == [403]
    assert [answer.headers["cache-control"] for answer in answers] == ["no-store"] * 3


def test_the_derived_browser_paths_spend_one_sign_in_budget() -> None:
    host = _a_gated_host(rate_budget=3)

    statuses = [
        host.client.get(START_PATH).status_code,
        host.client.get(CALLBACK_PATH).status_code,
        host.client.post(LOGOUT_PATH, headers=SAME_ORIGIN_FORM).status_code,
        host.client.get(START_PATH).status_code,
    ]

    assert statuses[-1] == 429
    assert 429 not in statuses[:-1]
