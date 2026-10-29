"""The bearer gate's person paths: a token on the host's API paths is the account behind it.

The app is the real stack over `an_auth_app`, once behind the session gate (SG) and once
without one (NG); the token is a real RS256 `at+jwt`; the sign-in transaction is the host's
`RecordingSignInTransaction`, per-call (PC) or rolling back (RB).
"""

from __future__ import annotations

import hashlib
import logging
from collections.abc import Iterator
from contextlib import AbstractContextManager, contextmanager
from typing import Any

import pytest
from fastapi import Depends, FastAPI, Request
from httpx import Response

from tests.support.gate_arrangement import (
    A_TOKEN,
    EXPORT_PATH,
    FOREIGN_SECRET_PATH,
    MACHINE_AS_PERSON_PATH,
    MACHINE_SESSION_PATH,
    PERSON_ADMIN_ME_PATH,
    PERSON_ADMITTED_ADMIN_PATH,
    PERSON_ADMITTED_ME_PATH,
    PERSON_CALLER_PATH,
    PERSON_INSUFFICIENT_SCOPE,
    PERSON_INVALID_REQUEST,
    PERSON_INVALID_TOKEN,
    PERSON_ME_PATH,
    PERSON_PATHS,
    PERSON_PREFIX,
    PERSON_REALM,
    REALM_INSUFFICIENT_SCOPE,
    BearerApp,
    a_bearer_app,
    a_key_set_answering,
    a_token,
    bearing,
    relayed,
)
from tests.support.oidc_arrangement import ABSENT, OPERATOR_SUBJECT
from tests.support.oidc_login_host import (
    RecordingSignInTransaction,
    StoreDown,
    TransactionKind,
    failing,
)
from tests.support.webauth_arrangement import (
    ADMIN_ROLE,
    LOGIN_REDIRECT,
    MEMBER_ROLE,
    FakeUser,
)
from webauth.dependencies import current_user_dependency
from webauth.https_client import KeySetFetchError
from webauth.middleware import admitted_user
from webauth.policies import PathRules, PublicRule, RateLimitBudget, RateLimitPolicy
from webauth.ports import AccountEvent, AccountEventKind, AuthenticatedUser, SignInStores

ADMIN_TOKEN = A_TOKEN
MEMBER_TOKEN = a_token(groups=["/apps/x"])
OUTSIDER_TOKEN = a_token(groups=["/apps/elsewhere"])
LENA_TOKEN = a_token(preferred_username="lena")
OPTIONAL_PATH = "/optional"
UNGATED_ME_PATH = "/me"

BOTH_HOSTS = pytest.mark.parametrize(
    "session_gate", [pytest.param(True, id="SG"), pytest.param(False, id="NG")],
)
BOTH_TRANSACTIONS = pytest.mark.parametrize(
    "kind",
    [
        pytest.param(TransactionKind.PER_CALL, id="PC"),
        pytest.param(TransactionKind.ROLLING_BACK, id="RB"),
    ],
)


def a_lena() -> FakeUser:
    return FakeUser(id=OPERATOR_SUBJECT, username="lena", role=MEMBER_ROLE)


def a_transaction_failing_to_be_created() -> AbstractContextManager[SignInStores]:
    raise StoreDown


def a_transaction_failing_to_be_entered() -> AbstractContextManager[SignInStores]:
    @contextmanager
    def never_entered() -> Iterator[SignInStores]:
        raise StoreDown
        yield  # pragma: no cover

    return never_entered()


def a_person_app(**keywords: Any) -> BearerApp:
    return a_bearer_app(person_paths=PERSON_PATHS, **keywords)


def the_account(app: BearerApp) -> Any:
    assert app.accounts is not None
    return next((user for user in app.accounts.list() if user.id == OPERATOR_SUBJECT), None)


def the_challenge(response: Response) -> str | None:
    return response.headers.get("www-authenticate")


def ran(app: BearerApp) -> list[str]:
    return app.auth.route_runs


@BOTH_HOSTS
def test_a_token_on_a_person_path_is_the_account_behind_its_subject(session_gate: bool) -> None:
    app = a_person_app(session_gate=session_gate, known_accounts=(a_lena(),))

    response = app.ask(PERSON_ME_PATH, authorization=bearing(MEMBER_TOKEN))

    assert (response.status_code, response.json()) == (
        200, {"id": OPERATOR_SUBJECT, "username": "lena", "role": MEMBER_ROLE, "session": None},
    )
    assert app.auth.authenticated == [AuthenticatedUser(OPERATOR_SUBJECT, "lena", MEMBER_ROLE)]


@BOTH_TRANSACTIONS
@pytest.mark.parametrize(
    ("token", "username"),
    [
        pytest.param(LENA_TOKEN, "lena", id="preferred-username"),
        pytest.param(ADMIN_TOKEN, OPERATOR_SUBJECT, id="subject-fallback"),
    ],
)
def test_the_first_token_of_a_new_subject_creates_its_account_as_a_sign_in_does(
    kind: TransactionKind, token: str, username: str,
) -> None:
    app = a_person_app(transaction_kind=kind)

    first = app.ask(PERSON_ME_PATH, authorization=bearing(token))
    second = app.ask(PERSON_ME_PATH, authorization=bearing(token))

    assert (first.status_code, first.json()["username"], second.json()["username"]) == (
        200, username, username,
    )
    assert app.audit is not None
    assert app.audit.account_events == [
        AccountEvent(
            kind=AccountEventKind.USER_CREATED, actor_id=None,
            subject_id=OPERATOR_SUBJECT, role=ADMIN_ROLE,
        ),
    ]
    assert the_account(app).username == username


@BOTH_TRANSACTIONS
def test_the_role_follows_the_tokens_groups_and_is_stored_as_at_sign_in(
    kind: TransactionKind,
) -> None:
    app = a_person_app(transaction_kind=kind, known_accounts=(a_lena(),))

    def asked_with(token: str) -> str:
        return app.ask(PERSON_ME_PATH, authorization=bearing(token)).json()["role"]

    unchanged = asked_with(MEMBER_TOKEN)
    promoted = asked_with(ADMIN_TOKEN)
    promoted_again = asked_with(ADMIN_TOKEN)
    demoted = asked_with(MEMBER_TOKEN)

    assert (unchanged, promoted, promoted_again, demoted) == (
        MEMBER_ROLE, ADMIN_ROLE, ADMIN_ROLE, MEMBER_ROLE,
    )
    assert app.audit is not None
    assert app.audit.account_events == [
        AccountEvent(
            kind=AccountEventKind.ROLE_CHANGED, actor_id=None, subject_id=OPERATOR_SUBJECT,
            role=ADMIN_ROLE, previous_role=MEMBER_ROLE,
        ),
        AccountEvent(
            kind=AccountEventKind.ROLE_CHANGED, actor_id=None, subject_id=OPERATOR_SUBJECT,
            role=MEMBER_ROLE, previous_role=ADMIN_ROLE,
        ),
    ]
    assert the_account(app).role == MEMBER_ROLE


@BOTH_HOSTS
def test_a_token_of_a_person_outside_the_app_is_refused_before_any_store_is_touched(
    session_gate: bool,
) -> None:
    app = a_person_app(session_gate=session_gate)

    response = app.ask(PERSON_ME_PATH, authorization=bearing(OUTSIDER_TOKEN))

    assert (response.status_code, response.json(), the_challenge(response)) == (
        403, {"detail": "No access"}, PERSON_INSUFFICIENT_SCOPE,
    )
    assert isinstance(app.transaction, RecordingSignInTransaction)
    assert (app.transaction.entries, the_account(app), ran(app)) == (0, None, [])


@BOTH_TRANSACTIONS
def test_a_username_the_store_refuses_answers_403_login_failed_without_a_challenge(
    kind: TransactionKind,
) -> None:
    app = a_person_app(transaction_kind=kind)
    taken = a_token(preferred_username="alice")

    response = app.ask(PERSON_ME_PATH, authorization=bearing(taken))

    assert (response.status_code, response.json(), the_challenge(response)) == (
        403, {"detail": "Login failed"}, None,
    )
    assert app.audit is not None
    assert (the_account(app), app.audit.account_events, ran(app)) == (None, [], [])


NO_BEARER_CREDENTIAL = [
    pytest.param({}, {}, id="none"),
    pytest.param({"authorization": ("Basic dXNlcjpwYXNz",)}, {}, id="basic"),
    pytest.param({"authorization": ("DPoP abc",)}, {}, id="dpop"),
    pytest.param({}, {"params": {"access_token": "throwaway"}}, id="query-only"),
]


@BOTH_HOSTS
@pytest.mark.parametrize(("credentials", "request_keywords"), NO_BEARER_CREDENTIAL)
def test_without_a_bearer_credential_a_person_path_is_decided_by_the_session(
    session_gate: bool, credentials: dict[str, Any], request_keywords: dict[str, Any],
) -> None:
    app = a_person_app(session_gate=session_gate)

    refused = app.ask(PERSON_ME_PATH, **credentials, **request_keywords)
    admitted = app.ask(PERSON_ME_PATH, cookie=True, **credentials, **request_keywords)

    assert (refused.status_code, refused.json(), the_challenge(refused)) == (
        401, {"detail": "Authentication required"}, PERSON_REALM,
    )
    assert (admitted.status_code, admitted.json()["username"]) == (200, "alice")
    assert isinstance(app.transaction, RecordingSignInTransaction)
    assert app.transaction.entries == 0


MALFORMED_OR_INVALID = [
    pytest.param(
        (f"Bearer {ADMIN_TOKEN}", f"Bearer {ADMIN_TOKEN}"), {}, None,
        PERSON_INVALID_REQUEST, "Invalid request", id="two-lines",
    ),
    pytest.param(
        (f"Bearer {ADMIN_TOKEN} extra",), {}, None,
        PERSON_INVALID_REQUEST, "Invalid request", id="two-credentials",
    ),
    pytest.param(
        (f"Bearer {ADMIN_TOKEN}",), {"params": {"access_token": "second"}}, None,
        PERSON_INVALID_REQUEST, "Invalid request", id="a-second-method",
    ),
    pytest.param(
        ("Bearer",), {}, None, PERSON_INVALID_REQUEST, "Invalid request", id="no-credential",
    ),
    pytest.param(
        ("=x",), {}, None, PERSON_INVALID_REQUEST, "Invalid request", id="no-scheme",
    ),
    pytest.param(
        ("Bearer a$b",), {}, None, PERSON_INVALID_TOKEN, "Invalid token", id="not-a-b64token",
    ),
    pytest.param(
        (f"Bearer {a_token(sub=ABSENT)}",), {}, None,
        PERSON_INVALID_TOKEN, "Invalid token", id="no-subject",
    ),
    pytest.param(
        (f"Bearer {ADMIN_TOKEN}",), {}, KeySetFetchError("down"),
        PERSON_INVALID_TOKEN, "Invalid token", id="key-set-down",
    ),
]


@pytest.mark.parametrize(
    ("authorization", "request_keywords", "key_set_failure", "challenge", "detail"),
    MALFORMED_OR_INVALID,
)
def test_a_person_path_refuses_a_malformed_or_invalid_token_with_a_challenge_without_realm(
    authorization: tuple[str, ...],
    request_keywords: dict[str, Any],
    key_set_failure: Exception | None,
    challenge: str,
    detail: str,
) -> None:
    app = a_person_app(key_sets=a_key_set_answering(key_set_failure))

    response = app.ask(PERSON_ME_PATH, authorization=authorization, **request_keywords)

    assert (response.status_code, response.json(), the_challenge(response)) == (
        401, {"detail": detail}, challenge,
    )
    assert isinstance(app.transaction, RecordingSignInTransaction)
    assert (app.transaction.entries, ran(app)) == (0, [])


@pytest.mark.parametrize(
    ("claims", "admitted"),
    [
        pytest.param({}, True, id="hal"),
        pytest.param({"azp": "another-client"}, False, id="another-client"),
        pytest.param({"azp": ABSENT}, False, id="no-azp"),
    ],
)
def test_a_person_path_admits_exactly_the_clients_the_machine_paths_admit(
    claims: dict[str, Any], admitted: bool,
) -> None:
    app = a_person_app()
    token = bearing(a_token(**claims))

    machine = app.ask(EXPORT_PATH, authorization=token)
    person = app.ask(PERSON_ME_PATH, authorization=token)

    assert (machine.status_code == 200, person.status_code == 200) == (admitted, admitted)


@BOTH_HOSTS
@pytest.mark.parametrize("method", ["POST", "DELETE"])
def test_a_token_post_on_a_person_path_needs_no_origin_and_no_cookie(
    session_gate: bool, method: str,
) -> None:
    app = a_person_app(session_gate=session_gate)

    response = app.ask(PERSON_ME_PATH, method=method, authorization=bearing(MEMBER_TOKEN))

    assert (response.status_code, response.json()["id"]) == (200, OPERATOR_SUBJECT)


@BOTH_HOSTS
def test_beside_a_token_the_cookie_decides_nothing_and_names_no_session(
    session_gate: bool, monkeypatch: pytest.MonkeyPatch,
) -> None:
    app = a_person_app(session_gate=session_gate)
    failing(app.auth.sessions, "load", monkeypatch)
    failing(app.auth.sessions, "touch", monkeypatch)

    response = app.ask(PERSON_ME_PATH, authorization=bearing(MEMBER_TOKEN), cookie=True)

    assert (response.status_code, response.json()) == (
        200, {"id": OPERATOR_SUBJECT, "username": OPERATOR_SUBJECT, "role": MEMBER_ROLE,
              "session": None},
    )


def test_a_machine_admission_beside_a_cookie_names_no_session() -> None:
    app = a_person_app()

    response = app.ask(MACHINE_SESSION_PATH, authorization=bearing(ADMIN_TOKEN), cookie=True)

    assert (response.status_code, response.json()) == (200, {"session": None})


ADMIN_READERS = pytest.mark.parametrize(
    ("session_gate", "path"),
    [
        pytest.param(True, PERSON_ADMITTED_ADMIN_PATH, id="SG-admitted_admin"),
        pytest.param(True, PERSON_ADMIN_ME_PATH, id="SG-admin_user"),
        pytest.param(False, PERSON_ADMIN_ME_PATH, id="NG-admin_user"),
    ],
)


@ADMIN_READERS
def test_the_admin_readers_admit_an_admin_token_and_refuse_a_user_token_with_insufficient_scope(
    session_gate: bool, path: str,
) -> None:
    app = a_person_app(session_gate=session_gate)

    admitted = app.ask(path, authorization=bearing(ADMIN_TOKEN))
    refused = app.ask(path, authorization=bearing(MEMBER_TOKEN))

    assert (admitted.status_code, admitted.json()["role"]) == (200, ADMIN_ROLE)
    assert (refused.status_code, refused.json(), the_challenge(refused)) == (
        403, {"detail": "Admin access required"}, PERSON_INSUFFICIENT_SCOPE,
    )


@BOTH_HOSTS
def test_admitted_user_returns_the_token_person(session_gate: bool) -> None:
    app = a_person_app(session_gate=session_gate)

    response = app.ask(PERSON_ADMITTED_ME_PATH, authorization=bearing(ADMIN_TOKEN))

    assert (response.status_code, response.json()) == (200, {"username": OPERATOR_SUBJECT})


class TestEachModeKeepsItsReader:
    def test_bearer_caller_raises_on_a_person_admission(self) -> None:
        app = a_person_app()

        response = app.ask(PERSON_CALLER_PATH, authorization=bearing(ADMIN_TOKEN))

        assert response.status_code == 500

    def test_current_user_raises_on_a_machine_admission(self) -> None:
        app = a_person_app()

        response = app.ask(MACHINE_AS_PERSON_PATH, authorization=bearing(ADMIN_TOKEN))

        assert response.status_code == 500


class TestAPathBothRulesSelectIsAMachinePath:
    def test_an_admin_token_is_a_caller_and_no_account_is_created(self) -> None:
        app = a_person_app()

        response = app.ask(EXPORT_PATH, authorization=bearing(ADMIN_TOKEN))

        assert (response.status_code, response.json()) == (200, {"subject": OPERATOR_SUBJECT})
        assert isinstance(app.transaction, RecordingSignInTransaction)
        assert (app.transaction.entries, the_account(app)) == (0, None)

    def test_a_user_token_is_refused_as_on_any_machine_path(self) -> None:
        app = a_person_app()

        response = app.ask(EXPORT_PATH, authorization=bearing(MEMBER_TOKEN))

        assert (response.status_code, response.json(), the_challenge(response)) == (
            403, {"detail": "Admin access required"}, REALM_INSUFFICIENT_SCOPE,
        )


class TestAFailingTransactionIsTheLibrary500:
    @pytest.mark.parametrize("entry", ["creating", "entering"])
    def test_a_failure_creating_or_entering_the_transaction_propagates_and_runs_no_route(
        self, entry: str,
    ) -> None:
        transaction = (
            a_transaction_failing_to_be_created
            if entry == "creating"
            else a_transaction_failing_to_be_entered
        )
        app = a_person_app(transaction=transaction)

        assert app.transaction is transaction
        response = app.ask(PERSON_ME_PATH, authorization=bearing(ADMIN_TOKEN))

        assert app.audit is not None
        assert (response.status_code, ran(app), the_account(app), app.audit.account_events) == (
            500, [], None, [],
        )

    @BOTH_TRANSACTIONS
    @pytest.mark.parametrize(
        ("broken", "kept_by_a_per_call_host"),
        [
            pytest.param("store", None, id="store"),
            pytest.param("audit-after-created", ADMIN_ROLE, id="audit-after-user-created"),
            pytest.param("audit-after-role-changed", ADMIN_ROLE, id="audit-after-role-changed"),
            pytest.param("exit", ADMIN_ROLE, id="exit"),
        ],
    )
    def test_a_failing_account_store_audit_or_exit_propagates_and_keeps_only_what_the_host_keeps(
        self,
        kind: TransactionKind,
        broken: str,
        kept_by_a_per_call_host: str | None,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        promoted = broken == "audit-after-role-changed"
        app = a_person_app(transaction_kind=kind, known_accounts=(a_lena(),) if promoted else ())
        assert isinstance(app.transaction, RecordingSignInTransaction)
        assert app.accounts is not None
        assert app.audit is not None
        if broken == "store":
            failing(app.accounts, "get", monkeypatch)
        elif broken == "exit":
            app.transaction.exit_failure = StoreDown()
        else:
            failing(app.audit, "account_event", monkeypatch)

        response = app.ask(PERSON_ME_PATH, authorization=bearing(ADMIN_TOKEN))

        kept = kept_by_a_per_call_host if kind is TransactionKind.PER_CALL else (
            MEMBER_ROLE if promoted else None
        )
        account = the_account(app)
        assert (response.status_code, ran(app)) == (500, [])
        assert (None if account is None else account.role) == kept


@BOTH_TRANSACTIONS
def test_a_token_request_enters_one_sign_in_transaction_and_reads_no_record_after_its_exit(
    kind: TransactionKind,
) -> None:
    app = a_person_app(transaction_kind=kind, strict_records=True, known_accounts=(a_lena(),))

    response = app.ask(PERSON_ME_PATH, authorization=bearing(MEMBER_TOKEN))

    assert isinstance(app.transaction, RecordingSignInTransaction)
    assert (response.status_code, app.transaction.entries) == (200, 1)


def test_no_person_admission_holds_the_token_or_its_digest_in_an_answer_or_a_log(
    caplog: pytest.LogCaptureFixture,
) -> None:
    app = a_person_app()
    relay = relayed(app.auth)
    secrets = [ADMIN_TOKEN, hashlib.sha256(f"Bearer {ADMIN_TOKEN}".encode()).hexdigest()]
    caplog.set_level(logging.DEBUG)

    admitted = app.ask(PERSON_ME_PATH, authorization=bearing(ADMIN_TOKEN))
    refused = app.ask(PERSON_ME_PATH, authorization=bearing(f"{ADMIN_TOKEN}x"))

    shown = [
        *(f"{response.headers}{response.text}" for response in (admitted, refused)),
        caplog.text,
        repr({key: value for key, value in relay.added.items() if key != "webauth.bearer_gate"}),
    ]
    assert all(secret not in text for secret in secrets for text in shown)


def test_a_token_request_on_a_person_path_spends_the_address_budget() -> None:
    budget = RateLimitPolicy(default=RateLimitBudget("api", 1, 60))
    app = a_person_app(policies={"rate_limit": budget})

    app.ask(PERSON_ME_PATH, authorization=bearing(ADMIN_TOKEN))
    second = app.ask(PERSON_ME_PATH, authorization=bearing(ADMIN_TOKEN))

    assert (second.status_code, "retry-after" in second.headers) == (429, True)


class TestAStrictReaderRefusesAPersonAdmissionMadeForAnotherPathOrHeader:
    @pytest.mark.parametrize(
        ("path", "with_header"),
        [
            pytest.param(UNGATED_ME_PATH, True, id="current_user-another-path"),
            pytest.param(UNGATED_ME_PATH, False, id="current_user-no-header"),
            pytest.param(OPTIONAL_PATH, True, id="admitted_user-another-path"),
            pytest.param(OPTIONAL_PATH, False, id="admitted_user-no-header"),
        ],
    )
    def test_a_planted_admission_is_read_by_no_session_reader(
        self, path: str, with_header: bool,
    ) -> None:
        app = a_person_app()
        relay = relayed(app.auth)
        app.ask(PERSON_ME_PATH, authorization=bearing(ADMIN_TOKEN))
        app.auth.route_runs.clear()
        relay.replay = dict(relay.added)

        response = app.ask(
            path, cookie=True, authorization=bearing(ADMIN_TOKEN) if with_header else (),
        )

        assert response.status_code == 500
        assert ran(app) == [] or ran(app) == [OPTIONAL_PATH]


class TestAPersonAdmissionIsNotHonouredByAnotherApplication:
    @pytest.mark.parametrize("route", ["current_user", "admitted_user"])
    def test_a_sub_app_below_a_person_path_raises_when_it_asks_for_the_account(
        self, route: str,
    ) -> None:
        app = a_person_app()
        inner = FastAPI()
        app.auth.app.mount(f"{PERSON_PREFIX}sub", inner)
        dependencies = current_user_dependency(
            session_store=lambda: app.auth.sessions, on_authenticated=lambda user: None,
        )

        @inner.get("/current")
        def current(
            _user: AuthenticatedUser = Depends(dependencies.current_user),
        ) -> dict[str, str]:
            return {"ran": "current_user"}

        @inner.get("/admitted")
        def admitted(request: Request) -> dict[str, str | None]:
            user = admitted_user(request)
            return {"ran": None if user is None else user.username}

        path = f"{PERSON_PREFIX}sub/{'current' if route == 'current_user' else 'admitted'}"
        response = app.ask(path, authorization=bearing(ADMIN_TOKEN))

        assert response.status_code == 500


@BOTH_HOSTS
def test_a_person_path_refused_for_want_of_a_session_challenges_with_bearer(
    session_gate: bool,
) -> None:
    app = a_person_app(session_gate=session_gate)

    readers = [PERSON_ME_PATH, PERSON_ADMIN_ME_PATH]
    answers = [app.ask(path) for path in readers]

    assert [(answer.status_code, the_challenge(answer)) for answer in answers] == [
        (401, PERSON_REALM), (401, PERSON_REALM),
    ]
    outside = app.ask(UNGATED_ME_PATH)
    assert (outside.status_code, the_challenge(outside)) == (401, None)


def test_the_admitted_admin_401_of_a_person_path_without_a_gate_admission_challenges() -> None:
    opened = PublicRule(PathRules(exact=frozenset({PERSON_ADMITTED_ADMIN_PATH})))
    app = a_person_app(public=(opened,))

    response = app.ask(PERSON_ADMITTED_ADMIN_PATH)

    assert (response.status_code, the_challenge(response)) == (401, PERSON_REALM)


@BOTH_HOSTS
def test_a_navigation_to_a_person_path_still_gets_its_login_redirect(session_gate: bool) -> None:
    app = a_person_app(session_gate=session_gate, login_redirect=LOGIN_REDIRECT)

    navigation = app.ask(
        PERSON_ME_PATH, headers={"accept": "text/html"}, follow_redirects=False,
    )
    api_call = app.ask(PERSON_ME_PATH, headers={"accept": "application/json"})

    assert (navigation.status_code, the_challenge(navigation)) == (302, None)
    assert (api_call.status_code, the_challenge(api_call)) == (401, PERSON_REALM)


@ADMIN_READERS
def test_a_cookie_person_refused_by_the_admin_readers_gets_no_challenge(
    session_gate: bool, path: str,
) -> None:
    app = a_person_app(session_gate=session_gate, cookie_role=MEMBER_ROLE)

    response = app.ask(path, cookie=True)

    assert (response.status_code, response.json(), the_challenge(response)) == (
        403, {"detail": "Admin access required"}, None,
    )


def test_a_person_path_refuses_a_token_for_another_audience_with_invalid_token() -> None:
    app = a_person_app()

    response = app.ask(
        PERSON_ME_PATH, authorization=bearing(a_token(aud="another-application")),
    )

    assert (response.status_code, the_challenge(response)) == (401, PERSON_INVALID_TOKEN)


def test_one_admin_token_opens_both_a_machine_path_and_a_person_path() -> None:
    app = a_person_app()

    machine = app.ask(EXPORT_PATH, authorization=bearing(ADMIN_TOKEN))
    person = app.ask(PERSON_ME_PATH, authorization=bearing(ADMIN_TOKEN))

    assert (machine.status_code, person.status_code) == (200, 200)


def test_a_user_token_that_opens_a_person_path_is_refused_on_a_machine_path_with_insufficient_scope(
) -> None:
    app = a_person_app()

    person = app.ask(PERSON_ME_PATH, authorization=bearing(MEMBER_TOKEN))
    machine = app.ask(EXPORT_PATH, authorization=bearing(MEMBER_TOKEN))

    assert person.status_code == 200
    assert (machine.status_code, the_challenge(machine)) == (403, REALM_INSUFFICIENT_SCOPE)


@BOTH_HOSTS
@pytest.mark.parametrize("method", ["GET", "POST"])
def test_a_foreign_bearer_secret_on_a_path_neither_rule_selects_reaches_its_route_untouched(
    session_gate: bool, method: str,
) -> None:
    app = a_person_app(session_gate=session_gate)

    response = app.ask(FOREIGN_SECRET_PATH, method=method, authorization=("Bearer s3cret",))

    assert (response.status_code, response.json(), the_challenge(response)) == (
        200, {"authorization": "Bearer s3cret"}, None,
    )
    assert app.key_sets.fetched_urls == []


@BOTH_HOSTS
@pytest.mark.parametrize(
    ("authorization", "request_keywords"),
    [
        pytest.param((f"Bearer {ADMIN_TOKEN}", f"Bearer {ADMIN_TOKEN}"), {}, id="malformed"),
        pytest.param((f"Bearer {ADMIN_TOKEN}x",), {}, id="invalid"),
    ],
)
def test_an_invalid_or_malformed_token_beside_a_valid_cookie_never_falls_back_to_the_cookie(
    session_gate: bool,
    authorization: tuple[str, ...],
    request_keywords: dict[str, Any],
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    app = a_person_app(session_gate=session_gate)
    failing(app.auth.sessions, "load", monkeypatch)

    response = app.ask(PERSON_ME_PATH, authorization=authorization, cookie=True)

    assert response.status_code == 401
    assert the_challenge(response) in {PERSON_INVALID_REQUEST, PERSON_INVALID_TOKEN}
    assert ran(app) == []


@BOTH_HOSTS
def test_a_cookie_only_post_on_a_person_path_without_origin_is_still_refused_by_csrf(
    session_gate: bool,
) -> None:
    app = a_person_app(session_gate=session_gate)

    response = app.ask(PERSON_ME_PATH, method="POST", cookie=True)

    assert (response.status_code, response.json()) == (403, {"detail": "Missing Origin header"})


def test_the_gate_names_no_machine_paths_when_it_has_person_paths_alone() -> None:
    app = a_bearer_app(paths=PathRules(), person_paths=PERSON_PATHS)

    response = app.ask(PERSON_ME_PATH, authorization=bearing(MEMBER_TOKEN))

    assert response.status_code == 200
