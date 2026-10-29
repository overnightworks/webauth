"""The bearer gate: hal's access token alone opens the host's machine paths.

The app is the real stack over `an_auth_app`; the token is a real RS256 `at+jwt`
verified against a fake key-set endpoint, and the clocks are fakes.
"""

from __future__ import annotations

import asyncio
import base64
import hashlib
import logging
import threading
from contextlib import AbstractContextManager
from dataclasses import dataclass
from typing import Any

import httpx
import pytest
from httpx import Response

from tests.support.gate_arrangement import (
    A_TOKEN,
    ADMISSION,
    EXPORT_PATH,
    MACHINE_PATHS,
    REALM,
    REALM_INSUFFICIENT_SCOPE,
    REALM_INVALID_REQUEST,
    REALM_INVALID_TOKEN,
    UNDECLARED_PATH,
    BearerApp,
    a_bearer_app,
    a_bearer_gate,
    a_key_set_answering,
    a_token,
    assert_answers_no_store,
    assert_no_store_and_no_cookie,
    bearing,
)
from tests.support.oidc_arrangement import (
    ABSENT,
    OPERATOR_SUBJECT,
    a_relying_party,
    an_access_token,
)
from tests.support.webauth_arrangement import (
    HTTPS_TEST_SERVER,
    an_http_scope,
    drive,
    starts,
)
from webauth.https_client import KeySetFetchError
from webauth.middleware import BearerGate, PersonPaths
from webauth.oidc_login import AdmissionConfig, NoAdmins
from webauth.policies import AuthorizedParties, PathRules, PathShape, PublicRule
from webauth.ports import SignInStores

HEALTH_PATH = "/health"
GATE_LOGGER = "webauth.middleware.bearer_gate"


def a_transaction_never_entered() -> AbstractContextManager[SignInStores]:
    raise AssertionError("the sign-in transaction was entered")


@dataclass(frozen=True)
class Answer:
    status: int
    challenge: str
    detail: str
    level: int
    logged: tuple[str, ...]


NO_CREDENTIALS = Answer(401, REALM, "Authentication required", logging.INFO, ("no-credentials",))
INVALID_REQUEST = Answer(
    401, REALM_INVALID_REQUEST, "Invalid request", logging.WARNING, ("invalid-request",),
)
NOT_A_TOKEN = Answer(
    401, REALM_INVALID_TOKEN, "Invalid token", logging.WARNING, ("invalid-token",),
)


def a_refused_token(*logged: str) -> Answer:
    return Answer(401, REALM_INVALID_TOKEN, "Invalid token", logging.WARNING, logged)


INSUFFICIENT_SCOPE = Answer(
    403, REALM_INSUFFICIENT_SCOPE, "Admin access required", logging.WARNING,
    ("insufficient-scope",),
)
PLAIN_GET: dict[str, Any] = {}
FORM_BODY_DELETE: dict[str, Any] = {"method": "DELETE", "data": {"access_token": "throwaway"}}
ONLY_THE_APP_GROUP = a_token(groups=["/apps/x"])
KEY_SET_DOWN = KeySetFetchError("the issuer is down")

# (Authorization lines, query string, key-set response, answer, sent, id)
REFUSED = [
    pytest.param((), "", None, NO_CREDENTIALS, PLAIN_GET, id="H01a-no-header"),
    pytest.param(("",), "", None, NO_CREDENTIALS, PLAIN_GET, id="H01b-empty-value"),
    pytest.param(("Basic dXNlcjpwYXNz",), "", None, NO_CREDENTIALS, PLAIN_GET, id="H01c-basic"),
    pytest.param(("Bearerx abc",), "", None, NO_CREDENTIALS, PLAIN_GET, id="H01d-another-scheme"),
    pytest.param((), "?access_token=throwaway", None, NO_CREDENTIALS, PLAIN_GET,
                 id="H01e-query-alone"),
    pytest.param((), "", None, NO_CREDENTIALS, FORM_BODY_DELETE, id="H01f-form-body"),
    pytest.param((f"Bearer {A_TOKEN}", f"Bearer {A_TOKEN}"), "", None, INVALID_REQUEST, PLAIN_GET,
                 id="H02a-two-lines"),
    pytest.param((f"Bearer {A_TOKEN}, Basic stray",), "", None, INVALID_REQUEST, PLAIN_GET,
                 id="H02b-combined-credentials"),
    pytest.param(("Bearer",), "", None, INVALID_REQUEST, PLAIN_GET, id="H02c-no-credential"),
    pytest.param(("=abc",), "", None, INVALID_REQUEST, PLAIN_GET, id="H02d-no-scheme"),
    pytest.param((f"Bearer\t{A_TOKEN}",), "", None, INVALID_REQUEST, PLAIN_GET, id="H02e-tab"),
    pytest.param((f"Bearer {A_TOKEN} stray",), "", None, INVALID_REQUEST, PLAIN_GET,
                 id="H02f-second-word"),
    pytest.param(bearing(A_TOKEN), "?access_token=throwaway", None, INVALID_REQUEST, PLAIN_GET,
                 id="H02g-two-methods"),
    pytest.param(("Bearer abc!def",), "", None, NOT_A_TOKEN, PLAIN_GET, id="H04-not-a-b64token"),
    pytest.param(bearing(an_access_token(header={"typ": "JWT"})), "", None,
                 a_refused_token("access-token-rejected", "invalid-token-type"), PLAIN_GET,
                 id="T02a-another-type"),
    pytest.param(bearing(a_token(aud=["notes-app", "another-app"])), "", None,
                 a_refused_token("invalid-access-claim"), PLAIN_GET, id="T02b-two-audiences"),
    pytest.param(bearing(A_TOKEN), "", KEY_SET_DOWN,
                 a_refused_token("access-token-rejected", "key-set-unavailable"), PLAIN_GET,
                 id="T02c-key-set-unavailable"),
    pytest.param(bearing(a_token(azp="another-client")), "", None,
                 a_refused_token("authorized-party-mismatch"), PLAIN_GET, id="T02d-another-client"),
    pytest.param(bearing(ONLY_THE_APP_GROUP), "", None, INSUFFICIENT_SCOPE, PLAIN_GET,
                 id="T03d-a-member-who-is-no-admin"),
    pytest.param(bearing(a_token(groups=["/apps/x", "/apps/x/administrators"])), "", None,
                 INSUFFICIENT_SCOPE, PLAIN_GET, id="T03b-a-group-that-is-not-below-admin"),
    pytest.param(bearing(a_token(groups=ABSENT)), "", None, INSUFFICIENT_SCOPE, PLAIN_GET,
                 id="T03c-no-groups"),
]



@pytest.mark.parametrize(("lines", "query", "key_set_response", "answer", "sent"), REFUSED)
def test_a_request_without_a_valid_admin_token_is_refused_with_a_challenge(
    lines: tuple[str, ...],
    query: str,
    key_set_response: Exception | None,
    answer: Answer,
    sent: dict[str, Any],
) -> None:
    app = a_bearer_app(key_sets=a_key_set_answering(key_set_response))

    response = app.ask(EXPORT_PATH + query, authorization=lines, cookie=True, **sent)

    assert (response.status_code, response.headers["www-authenticate"], response.json()) == (
        answer.status, answer.challenge, {"detail": answer.detail},
    )
    assert_answers_no_store(response)
    assert app.auth.route_runs == []


def test_a_not_a_b64token_credential_reaches_no_key_set() -> None:
    app = a_bearer_app()

    app.ask(authorization=("Bearer abc!def",))

    assert app.key_sets.fetched_urls == []


@pytest.mark.parametrize(("lines", "query", "key_set_response", "answer", "sent"), REFUSED)
def test_every_refusal_is_logged_once_with_its_case_or_reason(
    lines: tuple[str, ...],
    query: str,
    key_set_response: Exception | None,
    answer: Answer,
    sent: dict[str, Any],
    caplog: pytest.LogCaptureFixture,
) -> None:
    app = a_bearer_app(key_sets=a_key_set_answering(key_set_response))

    with caplog.at_level(logging.DEBUG):
        app.ask(EXPORT_PATH + query, authorization=lines, **sent)

    records = gate_records(caplog)
    assert [record.levelno for record in records] == [answer.level]
    assert all(word in records[0].getMessage() for word in answer.logged)


def gate_records(caplog: pytest.LogCaptureFixture) -> list[logging.LogRecord]:
    return [record for record in caplog.records if record.name == GATE_LOGGER]


SCHEMES = {"bearer", "basic"}


def secrets_of(
    lines: tuple[str, ...], query: str = "", sent: dict[str, Any] | None = None,
) -> tuple[str, ...]:
    """What the scenario sends that must never be echoed: every word besides a scheme,
    every header value that carries one, the query's and the form's values, and the
    digests of each header value in every encoding a record could carry, the raw bytes'
    repr included."""
    words = {
        word for line in lines for word in line.replace(",", " ").split()
        if word.lower() not in SCHEMES
    }
    carrying = {line for line in lines if any(word in line for word in words)}
    values = {part.partition("=")[2] for part in query[1:].split("&")}
    values |= set((sent or {}).get("data", {}).values())
    plain = (words | carrying | values) - {""}
    return (*sorted(plain), *(d for line in lines if line for d in digests_of(line)))


def digests_of(value: str) -> tuple[str, ...]:
    digest = hashlib.sha256(value.encode("latin-1")).digest()
    padded = (base64.b64encode(digest).decode(), base64.urlsafe_b64encode(digest).decode())
    return (digest.hex(), repr(digest), *padded, *(encoded.rstrip("=") for encoded in padded))


def assert_nothing_leaks(
    secrets: tuple[str, ...], caplog: pytest.LogCaptureFixture, *responses: Response,
) -> None:
    headers = [
        f"{name}: {value}" for response in responses for name, value in response.headers.items()
    ]
    library_log = "\n".join(
        caplog.handler.format(record) for record in caplog.records
        if record.name.split(".")[0] == "webauth"
    )
    haystacks = (library_log, *(response.text for response in responses), *headers)
    assert [secret for secret in secrets for haystack in haystacks if secret in haystack] == []
    for record in gate_records(caplog):
        assert EXPORT_PATH not in record.getMessage()
        assert OPERATOR_SUBJECT not in record.getMessage()


ADMITTED = [
    pytest.param(f"bearer {A_TOKEN}", id="H03a-lowercase-scheme"),
    pytest.param(f"BEARER {A_TOKEN}", id="H03b-uppercase-scheme"),
    pytest.param(f"Bearer  {A_TOKEN}", id="H03c-two-spaces"),
    pytest.param(f"Bearer {A_TOKEN}", id="T01-the-admin-token"),
    pytest.param(f"Bearer {a_token(groups=['/apps/x', '/apps/x/admin/ops'])}",
                 id="T03a-a-group-below-admin"),
]


@pytest.mark.parametrize("line", ADMITTED)
def test_an_admin_token_is_admitted_and_its_subject_is_the_caller(line: str) -> None:
    app = a_bearer_app()

    response = app.ask(authorization=(line,))

    assert (response.status_code, response.json()) == (200, {"subject": OPERATOR_SUBJECT})
    assert "www-authenticate" not in response.headers
    assert_answers_no_store(response)


@pytest.mark.parametrize(("lines", "query", "key_set_response", "answer", "sent"), REFUSED)
def test_no_refusal_holds_the_token_the_header_or_its_digest_in_a_record_or_an_answer(
    lines: tuple[str, ...],
    query: str,
    key_set_response: Exception | None,
    answer: Answer,
    sent: dict[str, Any],
    caplog: pytest.LogCaptureFixture,
) -> None:
    del answer
    app = a_bearer_app(key_sets=a_key_set_answering(key_set_response))

    with caplog.at_level(logging.DEBUG):
        response = app.ask(EXPORT_PATH + query, authorization=lines, **sent)

    assert_nothing_leaks(secrets_of(lines, query, sent), caplog, response)


@pytest.mark.parametrize("line", ADMITTED)
def test_no_admission_holds_the_token_the_header_or_its_digest_in_a_record_or_an_answer(
    line: str, caplog: pytest.LogCaptureFixture,
) -> None:
    app = a_bearer_app()

    with caplog.at_level(logging.DEBUG):
        response = app.ask(authorization=(line,))

    assert_nothing_leaks(secrets_of((line,)), caplog, response)


def test_a_member_without_the_admin_group_is_refused_with_insufficient_scope_only() -> None:
    app = a_bearer_app()

    response = app.ask(authorization=bearing(ONLY_THE_APP_GROUP))

    assert response.status_code == 403
    assert app.auth.route_runs == []


def test_a_failing_key_set_fetch_is_the_library_500(caplog: pytest.LogCaptureFixture) -> None:
    app = a_bearer_app(key_sets=a_key_set_answering(RuntimeError("the fetch crashed")))

    with caplog.at_level(logging.DEBUG):
        response = app.ask(authorization=bearing(A_TOKEN))

    assert response.status_code == 500
    assert_answers_no_store(response)
    assert_nothing_leaks(secrets_of(bearing(A_TOKEN)), caplog, response)


FETCH_BOUND_SECONDS = 3


@pytest.mark.anyio
async def test_a_blocked_key_set_fetch_stalls_no_other_request(
    caplog: pytest.LogCaptureFixture,
) -> None:
    fetch_started = threading.Event()
    release_fetch = threading.Event()
    fetch_returned = threading.Event()

    def block_until_released() -> None:
        fetch_started.set()
        release_fetch.wait(timeout=FETCH_BOUND_SECONDS)
        fetch_returned.set()

    key_sets = a_key_set_answering()
    key_sets.before_answer = block_until_released
    app = a_bearer_app(
        key_sets=key_sets, public=(PublicRule(PathRules(exact=frozenset({HEALTH_PATH}))),),
    )
    transport = httpx.ASGITransport(app=app.auth.app)

    with caplog.at_level(logging.DEBUG):
        async with httpx.AsyncClient(transport=transport, base_url=HTTPS_TEST_SERVER) as client:
            blocked = asyncio.create_task(
                client.get(EXPORT_PATH, headers={"authorization": f"Bearer {A_TOKEN}"}),
            )
            try:
                started = await asyncio.to_thread(fetch_started.wait, FETCH_BOUND_SECONDS)
                health = await asyncio.wait_for(client.get(HEALTH_PATH), FETCH_BOUND_SECONDS)
                fetch_still_blocked = not fetch_returned.is_set()
            finally:
                release_fetch.set()
                admitted = await asyncio.wait_for(blocked, FETCH_BOUND_SECONDS)

    assert (started, health.status_code, fetch_still_blocked, admitted.status_code) == (
        True, 200, True, 200,
    )
    assert_answers_no_store(admitted)
    assert_nothing_leaks(secrets_of(bearing(A_TOKEN)), caplog, health, admitted)


class TestAGateIsBuiltFromSoundParts:
    @pytest.mark.parametrize(
        ("changes", "error"),
        [
            pytest.param({"paths": PathRules()}, ValueError, id="G01a-no-paths"),
            pytest.param(
                {"admission": AdmissionConfig(
                    bound_issuer=ADMISSION.bound_issuer, login_group="/apps/x",
                    admin_group=NoAdmins.IN_THIS_APP,
                )},
                ValueError, id="G01b-no-admins",
            ),
            pytest.param(
                {"admission": AdmissionConfig(
                    bound_issuer="https://login.example.org/realms/elsewhere",
                    login_group="/apps/x", admin_group="/apps/x/admin",
                )},
                ValueError, id="G01c-another-issuer",
            ),
            pytest.param(
                {"authorized_parties": frozenset({"hal"})}, TypeError, id="G01d-a-bare-set",
            ),
        ],
    )
    def test_an_unsound_gate_is_refused_at_construction(
        self, changes: dict[str, Any], error: type[Exception],
    ) -> None:
        arguments = {
            "paths": MACHINE_PATHS,
            "relying_party": a_relying_party(),
            "admission": ADMISSION,
            "authorized_parties": AuthorizedParties(frozenset({"hal"})),
        }

        with pytest.raises(error):
            BearerGate(**{**arguments, **changes})

    def test_person_paths_without_a_path_are_refused_at_construction(self) -> None:
        no_path = PathRules()

        with pytest.raises(ValueError, match="at least one path"):
            PersonPaths(no_path, transaction=a_transaction_never_entered)

    def test_a_no_admins_app_may_name_person_paths_alone(self) -> None:
        gate = a_bearer_gate(
            paths=PathRules(),
            person_paths=PersonPaths(PathRules(prefixes=("/api/",)), a_transaction_never_entered),
            admission=AdmissionConfig(
                bound_issuer=ADMISSION.bound_issuer, login_group="/apps/x",
                admin_group=NoAdmins.IN_THIS_APP,
            ),
        )

        assert gate.paths == PathRules()


class TestWithoutAGateTheAdminPathsStayWithTheSession:
    def test_a_token_alone_on_a_get_meets_the_session_gate(self) -> None:
        app = a_bearer_app(gated=False)

        response = app.ask(authorization=bearing(A_TOKEN))

        assert (response.status_code, response.json()) == (
            401, {"detail": "Authentication required"},
        )

    def test_a_token_alone_on_a_delete_meets_the_csrf_origin_check(self) -> None:
        app = a_bearer_app(gated=False)

        response = app.ask(method="DELETE", authorization=bearing(A_TOKEN))

        assert (response.status_code, response.json()) == (
            403, {"detail": "Missing Origin header"},
        )


def an_answer_to(app: BearerApp, path: str, **scope: Any) -> tuple[int, dict[str, str]]:
    request = an_http_scope(app.auth.app, path, **scope)
    messages, raised = asyncio.run(drive(app.auth.app, request))
    assert raised is None
    start = starts(messages)[0]
    return start["status"], {name.decode(): value.decode() for name, value in start["headers"]}


def the_cookie(app: BearerApp) -> list[tuple[bytes, bytes]]:
    return [(b"cookie", app.cookie.encode())]


class TestThePathIsTheOneTheRouterRoutes:
    @pytest.mark.parametrize("encoded", ["%3F", "%23"], ids=["P01a-question", "P01b-hash"])
    def test_an_encoded_delimiter_does_not_hide_a_path_from_the_gate(self, encoded: str) -> None:
        shape = PathRules(shapes=(PathShape("/api/admin/people/", "/export"),))
        app = a_bearer_app(paths=shape)

        response = app.ask(f"/api/admin/people/alice{encoded}x/export", cookie=True)

        assert (response.status_code, response.headers["www-authenticate"]) == (401, REALM)
        assert_answers_no_store(response)
        assert app.auth.route_runs == []

    @pytest.mark.parametrize(
        "path",
        [
            pytest.param("/api/admin/people/../export", id="P02a-dot-dot"),
            pytest.param("/api/admin/./export", id="P02b-dot"),
        ],
    )
    def test_a_dot_segment_is_matched_as_written(self, path: str) -> None:
        app = a_bearer_app()

        status, headers = an_answer_to(app, path, headers=the_cookie(app))

        assert (status, headers["www-authenticate"]) == (401, REALM)
        assert_no_store_and_no_cookie(headers)

    @pytest.mark.parametrize(
        ("rule", "gated"),
        [
            pytest.param("/api/admin/", True, id="P03a-rule-below-the-root-path"),
            pytest.param("/app/api/admin/", False, id="P03b-rule-with-the-root-path"),
        ],
    )
    def test_a_root_path_the_server_supplies_is_stripped_from_the_path(
        self, rule: str, gated: bool,
    ) -> None:
        app = a_bearer_app(paths=PathRules(prefixes=(rule,)))

        status, headers = an_answer_to(
            app, f"/app{UNDECLARED_PATH}", root_path="/app", headers=the_cookie(app),
        )

        outcome = (status, app.auth.route_runs == [])
        expected = (401, True) if gated else (200, False)
        assert outcome == expected
        if gated:
            assert headers["www-authenticate"] == REALM
            assert_no_store_and_no_cookie(headers)

    @pytest.mark.parametrize(
        ("rule", "path", "gated"),
        [
            pytest.param("/api/admin/", UNDECLARED_PATH, True, id="P03c-rule-below-the-root-path"),
            pytest.param(
                "/api/admin/", f"/app{UNDECLARED_PATH}", True, id="P03d-the-unstripped-path",
            ),
            pytest.param(
                "/app/api/admin/", UNDECLARED_PATH, False, id="P03e-rule-with-the-root-path",
            ),
        ],
    )
    def test_a_root_path_the_application_supplies_is_stripped_from_the_path(
        self, rule: str, path: str, gated: bool,
    ) -> None:
        app = a_bearer_app(paths=PathRules(prefixes=(rule,)), root_path="/app")

        response = app.ask(path, cookie=True)

        outcome = (response.status_code, app.auth.route_runs == [])
        expected = (401, True) if gated else (200, False)
        assert outcome == expected
        if gated:
            assert response.headers["www-authenticate"] == REALM
            assert_answers_no_store(response)


PREFLIGHT = {"origin": "https://evil.test", "access-control-request-method": "DELETE"}


class TestEveryMethodIsGated:
    @pytest.mark.parametrize("method", ["HEAD", "OPTIONS"])
    def test_head_and_options_without_a_token_are_refused(self, method: str) -> None:
        app = a_bearer_app()

        response = app.ask(method=method, headers=PREFLIGHT)

        assert (response.status_code, response.headers["www-authenticate"]) == (401, REALM)
        assert_answers_no_store(response)

    @pytest.mark.parametrize("method", ["HEAD", "OPTIONS"])
    def test_head_and_options_with_a_token_reach_the_router_that_knows_neither(
        self, method: str,
    ) -> None:
        app = a_bearer_app()

        response = app.ask(method=method, authorization=bearing(A_TOKEN), headers=PREFLIGHT)

        assert response.status_code == 405
        assert_answers_no_store(response)
