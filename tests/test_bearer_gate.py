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
from dataclasses import dataclass, field
from typing import Any

import httpx
import pytest
from fastapi import Depends, Request
from httpx import Response
from starlette.middleware import Middleware
from oidc_arrangement import (
    ABSENT,
    ACCESS_TOKEN_NOW,
    ACCESS_TOKEN_SUBJECT,
    FakeClock,
    FakeKeySetEndpoint,
    a_relying_party,
    an_access_token,
    key_set_document,
    public_jwk,
    rsa_key,
)
from webauth_arrangement import (
    ADMIN_ROLE,
    HTTPS_TEST_SERVER,
    AuthApp,
    FakeUser,
    a_session,
    an_auth_app,
    an_http_scope,
    drive,
    session_cookie_header,
    starts,
)

from webauth.https_client import KeySetFetchError
from webauth.middleware import BearerGate, bearer_caller
from webauth.oidc_login import AdmissionConfig, NoAdmins
from webauth.policies import AuthorizedParties, CsrfPolicy, PathRules, PathShape, PublicRule
from webauth.ports import BearerCaller

MACHINE_PREFIX = "/api/admin/"
EXPORT_PATH = "/api/admin/export"
UNDECLARED_PATH = "/api/admin/forgotten"
RAISING_PATH = "/api/admin/boom"
PEOPLE_PATH = "/api/admin/people/{subject}/export"
UNGATED_EXPORT_PATH = "/ungated-export"
HEALTH_PATH = "/health"
GATE_LOGGER = "webauth.middleware.bearer_gate"
REALM = 'Bearer realm="admin"'
REALM_INVALID_REQUEST = f'{REALM}, error="invalid_request"'
REALM_INVALID_TOKEN = f'{REALM}, error="invalid_token"'
REALM_INSUFFICIENT_SCOPE = f'{REALM}, error="insufficient_scope"'
ADMISSION = AdmissionConfig(
    bound_issuer=a_relying_party().issuer, login_group="/apps/x", admin_group="/apps/x/admin",
)
MACHINE_PATHS = PathRules(prefixes=(MACHINE_PREFIX,))
CSRF_STACK = {"csrf_origin": CsrfPolicy(), "csrf_token": CsrfPolicy()}


def a_token(**claims: Any) -> str:
    return an_access_token(claims=claims)


def bearing(token: str) -> tuple[str, ...]:
    return (f"Bearer {token}",)


def a_bearer_gate(
    *,
    paths: PathRules = MACHINE_PATHS,
    key_sets: FakeKeySetEndpoint | None = None,
    clock: FakeClock | None = None,
) -> BearerGate:
    return BearerGate(
        paths=paths,
        relying_party=a_relying_party(fetch_key_set=key_sets, wall_clock=clock),
        admission=ADMISSION,
        authorized_parties=AuthorizedParties(frozenset({"hal"})),
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


def a_bearer_app(
    *,
    paths: PathRules = MACHINE_PATHS,
    key_sets: FakeKeySetEndpoint | None = None,
    gated: bool = True,
    policies: dict[str, Any] | None = None,
    inner_middleware: tuple[Middleware, ...] = (),
    **auth_app_keywords: Any,
) -> BearerApp:
    """An app whose machine paths sit behind a bearer gate (or none, when `gated` is false).

    It serves `EXPORT_PATH` and `UNGATED_EXPORT_PATH` (read `bearer_caller`),
    `UNDECLARED_PATH` and `PEOPLE_PATH` (read nothing) and `RAISING_PATH`, besides the
    arrangement's own routes; the session store holds an admin's session, whose cookie
    is `BearerApp.cookie`.
    """
    key_sets = key_sets or a_key_set_answering()
    clock = FakeClock(float(ACCESS_TOKEN_NOW))
    record = a_session(user=FakeUser(role=ADMIN_ROLE))
    stack = {"bearer_gate": a_bearer_gate(paths=paths, key_sets=key_sets, clock=clock)} if gated else {}
    auth = an_auth_app(
        record,
        gate=True,
        raise_server_exceptions=False,
        stack_policies={**CSRF_STACK, **stack, **(policies or {})},
        **auth_app_keywords,
    )

    auth.app.user_middleware.extend(inner_middleware)

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

    @auth.app.get(RAISING_PATH)
    def raising(_caller: BearerCaller = Depends(bearer_caller)) -> None:
        raise RuntimeError("the route failed")

    return BearerApp(
        auth, key_sets, clock, cookie=session_cookie_header(auth.signed_cookie()),
    )


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
A_TOKEN = a_token()
ONLY_THE_APP_GROUP = a_token(groups=["/apps/x"])
KEY_SET_DOWN = KeySetFetchError("the issuer is down")

# (id, Authorization lines, query string, key-set response, answer)
REFUSED = [
    pytest.param((), "", None, NO_CREDENTIALS, id="H01a-no-header"),
    pytest.param(("",), "", None, NO_CREDENTIALS, id="H01b-empty-value"),
    pytest.param(("Basic dXNlcjpwYXNz",), "", None, NO_CREDENTIALS, id="H01c-basic"),
    pytest.param(("Bearerx abc",), "", None, NO_CREDENTIALS, id="H01d-another-scheme"),
    pytest.param((), "?access_token=throwaway", None, NO_CREDENTIALS, id="H01e-query-alone"),
    pytest.param((f"Bearer {A_TOKEN}", f"Bearer {A_TOKEN}"), "", None, INVALID_REQUEST,
                 id="H02a-two-lines"),
    pytest.param((f"Bearer {A_TOKEN}, Basic x",), "", None, INVALID_REQUEST,
                 id="H02b-combined-credentials"),
    pytest.param(("Bearer",), "", None, INVALID_REQUEST, id="H02c-no-credential"),
    pytest.param(("=abc",), "", None, INVALID_REQUEST, id="H02d-no-scheme"),
    pytest.param((f"Bearer\t{A_TOKEN}",), "", None, INVALID_REQUEST, id="H02e-tab"),
    pytest.param((f"Bearer {A_TOKEN} x",), "", None, INVALID_REQUEST, id="H02f-second-word"),
    pytest.param(bearing(A_TOKEN), "?access_token=throwaway", None, INVALID_REQUEST,
                 id="H02g-two-methods"),
    pytest.param(("Bearer abc!def",), "", None, NOT_A_TOKEN, id="H04-not-a-b64token"),
    pytest.param(bearing(an_access_token(header={"typ": "JWT"})), "", None,
                 a_refused_token("access-token-rejected", "invalid-token-type"),
                 id="T02a-another-type"),
    pytest.param(bearing(a_token(aud=["notes-app", "another-app"])), "", None,
                 a_refused_token("invalid-access-claim"), id="T02b-two-audiences"),
    pytest.param(bearing(A_TOKEN), "", KEY_SET_DOWN,
                 a_refused_token("access-token-rejected", "key-set-unavailable"),
                 id="T02c-key-set-unavailable"),
    pytest.param(bearing(a_token(azp="another-client")), "", None,
                 a_refused_token("authorized-party-mismatch"), id="T02d-another-client"),
    pytest.param(bearing(ONLY_THE_APP_GROUP), "", None, INSUFFICIENT_SCOPE,
                 id="T03b-a-member-who-is-no-admin"),
    pytest.param(bearing(a_token(groups=["/apps/x", "/apps/x/administrators"])), "", None,
                 INSUFFICIENT_SCOPE, id="T03b-a-group-that-is-not-below-admin"),
    pytest.param(bearing(a_token(groups=ABSENT)), "", None, INSUFFICIENT_SCOPE,
                 id="T03c-no-groups"),
]


def assert_answers_no_store(response: Response) -> None:
    assert response.headers["cache-control"] == "no-store"
    assert "set-cookie" not in response.headers


@pytest.mark.parametrize(("lines", "query", "key_set_response", "answer"), REFUSED)
def test_a_request_without_a_valid_admin_token_is_refused_with_a_challenge(
    lines: tuple[str, ...], query: str, key_set_response: Exception | None, answer: Answer,
) -> None:
    app = a_bearer_app(key_sets=a_key_set_answering(key_set_response))

    response = app.ask(EXPORT_PATH + query, authorization=lines, cookie=True)

    assert (response.status_code, response.headers["www-authenticate"], response.json()) == (
        answer.status, answer.challenge, {"detail": answer.detail},
    )
    assert_answers_no_store(response)
    assert app.auth.route_runs == []


def test_a_form_body_token_is_no_credential_at_all() -> None:
    app = a_bearer_app()

    response = app.ask(method="DELETE", data={"access_token": "throwaway"})

    assert (response.status_code, response.headers["www-authenticate"]) == (401, REALM)


def test_a_not_a_b64token_credential_reaches_no_key_set() -> None:
    app = a_bearer_app()

    app.ask(authorization=("Bearer abc!def",))

    assert app.key_sets.fetched_urls == []


@pytest.mark.parametrize(("lines", "query", "key_set_response", "answer"), REFUSED)
def test_every_refusal_is_logged_once_with_its_case_or_reason(
    lines: tuple[str, ...],
    query: str,
    key_set_response: Exception | None,
    answer: Answer,
    caplog: pytest.LogCaptureFixture,
) -> None:
    app = a_bearer_app(key_sets=a_key_set_answering(key_set_response))

    with caplog.at_level(logging.DEBUG):
        app.ask(EXPORT_PATH + query, authorization=lines)

    records = [record for record in caplog.records if record.name == GATE_LOGGER]
    assert [record.levelno for record in records] == [answer.level]
    assert all(word in records[0].getMessage() for word in answer.logged)


def leaks_of(secrets: tuple[str, ...], *haystacks: str) -> list[str]:
    return [secret for secret in secrets for haystack in haystacks if secret in haystack]


def digests_of(value: str) -> tuple[str, ...]:
    digest = hashlib.sha256(value.encode("latin-1")).digest()
    return (digest.hex(), base64.b64encode(digest).decode(), base64.urlsafe_b64encode(digest).decode())


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

    assert (response.status_code, response.json()) == (200, {"subject": ACCESS_TOKEN_SUBJECT})
    assert "www-authenticate" not in response.headers
    assert_answers_no_store(response)


@pytest.mark.parametrize(("lines", "query", "key_set_response", "answer"), REFUSED)
def test_no_log_record_or_answer_holds_the_token_the_header_or_its_digest(
    lines: tuple[str, ...],
    query: str,
    key_set_response: Exception | None,
    answer: Answer,
    caplog: pytest.LogCaptureFixture,
) -> None:
    del answer
    app = a_bearer_app(key_sets=a_key_set_answering(key_set_response))
    credentials = tuple(word for line in lines for word in line.replace(",", " ").split()[1:])
    secrets = (*lines, *credentials, *(d for line in lines for d in digests_of(line)))

    with caplog.at_level(logging.DEBUG):
        response = app.ask(EXPORT_PATH + query, authorization=lines)

    headers = " ".join(f"{name}: {value}" for name, value in response.headers.items())
    assert leaks_of(tuple(s for s in secrets if len(s) > 8), caplog.text, response.text, headers) == []


def test_an_admitted_request_leaks_the_token_into_no_log_record(
    caplog: pytest.LogCaptureFixture,
) -> None:
    app = a_bearer_app()

    with caplog.at_level(logging.DEBUG):
        response = app.ask(authorization=bearing(A_TOKEN))

    assert leaks_of((A_TOKEN, *digests_of(f"Bearer {A_TOKEN}")), caplog.text, response.text) == []


def test_a_member_without_the_admin_group_is_refused_with_insufficient_scope_only() -> None:
    app = a_bearer_app()

    response = app.ask(authorization=bearing(ONLY_THE_APP_GROUP))

    assert response.status_code == 403
    assert app.auth.route_runs == []


def test_a_failing_key_set_fetch_is_the_library_500() -> None:
    app = a_bearer_app(key_sets=a_key_set_answering(RuntimeError("the fetch crashed")))

    response = app.ask(authorization=bearing(A_TOKEN))

    assert response.status_code == 500
    assert_answers_no_store(response)


@pytest.mark.anyio
async def test_a_blocked_key_set_fetch_stalls_no_other_request() -> None:
    released = threading.Event()
    key_sets = a_key_set_answering()
    key_sets.before_answer = lambda: released.wait(timeout=5)
    app = a_bearer_app(
        key_sets=key_sets, public=(PublicRule(PathRules(exact=frozenset({HEALTH_PATH}))),),
    )
    transport = httpx.ASGITransport(app=app.auth.app)

    async with httpx.AsyncClient(transport=transport, base_url=HTTPS_TEST_SERVER) as client:
        blocked = asyncio.create_task(
            client.get(EXPORT_PATH, headers={"authorization": f"Bearer {A_TOKEN}"}),
        )
        try:
            while not key_sets.fetched_urls:
                await asyncio.sleep(0.01)
            health = await asyncio.wait_for(client.get(HEALTH_PATH), timeout=3)
        finally:
            released.set()
        admitted = await blocked

    assert (health.status_code, admitted.status_code) == (200, 200)


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


class TestWithoutAGateTheAdminPathsStayWithTheSession:
    def test_a_token_alone_on_a_get_meets_the_session_gate(self) -> None:
        app = a_bearer_app(gated=False)

        response = app.ask(authorization=bearing(A_TOKEN))

        assert (response.status_code, response.json()) == (
            401, {"detail": "Authentication required"},
        )

    def test_a_token_alone_on_a_delete_meets_the_csrf_token_check(self) -> None:
        app = a_bearer_app(gated=False)

        response = app.ask(method="DELETE", authorization=bearing(A_TOKEN))

        assert response.status_code == 403


def an_answer_to(app: BearerApp, path: str, **scope: Any) -> tuple[int, dict[str, str]]:
    request = an_http_scope(app.auth.app, path, **scope)
    messages, raised = asyncio.run(drive(app.auth.app, request))
    assert raised is None
    start = starts(messages)[0]
    return start["status"], {name.decode(): value.decode() for name, value in start["headers"]}


def the_cookie(app: BearerApp) -> list[tuple[bytes, bytes]]:
    return [(b"cookie", app.cookie.encode())]


class TestThePathIsTheDecodedPathTheRouterMatches:
    @pytest.mark.parametrize("encoded", ["%3F", "%23"], ids=["P01a-question", "P01b-hash"])
    def test_an_encoded_delimiter_does_not_hide_a_path_from_the_gate(self, encoded: str) -> None:
        shape = PathRules(shapes=(PathShape("/api/admin/people/", "/export"),))
        app = a_bearer_app(paths=shape)

        response = app.ask(f"/api/admin/people/alice{encoded}x/export", cookie=True)

        assert (response.status_code, response.headers["www-authenticate"]) == (401, REALM)
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

    @pytest.mark.parametrize(
        ("rule", "gated"),
        [
            pytest.param("/app/api/admin/", True, id="P03a-rule-with-the-root-path"),
            pytest.param("/api/admin/", False, id="P03b-rule-without-the-root-path"),
        ],
    )
    def test_a_root_path_the_server_supplies_is_part_of_the_path(
        self, rule: str, gated: bool,
    ) -> None:
        app = a_bearer_app(paths=PathRules(prefixes=(rule,)))

        status, _headers = an_answer_to(
            app, f"/app{UNDECLARED_PATH}", root_path="/app", headers=the_cookie(app),
        )

        assert (status, app.auth.route_runs == []) == ((401, True) if gated else (200, False))

    @pytest.mark.parametrize(
        ("rule", "gated"),
        [
            pytest.param("/api/admin/", True, id="P03c-rule-without-the-root-path"),
            pytest.param("/app/api/admin/", False, id="P03d-rule-with-the-root-path"),
        ],
    )
    def test_a_root_path_the_application_supplies_is_not_part_of_the_path(
        self, rule: str, gated: bool,
    ) -> None:
        app = a_bearer_app(paths=PathRules(prefixes=(rule,)), root_path="/app")

        response = app.ask(UNDECLARED_PATH, cookie=True)

        assert (response.status_code, app.auth.route_runs == []) == (
            (401, True) if gated else (200, False)
        )


class TestEveryMethodIsGated:
    @pytest.mark.parametrize("method", ["HEAD", "OPTIONS"])
    def test_head_and_options_without_a_token_are_refused(self, method: str) -> None:
        app = a_bearer_app()
        preflight = {"origin": "https://evil.test", "access-control-request-method": "DELETE"}

        response = app.ask(method=method, headers=preflight)

        assert (response.status_code, response.headers["www-authenticate"]) == (401, REALM)

    @pytest.mark.parametrize("method", ["HEAD", "OPTIONS"])
    def test_head_and_options_with_a_token_reach_the_router_that_knows_neither(
        self, method: str,
    ) -> None:
        app = a_bearer_app()

        response = app.ask(method=method, authorization=bearing(A_TOKEN))

        assert response.status_code == 405
