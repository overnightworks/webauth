"""The CSRF origin check: Sec-Fetch-Site first, Origin allowlist as fallback."""

from __future__ import annotations

from collections.abc import Callable
from typing import TypedDict

import pytest
from fastapi import FastAPI, Request
from fastapi.testclient import TestClient
from httpx import Response

from tests.support.gated_stack_arrangement import install_the_gated_stack
from tests.support.webauth_arrangement import (
    ALLOWED_ORIGIN,
    API_PATH,
    AuthApp,
    a_session,
    a_web_auth_config,
    an_auth_app,
    session_cookie_header,
)
from webauth.config import WebAuthConfig
from webauth.policies import CsrfPolicy, PathRules, PathShape, PublicRule

FOREIGN_ORIGIN = "https://evil.test"
OK = {"status": "ok"}
CROSS_ORIGIN_DETAIL = {"detail": "Cross-origin request rejected"}
MISSING_ORIGIN_DETAIL = {"detail": "Missing Origin header"}


WEBHOOK_EXACT_PATH = "/webhook/exact"
WEBHOOK_PREFIX = "/webhook/provider/"
WEBHOOK_PATH = f"{WEBHOOK_PREFIX}event"
WEBHOOK_SIBLING_PATH = "/webhook/providerx"


def an_origin_guarded_client(config: WebAuthConfig | None = None) -> TestClient:
    app = FastAPI()
    install_the_gated_stack(app, config=config or a_web_auth_config(), csrf_origin=CsrfPolicy())

    @app.api_route(API_PATH, methods=["GET", "POST", "PUT", "PATCH", "DELETE"])
    def ok() -> dict[str, str]:
        return OK

    return TestClient(app, base_url=ALLOWED_ORIGIN)


def a_protect_everything_client() -> tuple[TestClient, list[str]]:
    """A client over one POST route per path, and the paths whose routes ran."""
    app = FastAPI()
    install_the_gated_stack(
        app,
        config=a_web_auth_config(),
        csrf_origin=CsrfPolicy(
            exempt=PathRules(
                exact=frozenset({WEBHOOK_EXACT_PATH}),
                prefixes=(WEBHOOK_PREFIX,),
            )
        ),
    )
    route_runs: list[str] = []

    def a_route_recording(path: str) -> Callable[[], dict[str, str]]:
        def run() -> dict[str, str]:
            route_runs.append(path)
            return OK

        return run

    for path in (API_PATH, WEBHOOK_EXACT_PATH, WEBHOOK_PATH, WEBHOOK_SIBLING_PATH):
        app.add_api_route(path, a_route_recording(path), methods=["POST"])
    return TestClient(app, base_url=ALLOWED_ORIGIN), route_runs


def _call(method: str, headers: dict[str, str]) -> Response:
    client = an_origin_guarded_client()
    if method == "GET":
        return client.get(API_PATH, headers=headers)
    return client.post(API_PATH, json={"n": 1}, headers=headers)


@pytest.mark.parametrize(
    ("method", "headers", "status", "body"),
    [
        pytest.param(
            "POST",
            {"sec-fetch-site": "same-origin"},
            200,
            OK,
            id="same-origin-without-origin-passes",
        ),
        pytest.param(
            "POST",
            {"sec-fetch-site": "same-origin", "referer": f"{FOREIGN_ORIGIN}/page"},
            200,
            OK,
            id="same-origin-with-foreign-referer-passes",
        ),
        pytest.param(
            "POST",
            {"origin": ALLOWED_ORIGIN, "referer": f"{FOREIGN_ORIGIN}/page"},
            200,
            OK,
            id="allowed-origin-with-foreign-referer-passes",
        ),
        pytest.param(
            "POST",
            {"sec-fetch-site": "same-origin", "origin": FOREIGN_ORIGIN},
            200,
            OK,
            id="same-origin-with-foreign-origin-passes",
        ),
        pytest.param(
            "POST",
            {"sec-fetch-site": "cross-site", "origin": ALLOWED_ORIGIN},
            403,
            CROSS_ORIGIN_DETAIL,
            id="cross-site-wins-over-allowlisted-origin",
        ),
        pytest.param(
            "POST",
            {"sec-fetch-site": "same-site", "origin": ALLOWED_ORIGIN},
            200,
            OK,
            id="same-site-with-allowlisted-origin-passes",
        ),
        pytest.param(
            "POST",
            {"sec-fetch-site": "same-site", "origin": FOREIGN_ORIGIN},
            403,
            CROSS_ORIGIN_DETAIL,
            id="same-site-with-foreign-origin-refused",
        ),
        pytest.param(
            "POST",
            {"origin": ALLOWED_ORIGIN},
            200,
            OK,
            id="absent-header-allowlisted-origin-passes",
        ),
        pytest.param(
            "POST",
            {"origin": FOREIGN_ORIGIN},
            403,
            CROSS_ORIGIN_DETAIL,
            id="absent-header-foreign-origin-refused",
        ),
        pytest.param(
            "POST",
            {"sec-fetch-site": "same-site"},
            403,
            MISSING_ORIGIN_DETAIL,
            id="same-site-without-origin-refused",
        ),
        pytest.param(
            "POST",
            {"sec-fetch-site": "same-site", "referer": f"{ALLOWED_ORIGIN}/page"},
            403,
            MISSING_ORIGIN_DETAIL,
            id="same-site-without-origin-with-allowed-referer-refused",
        ),
        pytest.param(
            "POST",
            {"sec-fetch-site": "garbage", "origin": ALLOWED_ORIGIN},
            403,
            CROSS_ORIGIN_DETAIL,
            id="unknown-fetch-site-wins-over-allowlisted-origin",
        ),
        pytest.param(
            "POST",
            {"sec-fetch-site": "none"},
            403,
            CROSS_ORIGIN_DETAIL,
            id="none-with-post-refused",
        ),
        pytest.param(
            "GET",
            {"sec-fetch-site": "cross-site"},
            200,
            OK,
            id="safe-method-cross-site-passes",
        ),
    ],
)
def test_a_request_is_judged_by_sec_fetch_site_then_origin(
    method: str,
    headers: dict[str, str],
    status: int,
    body: dict[str, str],
) -> None:
    """CSRF-03, CSRF-05, CSRF-06, CSRF-07, CSRF-08, CSRF-09: same-origin passes without a token.

    Same-site or an absent header falls back to Origin; any other value is refused.
    A foreign Referer beside valid provenance changes nothing.
    """
    response = _call(method, headers)

    assert response.status_code == status
    assert response.json() == body


class BodyContent(TypedDict, total=False):
    json: dict[str, int]
    data: dict[str, str]
    files: dict[str, tuple[str, bytes]]
    content: bytes


class RequestBody(BodyContent, total=False):
    headers: dict[str, str]


PROVENANCE_FREE_BODIES = [
    pytest.param({}, id="no body"),
    pytest.param({"json": {"n": 1}}, id="json"),
    pytest.param({"data": {"n": "1"}}, id="urlencoded"),
    pytest.param({"files": {"f": ("f.txt", b"x")}}, id="multipart"),
    pytest.param(
        {"content": b"n=1", "headers": {"content-type": "text/plain"}},
        id="text-plain",
    ),
    pytest.param(
        {"content": b"n=1", "headers": {"content-type": "application/octet-stream"}},
        id="octet-stream",
    ),
]


@pytest.mark.parametrize("method", ["POST", "PUT", "PATCH", "DELETE"])
@pytest.mark.parametrize("body", PROVENANCE_FREE_BODIES)
def test_a_state_changing_request_without_provenance_is_refused_whatever_its_body(
    method: str,
    body: RequestBody,
) -> None:
    """CSRF-04, CSRF-08: a state-changing request without provenance is refused, body or not."""
    client = an_origin_guarded_client()

    response = client.request(method, API_PATH, **body)

    assert response.status_code == 403
    assert response.json() == MISSING_ORIGIN_DETAIL


@pytest.mark.parametrize(
    "headers",
    [
        pytest.param({"referer": f"{ALLOWED_ORIGIN}/page"}, id="an allowed referer"),
    ],
)
@pytest.mark.parametrize("method", ["POST", "PUT", "PATCH", "DELETE"])
@pytest.mark.parametrize("body", PROVENANCE_FREE_BODIES[1:3])
def test_the_referer_is_not_read(
    method: str,
    headers: dict[str, str],
    body: BodyContent,
) -> None:
    """CSRF-09: an allowed Referer is no provenance."""
    client = an_origin_guarded_client()

    response = client.request(method, API_PATH, headers=headers, **body)

    assert response.status_code == 403
    assert response.json() == MISSING_ORIGIN_DETAIL


def test_same_origin_fetch_site_passes_despite_a_null_origin() -> None:
    response = _call("POST", {"sec-fetch-site": "same-origin", "origin": "null"})

    assert response.status_code == 200


@pytest.mark.parametrize(
    ("path", "exempt"),
    [
        pytest.param(API_PATH, False, id="a route nobody listed"),
        pytest.param(WEBHOOK_EXACT_PATH, True, id="an exempt exact path"),
        pytest.param(WEBHOOK_PATH, True, id="a child of the exempt prefix"),
        pytest.param(WEBHOOK_SIBLING_PATH, False, id="a sibling of the exempt prefix"),
    ],
)
@pytest.mark.parametrize(
    ("headers", "checked_answer"),
    [
        pytest.param({"origin": FOREIGN_ORIGIN}, (403, CROSS_ORIGIN_DETAIL), id="a foreign Origin"),
        pytest.param({}, (403, MISSING_ORIGIN_DETAIL), id="no provenance"),
        pytest.param({"sec-fetch-site": "same-origin"}, (200, OK), id="same-origin"),
    ],
)
def test_protect_everything_checks_every_route_but_the_exempt_ones(
    path: str,
    exempt: bool,
    headers: dict[str, str],
    checked_answer: tuple[int, dict[str, str]],
) -> None:
    """CSRF-10, CSRF-11: an exempt path bypasses the check, an adjacent one does not."""
    client, route_runs = a_protect_everything_client()

    response = client.post(path, json={"n": 1}, headers=headers)

    answer = (200, OK) if exempt else checked_answer
    outcome = (response.status_code, response.json())
    assert outcome == answer
    assert route_runs == ([path] if answer[0] == 200 else [])


@pytest.mark.parametrize("method", ["GET", "HEAD", "OPTIONS"])
def test_a_safe_method_without_provenance_reaches_its_route(method: str) -> None:
    app = FastAPI()
    install_the_gated_stack(app, config=a_web_auth_config(), csrf_origin=CsrfPolicy())
    app.add_api_route(API_PATH, lambda: OK, methods=[method])

    response = TestClient(app, base_url=ALLOWED_ORIGIN).request(method, API_PATH)

    assert response.status_code == 200


def test_a_valid_session_cookie_is_not_provenance() -> None:
    auth = an_auth_app(
        a_session(),
        gate=True,
        stack_policies={"csrf_origin": CsrfPolicy()},
    )
    cookie = session_cookie_header(auth.signed_cookie())

    response = auth.client.post("/optional", headers={"cookie": cookie})

    assert response.status_code == 403
    assert response.json() == MISSING_ORIGIN_DETAIL
    assert auth.route_runs == []
    passing = auth.client.post(
        "/optional",
        headers={"cookie": cookie, "sec-fetch-site": "same-origin"},
    )
    assert passing.status_code == 200
    assert auth.route_runs == ["/optional"]


PERSON_EXPORT_ROUTE = "/api/people/{subject}/export"
HOOK_ROUTE = "/hooks/{name}"
HOOK_EXEMPT_PATH = "/hooks/stripe"
PERSON_EXPORT_SHAPE = CsrfPolicy(exempt=PathRules(shapes=(PathShape("/api/people/", "/export"),)))
HOOK_EXEMPTION = CsrfPolicy(exempt=PathRules(exact=frozenset({HOOK_EXEMPT_PATH})))


def a_stack_with_parametrised_post_routes(**stack_policies: CsrfPolicy) -> AuthApp:
    """The full stack over POST routes whose path parameter the router decodes."""
    auth = an_auth_app(
        None,
        gate=True,
        public=(PublicRule(PathRules(prefixes=("/api/", "/hooks/"))),),
        stack_policies=stack_policies,
    )

    def run(request: Request) -> dict[str, str]:
        auth.route_runs.append(request.scope["path"])
        return OK

    auth.app.add_api_route(PERSON_EXPORT_ROUTE, run, methods=["POST"])
    auth.app.add_api_route(HOOK_ROUTE, run, methods=["POST"])
    return auth


ROUTED_PATH_CASES = [
    pytest.param(
        PERSON_EXPORT_SHAPE,
        "/api/people/alice/export",
        "/api/people/alice/export",
        False,
        id="shape-plain",
    ),
    pytest.param(
        PERSON_EXPORT_SHAPE,
        "/api/people/alice%3Fx/export",
        "/api/people/alice?x/export",
        False,
        id="shape-encoded-question-mark",
    ),
    pytest.param(
        PERSON_EXPORT_SHAPE,
        "/api/people/alice%23x/export",
        "/api/people/alice#x/export",
        False,
        id="shape-encoded-hash",
    ),
    pytest.param(
        HOOK_EXEMPTION,
        HOOK_EXEMPT_PATH,
        HOOK_EXEMPT_PATH,
        False,
        id="exempt-exact",
    ),
    pytest.param(
        HOOK_EXEMPTION,
        "/hooks/stripe%3Fx",
        "/hooks/stripe?x",
        True,
        id="exempt-exact-encoded-question-mark",
    ),
    pytest.param(
        HOOK_EXEMPTION,
        "/hooks/stripe%23x",
        "/hooks/stripe#x",
        True,
        id="exempt-exact-encoded-hash",
    ),
]


@pytest.mark.parametrize(("policy", "sent_path", "routed_path", "refused"), ROUTED_PATH_CASES)
def test_the_csrf_origin_rule_is_chosen_by_the_path_the_router_routes(
    policy: CsrfPolicy,
    sent_path: str,
    routed_path: str,
    refused: bool,
) -> None:
    auth = a_stack_with_parametrised_post_routes(csrf_origin=policy)

    response = auth.client.post(sent_path, headers={"origin": FOREIGN_ORIGIN})

    assert response.status_code == (403 if refused else 200)
    assert auth.route_runs == ([] if refused else [routed_path])
