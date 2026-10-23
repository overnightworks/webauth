"""CsrfOriginMiddleware: Sec-Fetch-Site first, Origin allowlist as fallback."""

from __future__ import annotations

import pytest
from fastapi import FastAPI, Request
from fastapi.testclient import TestClient
from httpx import Response
from webauth_arrangement import (
    ALLOWED_HOST,
    ALLOWED_ORIGIN,
    API_PATH,
    AuthApp,
    a_session,
    a_web_auth_config,
    an_auth_app,
    session_cookie_header,
)

from webauth.config import WebAuthConfig, install_web_auth_config
from webauth.middleware import CsrfOriginMiddleware
from webauth.policies import CsrfPolicy, PathRules, PathShape, PublicRule

FOREIGN_ORIGIN = "https://evil.test"
SIBLING_ORIGIN = "https://evil.notes.example"
OK = {"status": "ok"}
CROSS_ORIGIN_DETAIL = {"detail": "Cross-origin request rejected"}
MISSING_ORIGIN_DETAIL = {"detail": "Missing Origin header"}


WEBHOOK_PREFIX = "/webhook/provider/"
WEBHOOK_PATH = f"{WEBHOOK_PREFIX}event"
WEBHOOK_SIBLING_PATH = "/webhook/providerx"


def an_origin_guarded_client(config: WebAuthConfig | None = None) -> TestClient:
    app = FastAPI()
    install_web_auth_config(app, config or a_web_auth_config())
    app.add_middleware(
        CsrfOriginMiddleware,
        policy=CsrfPolicy(),
    )

    @app.api_route(API_PATH, methods=["GET", "POST", "PUT", "PATCH", "DELETE"])
    def ok() -> dict[str, str]:
        return OK

    return TestClient(app, base_url=ALLOWED_ORIGIN)


def a_protect_everything_client() -> TestClient:
    app = FastAPI()
    install_web_auth_config(app, a_web_auth_config())
    app.add_middleware(
        CsrfOriginMiddleware,
        policy=CsrfPolicy(exempt=PathRules(prefixes=(WEBHOOK_PREFIX,))),
    )

    @app.api_route(API_PATH, methods=["POST"])
    def ok() -> dict[str, str]:
        return OK

    @app.api_route(WEBHOOK_PATH, methods=["POST"])
    def webhook() -> dict[str, str]:
        return OK

    return TestClient(app, base_url=ALLOWED_ORIGIN)


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
            {"sec-fetch-site": "same-site", "origin": SIBLING_ORIGIN},
            403,
            CROSS_ORIGIN_DETAIL,
            id="same-site-unlisted-sibling-refused",
        ),
        pytest.param(
            "POST",
            {"origin": SIBLING_ORIGIN},
            403,
            CROSS_ORIGIN_DETAIL,
            id="absent-header-unlisted-sibling-refused",
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
    response = _call(method, headers)

    assert response.status_code == status
    assert response.json() == body


PROVENANCE_FREE_BODIES = [
    pytest.param({}, id="no body"),
    pytest.param({"json": {"n": 1}}, id="json"),
    pytest.param({"data": {"n": "1"}}, id="urlencoded"),
    pytest.param({"files": {"f": ("f.txt", b"x")}}, id="multipart"),
    pytest.param(
        {"content": b"n=1", "headers": {"content-type": "text/plain"}}, id="text-plain",
    ),
    pytest.param(
        {"content": b"n=1", "headers": {"content-type": "application/octet-stream"}},
        id="octet-stream",
    ),
]


@pytest.mark.parametrize("method", ["POST", "PUT", "PATCH", "DELETE"])
@pytest.mark.parametrize("body", PROVENANCE_FREE_BODIES)
def test_a_state_changing_request_without_provenance_is_refused_whatever_its_body(
    method: str, body: dict[str, object],
) -> None:
    client = an_origin_guarded_client()

    response = client.request(method, API_PATH, **body)

    assert response.status_code == 403
    assert response.json() == MISSING_ORIGIN_DETAIL


@pytest.mark.parametrize(
    "headers",
    [
        pytest.param({"referer": f"{ALLOWED_ORIGIN}/page"}, id="an allowed referer"),
        pytest.param({"referer": "null"}, id="a null referer"),
        pytest.param({"referer": "http://[bad"}, id="a referer that cannot be parsed"),
        pytest.param({"referer": ""}, id="an empty referer"),
        pytest.param(
            {"referer": f"https://{ALLOWED_HOST}:password@evil.test/"},
            id="a referer whose userinfo spells the allowed host",
        ),
    ],
)
@pytest.mark.parametrize("method", ["POST", "PUT", "PATCH", "DELETE"])
@pytest.mark.parametrize("body", PROVENANCE_FREE_BODIES[1:3])
def test_the_referer_is_not_read(
    method: str, headers: dict[str, str], body: dict[str, object],
) -> None:
    client = an_origin_guarded_client()

    response = client.request(method, API_PATH, headers=headers, **body)

    assert response.status_code == 403
    assert response.json() == MISSING_ORIGIN_DETAIL


@pytest.mark.parametrize(
    "headers",
    [
        pytest.param({"origin": "null"}, id="a null origin"),
        pytest.param({"origin": "http://"}, id="an origin without a host"),
        pytest.param({"origin": "http://[bad"}, id="an origin that cannot be parsed"),
        pytest.param(
            {"sec-fetch-site": "same-site", "origin": "null"}, id="a null origin on same-site",
        ),
        pytest.param({"origin": ""}, id="an empty origin"),
        pytest.param(
            {"origin": "", "referer": f"{ALLOWED_ORIGIN}/page"},
            id="an empty origin beside an allowed referer",
        ),
        pytest.param(
            {"origin": f"{ALLOWED_ORIGIN}:evil"}, id="an origin with a non-numeric port",
        ),
        pytest.param({"origin": "https://[::1]:evil"}, id="an IPv6 origin with a non-numeric port"),
        pytest.param(
            {"origin": f"https://{ALLOWED_HOST}:password@evil.test"},
            id="an origin whose userinfo spells the allowed host",
        ),
    ],
)
def test_an_origin_that_names_no_host_is_refused_like_a_foreign_one(
    headers: dict[str, str],
) -> None:
    response = _call("POST", headers)

    assert response.status_code == 403
    assert response.json() == CROSS_ORIGIN_DETAIL


@pytest.mark.parametrize(
    "origin",
    [
        pytest.param("https://notes.example.evil.test", id="the host as a prefix"),
        pytest.param("https://notes.example@evil.test", id="the host as userinfo"),
    ],
)
def test_an_origin_that_only_resembles_the_exact_host_is_refused(origin: str) -> None:
    response = _call("POST", {"origin": origin})

    assert response.status_code == 403
    assert response.json() == CROSS_ORIGIN_DETAIL


@pytest.mark.parametrize(
    ("allowed_entry", "origin"),
    [
        pytest.param("[::1]", "https://[::1]", id="a bracketed IPv6 host"),
        pytest.param("[::1]:8000", "https://[::1]:8000", id="a bracketed IPv6 host with a port"),
    ],
)
def test_an_exact_entry_matches_a_bracketed_ipv6_origin(allowed_entry: str, origin: str) -> None:
    client = an_origin_guarded_client(
        a_web_auth_config(allowed_hosts_exact=frozenset({allowed_entry})),
    )

    response = client.post(API_PATH, json={"n": 1}, headers={"origin": origin})

    assert response.status_code == 200


@pytest.mark.parametrize("origin", ["http://localhost:8000", "http://127.0.0.1:5173"])
def test_listing_localhost_and_loopback_admits_their_origins_on_any_port(origin: str) -> None:
    client = an_origin_guarded_client(a_web_auth_config(
        allowed_hosts_exact=frozenset({"localhost", "127.0.0.1"}),
    ))

    response = client.post(API_PATH, json={"n": 1}, headers={"origin": origin})

    assert response.status_code == 200


@pytest.mark.parametrize(
    ("origin", "status"),
    [
        pytest.param("https://notes.example:8443", 200, id="the listed port"),
        pytest.param("https://notes.example:9443", 403, id="another port"),
        pytest.param("https://notes.example", 403, id="the bare host"),
    ],
)
def test_a_host_listed_with_a_port_admits_only_that_port(origin: str, status: int) -> None:
    client = an_origin_guarded_client(
        a_web_auth_config(allowed_hosts_exact=frozenset({"notes.example:8443"})),
    )

    response = client.post(API_PATH, json={"n": 1}, headers={"origin": origin})

    assert response.status_code == status
    if status == 403:
        assert response.json() == CROSS_ORIGIN_DETAIL


def test_same_origin_fetch_site_passes_despite_a_null_origin() -> None:
    response = _call("POST", {"sec-fetch-site": "same-origin", "origin": "null"})

    assert response.status_code == 200


def test_the_exact_host_with_a_port_is_allowed() -> None:
    response = _call("POST", {"origin": f"{ALLOWED_ORIGIN}:8000"})

    assert response.status_code == 200


@pytest.mark.parametrize(
    ("path", "headers", "status", "body"),
    [
        pytest.param(
            API_PATH, {"origin": FOREIGN_ORIGIN}, 403, CROSS_ORIGIN_DETAIL,
            id="a route nobody listed is checked by default",
        ),
        pytest.param(
            WEBHOOK_PATH, {"origin": FOREIGN_ORIGIN}, 200, OK,
            id="a named exempt prefix passes a foreign origin",
        ),
        pytest.param(
            WEBHOOK_SIBLING_PATH, {"origin": FOREIGN_ORIGIN}, 403, CROSS_ORIGIN_DETAIL,
            id="a sibling of an exempt prefix stays protected",
        ),
        pytest.param(
            WEBHOOK_PATH, {}, 200, OK, id="an exempt prefix passes without provenance",
        ),
        pytest.param(
            WEBHOOK_SIBLING_PATH, {}, 403, MISSING_ORIGIN_DETAIL,
            id="a sibling of an exempt prefix is refused without provenance",
        ),
    ],
)
def test_protect_everything_checks_every_route_but_the_exempt_ones(
    path: str, headers: dict[str, str], status: int, body: dict[str, str],
) -> None:
    client = a_protect_everything_client()

    response = client.post(path, json={"n": 1}, headers=headers)

    assert response.status_code == status
    assert response.json() == body


@pytest.mark.parametrize("method", ["GET", "HEAD", "OPTIONS"])
def test_a_safe_method_without_provenance_reaches_its_route(method: str) -> None:
    app = FastAPI()
    install_web_auth_config(app, a_web_auth_config())
    app.add_middleware(CsrfOriginMiddleware, policy=CsrfPolicy())
    app.add_api_route(API_PATH, lambda: OK, methods=[method])

    response = TestClient(app, base_url=ALLOWED_ORIGIN).request(method, API_PATH)

    assert response.status_code == 200


def test_a_valid_session_cookie_is_not_provenance() -> None:
    auth = an_auth_app(
        a_session(), gate=True, stack_policies={"csrf_origin": CsrfPolicy()},
    )
    cookie = session_cookie_header(auth.signed_cookie())

    response = auth.client.post("/optional", headers={"cookie": cookie})

    assert response.status_code == 403
    assert response.json() == MISSING_ORIGIN_DETAIL
    assert auth.route_runs == []
    passing = auth.client.post(
        "/optional", headers={"cookie": cookie, "sec-fetch-site": "same-origin"},
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
        PERSON_EXPORT_SHAPE, "/api/people/alice/export", "/api/people/alice/export", False,
        id="shape-plain",
    ),
    pytest.param(
        PERSON_EXPORT_SHAPE, "/api/people/alice%3Fx/export", "/api/people/alice?x/export",
        False, id="shape-encoded-question-mark",
    ),
    pytest.param(
        PERSON_EXPORT_SHAPE, "/api/people/alice%23x/export", "/api/people/alice#x/export",
        False, id="shape-encoded-hash",
    ),
    pytest.param(
        HOOK_EXEMPTION, HOOK_EXEMPT_PATH, HOOK_EXEMPT_PATH, False, id="exempt-exact",
    ),
    pytest.param(
        HOOK_EXEMPTION, "/hooks/stripe%3Fx", "/hooks/stripe?x", True,
        id="exempt-exact-encoded-question-mark",
    ),
    pytest.param(
        HOOK_EXEMPTION, "/hooks/stripe%23x", "/hooks/stripe#x", True,
        id="exempt-exact-encoded-hash",
    ),
]


@pytest.mark.parametrize(("policy", "sent_path", "routed_path", "refused"), ROUTED_PATH_CASES)
def test_the_csrf_origin_rule_is_chosen_by_the_path_the_router_routes(
    policy: CsrfPolicy, sent_path: str, routed_path: str, refused: bool,
) -> None:
    auth = a_stack_with_parametrised_post_routes(csrf_origin=policy)

    response = auth.client.post(sent_path, headers={"origin": FOREIGN_ORIGIN})

    assert response.status_code == (403 if refused else 200)
    assert auth.route_runs == ([] if refused else [routed_path])


def test_an_exact_exempt_path_reaches_its_route_without_provenance() -> None:
    auth = a_stack_with_parametrised_post_routes(csrf_origin=HOOK_EXEMPTION)

    response = auth.client.post(HOOK_EXEMPT_PATH)

    assert response.status_code == 200
    assert auth.route_runs == [HOOK_EXEMPT_PATH]
