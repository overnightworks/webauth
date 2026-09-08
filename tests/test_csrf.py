"""CsrfOriginMiddleware: Sec-Fetch-Site first, Origin allowlist as fallback."""

from __future__ import annotations

import pytest
from fastapi import FastAPI
from fastapi.testclient import TestClient
from httpx import Response
from webauth_arrangement import ALLOWED_ORIGIN, API_PATH, a_web_auth_config

from webauth.config import install_web_auth_config
from webauth.middleware import CsrfOriginMiddleware
from webauth.policies import CsrfPolicy, PathRules

FOREIGN_ORIGIN = "https://evil.test"
OK = {"status": "ok"}
CROSS_ORIGIN_DETAIL = {"detail": "Cross-origin request rejected"}
MISSING_ORIGIN_DETAIL = {"detail": "Missing Origin header on form submission"}


WEBHOOK_PREFIX = "/webhook/provider/"
WEBHOOK_PATH = f"{WEBHOOK_PREFIX}event"
WEBHOOK_SIBLING_PATH = "/webhook/providerx"


def an_origin_guarded_client() -> TestClient:
    app = FastAPI()
    install_web_auth_config(app, a_web_auth_config())
    app.add_middleware(
        CsrfOriginMiddleware,
        policy=CsrfPolicy(protected=PathRules(prefixes=("/api/",))),
    )

    @app.api_route(API_PATH, methods=["GET", "POST"])
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


def _call(method: str, headers: dict[str, str], *, as_form: bool = False) -> Response:
    client = an_origin_guarded_client()
    if method == "GET":
        return client.get(API_PATH, headers=headers)
    if as_form:
        return client.post(
            API_PATH,
            content=b"n=1",
            headers={**headers, "content-type": "application/x-www-form-urlencoded"},
        )
    return client.post(API_PATH, json={"n": 1}, headers=headers)


@pytest.mark.parametrize(
    ("method", "headers", "as_form", "status", "body"),
    [
        pytest.param(
            "POST",
            {"sec-fetch-site": "same-origin"},
            False,
            200,
            OK,
            id="same-origin-without-origin-passes",
        ),
        pytest.param(
            "POST",
            {"sec-fetch-site": "same-origin", "origin": FOREIGN_ORIGIN},
            False,
            200,
            OK,
            id="same-origin-with-foreign-origin-passes",
        ),
        pytest.param(
            "POST",
            {"sec-fetch-site": "cross-site", "origin": ALLOWED_ORIGIN},
            False,
            403,
            CROSS_ORIGIN_DETAIL,
            id="cross-site-wins-over-allowlisted-origin",
        ),
        pytest.param(
            "POST",
            {"sec-fetch-site": "same-site", "origin": ALLOWED_ORIGIN},
            False,
            200,
            OK,
            id="same-site-with-allowlisted-origin-passes",
        ),
        pytest.param(
            "POST",
            {"sec-fetch-site": "same-site", "origin": FOREIGN_ORIGIN},
            False,
            403,
            CROSS_ORIGIN_DETAIL,
            id="same-site-with-foreign-origin-refused",
        ),
        pytest.param(
            "POST",
            {"origin": ALLOWED_ORIGIN},
            False,
            200,
            OK,
            id="absent-header-allowlisted-origin-passes",
        ),
        pytest.param(
            "POST",
            {"origin": FOREIGN_ORIGIN},
            False,
            403,
            CROSS_ORIGIN_DETAIL,
            id="absent-header-foreign-origin-refused",
        ),
        pytest.param(
            "POST",
            {},
            False,
            200,
            OK,
            id="absent-both-json-passes",
        ),
        pytest.param(
            "POST",
            {},
            True,
            403,
            MISSING_ORIGIN_DETAIL,
            id="absent-both-form-refused",
        ),
        pytest.param(
            "POST",
            {"sec-fetch-site": "none"},
            False,
            403,
            CROSS_ORIGIN_DETAIL,
            id="none-with-post-refused",
        ),
        pytest.param(
            "GET",
            {"sec-fetch-site": "cross-site"},
            False,
            200,
            OK,
            id="safe-method-cross-site-passes",
        ),
    ],
)
def test_a_request_is_judged_by_sec_fetch_site_then_origin(
    method: str,
    headers: dict[str, str],
    as_form: bool,
    status: int,
    body: dict[str, str],
) -> None:
    response = _call(method, headers, as_form=as_form)

    assert response.status_code == status
    assert response.json() == body


def test_songmakers_json_post_without_either_header_is_unchanged() -> None:
    """Songmaker's TestClient path: JSON, no Sec-Fetch-Site, no Origin."""
    response = _call("POST", {})

    assert response.status_code == 200
    assert response.json() == OK


def test_protect_everything_refuses_a_route_nobody_listed() -> None:
    """A route added later, with no path rule naming it, is checked by default."""
    client = a_protect_everything_client()

    response = client.post(API_PATH, json={"n": 1}, headers={"origin": FOREIGN_ORIGIN})

    assert response.status_code == 403
    assert response.json() == CROSS_ORIGIN_DETAIL


def test_protect_everything_exempts_a_named_prefix() -> None:
    """A sessionless webhook under the exempt prefix passes a foreign Origin."""
    client = a_protect_everything_client()

    response = client.post(WEBHOOK_PATH, json={"n": 1}, headers={"origin": FOREIGN_ORIGIN})

    assert response.status_code == 200
    assert response.json() == OK


def test_protect_everything_keeps_a_sibling_of_an_exempt_prefix_protected() -> None:
    client = a_protect_everything_client()

    response = client.post(
        WEBHOOK_SIBLING_PATH, json={"n": 1}, headers={"origin": FOREIGN_ORIGIN},
    )

    assert response.status_code == 403
    assert response.json() == CROSS_ORIGIN_DETAIL


def test_explicit_protected_rules_refuse_an_exempt_rule() -> None:
    with pytest.raises(ValueError, match="exempt"):
        CsrfPolicy(
            protected=PathRules(prefixes=("/api/",)),
            exempt=PathRules(prefixes=(WEBHOOK_PREFIX,)),
        )
