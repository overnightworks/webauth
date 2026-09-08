"""CsrfOriginMiddleware: Sec-Fetch-Site first, Origin allowlist as fallback."""

from __future__ import annotations

import pytest
from fastapi import FastAPI
from fastapi.testclient import TestClient
from httpx import Response
from webauth_arrangement import a_web_auth_config

from webauth.config import install_web_auth_config
from webauth.middleware import CsrfOriginMiddleware
from webauth.policies import CsrfPolicy, PathRules

PROTECTED = "/api/thing"
ALLOWED_ORIGIN = "https://songmaker.example"
OK = {"status": "ok"}
CROSS_ORIGIN_DETAIL = {"detail": "Cross-origin request rejected"}
MISSING_ORIGIN_DETAIL = {"detail": "Missing Origin header on form submission"}


def an_origin_guarded_client() -> TestClient:
    app = FastAPI()
    install_web_auth_config(app, a_web_auth_config())
    app.add_middleware(
        CsrfOriginMiddleware,
        policy=CsrfPolicy(protected=PathRules(prefixes=("/api/",))),
    )

    @app.api_route(PROTECTED, methods=["GET", "POST"])
    def ok() -> dict[str, str]:
        return OK

    return TestClient(app, base_url=ALLOWED_ORIGIN)


def _post(headers: dict[str, str], *, as_form: bool = False) -> Response:
    client = an_origin_guarded_client()
    if as_form:
        return client.post(
            PROTECTED,
            content=b"n=1",
            headers={**headers, "content-type": "application/x-www-form-urlencoded"},
        )
    return client.post(PROTECTED, json={"n": 1}, headers=headers)


@pytest.mark.parametrize(
    ("headers", "as_form", "status", "body"),
    [
        pytest.param(
            {"sec-fetch-site": "same-origin"},
            False,
            200,
            OK,
            id="same-origin-without-origin-passes",
        ),
        pytest.param(
            {"sec-fetch-site": "cross-site", "origin": ALLOWED_ORIGIN},
            False,
            403,
            CROSS_ORIGIN_DETAIL,
            id="cross-site-wins-over-allowlisted-origin",
        ),
        pytest.param(
            {"origin": ALLOWED_ORIGIN},
            False,
            200,
            OK,
            id="absent-header-allowlisted-origin-passes",
        ),
        pytest.param(
            {},
            True,
            403,
            MISSING_ORIGIN_DETAIL,
            id="absent-both-form-refused",
        ),
        pytest.param(
            {"sec-fetch-site": "none"},
            False,
            403,
            CROSS_ORIGIN_DETAIL,
            id="none-with-post-refused",
        ),
        pytest.param(
            {"sec-fetch-site": "same-site"},
            False,
            403,
            CROSS_ORIGIN_DETAIL,
            id="same-site-refused",
        ),
    ],
)
def test_a_post_is_judged_by_sec_fetch_site_then_origin(
    headers: dict[str, str],
    as_form: bool,
    status: int,
    body: dict[str, str],
) -> None:
    response = _post(headers, as_form=as_form)

    assert response.status_code == status
    assert response.json() == body


def test_songmakers_json_post_without_either_header_is_unchanged() -> None:
    """Songmaker's TestClient path: JSON, no Sec-Fetch-Site, no Origin."""
    response = _post({})

    assert response.status_code == 200
    assert response.json() == OK


def test_a_safe_method_with_sec_fetch_site_none_passes() -> None:
    response = an_origin_guarded_client().get(
        PROTECTED,
        headers={"sec-fetch-site": "none"},
    )

    assert response.status_code == 200
    assert response.json() == OK
