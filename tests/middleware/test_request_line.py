"""What webauth puts on the request line of a host that installs logline's `RequestLineMiddleware`.

Each case runs the real stack with logline's middleware outermost, the way its README asks a host
to install it, and reads the one `request.ended` line the request wrote.
"""

from __future__ import annotations

import pytest

from tests.support.account_arrangement import FakeUser
from tests.support.gate_arrangement import (
    EXPORT_PATH,
    PERSON_ME_PATH,
    a_bearer_app,
    a_token,
    bearing,
)
from tests.support.oidc_arrangement import OPERATOR_SUBJECT
from tests.support.oidc_login_host import CALLBACK_PATH, SUBJECT, an_oidc_host
from tests.support.person_paths_arrangement import MEMBER_TOKEN, a_lena, a_person_app
from tests.support.request_line_arrangement import (
    FORWARDED_CLIENT,
    TRUSTED_PEER,
    a_client_behind_the_proxy,
    logging_request_lines,
    request_lines_written,
)
from tests.support.session_gate_arrangement import a_gated_app, ask, signed_in
from tests.support.webauth_arrangement import a_session
from webauth.policies import PathRules, RateLimitPolicy

UNTRUSTED_PEER = "198.51.100.77"
EXEMPT_PATH = "/not-limited"


def test_a_session_admitted_by_the_gate_is_the_sub_of_its_request_line(
    capsys: pytest.CaptureFixture[str],
) -> None:
    app = a_gated_app(a_session(user=FakeUser(id="user-1", username="alice")))
    logging_request_lines(app.app)

    with request_lines_written(capsys) as lines:
        response = ask(app, "/me", cookie=signed_in(app))

    (line,) = lines
    assert (response.status_code, line["sub"]) == (200, "user-1")


def test_a_request_the_session_gate_refuses_has_no_sub(capsys: pytest.CaptureFixture[str]) -> None:
    app = a_gated_app()
    logging_request_lines(app.app)

    with request_lines_written(capsys) as lines:
        response = ask(app, "/me")

    (line,) = lines
    assert (response.status_code, line["sub"]) == (401, None)


def test_a_token_on_a_person_path_is_the_sub_of_its_request_line(
    capsys: pytest.CaptureFixture[str],
) -> None:
    app = a_person_app(known_accounts=(a_lena(),))
    logging_request_lines(app.auth.app)

    with request_lines_written(capsys) as lines:
        response = app.ask(PERSON_ME_PATH, authorization=bearing(MEMBER_TOKEN))

    (line,) = lines
    assert (response.status_code, line["sub"]) == (200, OPERATOR_SUBJECT)


def test_a_machine_admitted_by_the_bearer_gate_has_no_sub(
    capsys: pytest.CaptureFixture[str],
) -> None:
    app = a_bearer_app()
    logging_request_lines(app.auth.app)

    with request_lines_written(capsys) as lines:
        response = app.ask(EXPORT_PATH, authorization=bearing(a_token()))

    (line,) = lines
    assert (response.status_code, line["sub"]) == (200, None)


def test_the_callback_that_signs_a_person_in_carries_the_person_on_its_own_line(
    capsys: pytest.CaptureFixture[str],
) -> None:
    host = an_oidc_host()
    logging_request_lines(host.client.app)  # pyright: ignore[reportArgumentType]
    query = host.sign_in_at_issuer()

    with request_lines_written(capsys) as lines:
        response = host.callback(query)

    (line,) = lines
    assert (response.status_code, line["route"], line["sub"]) == (303, CALLBACK_PATH, SUBJECT)


@pytest.mark.parametrize(
    ("peer", "expected"),
    [
        pytest.param(TRUSTED_PEER, FORWARDED_CLIENT, id="a-trusted-proxy-names-the-client"),
        pytest.param(UNTRUSTED_PEER, UNTRUSTED_PEER, id="an-untrusted-peer-names-itself"),
    ],
)
def test_the_client_address_webauth_resolves_is_the_ip_of_the_request_line(
    capsys: pytest.CaptureFixture[str],
    peer: str,
    expected: str,
) -> None:
    app = a_gated_app()
    logging_request_lines(app.app)

    with (
        request_lines_written(capsys) as lines,
        a_client_behind_the_proxy(app.app, peer=peer) as client,
    ):
        client.get("/me", headers={"x-forwarded-for": FORWARDED_CLIENT})

    (line,) = lines
    assert line["ip"] == expected


def test_a_path_the_rate_limit_exempts_still_carries_the_resolved_ip(
    capsys: pytest.CaptureFixture[str],
) -> None:
    exempt = RateLimitPolicy(exempt=PathRules(exact=frozenset({EXEMPT_PATH})))
    app = a_gated_app(stack_policies={"rate_limit": exempt})
    logging_request_lines(app.app)

    with request_lines_written(capsys) as lines, a_client_behind_the_proxy(app.app) as client:
        client.get(EXEMPT_PATH, headers={"x-forwarded-for": FORWARDED_CLIENT})

    (line,) = lines
    assert line["ip"] == FORWARDED_CLIENT
