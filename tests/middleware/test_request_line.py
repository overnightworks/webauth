"""What webauth puts on the request line of a host that installs logline's `RequestLineMiddleware`.

Each case runs the real stack with logline's middleware outermost, the way its README asks a host
to install it, and reads the one `request.ended` line the request wrote.
"""

from __future__ import annotations

import json
from typing import TYPE_CHECKING

import pytest

from tests.support.account_arrangement import FakeUser
from tests.support.agent_arrangement import an_agent_group_token
from tests.support.gate_arrangement import (
    EXPORT_PATH,
    PERSON_ME_PATH,
    PERSON_PATHS,
    a_bearer_app,
    a_known_person,
    a_resource,
    a_token,
    an_interactive_agent_token,
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
from tests.support.webauth_arrangement import SESSION_ID, a_session
from webauth.policies import PathRules, RateLimitPolicy

if TYPE_CHECKING:
    from collections.abc import Callable

    from webauth.middleware import ProtectedResource

UNTRUSTED_PEER = "198.51.100.77"
EXEMPT_PATH = "/not-limited"
OVERSIZED_BODY = b"x" * 1_000_000
NOT_AN_ADDRESS = "not-an-address"


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


@pytest.mark.parametrize(
    ("token_of", "known_accounts"),
    [
        pytest.param(an_interactive_agent_token, (a_known_person(),), id="a-person"),
        pytest.param(an_agent_group_token, (), id="an-agent-account-the-resource-creates"),
    ],
)
def test_an_account_admitted_at_a_protected_resource_is_the_sub_of_its_request_line(
    capsys: pytest.CaptureFixture[str],
    token_of: Callable[[ProtectedResource], str],
    known_accounts: tuple[FakeUser, ...],
) -> None:
    resource = a_resource()
    app = a_bearer_app(paths=PathRules(), resource=resource, known_accounts=known_accounts)
    logging_request_lines(app.auth.app)

    with request_lines_written(capsys) as lines:
        response = app.ask(resource.entry_point, authorization=bearing(token_of(resource)))

    (line,) = lines
    assert (response.status_code, line["sub"]) == (200, OPERATOR_SUBJECT)


@pytest.mark.parametrize(
    ("path", "token", "status"),
    [
        pytest.param(PERSON_ME_PATH, "not-a-token", 401, id="a-token-that-does-not-verify"),
        pytest.param(
            a_resource().entry_point,
            an_interactive_agent_token(a_resource()),
            403,
            id="a-subject-no-account-has-at-a-resource",
        ),
    ],
)
def test_a_token_the_bearer_gate_refuses_has_no_sub(
    capsys: pytest.CaptureFixture[str],
    path: str,
    token: str,
    status: int,
) -> None:
    app = a_bearer_app(person_paths=PERSON_PATHS, resource=a_resource())
    logging_request_lines(app.auth.app)

    with request_lines_written(capsys) as lines:
        response = app.ask(path, authorization=bearing(token))

    (line,) = lines
    assert (response.status_code, line["sub"]) == (status, None)


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


def test_a_malformed_forwarding_header_leaves_the_peer_as_the_ip(
    capsys: pytest.CaptureFixture[str],
) -> None:
    app = a_gated_app()
    logging_request_lines(app.app)

    with request_lines_written(capsys) as lines, a_client_behind_the_proxy(app.app) as client:
        client.get("/me", headers={"x-forwarded-for": NOT_AN_ADDRESS})

    (line,) = lines
    assert line["ip"] == TRUSTED_PEER


@pytest.mark.parametrize(
    ("path", "method", "body", "status"),
    [
        pytest.param("/me%0A", "GET", b"", 400, id="a-path-with-a-control-character"),
        pytest.param("/me", "POST", OVERSIZED_BODY, 413, id="a-body-declared-over-the-limit"),
    ],
)
def test_a_request_refused_ahead_of_the_rate_limit_carries_the_resolved_ip(
    capsys: pytest.CaptureFixture[str],
    path: str,
    method: str,
    body: bytes,
    status: int,
) -> None:
    app = a_gated_app()
    logging_request_lines(app.app)

    with request_lines_written(capsys) as lines, a_client_behind_the_proxy(app.app) as client:
        response = client.request(
            method, path, content=body, headers={"x-forwarded-for": FORWARDED_CLIENT}
        )

    (line,) = lines
    assert (response.status_code, line["ip"]) == (status, FORWARDED_CLIENT)


def test_a_request_line_holds_none_of_the_credentials_its_request_sent(
    capsys: pytest.CaptureFixture[str],
) -> None:
    session_app = a_gated_app()
    bearer_app = a_person_app(known_accounts=(a_lena(),))
    logging_request_lines(session_app.app)
    logging_request_lines(bearer_app.auth.app)
    cookie = signed_in(session_app)

    with request_lines_written(capsys) as lines:
        ask(session_app, "/me", cookie=cookie)
        bearer_app.ask(PERSON_ME_PATH, authorization=bearing(MEMBER_TOKEN))

    written = [json.dumps(line) for line in lines]
    secrets = (MEMBER_TOKEN, cookie, session_app.signed_cookie(), SESSION_ID)
    assert (len(written), [s for s in secrets if any(s in line for line in written)]) == (2, [])
