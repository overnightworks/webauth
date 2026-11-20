"""The sign-in callback writes one line for each outcome (LOG-07)."""

from __future__ import annotations

import logging
import urllib.parse
from dataclasses import replace
from typing import TYPE_CHECKING

import pytest
from fastapi import Request  # noqa: TC002  # the hook's annotation is read by the host
from starlette.responses import Response

from tests.support.account_arrangement import FakeUser
from tests.support.log_records import fields_of
from tests.support.oidc_login_host import (
    ADMISSION,
    SUBJECT,
    OidcHost,
    StoreDown,
    TransactionKind,
    an_oidc_host,
)
from webauth.admission import AdmissionRefusal
from webauth.jwt_verification import RejectionReason
from webauth.oidc import IdpErrorCode, OidcRefusalReason

if TYPE_CHECKING:
    from collections.abc import Callable

    from webauth.sign_in_routes import SignInRefusal

_LOGGER_NAME = "webauth.sign_in_routes"
_OTHER_IDP_ERROR = "_OTHER"
_VISITOR_CHOSEN_CODE = "visitor_chosen_code"
_RETURN_PATH = "/albums/secret-return-path"
_USERNAME = "lena"


type _Line = tuple[str, int, dict[str, object]]


def _lines(caplog: pytest.LogCaptureFixture) -> list[_Line]:
    return [
        (record.getMessage(), record.levelno, fields_of(record))
        for record in caplog.records
        if record.name == _LOGGER_NAME
    ]


def _the_state_dropped(_host: OidcHost, query: str) -> str:
    return query.replace("state=", "other=")


def _the_code_of_another_login(_host: OidcHost, query: str) -> str:
    return query.replace("code=", "code=not-issued-")


def _denied_with(error: str) -> Callable[[OidcHost, str], str]:
    def denied(_host: OidcHost, query: str) -> str:
        state = urllib.parse.parse_qs(query)["state"][0]
        return urllib.parse.urlencode({"state": state, "error": error})

    return denied


def _the_id_token_garbled(host: OidcHost, query: str) -> str:
    host.issuer.code_answer_members["id_token"] = "not-a-jwt"  # noqa: S105
    return query


def _unchanged(_host: OidcHost, query: str) -> str:
    return query


_A_FOREIGN_ISSUER = replace(ADMISSION, bound_issuer="https://other.example/realms/lab")

_REFUSALS = [
    pytest.param(
        an_oidc_host,
        _the_state_dropped,
        {"reason": OidcRefusalReason.STATE_MISMATCH.value},
        id="before the pending cookie is selected",
    ),
    pytest.param(
        an_oidc_host,
        _the_code_of_another_login,
        {
            "reason": OidcRefusalReason.TOKEN_REQUEST_REFUSED.value,
            "idp_error": IdpErrorCode.INVALID_GRANT.value,
        },
        id="a registered code from the token endpoint",
    ),
    pytest.param(
        an_oidc_host,
        _denied_with(IdpErrorCode.ACCESS_DENIED.value),
        {
            "reason": OidcRefusalReason.AUTHORIZATION_DENIED.value,
            "idp_error": IdpErrorCode.ACCESS_DENIED.value,
        },
        id="a registered code from the authorization endpoint",
    ),
    pytest.param(
        an_oidc_host,
        _denied_with(_VISITOR_CHOSEN_CODE),
        {
            "reason": OidcRefusalReason.AUTHORIZATION_DENIED.value,
            "idp_error": _OTHER_IDP_ERROR,
        },
        id="an unregistered code",
    ),
    pytest.param(
        an_oidc_host,
        _denied_with("<not a code>"),
        {"reason": OidcRefusalReason.AUTHORIZATION_DENIED.value},
        id="no code at all",
    ),
    pytest.param(
        an_oidc_host,
        _the_id_token_garbled,
        {
            "reason": OidcRefusalReason.ID_TOKEN_REJECTED.value,
            "token_rejection": RejectionReason.MALFORMED_TOKEN.value,
        },
        id="an ID token the verifier rejects",
    ),
    pytest.param(
        lambda: an_oidc_host(groups_claim=()),
        _unchanged,
        {"reason": AdmissionRefusal.NOT_A_MEMBER.value},
        id="a person outside the app",
    ),
    pytest.param(
        lambda: an_oidc_host(admission=_A_FOREIGN_ISSUER),
        _unchanged,
        {"reason": AdmissionRefusal.FOREIGN_ISSUER.value},
        id="a foreign issuer",
    ),
    pytest.param(
        lambda: an_oidc_host(FakeUser(id="user-7", username=_USERNAME)),
        _unchanged,
        {"reason": AdmissionRefusal.USERNAME_TAKEN.value},
        id="a taken username in the transaction",
    ),
]


@pytest.mark.parametrize(("host", "returned_query", "fields"), _REFUSALS)
def test_each_refusal_writes_one_sign_in_refused_line_at_info(
    host: Callable[[], OidcHost],
    returned_query: Callable[[OidcHost, str], str],
    fields: dict[str, object],
    caplog: pytest.LogCaptureFixture,
) -> None:
    """LOG-07: the event and its fields, at INFO, for every kind of refusal."""
    refused_host = host()
    query = returned_query(refused_host, refused_host.sign_in_at_issuer())
    caplog.set_level(logging.DEBUG)

    refused_host.callback(query)

    assert _lines(caplog) == [("sign_in.refused", logging.INFO, fields)]


def test_a_missing_pending_login_writes_one_sign_in_refused_line(
    caplog: pytest.LogCaptureFixture,
) -> None:
    host = an_oidc_host()
    query = host.sign_in_at_issuer()
    caplog.set_level(logging.DEBUG)

    host.callback(query, cookie="unrelated=1")

    assert _lines(caplog) == [
        ("sign_in.refused", logging.INFO, {"reason": OidcRefusalReason.STATE_MISMATCH.value})
    ]


def test_a_refused_line_holds_no_value_a_visitor_or_the_person_supplied(
    caplog: pytest.LogCaptureFixture,
) -> None:
    """REFUSE-27: the identity, the username, the tokens and the return path stay out."""
    host = an_oidc_host(groups_claim=())
    query = host.sign_in_at_issuer(return_to=_RETURN_PATH)
    visitor_query = _denied_with(_VISITOR_CHOSEN_CODE)(host, query)
    caplog.set_level(logging.DEBUG)

    host.callback(visitor_query)
    host.callback(query)

    logged = str(_lines(caplog))
    assert [name for name, _, _ in _lines(caplog)] == ["sign_in.refused"] * 2
    for value in (SUBJECT, _USERNAME, _RETURN_PATH, _VISITOR_CHOSEN_CODE, *host.issued_id_tokens):
        assert value not in logged


def test_the_refused_line_is_written_before_the_hook_runs(
    caplog: pytest.LogCaptureFixture,
) -> None:
    host = an_oidc_host(groups_claim=())
    written_before_the_hook: list[list[str]] = []

    def hook(_request: Request, _refusal: SignInRefusal) -> Response:
        written_before_the_hook.append([name for name, _, _ in _lines(caplog)])
        return Response(status_code=403)

    host.answer_refusals = hook
    caplog.set_level(logging.DEBUG)

    host.callback(host.sign_in_at_issuer())

    assert written_before_the_hook == [["sign_in.refused"]]


def test_a_hook_that_raises_leaves_one_refused_line_and_the_500(
    caplog: pytest.LogCaptureFixture,
) -> None:
    """SIGNIN-31: the line stands once, the answer is the plain 500."""
    host = an_oidc_host(groups_claim=())

    def raising_hook(_request: Request, _refusal: SignInRefusal) -> Response:
        raise StoreDown

    host.answer_refusals = raising_hook
    caplog.set_level(logging.DEBUG)

    response = host.callback(host.sign_in_at_issuer())

    assert response.status_code == 500
    assert [name for name, _, _ in _lines(caplog)] == ["sign_in.refused"]


@pytest.mark.parametrize(
    "users",
    [
        pytest.param((), id="a first sign-in"),
        pytest.param((FakeUser(id=SUBJECT, username=_USERNAME),), id="a returning sign-in"),
    ],
)
def test_a_completed_sign_in_writes_one_line_at_info_with_the_sub_alone(
    users: tuple[FakeUser, ...],
    caplog: pytest.LogCaptureFixture,
) -> None:
    host = an_oidc_host(*users)
    query = host.sign_in_at_issuer(return_to=_RETURN_PATH)
    caplog.set_level(logging.DEBUG)

    response = host.callback(query)

    assert response.status_code == 303
    assert _lines(caplog) == [("sign_in.completed", logging.INFO, {"sub": SUBJECT})]


def test_a_sign_in_that_fails_to_commit_writes_no_sign_in_line(
    caplog: pytest.LogCaptureFixture,
) -> None:
    """A failure that becomes the plain 500 is neither a refusal nor a completed sign-in."""
    host = an_oidc_host(transaction_kind=TransactionKind.ROLLING_BACK)
    host.sessions.commit_failure = StoreDown()
    query = host.sign_in_at_issuer()
    caplog.set_level(logging.DEBUG)

    response = host.callback(query)

    assert response.status_code == 500
    assert _lines(caplog) == []
