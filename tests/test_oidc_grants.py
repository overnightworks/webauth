"""The refresh grant and the workload grant `OidcRelyingParty` posts to the token endpoint.

Each yields its access token or a refusal with its reason, and no repr shows a token.
"""

from __future__ import annotations

from collections.abc import Callable
from typing import Any

import pytest
from pydantic import SecretStr

from tests.support.oidc_arrangement import (
    ABSENT,
    ACCESS_TOKEN_NOW,
    CLIENT_SECRET,
    ISSUED_REFRESH_TOKEN,
    TOKEN_ENDPOINT,
    FakeClock,
    FakeIssuer,
    FakeTokenEndpoint,
    a_fake_id_token,
    a_realm_client_config,
    changed,
    token_endpoint_answer,
)
from tests.support.oidc_relying_party import (
    BASIC_AUTHORIZATION,
    OUTSIDE_THE_REFRESH_TOKEN_GRAMMAR,
    TOKEN_AT_BOTH_ENDS,
    a_relying_party_for,
)
from webauth.oidc import (
    OidcRefusal,
    OidcRefusalReason,
    OidcRelyingParty,
    RenewedAccess,
    TokenEndpointAnswer,
    TokenEndpointError,
    TokenRequestPost,
)


def _renewed_access_token(relying_party: OidcRelyingParty) -> SecretStr | OidcRefusal:
    outcome = relying_party.renew_access(SecretStr(ISSUED_REFRESH_TOKEN))
    return outcome.access_token if isinstance(outcome, RenewedAccess) else outcome


def _workload_access_token(relying_party: OidcRelyingParty) -> SecretStr | OidcRefusal:
    return relying_party.workload_access_token(scopes=("svc-audience",))


_BOTH_GRANTS = pytest.mark.parametrize(
    "grant",
    [
        pytest.param(_renewed_access_token, id="refresh-grant"),
        pytest.param(_workload_access_token, id="workload-grant"),
    ],
)


def _granting(endpoint: TokenRequestPost) -> OidcRelyingParty:
    return a_relying_party_for(
        endpoint, a_realm_client_config(), FakeClock(float(ACCESS_TOKEN_NOW))
    )


def _grant_answer(status: int = 200, **changes: Any) -> FakeTokenEndpoint:
    document = changed({"access_token": "granted-token", "token_type": "Bearer"}, changes)
    return FakeTokenEndpoint(answer=token_endpoint_answer(status, document))


def _an_issuer() -> FakeIssuer:
    return FakeIssuer(mint_id_token=a_fake_id_token)


def test_renewing_access_posts_the_refresh_grant_and_yields_the_rotated_tokens() -> None:
    issuer = _an_issuer()

    outcome = _granting(issuer).renew_access(SecretStr(ISSUED_REFRESH_TOKEN))

    [request] = issuer.requests
    assert request.url == TOKEN_ENDPOINT
    assert dict(request.form) == {
        "grant_type": "refresh_token",
        "refresh_token": ISSUED_REFRESH_TOKEN,
    }
    assert request.authorization.get_secret_value() == BASIC_AUTHORIZATION
    assert isinstance(outcome, RenewedAccess)
    assert outcome.refresh_token is not None
    assert outcome.refresh_token.get_secret_value() != ISSUED_REFRESH_TOKEN
    assert isinstance(_granting(issuer).renew_access(outcome.refresh_token), RenewedAccess)


def test_a_refresh_answer_without_a_refresh_token_yields_none() -> None:
    issuer = _an_issuer()
    issuer.refresh_answer_members = {"refresh_token": ABSENT}

    outcome = _granting(issuer).renew_access(SecretStr(ISSUED_REFRESH_TOKEN))

    assert isinstance(outcome, RenewedAccess)
    assert outcome.refresh_token is None


@_BOTH_GRANTS
@pytest.mark.parametrize("token_type", ["Bearer", "bearer", "BEARER"])
def test_a_grant_accepts_a_bearer_token_type_in_any_ascii_case(
    grant: Callable[[OidcRelyingParty], SecretStr | OidcRefusal], token_type: str
) -> None:
    outcome = grant(_granting(_grant_answer(token_type=token_type)))

    assert outcome == SecretStr("granted-token")


_NOT_A_BEARER_ACCESS_TOKEN = {
    "token-type-missing": {"token_type": ABSENT},
    "token-type-a-number": {"token_type": 7},
    "token-type-mac": {"token_type": "MAC"},
    "token-type-with-a-trailing-space": {"token_type": "Bearer "},
    "token-type-a-non-ascii-look-alike": {"token_type": "B\u0435arer"},
    "access-token-missing": {"access_token": ABSENT},
    "access-token-a-number": {"access_token": 7},
    "access-token-empty": {"access_token": ""},
    "access-token-with-a-carriage-return": {"access_token": "token\r"},
    "access-token-with-a-line-feed": {"access_token": "token\n"},
    "access-token-with-a-space": {"access_token": "to ken"},
}


@_BOTH_GRANTS
@pytest.mark.parametrize(
    "changes", _NOT_A_BEARER_ACCESS_TOKEN.values(), ids=list(_NOT_A_BEARER_ACCESS_TOKEN)
)
def test_a_grant_answer_that_is_no_bearer_access_token_is_refused(
    grant: Callable[[OidcRelyingParty], SecretStr | OidcRefusal], changes: dict[str, Any]
) -> None:
    assert grant(_granting(_grant_answer(**changes))) == OidcRefusal(
        OidcRefusalReason.TOKEN_ENDPOINT_FAILED
    )


@pytest.mark.parametrize(
    "refresh_token",
    OUTSIDE_THE_REFRESH_TOKEN_GRAMMAR.values(),
    ids=list(OUTSIDE_THE_REFRESH_TOKEN_GRAMMAR),
)
def test_a_refresh_answer_with_a_refresh_token_outside_the_grammar_is_refused(
    refresh_token: object,
) -> None:
    endpoint = _grant_answer(refresh_token=refresh_token)

    outcome = _granting(endpoint).renew_access(SecretStr(ISSUED_REFRESH_TOKEN))

    assert outcome == OidcRefusal(OidcRefusalReason.TOKEN_ENDPOINT_FAILED)


@pytest.mark.parametrize(
    "refresh_token",
    [value for value in OUTSIDE_THE_REFRESH_TOKEN_GRAMMAR.values() if isinstance(value, str)],
    ids=[
        name for name, value in OUTSIDE_THE_REFRESH_TOKEN_GRAMMAR.items() if isinstance(value, str)
    ],
)
def test_a_refresh_token_outside_the_grammar_is_refused_without_a_request(
    refresh_token: str,
) -> None:
    endpoint = _grant_answer()

    outcome = _granting(endpoint).renew_access(SecretStr(refresh_token))

    assert outcome == OidcRefusal(OidcRefusalReason.TOKEN_ENDPOINT_FAILED)
    assert endpoint.requests == []


def test_a_refresh_token_at_both_ends_of_the_grammar_is_sent_and_received_exactly() -> None:
    issuer = _an_issuer()
    issuer.refresh_tokens.add(TOKEN_AT_BOTH_ENDS)
    issuer.refresh_answer_members = {"refresh_token": TOKEN_AT_BOTH_ENDS}

    outcome = _granting(issuer).renew_access(SecretStr(TOKEN_AT_BOTH_ENDS))

    [request] = issuer.requests
    assert request.form["refresh_token"] == TOKEN_AT_BOTH_ENDS
    assert isinstance(outcome, RenewedAccess)
    assert outcome.refresh_token == SecretStr(TOKEN_AT_BOTH_ENDS)


_REFUSED_GRANT_ANSWERS = [
    pytest.param(
        token_endpoint_answer(status, {"error": error}),
        OidcRefusal(OidcRefusalReason.TOKEN_REQUEST_REFUSED, idp_error=error),
        id=f"{status}-{error}",
    )
    for status, error in [
        (400, "invalid_grant"),
        (401, "invalid_client"),
        (400, "unauthorized_client"),
        (400, "invalid_scope"),
    ]
] + [
    pytest.param(answer, OidcRefusal(OidcRefusalReason.TOKEN_ENDPOINT_FAILED), id=name)
    for name, answer in {
        "server-error": token_endpoint_answer(503, {"error": "server_error"}),
        "non-json-answer": token_endpoint_answer(200, b"<html>signed in</html>"),
        "transport-error": TokenEndpointError("connection refused"),
    }.items()
]


@_BOTH_GRANTS
@pytest.mark.parametrize(("answer", "refusal"), _REFUSED_GRANT_ANSWERS)
def test_a_grant_the_issuer_refuses_or_fails_is_refused_with_its_reason(
    grant: Callable[[OidcRelyingParty], SecretStr | OidcRefusal],
    answer: TokenEndpointAnswer | Exception,
    refusal: OidcRefusal,
) -> None:
    assert grant(_granting(FakeTokenEndpoint(answer=answer))) == refusal


def test_a_refresh_token_the_issuer_never_issued_or_ended_is_invalid_grant() -> None:
    issuer = _an_issuer()
    relying_party = _granting(issuer)
    invalid_grant = OidcRefusal(OidcRefusalReason.TOKEN_REQUEST_REFUSED, idp_error="invalid_grant")

    assert relying_party.renew_access(SecretStr("never-issued")) == invalid_grant
    issuer.end_sso_session()
    assert relying_party.renew_access(SecretStr(ISSUED_REFRESH_TOKEN)) == invalid_grant


def test_a_workload_token_is_refused_while_the_client_has_no_service_account() -> None:
    issuer = _an_issuer()
    issuer.service_accounts_enabled = False

    assert _granting(issuer).workload_access_token(scopes=("svc-audience",)) == OidcRefusal(
        OidcRefusalReason.TOKEN_REQUEST_REFUSED, idp_error="unauthorized_client"
    )


@pytest.mark.parametrize(
    ("scopes", "posted_scope"),
    [
        pytest.param(("svc-audience",), "svc-audience", id="one-scope"),
        pytest.param(("svc-a-audience", "profile"), "svc-a-audience profile", id="several-scopes"),
        pytest.param(("a!b", "c#d", "[e]", "f~g"), "a!b c#d [e] f~g", id="boundary-punctuation"),
    ],
)
def test_the_workload_grant_posts_the_grant_type_and_the_scopes_with_the_clients_authorization(
    scopes: tuple[str, ...], posted_scope: str
) -> None:
    issuer = _an_issuer()

    outcome = _granting(issuer).workload_access_token(scopes=scopes)

    [request] = issuer.requests
    assert request.url == TOKEN_ENDPOINT
    assert dict(request.form) == {"grant_type": "client_credentials", "scope": posted_scope}
    assert request.authorization.get_secret_value() == BASIC_AUTHORIZATION
    assert isinstance(outcome, SecretStr)


@pytest.mark.parametrize(
    "scopes",
    [
        pytest.param((), id="empty-tuple"),
        pytest.param(["svc"], id="list"),
        pytest.param("svc", id="one-string"),
        pytest.param((1,), id="non-string-token"),
        pytest.param(("",), id="empty-token"),
        pytest.param((" svc",), id="leading-space"),
        pytest.param(("svc ",), id="trailing-space"),
        pytest.param(("a b",), id="inner-space"),
        pytest.param(('a"b',), id="double-quote"),
        pytest.param(("a\\b",), id="backslash"),
        pytest.param(("a\x7fb",), id="delete-character"),
        pytest.param(("a\nb",), id="control-character"),
        pytest.param(("a\u00e4b",), id="non-ascii-character"),
    ],
)
def test_the_workload_grant_refuses_scopes_outside_the_scope_token_grammar_and_posts_nothing(
    scopes: object,
) -> None:
    issuer = _an_issuer()
    grant = _granting(issuer).workload_access_token

    with pytest.raises(ValueError, match="scopes"):
        grant(scopes=scopes)  # type: ignore[arg-type]

    assert issuer.requests == []


@pytest.mark.parametrize(
    "call",
    [
        pytest.param(lambda grant: grant(), id="without-scopes"),
        pytest.param(lambda grant: grant(("svc",)), id="scopes-positional"),
    ],
)
def test_the_workload_grant_takes_scopes_only_by_keyword_and_posts_nothing(
    call: Callable[[Callable[..., object]], object],
) -> None:
    issuer = _an_issuer()
    grant = _granting(issuer).workload_access_token

    with pytest.raises(TypeError, match="scopes|positional"):
        call(grant)

    assert issuer.requests == []


def test_two_workload_calls_post_twice_and_yield_two_different_tokens() -> None:
    issuer = _an_issuer()
    relying_party = _granting(issuer)

    first = relying_party.workload_access_token(scopes=("svc-audience",))
    second = relying_party.workload_access_token(scopes=("svc-audience",))

    assert len(issuer.requests) == 2
    assert isinstance(first, SecretStr)
    assert isinstance(second, SecretStr)
    assert first != second


def test_no_repr_shows_a_token_a_grant_sent_or_received() -> None:
    issuer = _an_issuer()
    relying_party = _granting(issuer)
    renewed = relying_party.renew_access(SecretStr(ISSUED_REFRESH_TOKEN))
    workload = relying_party.workload_access_token(scopes=("svc-audience",))
    assert isinstance(renewed, RenewedAccess)
    assert renewed.refresh_token is not None
    assert isinstance(workload, SecretStr)

    shown = " ".join(repr(each) for each in (renewed, workload, *issuer.requests))

    for secret in (
        ISSUED_REFRESH_TOKEN,
        renewed.access_token.get_secret_value(),
        renewed.refresh_token.get_secret_value(),
        workload.get_secret_value(),
        CLIENT_SECRET,
        BASIC_AUTHORIZATION,
    ):
        assert secret not in shown
