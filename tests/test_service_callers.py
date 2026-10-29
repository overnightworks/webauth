"""The workload proof a service runs on an app's own token: `ServiceCallerCheck.workload_caller`.

A valid token of a registered workload yields its caller; every fault yields the
first refusal of the documented order.
"""

from __future__ import annotations

import logging
from collections.abc import Callable
from dataclasses import replace
from typing import Any

import pytest

from tests.support.oidc_arrangement import (
    ABSENT,
    ACCESS_TOKEN_LEEWAY_SECONDS,
    ACCESS_TOKEN_LIFETIME_SECONDS,
    ACCESS_TOKEN_NOW,
    REALM_ISSUER,
    REALM_JWKS_URL,
    FakeClock,
    FakeKeySetEndpoint,
    an_access_token,
    key_set_document,
    public_jwk,
    rsa_key,
)
from webauth.https_client import KeySetFetchError
from webauth.jwt_verification import RejectionReason
from webauth.oidc_login import AdmissionConfig, EverySubject, NoAdmins
from webauth.service_callers import (
    CallerRefusal,
    CallerRefusalReason,
    Principal,
    RegisteredApp,
    ServiceCallerCheck,
    ServiceIdentity,
    WorkloadCaller,
)

CALLEE = "speech-runtime"
WORKLOAD_ROLE = "workload"
GROUP_CLAIM = "groups"
WORKLOAD_CLIENT = "notes-workload"
MAX_WORKLOAD_SECONDS = ACCESS_TOKEN_LIFETIME_SECONDS
# Canaries: recognisable text that appears nowhere in the configuration
SUBJECT_CANARY = "subject-canary-7f3a"
CLIENT_CANARY = "client-canary-9b1c"
GROUP_CANARY = "/group-canary-4d2e"
SECRET_PATH = "/realms/workshop/certs-secret-path-5e6f"
UNREGISTERED = "unregistered-client"


def an_app_admission() -> AdmissionConfig:
    return AdmissionConfig(
        bound_issuer=REALM_ISSUER,
        login_group="/apps/notes",
        admin_group=NoAdmins.IN_THIS_APP,
    )


def a_service_identity(**changes: Any) -> ServiceIdentity:
    arguments: dict[str, Any] = {
        "issuer": REALM_ISSUER,
        "audience": CALLEE,
        "jwks_url": REALM_JWKS_URL,
        "workload_role": WORKLOAD_ROLE,
        "group_claim": GROUP_CLAIM,
        "max_workload_seconds": MAX_WORKLOAD_SECONDS,
        "leeway_seconds": ACCESS_TOKEN_LEEWAY_SECONDS,
    }
    return ServiceIdentity(**{**arguments, **changes})


def a_registry(client: str = WORKLOAD_CLIENT) -> dict[str, RegisteredApp]:
    return {client: RegisteredApp(app="notes", admission=an_app_admission())}


def a_check(
    *,
    identity: ServiceIdentity | None = None,
    registered_apps: Any = None,
    fetch_key_set: Callable[[str], bytes] | None = None,
    monotonic_clock: Callable[[], float] | None = None,
) -> ServiceCallerCheck:
    return ServiceCallerCheck(
        identity or a_service_identity(),
        registered_apps=a_registry() if registered_apps is None else registered_apps,
        fetch_key_set=fetch_key_set
        or FakeKeySetEndpoint(key_set_document(public_jwk(rsa_key("current"), "current-key"))),
        wall_clock=FakeClock(float(ACCESS_TOKEN_NOW)),
        monotonic_clock=monotonic_clock or FakeClock(5_000.0),
    )


def a_workload_token(**claim_changes: Any) -> str:
    """The token of `WORKLOAD_CLIENT` for `CALLEE`, as Keycloak signs a client-credentials grant."""
    claims = {
        "aud": CALLEE,
        "azp": WORKLOAD_CLIENT,
        "client_id": WORKLOAD_CLIENT,
        "realm_access": {"roles": [WORKLOAD_ROLE]},
        "sub": SUBJECT_CANARY,
        **claim_changes,
    }
    return an_access_token(claims=claims)


def refused(outcome: object) -> CallerRefusal:
    assert isinstance(outcome, CallerRefusal)
    return outcome


@pytest.mark.parametrize("token", [None, ""])
def test_a_missing_token_is_refused_as_missing(token: str | None) -> None:
    assert a_check().workload_caller(token) == CallerRefusal(
        CallerRefusalReason.MISSING_TOKEN, None
    )


def test_a_valid_token_admits_the_registered_app_with_its_principal_and_groups() -> None:
    token = a_workload_token(groups=[GROUP_CANARY, "/other"])

    admitted = a_check().workload_caller(token)

    assert admitted == WorkloadCaller(
        app="notes",
        client_id=WORKLOAD_CLIENT,
        principal=Principal(issuer=REALM_ISSUER, subject=SUBJECT_CANARY),
        groups=frozenset({GROUP_CANARY, "/other"}),
    )


def test_a_token_may_name_other_audiences_beside_the_callee() -> None:
    admitted = a_check().workload_caller(a_workload_token(aud=[CALLEE, "other-service"]))

    assert isinstance(admitted, WorkloadCaller)


def test_a_key_set_that_cannot_be_fetched_is_unavailable_not_rejected() -> None:
    check = a_check(fetch_key_set=FakeKeySetEndpoint(KeySetFetchError("down")))

    assert check.workload_caller(a_workload_token()) == CallerRefusal(
        CallerRefusalReason.KEY_SET_UNAVAILABLE, None
    )


def test_a_cached_key_set_still_verifies_after_a_failed_refresh() -> None:
    endpoint = FakeKeySetEndpoint(key_set_document(public_jwk(rsa_key("current"), "current-key")))
    monotonic = FakeClock(5_000.0)
    check = a_check(fetch_key_set=endpoint, monotonic_clock=monotonic)
    assert isinstance(check.workload_caller(a_workload_token()), WorkloadCaller)
    endpoint.response = KeySetFetchError("down")
    monotonic.now += 60
    rotated = an_access_token(key_id="rotated-key", claims={"aud": CALLEE, "azp": WORKLOAD_CLIENT})
    assert refused(check.workload_caller(rotated)).reason is CallerRefusalReason.KEY_SET_UNAVAILABLE

    assert isinstance(check.workload_caller(a_workload_token()), WorkloadCaller)


def test_a_malformed_token_is_rejected_without_fetching_the_key_set() -> None:
    endpoint = FakeKeySetEndpoint(KeySetFetchError("down"))

    outcome = a_check(fetch_key_set=endpoint).workload_caller("not-a-token")

    assert outcome == CallerRefusal(
        CallerRefusalReason.TOKEN_REJECTED, RejectionReason.MALFORMED_TOKEN
    )
    assert endpoint.fetched_urls == []


@pytest.mark.parametrize(
    ("token", "rejection"),
    [
        pytest.param(
            an_access_token(key_name="foreign", claims={"aud": CALLEE}),
            RejectionReason.INVALID_SIGNATURE,
            id="bad-signature",
        ),
        pytest.param(
            a_workload_token(iss="https://other.example.org"),
            RejectionReason.INVALID_ISSUER,
            id="wrong-issuer",
        ),
        pytest.param(
            a_workload_token(aud="someone-else"),
            RejectionReason.INVALID_AUDIENCE,
            id="callee-not-in-aud",
        ),
        pytest.param(
            a_workload_token(
                iat=ACCESS_TOKEN_NOW - 1_000, exp=ACCESS_TOKEN_NOW - ACCESS_TOKEN_LEEWAY_SECONDS - 1
            ),
            RejectionReason.EXPIRED,
            id="expired-beyond-leeway",
        ),
        pytest.param(a_workload_token(sub=""), RejectionReason.INVALID_CLAIM, id="empty-subject"),
        pytest.param(
            a_workload_token(sub=7), RejectionReason.INVALID_CLAIM, id="non-string-subject"
        ),
    ],
)
def test_a_token_the_verifier_rejects_is_refused_with_its_reason(
    token: str, rejection: RejectionReason
) -> None:
    assert a_check().workload_caller(token) == CallerRefusal(
        CallerRefusalReason.TOKEN_REJECTED, rejection
    )


@pytest.mark.parametrize("subject", [ABSENT, "\ud800"], ids=["absent", "surrogate"])
def test_a_subject_that_is_absent_or_not_text_is_invalid(subject: object) -> None:
    outcome = a_check().workload_caller(a_workload_token(sub=subject))

    assert outcome == CallerRefusal(CallerRefusalReason.INVALID_SUBJECT, None)


@pytest.mark.parametrize(
    ("groups", "expected"),
    [
        pytest.param(ABSENT, frozenset(), id="absent-means-none"),
        pytest.param(["/a", "/b"], frozenset({"/a", "/b"}), id="a-list"),
    ],
)
def test_groups_are_the_list_of_the_claim_and_empty_when_absent(
    groups: object, expected: frozenset[str]
) -> None:
    admitted = a_check().workload_caller(a_workload_token(groups=groups))

    assert isinstance(admitted, WorkloadCaller)
    assert admitted.groups == expected


@pytest.mark.parametrize(
    "groups",
    ["/a", ["/a", 1], {"/a": True}, 5],
    ids=["string", "non-string-member", "object", "number"],
)
def test_groups_that_are_not_a_list_of_strings_are_malformed(groups: object) -> None:
    outcome = a_check().workload_caller(a_workload_token(groups=groups))

    assert outcome == CallerRefusal(CallerRefusalReason.MALFORMED_GROUPS, None)


def test_the_group_claim_named_by_the_service_is_the_one_read() -> None:
    check = a_check(identity=a_service_identity(group_claim="teams"))

    admitted = check.workload_caller(a_workload_token(teams=["/team"], groups=["/ignored"]))

    assert isinstance(admitted, WorkloadCaller)
    assert admitted.groups == frozenset({"/team"})


@pytest.mark.parametrize(
    "realm_access",
    [
        pytest.param(ABSENT, id="realm-access-absent"),
        pytest.param("workload", id="realm-access-not-an-object"),
        pytest.param({}, id="roles-absent"),
        pytest.param({"roles": WORKLOAD_ROLE}, id="roles-not-a-list"),
        pytest.param({"roles": ["other"]}, id="role-missing"),
    ],
)
def test_a_token_without_the_workload_role_is_not_a_workload(realm_access: object) -> None:
    outcome = a_check().workload_caller(a_workload_token(realm_access=realm_access))

    assert outcome == CallerRefusal(CallerRefusalReason.NOT_A_WORKLOAD, None)


@pytest.mark.parametrize(
    "binding",
    [
        pytest.param({"azp": ABSENT}, id="azp-absent"),
        pytest.param({"azp": ""}, id="azp-empty"),
        pytest.param({"azp": 5}, id="azp-not-a-string"),
        pytest.param({"client_id": ABSENT}, id="client-id-absent"),
        pytest.param({"client_id": ""}, id="client-id-empty"),
        pytest.param({"client_id": 5}, id="client-id-not-a-string"),
        pytest.param({"client_id": "another-client"}, id="client-id-differs-from-azp"),
    ],
)
def test_a_token_whose_client_is_not_bound_is_refused(binding: dict[str, object]) -> None:
    outcome = a_check().workload_caller(a_workload_token(**binding))

    assert outcome == CallerRefusal(CallerRefusalReason.UNBOUND_CLIENT, None)


def test_a_client_that_is_not_registered_is_refused() -> None:
    token = a_workload_token(azp=UNREGISTERED, client_id=UNREGISTERED)

    assert a_check().workload_caller(token) == CallerRefusal(
        CallerRefusalReason.UNREGISTERED_CLIENT, None
    )


def test_a_lifetime_at_the_maximum_is_admitted_and_one_second_above_is_refused() -> None:
    at_maximum = a_workload_token(exp=ACCESS_TOKEN_NOW + MAX_WORKLOAD_SECONDS)
    above = a_workload_token(exp=ACCESS_TOKEN_NOW + MAX_WORKLOAD_SECONDS + 1)
    check = a_check()

    assert isinstance(check.workload_caller(at_maximum), WorkloadCaller)
    assert check.workload_caller(above) == CallerRefusal(
        CallerRefusalReason.WORKLOAD_LIVES_TOO_LONG, None
    )


@pytest.mark.parametrize(
    ("changes", "reason"),
    [
        pytest.param(
            {"sub": ABSENT, "azp": UNREGISTERED, "client_id": UNREGISTERED},
            CallerRefusalReason.INVALID_SUBJECT,
            id="subject-before-registry",
        ),
        pytest.param(
            {"groups": "/a", "realm_access": {"roles": []}},
            CallerRefusalReason.MALFORMED_GROUPS,
            id="groups-before-role",
        ),
        pytest.param(
            {"realm_access": {"roles": []}, "azp": UNREGISTERED, "client_id": UNREGISTERED},
            CallerRefusalReason.NOT_A_WORKLOAD,
            id="role-before-registry",
        ),
        pytest.param(
            {"client_id": "another-client", "exp": ACCESS_TOKEN_NOW + MAX_WORKLOAD_SECONDS + 1},
            CallerRefusalReason.UNBOUND_CLIENT,
            id="binding-before-lifetime",
        ),
    ],
)
def test_the_first_fault_of_the_documented_order_is_the_one_refused(
    changes: dict[str, object], reason: CallerRefusalReason
) -> None:
    assert refused(a_check().workload_caller(a_workload_token(**changes))).reason is reason


@pytest.mark.parametrize(
    ("changes", "field"),
    [
        pytest.param({"issuer": ""}, "issuer", id="empty-issuer"),
        pytest.param({"issuer": 5}, "issuer", id="non-string-issuer"),
        pytest.param({"audience": ""}, "audience", id="empty-audience"),
        pytest.param({"workload_role": ""}, "workload_role", id="empty-role"),
        pytest.param({"group_claim": ""}, "group_claim", id="empty-group-claim"),
        pytest.param({"max_workload_seconds": 0}, "max_workload_seconds", id="zero-lifetime"),
        pytest.param({"max_workload_seconds": True}, "max_workload_seconds", id="boolean-lifetime"),
        pytest.param({"leeway_seconds": -1}, "leeway_seconds", id="negative-leeway"),
    ],
)
def test_an_invalid_identity_field_is_refused_by_name(
    changes: dict[str, object], field: str
) -> None:
    with pytest.raises(ValueError, match=field):
        a_service_identity(**changes)


def test_an_identity_refusal_never_quotes_the_key_set_url() -> None:
    secret_url = f"https://login.example.org{SECRET_PATH}"

    with pytest.raises(ValueError) as refusal:
        a_check(identity=a_service_identity(jwks_url="http://login.example.org" + SECRET_PATH))

    assert SECRET_PATH not in str(refusal.value)
    assert secret_url not in repr(a_service_identity(jwks_url=secret_url))


@pytest.mark.parametrize(
    ("registry", "mentions"),
    [
        pytest.param({}, "registered_apps", id="empty"),
        pytest.param(
            {"": RegisteredApp("notes", an_app_admission())}, "registered_apps", id="empty-key"
        ),
        pytest.param(
            {5: RegisteredApp("notes", an_app_admission())}, "registered_apps", id="non-string-key"
        ),
        pytest.param({WORKLOAD_CLIENT: "notes"}, "registered_apps", id="non-registered-app-value"),
        pytest.param(
            {
                WORKLOAD_CLIENT: RegisteredApp(
                    "notes",
                    AdmissionConfig(
                        bound_issuer="https://other.example.org",
                        login_group=EverySubject.OF_THE_BOUND_ISSUER,
                        admin_group=NoAdmins.IN_THIS_APP,
                    ),
                )
            },
            "bound_issuer",
            id="other-bound-issuer",
        ),
    ],
)
def test_an_invalid_registry_is_refused_by_name(registry: Any, mentions: str) -> None:
    with pytest.raises(ValueError, match=mentions):
        a_check(registered_apps=registry)


@pytest.mark.parametrize("app", ["", 5])
def test_a_registered_app_needs_a_non_empty_name(app: object) -> None:
    with pytest.raises(ValueError, match="app"):
        RegisteredApp(app=app, admission=an_app_admission())  # type: ignore[arg-type]


def test_a_non_https_key_set_url_is_refused() -> None:
    with pytest.raises(ValueError, match="https"):
        a_check(identity=a_service_identity(jwks_url="http://login.example.org/certs"))


def test_mutating_the_passed_registry_afterwards_changes_nothing() -> None:
    registry = a_registry()
    check = a_check(registered_apps=registry)

    registry.clear()
    registry["intruder"] = RegisteredApp("intruder", an_app_admission())

    assert isinstance(check.workload_caller(a_workload_token()), WorkloadCaller)


def test_a_refusal_rejects_a_token_rejection_that_does_not_match_its_reason() -> None:
    with pytest.raises(ValueError, match="token_rejection"):
        CallerRefusal(CallerRefusalReason.TOKEN_REJECTED, None)
    with pytest.raises(ValueError, match="token_rejection"):
        CallerRefusal(CallerRefusalReason.MISSING_TOKEN, RejectionReason.EXPIRED)


def test_nothing_taken_from_a_token_appears_in_a_repr_message_or_log(
    caplog: pytest.LogCaptureFixture,
) -> None:
    secret_url = f"https://login.example.org{SECRET_PATH}"
    identity = a_service_identity(jwks_url=secret_url)
    registry = {CLIENT_CANARY: RegisteredApp("notes", an_app_admission())}
    check = a_check(identity=replace(identity, jwks_url=REALM_JWKS_URL), registered_apps=registry)
    canaries = (SUBJECT_CANARY, CLIENT_CANARY, GROUP_CANARY)
    caller_token = a_workload_token(
        azp=CLIENT_CANARY, client_id=CLIENT_CANARY, groups=[GROUP_CANARY]
    )
    refused_tokens = [
        a_workload_token(azp=CLIENT_CANARY, client_id="other-client", groups=[GROUP_CANARY]),
        a_workload_token(groups=GROUP_CANARY),
        a_workload_token(realm_access={"roles": []}),
        a_workload_token(sub=ABSENT),
    ]
    with caplog.at_level(logging.DEBUG):
        admitted = check.workload_caller(caller_token)
        refusals = [check.workload_caller(token) for token in refused_tokens]
    assert isinstance(admitted, WorkloadCaller)
    with pytest.raises(ValueError) as configuration_refusal:
        a_service_identity(audience=5)

    shown = [
        repr(admitted),
        repr(admitted.principal),
        *(repr(refusal) for refusal in refusals),
        repr(identity),
        str(configuration_refusal.value),
        caplog.text,
    ]

    assert [text for text in shown if any(canary in text for canary in canaries)] == []
    assert [text for text in shown if SECRET_PATH in text] == []
    assert [
        record for record in caplog.records if record.name.startswith("webauth.service_callers")
    ] == []
