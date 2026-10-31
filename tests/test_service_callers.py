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
from webauth.oidc_login import AdmissionConfig, AppRole, EverySubject, NoAdmins
from webauth.service_callers import (
    CallerRefusal,
    CallerRefusalReason,
    PersonCaller,
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
# Canaries: recognisable text that appears nowhere in the configuration
SUBJECT_CANARY = "subject-canary-7f3a"
CLIENT_CANARY = "client-canary-9b1c"
GROUP_CANARY = "/group-canary-4d2e"
PERSON_SUBJECT_CANARY = "person-canary-2c8d"
PERSON_GROUP_CANARY = "/apps/notes/person-group-canary-6a0b"
CANARIES = (
    SUBJECT_CANARY,
    CLIENT_CANARY,
    GROUP_CANARY,
    PERSON_SUBJECT_CANARY,
    PERSON_GROUP_CANARY,
)
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


def a_person_token(**claim_changes: Any) -> str:
    """A person's token for `WORKLOAD_CLIENT`: no workload role, no `client_id`."""
    claims = {
        "aud": CALLEE,
        "azp": WORKLOAD_CLIENT,
        "sub": PERSON_SUBJECT_CANARY,
        "groups": ["/apps/notes"],
        **claim_changes,
    }
    return an_access_token(claims=claims)


def assert_message_keeps_identity_private(error: pytest.ExceptionInfo[ValueError]) -> None:
    message = str(error.value)
    leaked = [secret for secret in (REALM_JWKS_URL, SECRET_PATH, *CANARIES) if secret in message]
    assert leaked == []


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
    [None, "/a", ["/a", 1], {"/a": True}, 5],
    ids=["null", "string", "non-string-member", "object", "number"],
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


@pytest.mark.parametrize(
    "lifetime_seconds",
    [
        pytest.param(ACCESS_TOKEN_LIFETIME_SECONDS + 1, id="issuer-lifespan-plus-one"),
        pytest.param(24 * 60 * 60, id="one-day"),
    ],
)
def test_a_workload_token_lives_as_long_as_the_issuer_signed_it(lifetime_seconds: int) -> None:
    token = a_workload_token(exp=ACCESS_TOKEN_NOW + lifetime_seconds)
    check = a_check()

    assert isinstance(check.workload_caller(token), WorkloadCaller)
    assert isinstance(check.person_caller(token, a_person_token()), PersonCaller)


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
            {"groups": None, "realm_access": {"roles": []}},
            CallerRefusalReason.MALFORMED_GROUPS,
            id="null-groups-before-role",
        ),
        pytest.param(
            {"realm_access": {"roles": []}, "azp": UNREGISTERED, "client_id": UNREGISTERED},
            CallerRefusalReason.NOT_A_WORKLOAD,
            id="role-before-registry",
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
        pytest.param({"audience": 5}, "audience", id="non-string-audience"),
        pytest.param({"workload_role": ""}, "workload_role", id="empty-role"),
        pytest.param({"workload_role": 5}, "workload_role", id="non-string-role"),
        pytest.param({"group_claim": ""}, "group_claim", id="empty-group-claim"),
        pytest.param({"group_claim": 5}, "group_claim", id="non-string-group-claim"),
        pytest.param({"leeway_seconds": -1}, "leeway_seconds", id="negative-leeway"),
        pytest.param({"leeway_seconds": True}, "leeway_seconds", id="boolean-leeway"),
        pytest.param({"leeway_seconds": 1.5}, "leeway_seconds", id="float-leeway"),
        pytest.param({"leeway_seconds": "5"}, "leeway_seconds", id="string-leeway"),
    ],
)
def test_an_invalid_identity_field_is_refused_by_name(
    changes: dict[str, object], field: str
) -> None:
    secret_url = f"https://login.example.org{SECRET_PATH}"

    with pytest.raises(ValueError, match=field) as refusal:
        a_service_identity(jwks_url=secret_url, **changes)

    assert_message_keeps_identity_private(refusal)


def test_the_identity_repr_never_shows_the_key_set_url() -> None:
    secret_url = f"https://login.example.org{SECRET_PATH}"

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
    with pytest.raises(ValueError, match=mentions) as refusal:
        a_check(registered_apps=registry)

    assert_message_keeps_identity_private(refusal)


@pytest.mark.parametrize("app", ["", 5])
def test_a_registered_app_needs_a_non_empty_name(app: object) -> None:
    admission = an_app_admission()

    with pytest.raises(ValueError, match="app") as refusal:
        RegisteredApp(app=app, admission=admission)  # type: ignore[arg-type]

    assert_message_keeps_identity_private(refusal)


def test_a_non_https_key_set_url_is_refused() -> None:
    identity = a_service_identity(jwks_url=f"http://login.example.org{SECRET_PATH}")

    with pytest.raises(ValueError, match="https") as refusal:
        a_check(identity=identity)

    assert_message_keeps_identity_private(refusal)


def test_mutating_the_passed_registry_afterwards_changes_nothing() -> None:
    registry = a_registry()
    check = a_check(registered_apps=registry)

    registry.clear()
    registry["intruder"] = RegisteredApp("intruder", an_app_admission())

    assert isinstance(check.workload_caller(a_workload_token()), WorkloadCaller)


@pytest.mark.parametrize(
    ("reason", "rejection"),
    [
        pytest.param(CallerRefusalReason.TOKEN_REJECTED, None, id="rejected-without-rejection"),
        pytest.param(
            CallerRefusalReason.MISSING_TOKEN, RejectionReason.EXPIRED, id="missing-with-rejection"
        ),
    ],
)
def test_a_refusal_rejects_a_token_rejection_that_does_not_match_its_reason(
    reason: CallerRefusalReason, rejection: RejectionReason | None
) -> None:
    with pytest.raises(ValueError, match="token_rejection") as refusal:
        CallerRefusal(reason, rejection)

    assert_message_keeps_identity_private(refusal)


def test_nothing_taken_from_a_token_appears_in_a_repr_message_or_log(
    caplog: pytest.LogCaptureFixture,
) -> None:
    secret_url = f"https://login.example.org{SECRET_PATH}"
    identity = a_service_identity(jwks_url=secret_url)
    registry = {CLIENT_CANARY: RegisteredApp("notes", an_app_admission())}
    check = a_check(identity=replace(identity, jwks_url=REALM_JWKS_URL), registered_apps=registry)
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
    with pytest.raises(ValueError, match="audience") as configuration_refusal:
        a_service_identity(audience=5)

    shown = [
        repr(admitted),
        repr(admitted.principal),
        *(repr(refusal) for refusal in refusals),
        repr(identity),
        str(configuration_refusal.value),
        caplog.text,
    ]

    assert [text for text in shown if any(canary in text for canary in CANARIES)] == []
    assert [text for text in shown if SECRET_PATH in text] == []
    assert [
        record for record in caplog.records if record.name.startswith("webauth.service_callers")
    ] == []


def test_a_workload_with_a_person_is_admitted_with_the_persons_identity_and_role() -> None:
    admitted = a_check().person_caller(
        a_workload_token(), a_person_token(groups=[PERSON_GROUP_CANARY, "/apps/notes"])
    )

    assert admitted == PersonCaller(
        app="notes",
        client_id=WORKLOAD_CLIENT,
        principal=Principal(issuer=REALM_ISSUER, subject=PERSON_SUBJECT_CANARY),
        groups=frozenset({PERSON_GROUP_CANARY, "/apps/notes"}),
        role=AppRole.USER,
    )


@pytest.mark.parametrize(
    "changes",
    [
        pytest.param({"aud": [CALLEE, "other-service"]}, id="callee-beside-another-audience"),
        pytest.param({"realm_access": {"roles": [WORKLOAD_ROLE]}}, id="carries-workload-role"),
        pytest.param({"client_id": "another-client"}, id="carries-another-client-id"),
        pytest.param({"exp": ACCESS_TOKEN_NOW + ACCESS_TOKEN_LIFETIME_SECONDS + 1}, id="long-lived"),
    ],
)
def test_a_person_token_needs_no_workload_shape(changes: dict[str, object]) -> None:
    admitted = a_check().person_caller(a_workload_token(), a_person_token(**changes))

    assert isinstance(admitted, PersonCaller)


@pytest.mark.parametrize(
    ("admission", "person_groups", "role"),
    [
        pytest.param(
            replace(an_app_admission(), admin_group="/apps/notes/admin"),
            ["/apps/notes/admin"],
            AppRole.ADMIN,
            id="admin-group",
        ),
        pytest.param(
            replace(an_app_admission(), login_group=EverySubject.OF_THE_BOUND_ISSUER),
            ABSENT,
            AppRole.USER,
            id="every-subject-in-no-group",
        ),
    ],
)
def test_the_role_is_the_one_the_registered_admission_gives_the_persons_groups(
    admission: AdmissionConfig, person_groups: object, role: AppRole
) -> None:
    registry = {WORKLOAD_CLIENT: RegisteredApp(app="notes", admission=admission)}
    person = a_person_token(groups=person_groups)

    admitted = a_check(registered_apps=registry).person_caller(a_workload_token(), person)

    assert isinstance(admitted, PersonCaller)
    assert admitted.role is role


@pytest.mark.parametrize(
    ("workload_changes", "reason"),
    [
        pytest.param({"sub": ABSENT}, CallerRefusalReason.INVALID_SUBJECT, id="subject"),
        pytest.param({"groups": "/a"}, CallerRefusalReason.MALFORMED_GROUPS, id="groups"),
        pytest.param({"realm_access": ABSENT}, CallerRefusalReason.NOT_A_WORKLOAD, id="no-role"),
        pytest.param({"client_id": "other"}, CallerRefusalReason.UNBOUND_CLIENT, id="unbound"),
        pytest.param(
            {"azp": UNREGISTERED, "client_id": UNREGISTERED},
            CallerRefusalReason.UNREGISTERED_CLIENT,
            id="unregistered",
        ),
    ],
)
def test_a_workload_fault_is_refused_with_its_reason_beside_a_valid_person(
    workload_changes: dict[str, object], reason: CallerRefusalReason
) -> None:
    outcome = a_check().person_caller(a_workload_token(**workload_changes), a_person_token())

    assert outcome == CallerRefusal(reason, None)


@pytest.mark.parametrize("token", [None, ""])
@pytest.mark.parametrize("missing_workload", [True, False], ids=["workload", "person"])
def test_a_missing_token_of_either_kind_is_refused_as_missing(
    token: str | None, missing_workload: bool
) -> None:
    pair = (token, a_person_token()) if missing_workload else (a_workload_token(), token)

    assert a_check().person_caller(*pair) == CallerRefusal(CallerRefusalReason.MISSING_TOKEN, None)


@pytest.mark.parametrize(
    ("changes", "rejection"),
    [
        pytest.param({"aud": "someone-else"}, RejectionReason.INVALID_AUDIENCE, id="not-callee"),
        pytest.param(
            {"iat": ACCESS_TOKEN_NOW - 1_000, "exp": ACCESS_TOKEN_NOW - 100},
            RejectionReason.EXPIRED,
            id="expired",
        ),
    ],
)
def test_a_person_token_the_verifier_rejects_is_refused_with_its_reason(
    changes: dict[str, object], rejection: RejectionReason
) -> None:
    outcome = a_check().person_caller(a_workload_token(), a_person_token(**changes))

    assert outcome == CallerRefusal(CallerRefusalReason.TOKEN_REJECTED, rejection)


def test_a_person_token_with_a_bad_signature_is_rejected() -> None:
    forged = an_access_token(key_name="foreign", claims={"aud": CALLEE})

    assert refused(a_check().person_caller(a_workload_token(), forged)).token_rejection is (
        RejectionReason.INVALID_SIGNATURE
    )


def test_a_key_set_that_is_down_is_refused_at_the_workload_verifier_stage() -> None:
    check = a_check(fetch_key_set=FakeKeySetEndpoint(KeySetFetchError("down")))

    assert check.person_caller(a_workload_token(), a_person_token()) == CallerRefusal(
        CallerRefusalReason.KEY_SET_UNAVAILABLE, None
    )


@pytest.mark.parametrize(
    ("changes", "reason"),
    [
        pytest.param({"sub": ABSENT}, CallerRefusalReason.INVALID_SUBJECT, id="subject-absent"),
        pytest.param({"sub": "\ud800"}, CallerRefusalReason.INVALID_SUBJECT, id="surrogate"),
        pytest.param({"groups": None}, CallerRefusalReason.MALFORMED_GROUPS, id="null-groups"),
        pytest.param({"groups": "/a"}, CallerRefusalReason.MALFORMED_GROUPS, id="string-groups"),
        pytest.param(
            {"groups": ["/a", 1]}, CallerRefusalReason.MALFORMED_GROUPS, id="non-string-group"
        ),
        pytest.param({"azp": ABSENT}, CallerRefusalReason.CLIENT_MISMATCH, id="azp-absent"),
        pytest.param({"azp": 5}, CallerRefusalReason.CLIENT_MISMATCH, id="azp-not-a-string"),
        pytest.param(
            {"azp": "another-client"}, CallerRefusalReason.CLIENT_MISMATCH, id="azp-another-client"
        ),
        pytest.param({"sub": SUBJECT_CANARY}, CallerRefusalReason.SAME_SUBJECT, id="same-subject"),
        pytest.param({"groups": ["/x"]}, CallerRefusalReason.NOT_A_MEMBER, id="not-a-member"),
    ],
)
def test_a_person_fault_is_refused_with_its_reason(
    changes: dict[str, object], reason: CallerRefusalReason
) -> None:
    outcome = a_check().person_caller(a_workload_token(), a_person_token(**changes))

    assert outcome == CallerRefusal(reason, None)


@pytest.mark.parametrize(
    ("workload_changes", "person_changes", "reason"),
    [
        pytest.param(
            {"azp": UNREGISTERED, "client_id": UNREGISTERED},
            {"aud": "someone-else"},
            CallerRefusalReason.TOKEN_REJECTED,
            id="person-rejected-before-workload-registry",
        ),
        pytest.param(
            {"sub": ABSENT},
            {"aud": "someone-else"},
            CallerRefusalReason.TOKEN_REJECTED,
            id="person-rejected-before-workload-subject",
        ),
        pytest.param(
            {"azp": UNREGISTERED, "client_id": UNREGISTERED},
            {"azp": "another-client"},
            CallerRefusalReason.UNREGISTERED_CLIENT,
            id="workload-registry-before-client-mismatch",
        ),
        pytest.param(
            {},
            {"azp": "another-client", "sub": SUBJECT_CANARY},
            CallerRefusalReason.CLIENT_MISMATCH,
            id="client-mismatch-before-same-subject",
        ),
        pytest.param(
            {},
            {"sub": SUBJECT_CANARY, "groups": ["/apps/other"]},
            CallerRefusalReason.SAME_SUBJECT,
            id="same-subject-before-not-a-member",
        ),
        pytest.param(
            {"realm_access": {"roles": []}},
            {"groups": "/a"},
            CallerRefusalReason.MALFORMED_GROUPS,
            id="person-groups-before-workload-role",
        ),
    ],
)
def test_the_first_fault_of_the_person_order_is_the_one_refused(
    workload_changes: dict[str, object],
    person_changes: dict[str, object],
    reason: CallerRefusalReason,
) -> None:
    outcome = a_check().person_caller(
        a_workload_token(**workload_changes), a_person_token(**person_changes)
    )

    assert refused(outcome).reason is reason


@pytest.mark.parametrize(
    "workload_changes",
    [{"sub": ABSENT}, {"realm_access": {"roles": []}}],
    ids=["workload-subject-absent", "workload-without-role"],
)
def test_a_person_key_set_that_is_down_is_unavailable_before_workload_faults(
    workload_changes: dict[str, object],
) -> None:
    rotated_person = an_access_token(
        key_id="rotated-key", claims={"aud": CALLEE, "azp": WORKLOAD_CLIENT}
    )
    endpoint = FakeKeySetEndpoint(key_set_document(public_jwk(rsa_key("current"), "current-key")))
    monotonic = FakeClock(5_000.0)
    check = a_check(fetch_key_set=endpoint, monotonic_clock=monotonic)
    assert isinstance(check.person_caller(a_workload_token(), a_person_token()), PersonCaller)
    endpoint.response = KeySetFetchError("down")
    monotonic.now += 60

    outcome = check.person_caller(a_workload_token(**workload_changes), rotated_person)

    assert refused(outcome).reason is CallerRefusalReason.KEY_SET_UNAVAILABLE


def test_the_workload_path_never_asks_for_membership() -> None:
    token = a_workload_token(groups=["/apps/other"])

    assert isinstance(a_check().workload_caller(token), WorkloadCaller)


def test_nothing_taken_from_either_token_appears_in_a_repr_or_log(
    caplog: pytest.LogCaptureFixture,
) -> None:
    registry = {CLIENT_CANARY: RegisteredApp("notes", an_app_admission())}
    check = a_check(registered_apps=registry)
    workload = a_workload_token(azp=CLIENT_CANARY, client_id=CLIENT_CANARY)
    person = a_person_token(azp=CLIENT_CANARY, groups=["/apps/notes", PERSON_GROUP_CANARY])
    refused_people = [
        a_person_token(azp="another-client"),
        a_person_token(azp=CLIENT_CANARY, sub=SUBJECT_CANARY),
        a_person_token(azp=CLIENT_CANARY, groups=[PERSON_GROUP_CANARY]),
        a_person_token(azp=CLIENT_CANARY, groups=PERSON_GROUP_CANARY),
    ]
    with caplog.at_level(logging.DEBUG):
        admitted = check.person_caller(workload, person)
        refusals = [check.person_caller(workload, token) for token in refused_people]
    assert isinstance(admitted, PersonCaller)

    shown = [repr(admitted), repr(admitted.principal), *map(repr, refusals), caplog.text]

    assert [text for text in shown if any(canary in text for canary in CANARIES)] == []
    assert [
        record for record in caplog.records if record.name.startswith("webauth.service_callers")
    ] == []
