"""What `ServiceCallerCheck` refuses and admits, one rule of `docs/host-contract.md` at a time.

Each case drives `person_caller` through the faults of the rule's own wording, on either token
where the rule names both.
"""

from __future__ import annotations

import os
from collections.abc import Callable, Iterator, Mapping, MutableMapping
from dataclasses import replace
from typing import Any

import pytest

from tests.support.oidc_arrangement import (
    ABSENT,
    ACCESS_TOKEN_LIFETIME_SECONDS,
    ACCESS_TOKEN_NOW,
    FakeKeySetEndpoint,
    served_key_set,
)
from tests.support.service_caller_arrangement import (
    CALLEE,
    SUBJECT_CANARY,
    UNREGISTERED,
    WORKLOAD_CLIENT,
    WORKLOAD_ROLE,
    Fault,
    WholeToken,
    a_check,
    a_check_whose_key_set_went_down,
    a_person_token,
    a_registry,
    a_service_identity,
    a_workload_token,
    an_app_admission,
    on_person,
    on_workload,
    tokens_with,
)
from webauth.admission import AdmissionConfig, EverySubject
from webauth.https_client import KeySetFetchError
from webauth.jwt_verification import RejectionReason
from webauth.service_callers import (
    CallerRefusal,
    CallerRefusalClass,
    CallerRefusalReason,
    PersonCaller,
    RegisteredApp,
    ServiceCallerCheck,
    ServiceIdentity,
)

SIDES = pytest.mark.parametrize("side", ["workload", "person"])


class ForbiddenEnvironment(MutableMapping[str, str]):
    """An `os.environ` that fails the test on any access."""

    def __getitem__(self, key: str) -> str:
        raise AssertionError(f"the environment was read for {key}")

    def __setitem__(self, key: str, value: str) -> None:
        raise AssertionError(f"the environment was written for {key}")

    def __delitem__(self, key: str) -> None:
        raise AssertionError(f"the environment was changed for {key}")

    def __iter__(self) -> Iterator[str]:
        raise AssertionError("the environment was listed")

    def __len__(self) -> int:
        raise AssertionError("the environment was counted")


def a_registry_of(admission: AdmissionConfig) -> dict[str, RegisteredApp]:
    return {WORKLOAD_CLIENT: RegisteredApp(app="notes", admission=admission)}


@pytest.mark.parametrize(
    "without",
    [
        "identity",
        "issuer",
        "audience",
        "jwks_url",
        "workload_role",
        "group_claim",
        "leeway_seconds",
        "registered_apps",
        "fetch_key_set",
        "wall_clock",
        "monotonic_clock",
    ],
)
def test_nothing_a_check_is_built_from_has_a_default(without: str) -> None:
    """CALLER-01: a check cannot be built without its identity, a field of it, its registered
    apps or its key-set fetch and clocks."""
    identity_fields: dict[str, Any] = {
        "issuer": a_service_identity().issuer,
        "audience": CALLEE,
        "jwks_url": a_service_identity().jwks_url,
        "workload_role": WORKLOAD_ROLE,
        "group_claim": "groups",
        "leeway_seconds": 0,
    }
    others: dict[str, Any] = {
        "registered_apps": a_registry(),
        "fetch_key_set": FakeKeySetEndpoint(served_key_set()),
        "wall_clock": lambda: 0.0,
        "monotonic_clock": lambda: 0.0,
    }
    identity_fields.pop(without, None)
    others.pop(without, None)

    with pytest.raises(TypeError, match=without):
        if without == "identity":
            ServiceCallerCheck(**others)
        else:
            ServiceCallerCheck(ServiceIdentity(**identity_fields), **others)


def test_a_check_reads_nothing_from_the_environment(monkeypatch: pytest.MonkeyPatch) -> None:
    """CALLER-02: building a check and refusing or admitting a pair reads nothing from the
    environment."""
    endpoint = FakeKeySetEndpoint(served_key_set())
    workload, person = a_workload_token(), a_person_token()
    with monkeypatch.context() as scoped:
        scoped.setattr(os, "environ", ForbiddenEnvironment())
        check = a_check(fetch_key_set=endpoint)
        admitted = check.person_caller(workload, person)
        refused_outcome = check.person_caller(None, person)

    assert isinstance(admitted, PersonCaller)
    assert isinstance(refused_outcome, CallerRefusal)


def a_row(
    reason: CallerRefusalReason,
    refusal_class: CallerRefusalClass,
    faults: list[Fault],
    *,
    admission: AdmissionConfig | None = None,
    rejection: RejectionReason | None = None,
) -> list[pytest.ParameterSet]:
    return [
        pytest.param(
            fault,
            admission or an_app_admission(),
            reason,
            refusal_class,
            rejection,
            id=f"{reason}-{fault.side}-{index}",
        )
        for index, fault in enumerate(faults)
    ]


def both_sides(*changes: Mapping[str, object] | WholeToken) -> list[Fault]:
    return [Fault(side, change) for change in changes for side in ("workload", "person")]


UNAUTHENTICATED = CallerRefusalClass.UNAUTHENTICATED
FORBIDDEN = CallerRefusalClass.FORBIDDEN
EXPIRED_TOKEN = {"iat": ACCESS_TOKEN_NOW - 1_000, "exp": ACCESS_TOKEN_NOW - 100}
REASONS = CallerRefusalReason
THE_TABLE = [
    *a_row(
        REASONS.MISSING_TOKEN,
        UNAUTHENTICATED,
        both_sides(WholeToken.MISSING, WholeToken.EMPTY),
    ),
    *a_row(
        REASONS.KEY_SET_UNAVAILABLE,
        CallerRefusalClass.UNAVAILABLE,
        both_sides(WholeToken.KEY_SET_DOWN),
    ),
    *[
        row
        for changes, rejection in [
            ({"aud": "someone-else"}, RejectionReason.INVALID_AUDIENCE),
            ({"iss": "https://other.example.org"}, RejectionReason.INVALID_ISSUER),
            (EXPIRED_TOKEN, RejectionReason.EXPIRED),
            ({"sub": ""}, RejectionReason.INVALID_CLAIM),
            (WholeToken.FORGED, RejectionReason.INVALID_SIGNATURE),
            (WholeToken.MALFORMED, RejectionReason.MALFORMED_TOKEN),
            (WholeToken.UNSUPPORTED_ALGORITHM, RejectionReason.UNSUPPORTED_ALGORITHM),
        ]
        for row in a_row(
            REASONS.TOKEN_REJECTED, UNAUTHENTICATED, both_sides(changes), rejection=rejection
        )
    ],
    *a_row(
        REASONS.INVALID_SUBJECT,
        UNAUTHENTICATED,
        both_sides({"sub": ABSENT}, {"sub": "\ud800"}),
    ),
    *a_row(
        REASONS.MALFORMED_GROUPS,
        UNAUTHENTICATED,
        both_sides(
            {"groups": None},
            {"groups": "/a"},
            {"groups": ["/a", 1]},
            {"groups": {"/a": True}},
            {"groups": 5},
        ),
    ),
    *a_row(
        REASONS.NOT_A_WORKLOAD,
        FORBIDDEN,
        [
            on_workload(change)
            for change in [
                {"realm_access": ABSENT},
                {"realm_access": "workload"},
                {"realm_access": {}},
                {"realm_access": {"roles": WORKLOAD_ROLE}},
                {"realm_access": {"roles": ["other"]}},
            ]
        ],
    ),
    *a_row(
        REASONS.UNBOUND_CLIENT,
        FORBIDDEN,
        [
            on_workload(change)
            for change in [
                {"azp": ABSENT},
                {"azp": ""},
                {"azp": 5},
                {"client_id": ABSENT},
                {"client_id": ""},
                {"client_id": 5},
                {"client_id": "another-client"},
            ]
        ],
    ),
    *a_row(
        REASONS.UNREGISTERED_CLIENT,
        FORBIDDEN,
        [on_workload({"azp": UNREGISTERED, "client_id": UNREGISTERED})],
    ),
    *a_row(
        REASONS.CLIENT_MISMATCH,
        FORBIDDEN,
        [on_person(change) for change in [{"azp": ABSENT}, {"azp": 5}, {"azp": "another-client"}]],
    ),
    *a_row(REASONS.SAME_SUBJECT, FORBIDDEN, [on_person({"sub": SUBJECT_CANARY})]),
    *a_row(
        REASONS.NOT_A_MEMBER,
        FORBIDDEN,
        [on_person(change) for change in [{"groups": ["/x"]}, {"groups": []}, {"groups": ABSENT}]],
    ),
    *a_row(
        REASONS.NOT_A_MEMBER,
        FORBIDDEN,
        [on_person({})],
        admission=replace(an_app_admission(), login_group="/apps/other"),
    ),
]


@pytest.mark.parametrize(("fault", "admission", "reason", "refusal_class", "rejection"), THE_TABLE)
def test_a_fault_of_the_table_is_refused_with_its_reason_and_class(
    fault: Fault,
    admission: AdmissionConfig,
    reason: CallerRefusalReason,
    refusal_class: CallerRefusalClass,
    rejection: RejectionReason | None,
) -> None:
    """CALLER-08, CALLER-09, CALLER-10, CALLER-11, CALLER-12, CALLER-13, CALLER-14, CALLER-15,
    CALLER-16, CALLER-17, CALLER-18, CALLER-19, CALLER-25: each fault of a table row, in either
    token where the row names both, is refused with the row's reason and class; a verifier
    refusal other than an unavailable key set keeps its rejection."""
    check = a_check_whose_key_set_went_down(a_registry_of(admission))

    outcome = check.person_caller(*tokens_with(fault))

    assert outcome == CallerRefusal(reason, rejection)
    assert isinstance(outcome, CallerRefusal)
    assert outcome.refusal_class is refusal_class


@SIDES
@pytest.mark.parametrize(
    ("changes", "rejection"),
    [
        pytest.param(
            {"exp": ACCESS_TOKEN_NOW + ACCESS_TOKEN_LIFETIME_SECONDS + 1}, None, id="plus-one"
        ),
        pytest.param({"exp": ACCESS_TOKEN_NOW + 24 * 60 * 60}, None, id="one-day"),
        pytest.param(EXPIRED_TOKEN, RejectionReason.EXPIRED, id="expired"),
    ],
)
def test_a_token_is_bounded_by_its_exp_against_the_clock_and_by_nothing_else(
    side: str, changes: dict[str, object], rejection: RejectionReason | None
) -> None:
    """CALLER-20: a token of either kind lives as long as its `exp` says, however far past the
    issuer's own lifespan, and is refused once `exp` has passed the clock."""
    outcome = a_check().person_caller(*tokens_with(Fault(side, changes)))

    if rejection is None:
        assert isinstance(outcome, PersonCaller)
    else:
        assert outcome == CallerRefusal(CallerRefusalReason.TOKEN_REJECTED, rejection)


@SIDES
@pytest.mark.parametrize(
    ("audience", "rejection"),
    [
        pytest.param([CALLEE, "other-service"], None, id="callee-beside-another"),
        pytest.param("other-service", RejectionReason.INVALID_AUDIENCE, id="callee-absent"),
    ],
)
def test_the_audience_of_a_token_must_name_the_service_and_may_name_others(
    side: str, audience: object, rejection: RejectionReason | None
) -> None:
    """CALLER-28, CALLER-29: a token of either kind whose `aud` names the service beside others is
    admitted, and one that does not name the service is rejected."""
    outcome = a_check().person_caller(*tokens_with(Fault(side, {"aud": audience})))

    if rejection is None:
        assert isinstance(outcome, PersonCaller)
    else:
        assert outcome == CallerRefusal(CallerRefusalReason.TOKEN_REJECTED, rejection)


@pytest.mark.parametrize(
    ("side", "groups_of_the_caller"),
    [
        pytest.param("workload", frozenset({"/apps/notes"}), id="workload"),
        pytest.param("person", frozenset(), id="person"),
    ],
)
def test_a_null_group_claim_is_malformed_and_only_an_absent_one_means_no_groups(
    side: str, groups_of_the_caller: frozenset[str]
) -> None:
    """CALLER-26, CALLER-27: a JSON `null` group claim in either token is `MALFORMED_GROUPS`, and
    an absent claim is accepted as no groups."""
    admission = replace(an_app_admission(), login_group=EverySubject.OF_THE_BOUND_ISSUER)
    check = a_check(registered_apps=a_registry_of(admission))

    null_claim = check.person_caller(*tokens_with(Fault(side, {"groups": None})))
    absent_claim = check.person_caller(*tokens_with(Fault(side, {"groups": ABSENT})))

    assert null_claim == CallerRefusal(CallerRefusalReason.MALFORMED_GROUPS, None)
    assert isinstance(absent_claim, PersonCaller)
    assert absent_claim.groups == groups_of_the_caller


@pytest.mark.parametrize(
    ("make_check", "faults"),
    [
        pytest.param(
            lambda: a_check(fetch_key_set=FakeKeySetEndpoint(KeySetFetchError("down"))),
            [],
            id="nothing-cached",
        ),
        pytest.param(
            a_check_whose_key_set_went_down,
            [on_workload(WholeToken.KEY_SET_DOWN)],
            id="other-keys-cached-workload",
        ),
        pytest.param(
            a_check_whose_key_set_went_down,
            [on_person(WholeToken.KEY_SET_DOWN)],
            id="other-keys-cached-person",
        ),
    ],
)
def test_a_key_set_that_cannot_be_fetched_is_unavailable_for_a_key_that_is_not_cached(
    make_check: Callable[[], ServiceCallerCheck], faults: list[Fault]
) -> None:
    """CALLER-23: when the key set cannot be fetched and a token's key is not among the cached
    ones, with nothing cached or with other keys cached, the refusal is `KEY_SET_UNAVAILABLE`."""
    outcome = make_check().person_caller(*tokens_with(*faults))

    assert outcome == CallerRefusal(CallerRefusalReason.KEY_SET_UNAVAILABLE, None)


@SIDES
@pytest.mark.parametrize(
    "bad_token",
    [WholeToken.MALFORMED, WholeToken.UNSUPPORTED_ALGORITHM],
    ids=["malformed-header", "unsupported-algorithm"],
)
def test_a_malformed_header_or_unsupported_algorithm_is_rejected_before_any_key_lookup(
    side: str, bad_token: WholeToken
) -> None:
    """CALLER-22: a token of either kind with a malformed header or an unsupported algorithm
    is `TOKEN_REJECTED` and not `KEY_SET_UNAVAILABLE`, though its key is not cached and the key
    set cannot be fetched."""
    outcome = a_check_whose_key_set_went_down().person_caller(*tokens_with(Fault(side, bad_token)))

    assert isinstance(outcome, CallerRefusal)
    assert outcome.reason is CallerRefusalReason.TOKEN_REJECTED
