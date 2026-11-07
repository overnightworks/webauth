"""The order in which `ServiceCallerCheck.person_caller` checks a workload token and a person's.

Every case puts two faults on the pair and expects the refusal of the fault the order checks first.
"""

from __future__ import annotations

from dataclasses import fields
from itertools import combinations

import pytest

from tests.support.oidc_arrangement import ABSENT
from tests.support.service_caller_arrangement import (
    SUBJECT_CANARY,
    UNREGISTERED,
    Fault,
    WholeToken,
    a_check_whose_key_set_went_down,
    on_person,
    on_workload,
    refused,
    tokens_with,
)
from webauth.service_callers import CallerRefusal, CallerRefusalReason

# (stage, fault, the reason it is refused with) in the order `person_caller` checks them
CHECKS_IN_ORDER = [
    (0, on_workload(WholeToken.MISSING), CallerRefusalReason.MISSING_TOKEN),
    (1, on_workload({"aud": "someone-else"}), CallerRefusalReason.TOKEN_REJECTED),
    (1, on_workload(WholeToken.KEY_SET_DOWN), CallerRefusalReason.KEY_SET_UNAVAILABLE),
    (2, on_person(WholeToken.MISSING), CallerRefusalReason.MISSING_TOKEN),
    (3, on_person({"aud": "someone-else"}), CallerRefusalReason.TOKEN_REJECTED),
    (3, on_person(WholeToken.KEY_SET_DOWN), CallerRefusalReason.KEY_SET_UNAVAILABLE),
    (4, on_workload({"sub": ABSENT}), CallerRefusalReason.INVALID_SUBJECT),
    (5, on_workload({"groups": None}), CallerRefusalReason.MALFORMED_GROUPS),
    (6, on_person({"sub": ABSENT}), CallerRefusalReason.INVALID_SUBJECT),
    (7, on_person({"groups": None}), CallerRefusalReason.MALFORMED_GROUPS),
    (8, on_workload({"realm_access": {"roles": []}}), CallerRefusalReason.NOT_A_WORKLOAD),
    (9, on_workload({"azp": ABSENT}), CallerRefusalReason.UNBOUND_CLIENT),
    (
        10,
        on_workload({"azp": UNREGISTERED, "client_id": UNREGISTERED}),
        CallerRefusalReason.UNREGISTERED_CLIENT,
    ),
    (11, on_person({"azp": "another-client"}), CallerRefusalReason.CLIENT_MISMATCH),
    (12, on_person({"sub": SUBJECT_CANARY}), CallerRefusalReason.SAME_SUBJECT),
    (13, on_person({"groups": ["/x"]}), CallerRefusalReason.NOT_A_MEMBER),
]


def two_faults_at_once() -> list[pytest.ParameterSet]:
    cases = []
    for (first_stage, first, first_reason), (later_stage, later, later_reason) in combinations(
        CHECKS_IN_ORDER, 2
    ):
        if first_stage < later_stage and not first.conflicts_with(later):
            case_id = f"{first_reason}-{first.side}-before-{later_reason}-{later.side}"
            cases.append(pytest.param(first, later, first_reason, id=case_id))
    return cases


def an_unbound_client_with_an_unregistered_azp() -> pytest.ParameterSet:
    """Both faults sit on the workload token without sharing a claim: the `client_id` differs from
    the `azp`, and the `azp` is not registered."""
    return pytest.param(
        on_workload({"client_id": "another-client"}),
        on_workload({"azp": UNREGISTERED}),
        CallerRefusalReason.UNBOUND_CLIENT,
        id="unbound-client-before-unregistered-client-on-one-token",
    )


@pytest.mark.parametrize(
    ("first", "later", "reason"),
    [*two_faults_at_once(), an_unbound_client_with_an_unregistered_azp()],
)
def test_the_fault_checked_first_is_the_refusal_when_two_faults_come_at_once(
    first: Fault, later: Fault, reason: CallerRefusalReason
) -> None:
    """CALLER-06, CALLER-07: two faults at once are refused with the one the documented order
    checks first, and every `UNAUTHENTICATED` and `UNAVAILABLE` one comes before any `FORBIDDEN`
    one."""
    check = a_check_whose_key_set_went_down()

    outcome = check.person_caller(*tokens_with(later, first))

    assert refused(outcome).reason is reason


@pytest.mark.parametrize(
    "changes",
    [
        pytest.param(WholeToken.MISSING, id="missing"),
        pytest.param({"aud": "someone-else"}, id="audience"),
        pytest.param(WholeToken.FORGED, id="forged"),
        pytest.param(WholeToken.KEY_SET_DOWN, id="key-set-down"),
        pytest.param({"sub": ABSENT}, id="subject"),
        pytest.param({"groups": None}, id="groups"),
    ],
)
def test_a_refusal_is_the_same_whichever_token_is_at_fault(
    changes: dict[str, object] | WholeToken,
) -> None:
    """CALLER-05: the refusal of a fault in the workload token equals the refusal of the same
    fault in the person token, and it holds nothing but a reason and a token rejection."""
    check = a_check_whose_key_set_went_down()

    in_workload = check.person_caller(*tokens_with(on_workload(changes)))
    in_person = check.person_caller(*tokens_with(on_person(changes)))

    assert isinstance(in_workload, CallerRefusal)
    assert in_workload == in_person
    assert {each.name for each in fields(CallerRefusal)} == {"reason", "token_rejection"}
