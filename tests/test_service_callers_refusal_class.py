"""The class of each service caller refusal, as `docs/host-contract.md` tables it."""

from __future__ import annotations

import pytest

from webauth.jwt_verification import RejectionReason
from webauth.service_callers import CallerRefusal, CallerRefusalClass, CallerRefusalReason


@pytest.mark.parametrize(
    ("reason", "refusal_class"),
    [
        ("key-set-unavailable", CallerRefusalClass.UNAVAILABLE),
        ("missing-token", CallerRefusalClass.UNAUTHENTICATED),
        ("token-rejected", CallerRefusalClass.UNAUTHENTICATED),
        ("invalid-subject", CallerRefusalClass.UNAUTHENTICATED),
        ("malformed-groups", CallerRefusalClass.UNAUTHENTICATED),
        ("not-a-workload", CallerRefusalClass.FORBIDDEN),
        ("unbound-client", CallerRefusalClass.FORBIDDEN),
        ("unregistered-client", CallerRefusalClass.FORBIDDEN),
        ("workload-lives-too-long", CallerRefusalClass.FORBIDDEN),
        ("client-mismatch", CallerRefusalClass.FORBIDDEN),
        ("same-subject", CallerRefusalClass.FORBIDDEN),
        ("not-a-member", CallerRefusalClass.FORBIDDEN),
    ],
)
def test_a_refusal_names_the_class_the_host_contract_gives_its_reason(
    reason: str, refusal_class: CallerRefusalClass
) -> None:
    reason_member = CallerRefusalReason(reason)
    rejection = RejectionReason.EXPIRED if reason == "token-rejected" else None

    assert CallerRefusal(reason_member, rejection).refusal_class is refusal_class
