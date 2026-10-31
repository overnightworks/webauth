"""A service that admits an app acting as itself, typed against the public surface.

CI checks this file with a pinned pyright against the built wheel, so a change
to the service caller check or an export a service cannot import fails the
build instead of the service's next upgrade.
"""

from __future__ import annotations

from webauth.jwt_verification import KeySetFetch, MonotonicClock
from webauth.oidc_login import AdmissionConfig, AppRole, EverySubject, NoAdmins
from webauth.ports import WallClock
from webauth.service_callers import (
    CallerRefusal,
    CallerRefusalClass,
    PersonCaller,
    Principal,
    RegisteredApp,
    ServiceCallerCheck,
    ServiceIdentity,
    WorkloadCaller,
)


def a_service_builds_its_check(
    fetch_key_set: KeySetFetch, wall_clock: WallClock, monotonic_clock: MonotonicClock,
) -> ServiceCallerCheck:
    identity = ServiceIdentity(
        issuer="https://login.example.org/realms/workshop",
        audience="speech-runtime",
        jwks_url="https://login.example.org/realms/workshop/protocol/openid-connect/certs",
        workload_role="workload",
        group_claim="groups",
        leeway_seconds=30,
    )
    admission = AdmissionConfig(
        bound_issuer=identity.issuer,
        login_group=EverySubject.OF_THE_BOUND_ISSUER,
        admin_group=NoAdmins.IN_THIS_APP,
    )
    return ServiceCallerCheck(
        identity,
        registered_apps={"notes-workload": RegisteredApp(app="notes", admission=admission)},
        fetch_key_set=fetch_key_set,
        wall_clock=wall_clock,
        monotonic_clock=monotonic_clock,
    )


_WIRE_CODES = {
    CallerRefusalClass.UNAUTHENTICATED: 401,
    CallerRefusalClass.UNAVAILABLE: 503,
    CallerRefusalClass.FORBIDDEN: 403,
}


def a_service_maps_the_outcome_to_a_wire_code(check: ServiceCallerCheck, token: str | None) -> int:
    outcome = check.workload_caller(token)
    if isinstance(outcome, WorkloadCaller):
        principal: Principal = outcome.principal
        return len(outcome.groups) + len(principal.issuer)
    refusal: CallerRefusal = outcome
    return _WIRE_CODES[refusal.refusal_class]


def a_service_maps_a_person_outcome_to_a_wire_code(
    check: ServiceCallerCheck, workload_token: str | None, person_token: str | None
) -> int:
    outcome = check.person_caller(workload_token, person_token)
    if isinstance(outcome, PersonCaller):
        role: AppRole = outcome.role
        principal: Principal = outcome.principal
        return len(outcome.groups) + len(principal.subject) + len(role.value)
    refusal: CallerRefusal = outcome
    return _WIRE_CODES[refusal.refusal_class]
