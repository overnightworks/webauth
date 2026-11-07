"""The builders the service caller proofs share: the tokens of a workload and of a person, a check
over one registered app, and faults to put on either token."""

from __future__ import annotations

from collections.abc import Callable, Mapping
from dataclasses import dataclass
from enum import Enum, auto
from typing import Any

import pytest

from tests.support.oidc_arrangement import (
    ACCESS_TOKEN_LEEWAY_SECONDS,
    ACCESS_TOKEN_NOW,
    REALM_ISSUER,
    REALM_JWKS_URL,
    FakeClock,
    FakeKeySetEndpoint,
    an_access_token,
    served_key_set,
)
from webauth.admission import AdmissionConfig, NoAdmins
from webauth.https_client import KeySetFetchError
from webauth.service_callers import (
    CallerRefusal,
    CallerRefusalReason,
    RegisteredApp,
    ServiceCallerCheck,
    ServiceIdentity,
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
        fetch_key_set=fetch_key_set or FakeKeySetEndpoint(served_key_set()),
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


class WholeToken(Enum):
    """A fault that replaces a token instead of changing a claim of it."""

    MISSING = auto()
    EMPTY = auto()
    KEY_SET_DOWN = auto()
    FORGED = auto()
    MALFORMED = auto()
    UNSUPPORTED_ALGORITHM = auto()


@dataclass(frozen=True)
class Fault:
    """A fault on the token of `side`: changed claims, or a whole replacement token."""

    side: str
    changes: Mapping[str, object] | WholeToken

    def conflicts_with(self, other: Fault) -> bool:
        """Two faults on one token cannot both show when one replaces it or both set a claim."""
        if self.side != other.side:
            return False
        if isinstance(self.changes, WholeToken) or isinstance(other.changes, WholeToken):
            return True
        return bool(self.changes.keys() & other.changes.keys())


def on_workload(changes: Mapping[str, object] | WholeToken) -> Fault:
    return Fault("workload", changes)


def on_person(changes: Mapping[str, object] | WholeToken) -> Fault:
    return Fault("person", changes)


def a_replacement_token(kind: WholeToken) -> str | None:
    """The token a `WholeToken` fault puts in place of a valid one."""
    return {
        WholeToken.MISSING: None,
        WholeToken.EMPTY: "",
        WholeToken.KEY_SET_DOWN: an_access_token(
            key_id="rotated-key", claims={"aud": CALLEE, "azp": WORKLOAD_CLIENT}
        ),
        WholeToken.FORGED: an_access_token(key_name="foreign", claims={"aud": CALLEE}),
        WholeToken.MALFORMED: "not-a-token",
        WholeToken.UNSUPPORTED_ALGORITHM: an_access_token(
            key_id="rotated-key", header={"alg": "HS256"}
        ),
    }[kind]


def tokens_with(*faults: Fault) -> tuple[str | None, str | None]:
    """The workload token and the person token, valid but for the faults given."""
    tokens: list[str | None] = []
    for side, make in (("workload", a_workload_token), ("person", a_person_token)):
        own = [fault.changes for fault in faults if fault.side == side]
        whole = next((change for change in own if isinstance(change, WholeToken)), None)
        if whole is not None:
            tokens.append(a_replacement_token(whole))
            continue
        merged: dict[str, object] = {}
        for change in own:
            assert isinstance(change, Mapping)
            merged.update(change)
        tokens.append(make(**merged))
    return tokens[0], tokens[1]


def a_check_whose_key_set_went_down(
    registered_apps: Any = None, endpoint: FakeKeySetEndpoint | None = None
) -> ServiceCallerCheck:
    """A check that cached the default key, then lost its key set after the refresh cooldown;
    `endpoint` is the fake it fetches from, and has no fetch recorded when the check is returned."""
    endpoint = endpoint or FakeKeySetEndpoint(served_key_set())
    monotonic = FakeClock(5_000.0)
    check = a_check(
        registered_apps=registered_apps, fetch_key_set=endpoint, monotonic_clock=monotonic
    )
    warmed = check.person_caller(a_workload_token(), a_person_token())
    assert not (
        isinstance(warmed, CallerRefusal)
        and warmed.reason is CallerRefusalReason.KEY_SET_UNAVAILABLE
    )
    endpoint.response = KeySetFetchError("down")
    endpoint.fetched_urls.clear()
    monotonic.now += 60
    return check
