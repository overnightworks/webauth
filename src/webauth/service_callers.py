"""The proof a service runs on the token an app presents as itself.

A service builds one `ServiceCallerCheck` per process from the facts it owns
(`ServiceIdentity`) and the apps it registered, and calls `workload_caller` with
the bearer token of each request. The first fault, in the order of
`CallerRefusalReason`, is the refusal; the host maps it to a wire code: the
class of each reason is 503 (`KEY_SET_UNAVAILABLE`), 401 (`MISSING_TOKEN`,
`TOKEN_REJECTED`, `INVALID_SUBJECT`, `MALFORMED_GROUPS`) or 403 (the rest). Policy
stays with the service: its groups, routing and wire codes.

Nothing taken from a token (subject, client id, groups, any claim) appears in a
repr, an error message or a log record of this module, which logs nothing.
"""

from __future__ import annotations

from collections.abc import Mapping
from dataclasses import dataclass, field
from enum import StrEnum
from types import MappingProxyType

from webauth._validation import (
    is_utf8,
    require_non_empty_string,
    require_non_negative_whole_number,
    require_positive_whole_number,
)
from webauth.jwt_verification import (
    JwtVerifier,
    KeySetFetch,
    MonotonicClock,
    Rejected,
    RejectionReason,
)
from webauth.oidc_login import AdmissionConfig
from webauth.ports import WallClock

__all__ = [
    "CallerRefusal",
    "CallerRefusalReason",
    "Principal",
    "RegisteredApp",
    "ServiceCallerCheck",
    "ServiceIdentity",
    "WorkloadCaller",
]


@dataclass(frozen=True, kw_only=True)
class ServiceIdentity:
    """The deployment facts of one service: the issuer and its key-set URL, the
    audience that names the service, the realm role that marks a workload, the
    claim that holds groups, the longest workload token life and the clock leeway.

    ``jwks_url`` is left out of the repr: its path or query can carry a secret."""

    issuer: str
    audience: str
    jwks_url: str = field(repr=False)
    workload_role: str
    group_claim: str
    max_workload_seconds: int
    leeway_seconds: int

    def __post_init__(self) -> None:
        require_non_empty_string("issuer", self.issuer)
        require_non_empty_string("audience", self.audience)
        require_non_empty_string("workload_role", self.workload_role)
        require_non_empty_string("group_claim", self.group_claim)
        require_positive_whole_number(
            "max_workload_seconds", self.max_workload_seconds, unit="seconds"
        )
        require_non_negative_whole_number("leeway_seconds", self.leeway_seconds, unit="seconds")


@dataclass(frozen=True)
class RegisteredApp:
    """An app a service knows by name, with the admission its realm group grants."""

    app: str
    admission: AdmissionConfig

    def __post_init__(self) -> None:
        require_non_empty_string("app", self.app)


@dataclass(frozen=True)
class Principal:
    """The verified identity: the issuer and subject of a token. Its repr shows neither."""

    issuer: str = field(repr=False)
    subject: str = field(repr=False)


@dataclass(frozen=True)
class WorkloadCaller:
    """An app acting as itself. Its repr shows ``app`` only."""

    app: str
    client_id: str = field(repr=False)
    principal: Principal = field(repr=False)
    groups: frozenset[str] = field(repr=False)


class CallerRefusalReason(StrEnum):
    """The refusals, in the order they are checked."""

    MISSING_TOKEN = "missing-token"  # noqa: S105 - refusal reason not a credential
    KEY_SET_UNAVAILABLE = "key-set-unavailable"
    TOKEN_REJECTED = "token-rejected"  # noqa: S105 - refusal reason not a credential
    INVALID_SUBJECT = "invalid-subject"
    MALFORMED_GROUPS = "malformed-groups"
    NOT_A_WORKLOAD = "not-a-workload"
    UNBOUND_CLIENT = "unbound-client"
    UNREGISTERED_CLIENT = "unregistered-client"
    WORKLOAD_LIVES_TOO_LONG = "workload-lives-too-long"


@dataclass(frozen=True)
class CallerRefusal:
    """Why a caller was refused; ``token_rejection`` is the verifier's reason
    exactly when ``reason`` is ``TOKEN_REJECTED``."""

    reason: CallerRefusalReason
    token_rejection: RejectionReason | None

    def __post_init__(self) -> None:
        if (self.reason is CallerRefusalReason.TOKEN_REJECTED) != (
            self.token_rejection is not None
        ):
            raise ValueError("token_rejection is set exactly when the reason is TOKEN_REJECTED")


class ServiceCallerCheck:
    """Verifies the workload token of a caller for one service; one per process.

    ``registered_apps`` is keyed by workload client id and is copied. The one
    verifier accepts a token whose ``aud`` names the service among others."""

    def __init__(
        self,
        identity: ServiceIdentity,
        *,
        registered_apps: Mapping[str, RegisteredApp],
        fetch_key_set: KeySetFetch,
        wall_clock: WallClock,
        monotonic_clock: MonotonicClock,
    ) -> None:
        _require_registry(registered_apps, identity.issuer)
        self._identity = identity
        self._registered_apps: Mapping[str, RegisteredApp] = MappingProxyType(dict(registered_apps))
        self._verifier = JwtVerifier(
            issuer=identity.issuer,
            audiences=(identity.audience,),
            jwks_url=identity.jwks_url,
            leeway_seconds=identity.leeway_seconds,
            fetch_key_set=fetch_key_set,
            wall_clock=wall_clock,
            monotonic_clock=monotonic_clock,
        )

    def workload_caller(self, token: str | None) -> WorkloadCaller | CallerRefusal:
        """The app that presented ``token`` as itself, or the first refusal."""
        if not token:
            return CallerRefusal(CallerRefusalReason.MISSING_TOKEN, None)
        verified = self._verifier.verify(token)
        if isinstance(verified, Rejected):
            return _verifier_refusal(verified.reason)
        subject = verified.subject
        if subject is None or not is_utf8(subject):
            return CallerRefusal(CallerRefusalReason.INVALID_SUBJECT, None)
        claims = verified.claims
        groups = _groups(claims, self._identity.group_claim)
        if groups is None:
            return CallerRefusal(CallerRefusalReason.MALFORMED_GROUPS, None)
        if not _has_role(claims, self._identity.workload_role):
            return CallerRefusal(CallerRefusalReason.NOT_A_WORKLOAD, None)
        client_id = _bound_client_id(claims)
        if client_id is None:
            return CallerRefusal(CallerRefusalReason.UNBOUND_CLIENT, None)
        registered = self._registered_apps.get(client_id)
        if registered is None:
            return CallerRefusal(CallerRefusalReason.UNREGISTERED_CLIENT, None)
        if verified.expires_at - verified.issued_at > self._identity.max_workload_seconds:
            return CallerRefusal(CallerRefusalReason.WORKLOAD_LIVES_TOO_LONG, None)
        return WorkloadCaller(
            app=registered.app,
            client_id=client_id,
            principal=Principal(issuer=verified.issuer, subject=subject),
            groups=groups,
        )


def _require_registry(registered_apps: object, issuer: str) -> None:
    if not isinstance(registered_apps, Mapping) or not registered_apps:
        raise ValueError("registered_apps must be a non-empty mapping")
    for client_id, registered in registered_apps.items():
        require_non_empty_string("registered_apps key", client_id)
        if not isinstance(registered, RegisteredApp):
            raise ValueError("registered_apps values must be RegisteredApp")
        if registered.admission.bound_issuer != issuer:
            raise ValueError(
                "a registered app's admission bound_issuer must be the identity's issuer"
            )


def _verifier_refusal(reason: RejectionReason) -> CallerRefusal:
    if reason is RejectionReason.KEY_SET_UNAVAILABLE:
        return CallerRefusal(CallerRefusalReason.KEY_SET_UNAVAILABLE, None)
    return CallerRefusal(CallerRefusalReason.TOKEN_REJECTED, reason)


def _groups(claims: Mapping[str, object], group_claim: str) -> frozenset[str] | None:
    if group_claim not in claims:
        return frozenset()
    claim = claims[group_claim]
    if isinstance(claim, list) and all(isinstance(group, str) for group in claim):
        return frozenset(claim)
    return None


def _has_role(claims: Mapping[str, object], role: str) -> bool:
    realm_access = claims.get("realm_access")
    if not isinstance(realm_access, dict):
        return False
    roles = realm_access.get("roles")
    return isinstance(roles, list) and role in roles


def _bound_client_id(claims: Mapping[str, object]) -> str | None:
    authorized_party = claims.get("azp")
    client_id = claims.get("client_id")
    if isinstance(authorized_party, str) and authorized_party and client_id == authorized_party:
        return authorized_party
    return None
