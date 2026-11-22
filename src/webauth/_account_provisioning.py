"""Finding, creating, re-roling and re-kinding the account a sign-in or a bearer token names.

The sign-in callback and the bearer gate's person and resource paths admit an account through
these steps, so the middleware needs no sign-in module. The bearer gate's person paths admit the
holder of a verified access token with the same ``app_role`` and ``admit_account`` in one
``SignInTransaction`` entry: the account is created on its first token, its role follows the
token's groups, and no session is created. Nothing is committed, and the answer is built
inside the block.
"""

from __future__ import annotations

from typing import TYPE_CHECKING, Protocol

from webauth import admission as _admission
from webauth.ports import (
    AccountEvent,
    AccountEventKind,
    AccountKind,
    AuthenticatedUser,
    UsernameTakenError,
)

if TYPE_CHECKING:
    from webauth.admission import AdmissionConfig, AdmissionRefusal, GroupPath
    from webauth.oidc import VerifiedAccessToken
    from webauth.ports import (
        AuditSink,
        SignInTransaction,
        SubjectUserStore,
        UserRecord,
    )

__all__ = []


class UsernameTakenSignal(Exception):  # noqa: N818  # a signal inside the transaction, not an error
    """The store refused a new account's username. It leaves the transaction block as an
    exception, so the host's exit rolls back as it does for any failure, and the callback
    route answers it as ``AdmissionRefusal.USERNAME_TAKEN`` once the exit returned."""


class _Claimant(Protocol):
    """Whom the issuer vouched for: the ID token's identity or a verified access token."""

    @property
    def subject(self) -> str: ...

    @property
    def preferred_username(self) -> str | None: ...


def admit_token_holder(
    transaction: SignInTransaction,
    verified: VerifiedAccessToken,
    *,
    admission: AdmissionConfig,
) -> AuthenticatedUser | AdmissionRefusal:
    """The account behind a verified access token, admitted as a sign-in admits it.

    A non-member is refused before any store is touched. A member enters one
    ``SignInTransaction`` entry in which ``admit_account`` creates the account on
    its first token and follows the token's groups for the role; the answer is built
    inside the block, from the record the store returned. No session is created.
    Never commits. Runs on one worker thread, like every entry. A store, audit or
    exit failure propagates; a refused new username answers ``USERNAME_TAKEN`` once
    the exit returned.
    """
    derived = _admission.app_role(verified.groups, admission)
    if derived is None:
        return _admission.AdmissionRefusal.NOT_A_MEMBER
    role = derived.value
    try:
        with transaction() as stores:
            account = admit_account(verified, role, accounts=stores.accounts, audit=stores.audit)
            return AuthenticatedUser(
                id=account.id, username=account.username, role=account.role, agent=None
            )
    except UsernameTakenSignal:
        return _admission.AdmissionRefusal.USERNAME_TAKEN


def admit_resource_holder(
    transaction: SignInTransaction,
    verified: VerifiedAccessToken,
    *,
    required_group: GroupPath,
    admission: AdmissionConfig,
) -> AuthenticatedUser | AdmissionRefusal | None:
    """The account behind a token presented to a protected resource, always with the role
    "user", or ``None``.

    The token's groups must pass ``app_role`` against ``admission`` and hold
    ``required_group`` or a path below it; otherwise no store is touched. One
    ``SignInTransaction`` entry then reads ``accounts.get``. A token without the agent group
    (``verified.agent`` is ``None``) only reads: an unknown subject answers ``None``, and
    nothing is provisioned, re-roled or audited; the account's stored kind is not read, so
    the answer is a person even for a stored agent. A token with the agent group
    registers its account: an unknown subject gets one of the kind ``AGENT`` with the username
    of ``_username_for`` and ``USER_CREATED``, a stored ``PERSON`` is set to ``AGENT`` with
    ``KIND_CHANGED``, a stored ``AGENT`` is only read; the answer carries the agent's facts. The
    role is ``"user"``, never the account's, so an admin's agent token carries no admin right. The
    answer is built inside the block. Never commits; a store, audit or exit failure propagates;
    a refused new username answers ``USERNAME_TAKEN`` once the exit returned.
    """
    if _admission.app_role(verified.groups, admission) is None:
        return None
    if not _admission._is_member_of(required_group, verified.groups):
        return None
    try:
        with transaction() as stores:
            account = stores.accounts.get(verified.subject)
            if verified.agent is not None:
                account = _registered_agent(
                    verified, account, accounts=stores.accounts, audit=stores.audit
                )
            if account is None:
                return None
            return AuthenticatedUser(
                id=account.id,
                username=account.username,
                role=_admission.AppRole.USER.value,
                agent=verified.agent,
            )
    except UsernameTakenSignal:
        return _admission.AdmissionRefusal.USERNAME_TAKEN


def _registered_agent(
    verified: VerifiedAccessToken,
    account: UserRecord | None,
    *,
    accounts: SubjectUserStore,
    audit: AuditSink,
) -> UserRecord:
    """The account of an agent-group token: created, or set to the agent kind, on its admission."""
    if account is None:
        return _provision(
            verified,
            _admission.AppRole.USER.value,
            AccountKind.AGENT,
            accounts=accounts,
            audit=audit,
        )
    previous_kind = account.kind
    if previous_kind is AccountKind.AGENT:
        return account
    updated = accounts.set_kind(account.id, AccountKind.AGENT)
    audit.account_event(
        AccountEvent(
            kind=AccountEventKind.KIND_CHANGED,
            actor_id=None,
            subject_id=updated.id,
            account_kind=AccountKind.AGENT,
            previous_account_kind=previous_kind,
        )
    )
    return updated


def admit_account(
    claimant: _Claimant,
    role: str,
    *,
    accounts: SubjectUserStore,
    audit: AuditSink,
) -> UserRecord:
    """The account ``claimant`` signs in as, created on its first visit.

    A new subject gets an account with the issuer's ``preferred_username``, or
    the subject when it suggests none or only whitespace, and ``USER_CREATED``
    is recorded with no actor. A known subject keeps its account and username, whatever username the
    issuer now suggests, but its role follows the groups: a role that differs is written with
    ``SubjectUserStore.set_role`` and recorded as ``ROLE_CHANGED``; an equal role writes nothing.
    ``SubjectUserStore.get`` must compare exactly. A host that migrates legacy
    accounts makes sure that no legacy ``id`` can equal a subject of the bound
    issuer.

    ``UsernameTakenSignal`` is raised when the store refuses a new account's username. No
    username is looked up, so a store without a unique username admits a
    second subject whose ``preferred_username`` another account holds; disabling
    a person is done at the issuer. No local flag locks an account.

    Only the derived role is stored, never the groups. A host that migrates from
    a store with its own admins puts them into the admin group first, or they are
    demoted at their next login.
    """
    account = accounts.get(claimant.subject)
    if account is None:
        return _provision(claimant, role, AccountKind.PERSON, accounts=accounts, audit=audit)
    return _with_role(account, role, accounts=accounts, audit=audit)


def _with_role(
    account: UserRecord,
    role: str,
    *,
    accounts: SubjectUserStore,
    audit: AuditSink,
) -> UserRecord:
    previous_role = account.role
    if previous_role == role:
        return account
    updated = accounts.set_role(account.id, role)
    audit.account_event(
        AccountEvent(
            kind=AccountEventKind.ROLE_CHANGED,
            actor_id=None,
            subject_id=updated.id,
            role=role,
            previous_role=previous_role,
        )
    )
    return updated


def _provision(
    claimant: _Claimant,
    role: str,
    kind: AccountKind,
    *,
    accounts: SubjectUserStore,
    audit: AuditSink,
) -> UserRecord:
    username = _username_for(claimant)
    try:
        account = accounts.create_for_subject(claimant.subject, username, role, kind)
    except UsernameTakenError as refused:
        raise UsernameTakenSignal from refused
    audit.account_event(
        AccountEvent(
            kind=AccountEventKind.USER_CREATED,
            actor_id=None,
            subject_id=account.id,
            role=account.role,
        )
    )
    return account


def _username_for(claimant: _Claimant) -> str:
    """The issuer's suggested username, or the subject when it suggests a blank one."""
    suggested = claimant.preferred_username
    return suggested if suggested and not suggested.isspace() else claimant.subject
