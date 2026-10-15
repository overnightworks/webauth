"""Admitting a person an OpenID Connect issuer vouched for as an account.

The host's store is bound to one issuer — the ``issuer`` of its
``OidcClientConfig`` — and an account it provisions has the issuer's subject
as its ``id``. Moving to another issuer is therefore a migration of the
host's accounts, never a configuration change. The identity comes from
``webauth.oidc``, so a host using this module installs the ``jwt`` extra.

Admission holds the host's write lock and never commits: the host commits or
rolls back, and a refusal writes nothing.
"""

from __future__ import annotations

from enum import StrEnum
from typing import TYPE_CHECKING

from webauth.ports import UserManagementEvent, UserManagementEventKind

if TYPE_CHECKING:
    from webauth.config import WebAuthConfig
    from webauth.oidc import OidcIdentity
    from webauth.ports import AuditSink, SubjectUserStore, UserRecord, WriteLock


class AdmissionRefusal(StrEnum):
    """Why a verified identity does not become a signed-in account."""

    FOREIGN_ISSUER = "foreign-issuer"
    ACCOUNT_DEACTIVATED = "account-deactivated"
    SUBJECT_HELD_BY_PASSWORD_ACCOUNT = "subject-held-by-password-account"
    USERNAME_TAKEN = "username-taken"


def admit_identity(
    identity: OidcIdentity,
    *,
    bound_issuer: str,
    accounts: SubjectUserStore,
    lock: WriteLock,
    audit: AuditSink,
    config: WebAuthConfig,
) -> UserRecord | AdmissionRefusal:
    """The account ``identity`` signs in as, created on its first visit.

    A known subject keeps its account as it is, whatever username the issuer
    now suggests. A subject that names a password account is refused rather
    than linked: linking is each host's migration to decide.
    """
    if identity.issuer != bound_issuer:
        return AdmissionRefusal.FOREIGN_ISSUER
    with lock.hold():
        account = accounts.get(identity.subject)
        if account is None:
            return _provision(identity, accounts=accounts, audit=audit, config=config)
        if account.password_hash is not None:
            return AdmissionRefusal.SUBJECT_HELD_BY_PASSWORD_ACCOUNT
        if not account.is_active:
            return AdmissionRefusal.ACCOUNT_DEACTIVATED
        return account


def _provision(
    identity: OidcIdentity,
    *,
    accounts: SubjectUserStore,
    audit: AuditSink,
    config: WebAuthConfig,
) -> UserRecord | AdmissionRefusal:
    username = identity.preferred_username or identity.subject
    if accounts.get_by_username(username) is not None:
        return AdmissionRefusal.USERNAME_TAKEN
    account = accounts.create_for_subject(identity.subject, username, config.user_role)
    audit.user_management_event(UserManagementEvent(
        kind=UserManagementEventKind.USER_CREATED,
        actor_id=None,
        subject_id=account.id,
        role=account.role,
    ))
    return account
