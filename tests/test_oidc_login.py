"""An identity the bound issuer vouched for becomes, or reuses, an account."""

from __future__ import annotations

from copy import deepcopy
from dataclasses import asdict, dataclass, replace

import pytest
from webauth_arrangement import (
    MEMBER_ROLE,
    FakeUser,
    PasswordlessUser,
    RecordingAuditSink,
    StoredUser,
    UsersInMemory,
    WriteLockInMemory,
    a_web_auth_config,
)

from webauth.oidc import OidcIdentity
from webauth.oidc_login import AdmissionRefusal, admit_identity
from webauth.ports import SubjectUserStore, UserManagementEventKind, UserRecord

BOUND_ISSUER = "https://id.example/realms/lab"
SUBJECT = "5f0c2a1e-7d4b-4c55-9a51-2f8e3c6b1d90"
LENA = OidcIdentity(
    subject=SUBJECT,
    issuer=BOUND_ISSUER,
    groups=(),
    session_id=None,
    preferred_username="lena",
)


@dataclass
class Host:
    accounts: UsersInMemory
    audit: RecordingAuditSink
    lock: WriteLockInMemory

    def admit(self, identity: OidcIdentity) -> UserRecord | AdmissionRefusal:
        return admit_identity(
            identity,
            bound_issuer=BOUND_ISSUER,
            accounts=self.accounts,
            lock=self.lock,
            audit=self.audit,
            config=a_web_auth_config(),
        )


def a_host(*users: StoredUser) -> Host:
    lock = WriteLockInMemory()
    return Host(UsersInMemory(*users, lock=lock), RecordingAuditSink(), lock)


def test_the_in_memory_store_supplies_the_subject_port() -> None:
    assert isinstance(a_host().accounts, SubjectUserStore)


@pytest.mark.parametrize(("preferred_username", "username"), [
    pytest.param("lena", "lena", id="the issuer's suggested username"),
    pytest.param(None, SUBJECT, id="the subject when the issuer suggests none"),
    pytest.param("", SUBJECT, id="the subject when the suggestion is empty"),
])
def test_a_new_subject_creates_a_passwordless_member_account_and_reports_it(
    preferred_username: str | None, username: str,
) -> None:
    host = a_host()

    account = host.admit(replace(LENA, preferred_username=preferred_username))

    assert (account.id, account.username, account.role, account.is_active) == (
        SUBJECT, username, MEMBER_ROLE, True,
    )
    assert account.password_hash is None
    assert host.accounts.list() == [account]
    assert [asdict(event) for event in host.audit.user_management_events] == [{
        "kind": UserManagementEventKind.USER_CREATED,
        "actor_id": None,
        "subject_id": SUBJECT,
        "role": MEMBER_ROLE,
        "session_count": None,
        "session_ref": None,
    }]


def test_a_known_subject_reuses_its_account_unchanged_when_its_username_changed() -> None:
    host = a_host()
    first = host.admit(LENA)
    stored = deepcopy(host.accounts.list())

    again = host.admit(replace(LENA, preferred_username="lena.renamed"))

    assert again is first
    assert host.accounts.list() == stored
    assert len(host.audit.user_management_events) == 1


@pytest.mark.parametrize(("identity", "stored", "refusal"), [
    pytest.param(
        replace(LENA, issuer="https://other.example/realms/lab"), [],
        AdmissionRefusal.FOREIGN_ISSUER,
        id="an identity from another issuer",
    ),
    pytest.param(
        LENA, [PasswordlessUser(id=SUBJECT, is_active=False)],
        AdmissionRefusal.ACCOUNT_DEACTIVATED,
        id="a deactivated account",
    ),
    pytest.param(
        LENA, [FakeUser(id=SUBJECT, username="lena", password_hash="argon2:secret")],
        AdmissionRefusal.SUBJECT_HELD_BY_PASSWORD_ACCOUNT,
        id="a subject that names a password account",
    ),
    pytest.param(
        LENA, [FakeUser(id="user-7", username="lena")],
        AdmissionRefusal.USERNAME_TAKEN,
        id="a new subject whose username another account holds",
    ),
])
def test_a_refused_identity_changes_neither_the_store_nor_the_audit_log(
    identity: OidcIdentity, stored: list[StoredUser], refusal: AdmissionRefusal,
) -> None:
    host = a_host(*deepcopy(stored))

    assert host.admit(identity) is refusal
    assert host.accounts.list() == stored
    assert host.audit.user_management_events == []
