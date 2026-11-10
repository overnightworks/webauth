"""Admitting an identity the bound issuer vouched for: groups, roles, accounts.

These tests drive the callback's admission steps on their own: an
identity the bound issuer vouched for is decided, then becomes or reuses an account.
"""

from __future__ import annotations

from copy import deepcopy
from dataclasses import asdict, dataclass, replace

import pytest

from tests.support.account_arrangement import (
    MEMBER_ROLE,
    FakeUser,
    UsersInMemory,
    WriteLockInMemory,
    require_held_lock,
)
from tests.support.oidc_arrangement import a_fake_id_token
from tests.support.oidc_login_host import (
    ADMIN_GROUP,
    ADMISSION,
    BOUND_ISSUER,
    EVERYONE,
    EVERYONE_WITH_ADMIN_GROUP,
    LEGACY_ADMIN,
    LOGIN_GROUP,
    NO_ADMINS,
    SUBJECT,
)
from tests.support.webauth_arrangement import ADMIN_ROLE, RecordingAuditSink
from webauth.admission import (
    AdmissionConfig,
    AdmissionRefusal,
)
from webauth.oidc import (
    OidcIdentity,
)
from webauth.oidc_login import _admit_account, _decide_admission
from webauth.ports import (
    AccountEventKind,
    AccountKind,
    UserRecord,
)

LENA = OidcIdentity(
    subject=SUBJECT,
    issuer=BOUND_ISSUER,
    groups=(LOGIN_GROUP,),
    session_id=None,
    preferred_username="lena",
    id_token=a_fake_id_token("lena"),
    refresh_token=None,
)


LENA_IN_THE_ADMIN_GROUP = replace(LENA, groups=(ADMIN_GROUP,))


@dataclass
class Host:
    accounts: UsersInMemory
    audit: RecordingAuditSink
    lock: WriteLockInMemory

    def admit(
        self,
        identity: OidcIdentity,
        admission: AdmissionConfig = ADMISSION,
    ) -> UserRecord | AdmissionRefusal:
        decided = _decide_admission(identity, admission=admission)
        if isinstance(decided, AdmissionRefusal):
            return decided
        with self.lock.hold():
            return _admit_account(
                decided.identity,
                decided.role,
                accounts=self.accounts,
                audit=self.audit,
            )


def admitted_account(host: Host, identity: OidcIdentity) -> UserRecord:
    account = host.admit(identity)
    assert not isinstance(account, AdmissionRefusal)
    return account


def a_host(*users: FakeUser, store: type[UsersInMemory] = UsersInMemory) -> Host:
    lock = WriteLockInMemory()
    return Host(store(*users, lock=lock), RecordingAuditSink(), lock)


@pytest.mark.parametrize(
    ("preferred_username", "username"),
    [
        pytest.param("lena", "lena", id="the issuer's suggested username"),
        pytest.param(None, SUBJECT, id="the subject when the issuer suggests none"),
        pytest.param("", SUBJECT, id="the subject when the suggestion is empty"),
        pytest.param(" \t ", SUBJECT, id="the subject when the suggestion is only whitespace"),
    ],
)
def test_a_new_subject_creates_a_member_account_and_reports_it(
    preferred_username: str | None,
    username: str,
) -> None:
    host = a_host()

    account = admitted_account(host, replace(LENA, preferred_username=preferred_username))

    assert (account.id, account.username, account.role, account.kind) == (
        SUBJECT,
        username,
        MEMBER_ROLE,
        AccountKind.PERSON,
    )
    assert host.accounts.list() == [account]
    assert [asdict(event) for event in host.audit.account_events] == [
        {
            "kind": AccountEventKind.USER_CREATED,
            "actor_id": None,
            "subject_id": SUBJECT,
            "role": MEMBER_ROLE,
            "previous_role": None,
            "account_kind": None,
            "previous_account_kind": None,
        }
    ]


@pytest.mark.parametrize(
    ("groups", "admitted"),
    [
        pytest.param((LOGIN_GROUP,), True, id="the group itself"),
        pytest.param((f"{LOGIN_GROUP}/admin",), True, id="a subgroup only"),
        pytest.param((f"{LOGIN_GROUP}/admin/ops",), True, id="a deeper subgroup"),
        pytest.param(("/other", LOGIN_GROUP), True, id="the group among others"),
        pytest.param((), False, id="no groups, as a missing or empty claim reads"),
        pytest.param((f"{LOGIN_GROUP}2",), False, id="a group named like it with a suffix"),
        pytest.param(("/apps",), False, id="the parent of the group"),
        pytest.param(("/apps/other",), False, id="another app's group"),
        pytest.param(("lab",), False, id="the bare name"),
        pytest.param((LOGIN_GROUP.upper(),), False, id="another case"),
        pytest.param(tuple(f"/g/{n}" for n in range(1000)), False, id="a thousand foreign groups"),
        pytest.param(
            (*(f"/g/{n}" for n in range(1000)), LOGIN_GROUP),
            True,
            id="the group after a thousand others",
        ),
    ],
)
def test_a_person_is_admitted_when_a_group_is_the_login_group_or_below_it(
    groups: tuple[str, ...],
    *,
    admitted: bool,
) -> None:
    """APP-03, APP-14: only a person with the login group or a subgroup of it gets in."""
    host = a_host()

    outcome = host.admit(replace(LENA, groups=groups))

    assert (outcome is not AdmissionRefusal.NOT_A_MEMBER) is admitted
    assert len(host.accounts.list()) == int(admitted)


def test_the_every_subject_value_admits_a_person_without_groups() -> None:
    """APP-01: an app configured for every subject requires no login group."""
    host = a_host()
    account = host.admit(replace(LENA, groups=()), EVERYONE)

    assert account == host.accounts.get(SUBJECT)


def test_a_person_taken_out_of_the_group_is_refused_and_back_in_returns_to_the_account() -> None:
    """APP-06, APP-17, APP-18: a removed person is refused, keeps the account and returns to it."""
    host = a_host()
    first = host.admit(LENA)
    stored = deepcopy(host.accounts.list())

    assert host.admit(replace(LENA, groups=())) is AdmissionRefusal.NOT_A_MEMBER
    assert host.accounts.list() == stored

    assert host.admit(LENA) is first
    assert len(host.audit.account_events) == 1


FOREIGN_ISSUER = "https://other.example/realms/lab"


class UsersFailingOnAnyLookupOrWrite(UsersInMemory):
    """A store that fails when admission looks up, creates or changes an account."""

    def get(self, user_id: str) -> FakeUser | None:
        raise AssertionError(f"account {user_id!r} looked up")

    def create_for_subject(
        self, subject: str, username: str, role: str, kind: AccountKind
    ) -> FakeUser:
        raise AssertionError(f"account {subject!r} created")

    def set_role(self, user_id: str, role: str) -> FakeUser:
        raise AssertionError(f"account {user_id!r} changed")

    def set_kind(self, user_id: str, kind: AccountKind) -> FakeUser:
        raise AssertionError(f"account {user_id!r} changed")


@pytest.mark.parametrize(
    ("identity", "admission", "refusal"),
    [
        pytest.param(
            replace(LENA, groups=()),
            ADMISSION,
            AdmissionRefusal.NOT_A_MEMBER,
            id="a person outside the group",
        ),
        pytest.param(
            replace(LENA, issuer=FOREIGN_ISSUER, groups=()),
            ADMISSION,
            AdmissionRefusal.FOREIGN_ISSUER,
            id="a foreign issuer, checked before the group",
        ),
        pytest.param(
            replace(LENA, issuer=FOREIGN_ISSUER),
            EVERYONE,
            AdmissionRefusal.FOREIGN_ISSUER,
            id="a foreign issuer where every subject is admitted",
        ),
    ],
)
def test_an_identity_refused_before_its_account_writes_nothing(
    identity: OidcIdentity,
    admission: AdmissionConfig,
    refusal: AdmissionRefusal,
) -> None:
    """APP-05, APP-16: a refused identity reaches no account, whatever its issuer."""
    host = a_host(store=UsersFailingOnAnyLookupOrWrite)

    assert host.admit(identity, admission) is refusal
    assert host.accounts.list() == []
    assert host.audit.account_events == []


def test_a_stored_admin_outside_the_admin_group_is_demoted_and_audited_at_login() -> None:
    host = a_host(deepcopy(LEGACY_ADMIN))

    account = admitted_account(host, LENA)

    assert account is host.accounts.get(SUBJECT)
    assert (account.username, account.role) == ("lena.legacy", MEMBER_ROLE)
    assert [asdict(event) for event in host.audit.account_events] == [
        {
            "kind": AccountEventKind.ROLE_CHANGED,
            "actor_id": None,
            "subject_id": SUBJECT,
            "role": MEMBER_ROLE,
            "previous_role": ADMIN_ROLE,
            "account_kind": None,
            "previous_account_kind": None,
        }
    ]


@dataclass(frozen=True)
class RoleCase:
    stored_role: str | None
    groups: tuple[str, ...]
    admission: AdmissionConfig
    role: str
    changed: bool


@pytest.mark.parametrize(
    "case",
    [
        pytest.param(
            RoleCase(None, (LOGIN_GROUP,), ADMISSION, MEMBER_ROLE, False), id="a new member"
        ),
        pytest.param(
            RoleCase(None, (ADMIN_GROUP,), ADMISSION, ADMIN_ROLE, False),
            id="a new member of the admin group",
        ),
        pytest.param(
            RoleCase(None, (f"{ADMIN_GROUP}/ops",), ADMISSION, ADMIN_ROLE, False),
            id="a new member of a subgroup of the admin group",
        ),
        pytest.param(
            RoleCase(None, ("/apps/other/admin",), EVERYONE_WITH_ADMIN_GROUP, ADMIN_ROLE, False),
            id="a new member of the admin group under every subject",
        ),
        pytest.param(
            RoleCase(None, (ADMIN_GROUP,), NO_ADMINS, MEMBER_ROLE, False),
            id="a new person in a group named admin where the app has no admins",
        ),
        pytest.param(
            RoleCase(MEMBER_ROLE, (ADMIN_GROUP,), ADMISSION, ADMIN_ROLE, True),
            id="a member put into the admin group",
        ),
        pytest.param(
            RoleCase(ADMIN_ROLE, (LOGIN_GROUP,), ADMISSION, MEMBER_ROLE, True),
            id="an admin taken out of the admin group",
        ),
        pytest.param(
            RoleCase(ADMIN_ROLE, (ADMIN_GROUP,), ADMISSION, ADMIN_ROLE, False),
            id="an admin still in the admin group",
        ),
        pytest.param(
            RoleCase(MEMBER_ROLE, (LOGIN_GROUP,), ADMISSION, MEMBER_ROLE, False),
            id="a member outside the admin group",
        ),
        pytest.param(
            RoleCase(ADMIN_ROLE, (ADMIN_GROUP,), NO_ADMINS, MEMBER_ROLE, True),
            id="an admin where the app has no admins",
        ),
        pytest.param(
            RoleCase("owner", (LOGIN_GROUP,), ADMISSION, MEMBER_ROLE, True),
            id="a stored role the library does not know",
        ),
        pytest.param(
            RoleCase(MEMBER_ROLE, (f"{LOGIN_GROUP}/admins",), ADMISSION, MEMBER_ROLE, False),
            id="a group named like the admin group with a suffix",
        ),
        pytest.param(
            RoleCase(
                MEMBER_ROLE, (LOGIN_GROUP, ADMIN_GROUP.upper()), ADMISSION, MEMBER_ROLE, False
            ),
            id="the admin group in another case",
        ),
    ],
)
def test_an_account_gets_the_role_its_groups_derive_at_every_login(case: RoleCase) -> None:
    """APP-02, APP-04, APP-06, APP-12: the role follows the groups at every login."""
    host = a_host(
        *(
            [FakeUser(id=SUBJECT, username="lena", role=case.stored_role)]
            if case.stored_role
            else []
        )
    )

    account = host.admit(replace(LENA, groups=case.groups), case.admission)

    assert isinstance(account, FakeUser)
    assert account.role == case.role
    assert host.accounts.get(SUBJECT) is account
    kinds = [event.kind for event in host.audit.account_events]
    expected = (
        [AccountEventKind.ROLE_CHANGED]
        if case.changed
        else ([] if case.stored_role else [AccountEventKind.USER_CREATED])
    )
    assert kinds == expected


def test_the_roles_a_sign_in_stores_and_audits_are_plain_strings() -> None:
    """APP-10: a sign-in stores admin and user as plain strings."""
    host = a_host()

    created = admitted_account(host, LENA)
    promoted = admitted_account(host, LENA_IN_THE_ADMIN_GROUP)

    created_event, changed_event = host.audit.account_events
    assert (created_event.role, changed_event.previous_role, changed_event.role) == (
        MEMBER_ROLE,
        MEMBER_ROLE,
        ADMIN_ROLE,
    )
    assert {
        type(created_event.role),
        type(changed_event.previous_role),
        type(changed_event.role),
        type(created.role),
        type(promoted.role),
    } == {str}


def test_a_role_change_audit_event_carries_the_roles_and_no_username() -> None:
    host = a_host(FakeUser(id=SUBJECT, username="lena.private", role=MEMBER_ROLE))

    host.admit(LENA_IN_THE_ADMIN_GROUP)

    [event] = host.audit.account_events
    assert (event.actor_id, event.subject_id, event.previous_role, event.role) == (
        None,
        SUBJECT,
        MEMBER_ROLE,
        ADMIN_ROLE,
    )
    assert "lena.private" not in repr(event)


class UsersReplacingRecords(UsersInMemory):
    """A store whose records are frozen: a role write returns a new record."""

    def set_role(self, user_id: str, role: str) -> FakeUser:
        require_held_lock(self._lock)
        replaced = replace(self._users[user_id], role=role)
        self._users[user_id] = replaced
        self._usernames[replaced.username] = replaced
        return replaced


class UsersMissingTheRoleRow(UsersInMemory):
    """A store whose role write finds no row, as after a concurrent delete."""

    def set_role(self, user_id: str, role: str) -> FakeUser:
        require_held_lock(self._lock)
        raise LookupError(user_id)


class UsersRejectingNeedlessRoleWrites(UsersInMemory):
    """A store that fails on a role write that changes nothing."""

    def set_role(self, user_id: str, role: str) -> FakeUser:
        if self._users[user_id].role == role:
            raise AssertionError(f"role {role!r} written to an account that holds it")
        return super().set_role(user_id, role)


def test_admission_answers_the_record_the_role_write_returned() -> None:
    host = a_host(
        FakeUser(id=SUBJECT, username="lena", role=MEMBER_ROLE), store=UsersReplacingRecords
    )
    read_before = host.accounts.get(SUBJECT)

    account = admitted_account(host, LENA_IN_THE_ADMIN_GROUP)

    assert account is not read_before
    assert account is host.accounts.get(SUBJECT)
    assert account.role == ADMIN_ROLE


def test_a_role_write_that_finds_no_row_fails_admission_and_audits_nothing() -> None:
    host = a_host(
        FakeUser(id=SUBJECT, username="lena", role=MEMBER_ROLE), store=UsersMissingTheRoleRow
    )

    with pytest.raises(LookupError):
        host.admit(LENA_IN_THE_ADMIN_GROUP)

    assert host.audit.account_events == []


def test_a_role_that_does_not_change_is_written_by_no_second_login() -> None:
    host = a_host(store=UsersRejectingNeedlessRoleWrites)
    host.admit(LENA_IN_THE_ADMIN_GROUP)

    host.admit(LENA_IN_THE_ADMIN_GROUP)

    assert [event.kind for event in host.audit.account_events] == [
        AccountEventKind.USER_CREATED,
    ]


def test_a_known_subject_reuses_its_account_unchanged_when_its_username_changed() -> None:
    """APP-20: a known subject's account is found by subject, whatever its username."""
    host = a_host()
    first = host.admit(LENA)
    stored = deepcopy(host.accounts.list())

    again = host.admit(replace(LENA, preferred_username="lena.renamed"))

    assert again is first
    assert host.accounts.list() == stored
    assert len(host.audit.account_events) == 1


@pytest.mark.parametrize(
    ("identity", "stored", "refusal"),
    [
        pytest.param(
            replace(LENA, issuer="https://other.example/realms/lab"),
            [LEGACY_ADMIN],
            AdmissionRefusal.FOREIGN_ISSUER,
            id="another issuer's identity whose subject names a legacy admin",
        ),
    ],
)
def test_a_refused_identity_changes_neither_the_store_nor_the_audit_log(
    identity: OidcIdentity,
    stored: list[FakeUser],
    refusal: AdmissionRefusal,
) -> None:
    """APP-05: another issuer's identity never changes an account's role."""
    host = a_host(*deepcopy(stored))

    assert host.admit(identity) is refusal
    assert host.accounts.list() == stored
    assert host.audit.account_events == []
