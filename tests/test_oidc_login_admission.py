"""Admitting an identity the bound issuer vouched for: groups, roles, accounts.

These tests drive `admit_identity` and `app_role` on their own: an identity the
bound issuer vouched for becomes, or reuses, an account.
"""

from __future__ import annotations

from copy import deepcopy
from dataclasses import asdict, dataclass, replace

import pytest

from tests.support.oidc_login_host import (
    ADMIN_GROUP,
    ADMISSION,
    BOUND_ISSUER,
    LEGACY_ADMIN,
    LENA,
    LENA_IN_THE_ADMIN_GROUP,
    LOGIN_GROUP,
    SUBJECT,
    CountingWriteLock,
)
from tests.support.webauth_arrangement import (
    ADMIN_ROLE,
    MEMBER_ROLE,
    FakeUser,
    RecordingAuditSink,
    UsersInMemory,
    UsersWithCaseInsensitiveUsernames,
    UsersWithoutUniqueUsernames,
    WriteLockInMemory,
    _require_held_lock,
    a_web_auth_config,
)
from webauth.oidc import (
    OidcIdentity,
)
from webauth.oidc_login import (
    AdmissionConfig,
    AdmissionRefusal,
    AppRole,
    EverySubject,
    NoAdmins,
    admit_identity,
    app_role,
)
from webauth.ports import (
    AccountEventKind,
    UserRecord,
)


@dataclass
class Host:
    accounts: UsersInMemory
    audit: RecordingAuditSink
    lock: WriteLockInMemory

    def admit(
        self, identity: OidcIdentity, admission: AdmissionConfig = ADMISSION,
    ) -> UserRecord | AdmissionRefusal:
        return admit_identity(
            identity,
            admission=admission,
            accounts=self.accounts,
            lock=self.lock,
            audit=self.audit,
            config=a_web_auth_config(),
        )


def admitted_account(host: Host, identity: OidcIdentity) -> UserRecord:
    account = host.admit(identity)
    assert not isinstance(account, AdmissionRefusal)
    return account


def a_host(*users: FakeUser, store: type[UsersInMemory] = UsersInMemory) -> Host:
    lock = WriteLockInMemory()
    return Host(store(*users, lock=lock), RecordingAuditSink(), lock)


@pytest.mark.parametrize(("preferred_username", "username"), [
    pytest.param("lena", "lena", id="the issuer's suggested username"),
    pytest.param(None, SUBJECT, id="the subject when the issuer suggests none"),
    pytest.param("", SUBJECT, id="the subject when the suggestion is empty"),
    pytest.param(" \t ", SUBJECT, id="the subject when the suggestion is only whitespace"),
])
def test_a_new_subject_creates_a_member_account_and_reports_it(
    preferred_username: str | None, username: str,
) -> None:
    host = a_host()

    account = admitted_account(host, replace(LENA, preferred_username=preferred_username))

    assert (account.id, account.username, account.role) == (
        SUBJECT, username, MEMBER_ROLE,
    )
    assert host.accounts.list() == [account]
    assert [asdict(event) for event in host.audit.account_events] == [{
        "kind": AccountEventKind.USER_CREATED,
        "actor_id": None,
        "subject_id": SUBJECT,
        "role": MEMBER_ROLE,
        "previous_role": None,
    }]


@pytest.mark.parametrize(("groups", "admitted"), [
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
    pytest.param((*(f"/g/{n}" for n in range(1000)), LOGIN_GROUP), True,
                 id="the group after a thousand others"),
])
def test_a_person_is_admitted_when_a_group_is_the_login_group_or_below_it(
    groups: tuple[str, ...], *, admitted: bool,
) -> None:
    host = a_host()

    outcome = host.admit(replace(LENA, groups=groups))

    assert (outcome is not AdmissionRefusal.NOT_A_MEMBER) is admitted
    assert len(host.accounts.list()) == int(admitted)


def test_the_every_subject_value_admits_a_person_without_groups() -> None:
    host = a_host()
    account = host.admit(replace(LENA, groups=()), EVERYONE)

    assert account == host.accounts.get(SUBJECT)


def test_a_person_taken_out_of_the_group_is_refused_and_back_in_returns_to_the_account() -> None:
    host = a_host()
    first = host.admit(LENA)
    stored = deepcopy(host.accounts.list())

    assert host.admit(replace(LENA, groups=())) is AdmissionRefusal.NOT_A_MEMBER
    assert host.accounts.list() == stored

    assert host.admit(LENA) is first
    assert len(host.audit.account_events) == 1


FOREIGN_ISSUER = "https://other.example/realms/lab"
EVERYONE = replace(ADMISSION, login_group=EverySubject.OF_THE_BOUND_ISSUER)


@pytest.mark.parametrize(("identity", "admission", "refusal"), [
    pytest.param(
        replace(LENA, groups=()), ADMISSION, AdmissionRefusal.NOT_A_MEMBER,
        id="a person outside the group",
    ),
    pytest.param(
        replace(LENA, issuer=FOREIGN_ISSUER, groups=()), ADMISSION,
        AdmissionRefusal.FOREIGN_ISSUER, id="a foreign issuer, checked before the group",
    ),
    pytest.param(
        replace(LENA, issuer=FOREIGN_ISSUER), EVERYONE,
        AdmissionRefusal.FOREIGN_ISSUER, id="a foreign issuer where every subject is admitted",
    ),
])
def test_an_identity_refused_before_its_account_takes_no_lock_and_writes_nothing(
    identity: OidcIdentity, admission: AdmissionConfig, refusal: AdmissionRefusal,
) -> None:
    lock = CountingWriteLock()
    host = Host(UsersInMemory(lock=lock), RecordingAuditSink(), lock)

    assert host.admit(identity, admission) is refusal
    assert lock.times_taken == 0
    assert host.accounts.list() == []
    assert host.audit.account_events == []


@pytest.mark.parametrize(("login_group", "admin_group"), [
    pytest.param("/apps/lab", "/apps/lab/admin", id="a path with an admin group below it"),
    pytest.param("/apps/lab", "/apps/lab/ops/admin", id="an admin group two levels below"),
    pytest.param("/apps/Team A", "/apps/Team A/~admin", id="a space and a tilde inside a segment"),
    pytest.param("/apps/lab", NoAdmins.IN_THIS_APP, id="no admins in this app"),
    pytest.param(EverySubject.OF_THE_BOUND_ISSUER, "/apps/lab/admin", id="every subject"),
    pytest.param(EverySubject.OF_THE_BOUND_ISSUER, "/admins", id="every subject, any admin path"),
    pytest.param(EverySubject.OF_THE_BOUND_ISSUER, NoAdmins.IN_THIS_APP, id="neither group"),
])
def test_a_well_formed_admission_config_is_accepted(
    login_group: str | EverySubject, admin_group: str | NoAdmins,
) -> None:
    assert AdmissionConfig(
        bound_issuer=BOUND_ISSUER, login_group=login_group, admin_group=admin_group,
    )


MALFORMED_GROUP_PATHS = [
    pytest.param("", id="empty"),
    pytest.param("apps/lab", id="no leading slash"),
    pytest.param("/", id="a bare slash"),
    pytest.param("/apps/lab/", id="a trailing slash"),
    pytest.param("/apps//lab", id="an empty segment"),
    pytest.param("/apps/ lab", id="leading whitespace on a segment"),
    pytest.param("/apps/lab ", id="trailing whitespace on a segment"),
    pytest.param("/apps/\tlab", id="a tab inside a segment"),
    pytest.param("/apps/la\x00b", id="a control character"),
    pytest.param("/apps/la\nb", id="a newline"),
    pytest.param("/apps/la\u200bb", id="a zero-width space"),
    pytest.param("/apps/la\u2028b", id="a line separator"),
    pytest.param("/apps/la\u2029b", id="a paragraph separator"),
]


@pytest.mark.parametrize("login_group", [
    pytest.param(None, id="none"),
    pytest.param(7, id="an int"),
    *MALFORMED_GROUP_PATHS,
])
def test_a_malformed_login_group_fails_at_construction(login_group: object) -> None:
    with pytest.raises(ValueError):
        AdmissionConfig(
            bound_issuer=BOUND_ISSUER,
            login_group=login_group,  # pyright: ignore[reportArgumentType] -- malformed on purpose
            admin_group=NoAdmins.IN_THIS_APP,
        )


@pytest.mark.parametrize("admin_group", [
    pytest.param(None, id="none, as an unset variable reads"),
    pytest.param(7, id="an int"),
    pytest.param(EverySubject.OF_THE_BOUND_ISSUER, id="the every-subject value"),
    *MALFORMED_GROUP_PATHS,
])
def test_a_malformed_admin_group_fails_at_construction(admin_group: object) -> None:
    with pytest.raises(ValueError):
        AdmissionConfig(
            bound_issuer=BOUND_ISSUER,
            login_group=EverySubject.OF_THE_BOUND_ISSUER,
            admin_group=admin_group,  # pyright: ignore[reportArgumentType] -- malformed on purpose
        )


@pytest.mark.parametrize("admin_group", [
    pytest.param(LOGIN_GROUP, id="the login group itself"),
    pytest.param("/apps", id="the parent of the login group"),
    pytest.param("/apps/other/admin", id="another app's admin group"),
    pytest.param(f"{LOGIN_GROUP}2/admin", id="a group named like the login group with a suffix"),
    pytest.param(LOGIN_GROUP.upper() + "/admin", id="another case"),
])
def test_an_admin_group_outside_the_login_group_fails_at_construction(admin_group: str) -> None:
    message = f"admin_group must lie below login_group, such as {LOGIN_GROUP}/admin"
    with pytest.raises(ValueError, match=message):
        AdmissionConfig(
            bound_issuer=BOUND_ISSUER, login_group=LOGIN_GROUP, admin_group=admin_group,
        )


@pytest.mark.parametrize("settings", [
    pytest.param({"login_group": LOGIN_GROUP}, id="without an admin group"),
    pytest.param({"admin_group": ADMIN_GROUP}, id="without a login group"),
    pytest.param({}, id="without either"),
])
def test_an_admission_config_missing_a_required_group_setting_fails_at_construction(
    settings: dict[str, str],
) -> None:
    with pytest.raises(TypeError):
        AdmissionConfig(bound_issuer=BOUND_ISSUER, **settings)


def test_a_stored_admin_outside_the_admin_group_is_demoted_and_audited_at_login() -> None:
    host = a_host(deepcopy(LEGACY_ADMIN))

    account = admitted_account(host, LENA)

    assert account is host.accounts.get(SUBJECT)
    assert (account.username, account.role) == ("lena.legacy", MEMBER_ROLE)
    assert [asdict(event) for event in host.audit.account_events] == [{
        "kind": AccountEventKind.ROLE_CHANGED,
        "actor_id": None,
        "subject_id": SUBJECT,
        "role": MEMBER_ROLE,
        "previous_role": ADMIN_ROLE,
    }]


@dataclass(frozen=True)
class RoleCase:
    stored_role: str | None
    groups: tuple[str, ...]
    admission: AdmissionConfig
    role: str
    changed: bool


NO_ADMINS = replace(ADMISSION, admin_group=NoAdmins.IN_THIS_APP)
EVERYONE_WITH_ADMIN_GROUP = replace(EVERYONE, admin_group="/apps/other/admin")


@pytest.mark.parametrize("case", [
    pytest.param(RoleCase(None, (LOGIN_GROUP,), ADMISSION, MEMBER_ROLE, False),
                 id="a new member"),
    pytest.param(RoleCase(None, (ADMIN_GROUP,), ADMISSION, ADMIN_ROLE, False),
                 id="a new member of the admin group"),
    pytest.param(RoleCase(None, (f"{ADMIN_GROUP}/ops",), ADMISSION, ADMIN_ROLE, False),
                 id="a new member of a subgroup of the admin group"),
    pytest.param(RoleCase(None, ("/apps/other/admin",), EVERYONE_WITH_ADMIN_GROUP, ADMIN_ROLE,
                          False), id="a new member of the admin group under every subject"),
    pytest.param(RoleCase(None, (ADMIN_GROUP,), NO_ADMINS, MEMBER_ROLE, False),
                 id="a new person in a group named admin where the app has no admins"),
    pytest.param(RoleCase(MEMBER_ROLE, (ADMIN_GROUP,), ADMISSION, ADMIN_ROLE, True),
                 id="a member put into the admin group"),
    pytest.param(RoleCase(ADMIN_ROLE, (LOGIN_GROUP,), ADMISSION, MEMBER_ROLE, True),
                 id="an admin taken out of the admin group"),
    pytest.param(RoleCase(ADMIN_ROLE, (ADMIN_GROUP,), ADMISSION, ADMIN_ROLE, False),
                 id="an admin still in the admin group"),
    pytest.param(RoleCase(MEMBER_ROLE, (LOGIN_GROUP,), ADMISSION, MEMBER_ROLE, False),
                 id="a member outside the admin group"),
    pytest.param(RoleCase(ADMIN_ROLE, (ADMIN_GROUP,), NO_ADMINS, MEMBER_ROLE, True),
                 id="an admin where the app has no admins"),
    pytest.param(RoleCase("owner", (LOGIN_GROUP,), ADMISSION, MEMBER_ROLE, True),
                 id="a stored role the library does not know"),
    pytest.param(RoleCase(MEMBER_ROLE, (f"{LOGIN_GROUP}/admins",), ADMISSION, MEMBER_ROLE, False),
                 id="a group named like the admin group with a suffix"),
    pytest.param(RoleCase(MEMBER_ROLE, (LOGIN_GROUP, ADMIN_GROUP.upper()), ADMISSION,
                          MEMBER_ROLE, False), id="the admin group in another case"),
])
def test_an_account_gets_the_role_its_groups_derive_at_every_login(case: RoleCase) -> None:
    host = a_host(*(
        [FakeUser(id=SUBJECT, username="lena", role=case.stored_role)]
        if case.stored_role else []
    ))

    account = host.admit(replace(LENA, groups=case.groups), case.admission)

    assert isinstance(account, FakeUser)
    assert account.role == case.role
    assert host.accounts.get(SUBJECT) is account
    kinds = [event.kind for event in host.audit.account_events]
    expected = [AccountEventKind.ROLE_CHANGED] if case.changed else (
        [] if case.stored_role else [AccountEventKind.USER_CREATED]
    )
    assert kinds == expected


@pytest.mark.parametrize(("groups", "admission", "role"), [
    pytest.param((ADMIN_GROUP,), ADMISSION, AppRole.ADMIN, id="the admin group"),
    pytest.param((f"{ADMIN_GROUP}/ops",), ADMISSION, AppRole.ADMIN, id="an admin subgroup"),
    pytest.param((LOGIN_GROUP,), ADMISSION, AppRole.USER, id="the login group"),
    pytest.param((f"{LOGIN_GROUP}/staff",), ADMISSION, AppRole.USER, id="a login subgroup"),
    pytest.param((f"{LOGIN_GROUP}2",), ADMISSION, None, id="a group named like the login group"),
    pytest.param((), ADMISSION, None, id="no groups"),
    pytest.param((), EVERYONE, AppRole.USER, id="no groups under every subject"),
    pytest.param((ADMIN_GROUP,), EVERYONE, AppRole.ADMIN,
                 id="the admin group under every subject"),
    pytest.param((LOGIN_GROUP,), EVERYONE_WITH_ADMIN_GROUP, AppRole.USER,
                 id="every subject without the admin group"),
    pytest.param((ADMIN_GROUP,), NO_ADMINS, AppRole.USER, id="the admin path without admins"),
])
def test_app_role_names_the_role_the_groups_carry(
    groups: tuple[str, ...], admission: AdmissionConfig, role: AppRole | None,
) -> None:
    assert app_role(groups, admission) is role


def test_a_role_change_audit_event_carries_the_roles_and_no_username() -> None:
    host = a_host(FakeUser(id=SUBJECT, username="lena.private", role=MEMBER_ROLE))

    host.admit(LENA_IN_THE_ADMIN_GROUP)

    [event] = host.audit.account_events
    assert (event.actor_id, event.subject_id, event.previous_role, event.role) == (
        None, SUBJECT, MEMBER_ROLE, ADMIN_ROLE,
    )
    assert "lena.private" not in repr(event)


class UsersReplacingRecords(UsersInMemory):
    """A store whose records are frozen: a role write returns a new record."""

    def set_role(self, user_id: str, role: str) -> FakeUser:
        _require_held_lock(self._lock)
        replaced = replace(self._users[user_id], role=role)
        self._users[user_id] = replaced
        self._usernames[replaced.username] = replaced
        return replaced


class UsersMissingTheRoleRow(UsersInMemory):
    """A store whose role write finds no row, as after a concurrent delete."""

    def set_role(self, user_id: str, role: str) -> FakeUser:
        _require_held_lock(self._lock)
        raise LookupError(user_id)


class UsersRejectingNeedlessRoleWrites(UsersInMemory):
    """A store that fails on a role write that changes nothing."""

    def set_role(self, user_id: str, role: str) -> FakeUser:
        if self._users[user_id].role == role:
            raise AssertionError(f"role {role!r} written to an account that holds it")
        return super().set_role(user_id, role)


def test_admission_answers_the_record_the_role_write_returned() -> None:
    host = a_host(FakeUser(id=SUBJECT, username="lena", role=MEMBER_ROLE),
                  store=UsersReplacingRecords)
    read_before = host.accounts.get(SUBJECT)

    account = admitted_account(host, LENA_IN_THE_ADMIN_GROUP)

    assert account is not read_before
    assert account is host.accounts.get(SUBJECT)
    assert account.role == ADMIN_ROLE


def test_a_role_write_that_finds_no_row_fails_admission_and_audits_nothing() -> None:
    host = a_host(FakeUser(id=SUBJECT, username="lena", role=MEMBER_ROLE),
                  store=UsersMissingTheRoleRow)

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
    host = a_host()
    first = host.admit(LENA)
    stored = deepcopy(host.accounts.list())

    again = host.admit(replace(LENA, preferred_username="lena.renamed"))

    assert again is first
    assert host.accounts.list() == stored
    assert len(host.audit.account_events) == 1


@pytest.mark.parametrize(("identity", "stored", "refusal"), [
    pytest.param(
        replace(LENA, issuer="https://other.example/realms/lab"),
        [LEGACY_ADMIN],
        AdmissionRefusal.FOREIGN_ISSUER,
        id="another issuer's identity whose subject names a legacy admin",
    ),
    pytest.param(
        LENA, [FakeUser(id="user-7", username="lena")],
        AdmissionRefusal.USERNAME_TAKEN,
        id="a new subject whose username another account holds",
    ),
])
def test_a_refused_identity_changes_neither_the_store_nor_the_audit_log(
    identity: OidcIdentity, stored: list[FakeUser], refusal: AdmissionRefusal,
) -> None:
    host = a_host(*deepcopy(stored))

    assert host.admit(identity) is refusal
    assert host.accounts.list() == stored
    assert host.audit.account_events == []


def test_a_username_the_store_refuses_on_create_is_taken_and_nothing_is_written() -> None:
    stored = [FakeUser(id="user-7", username="Lena")]
    host = a_host(*deepcopy(stored), store=UsersWithCaseInsensitiveUsernames)

    assert host.admit(LENA) is AdmissionRefusal.USERNAME_TAKEN
    assert host.accounts.list() == stored
    assert host.audit.account_events == []


def test_a_store_without_unique_usernames_admits_two_subjects_sharing_one() -> None:
    host = a_host(store=UsersWithoutUniqueUsernames)
    other_lena = replace(LENA, subject="0b6f1d7e-3c8a-4e0b-8d52-6a1f9e4c7b23")

    first = admitted_account(host, LENA)
    second = admitted_account(host, other_lena)

    assert (first.id, second.id) == (LENA.subject, other_lena.subject)
    assert (first.username, second.username) == ("lena", "lena")
