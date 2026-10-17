"""Account administration through the same ports the hosts implement."""

from __future__ import annotations

from collections.abc import Callable
from contextlib import nullcontext
from dataclasses import asdict, replace
from datetime import datetime, timedelta, timezone

import pytest
from webauth_arrangement import (
    CLIENT_ADDRESS,
    CLIENT_USER_AGENT,
    FakeSessionRecord,
    FakeUser,
    LegibleHasher,
    LockNotHeldError,
    PasswordlessUser,
    UsersWithSetupRace,
    a_cheap_argon2id_hasher,
    a_user_management,
    a_web_auth_config,
)

from webauth.dependencies import AuthenticatedUser
from webauth.login import LoginOutcome, judge_credentials
from webauth.ports import (
    AuditSink,
    PasswordHasher,
    UnknownUserError,
    UserAdministrationStore,
    UserManagementError,
    UserManagementEventKind,
    UsernameTakenError,
    UserRecord,
    WriteLock,
)
from webauth.session_administration import NotAnAdminError, UnknownSessionError
from webauth.users import (
    LastAdminError,
    PasswordlessAccountError,
    SelfDeactivationError,
    SetupAlreadyDoneError,
    SetupRacedError,
    UnknownRoleError,
    UserManagement,
    WeakPasswordError,
    WrongPasswordError,
    complete_first_run_setup,
)

CHOSEN_PASSWORD = "River!Lantern92"
NEW_PASSWORD = "Mountain!Beacon83"
COMPOSED_PASSWORD = "Caf\u00e9!Lantern92"
DECOMPOSED_PASSWORD = "Cafe\u0301!Lantern92"
AdminOperation = Callable[[UserManagement, AuthenticatedUser], object]
RoleOperation = Callable[[UserManagement, AuthenticatedUser, str], object]
PasswordOperation = Callable[[UserManagement, AuthenticatedUser, str], object]


def create_member(management: UserManagement, actor: AuthenticatedUser) -> UserRecord:
    return management.create_user(
        actor, "new-account", CHOSEN_PASSWORD, management.config.user_role,
    )


def promote_subject(management: UserManagement, actor: AuthenticatedUser) -> UserRecord:
    return management.change_role(actor, "subject", management.config.admin_role)


def demote_subject(management: UserManagement, actor: AuthenticatedUser) -> UserRecord:
    return management.change_role(actor, "subject", management.config.user_role)


def deactivate_subject(management: UserManagement, actor: AuthenticatedUser) -> None:
    management.deactivate_user(actor, "subject")


def revoke_subject_sessions(management: UserManagement, actor: AuthenticatedUser) -> int:
    return management.revoke_user_sessions(actor, "subject")


def the_subject_signed_in(
    management: UserManagement, actor: AuthenticatedUser,
) -> AuthenticatedUser:
    return replace(actor, id="subject", username="member", role=management.config.user_role)


def reset_subject_password(
    management: UserManagement, actor: AuthenticatedUser, password: str,
) -> None:
    management.set_password(actor, "subject", password)


def change_subject_own_password(
    management: UserManagement, actor: AuthenticatedUser, password: str,
) -> None:
    management.change_own_password(
        the_subject_signed_in(management, actor), CHOSEN_PASSWORD, password,
    )


def to_new_password(change: PasswordOperation) -> AdminOperation:
    def change_to_new_password(management: UserManagement, actor: AuthenticatedUser) -> object:
        return change(management, actor, NEW_PASSWORD)
    return change_to_new_password


ADMIN_OPERATIONS = [
    pytest.param(create_member, id="create_user"),
    pytest.param(promote_subject, id="change_role"),
    pytest.param(deactivate_subject, id="deactivate_user"),
    pytest.param(revoke_subject_sessions, id="revoke_user_sessions"),
    pytest.param(lambda m, a: m.set_password(a, "subject", NEW_PASSWORD), id="set_password"),
]

def a_management_hashing_with(hasher: PasswordHasher) -> UserManagement:
    config = a_web_auth_config(
        admin_role="operator", user_role="member", password_hasher=hasher,
    )
    return a_user_management(
        FakeUser(
            id="actor", username="administrator", role=config.admin_role,
            password_hash=config.password_hasher.hash(CHOSEN_PASSWORD),
        ),
        FakeUser(
            id="subject", username="member", role=config.user_role,
            password_hash=config.password_hasher.hash(CHOSEN_PASSWORD),
        ),
        config=config,
    )


@pytest.fixture
def management() -> UserManagement:
    return a_management_hashing_with(LegibleHasher())


@pytest.fixture
def actor(management: UserManagement) -> AuthenticatedUser:
    return AuthenticatedUser(
        id="actor", username="administrator", role=management.config.admin_role, is_active=True,
    )


@pytest.fixture
def empty_management(management: UserManagement) -> UserManagement:
    return a_user_management(config=management.config)


@pytest.fixture
def stored_sessions(management: UserManagement) -> list[FakeSessionRecord]:
    return [
        management.sessions.create(
            user_id,
            datetime(2030, 1, 1, tzinfo=timezone.utc),
            ip_address=CLIENT_ADDRESS,
            user_agent=CLIENT_USER_AGENT,
        )
        for user_id in ("subject", "actor", "subject")
    ]


def test_REQ_ADMIN_02_setup_creates_the_first_administrator(
    empty_management: UserManagement,
) -> None:
    user = complete_first_run_setup(empty_management, "first-admin", CHOSEN_PASSWORD)

    assert empty_management.users.list() == [user]
    assert user.username == "first-admin"
    assert user.role == empty_management.config.admin_role
    assert user.is_active
    assert empty_management.config.password_hasher.verify(CHOSEN_PASSWORD, user.password_hash)


def test_REQ_ADMIN_02_repeating_setup_keeps_the_first_account(
    empty_management: UserManagement,
) -> None:
    user = complete_first_run_setup(empty_management, "first-admin", CHOSEN_PASSWORD)
    events = list(empty_management.audit.user_management_events)

    with pytest.raises(SetupAlreadyDoneError):
        complete_first_run_setup(empty_management, "second-admin", CHOSEN_PASSWORD)

    assert empty_management.users.list() == [user]
    assert empty_management.audit.user_management_events == events


def test_REQ_ADMIN_02_a_setup_race_requires_host_rollback_without_reporting_success(
    empty_management: UserManagement,
) -> None:
    management = replace(empty_management, users=UsersWithSetupRace(lock=empty_management.lock))

    with pytest.raises(SetupRacedError):
        complete_first_run_setup(management, "first-admin", CHOSEN_PASSWORD)

    with management.lock.hold():
        assert management.users.count() == 2
    assert management.audit.user_management_events == []


@pytest.mark.parametrize("is_active", [True, False])
def test_REQ_ADMIN_03_any_existing_account_closes_setup(
    empty_management: UserManagement, is_active: bool,
) -> None:
    existing = FakeUser(role=empty_management.config.user_role, is_active=is_active)
    management = a_user_management(existing, config=empty_management.config)

    with pytest.raises(SetupAlreadyDoneError):
        complete_first_run_setup(management, "first-admin", CHOSEN_PASSWORD)

    assert management.users.list() == [existing]
    assert management.audit.user_management_events == []


@pytest.mark.parametrize("role_field", ["admin_role", "user_role"])
def test_REQ_ADMIN_04_an_admin_creates_an_account_with_either_configured_role(
    management: UserManagement, actor: AuthenticatedUser, role_field: str,
) -> None:
    role = getattr(management.config, role_field)

    user = management.create_user(actor, "new-account", CHOSEN_PASSWORD, role)

    assert management.users.get_by_username("new-account") == user
    assert user.role == role
    assert user.is_active
    assert user.password_hash == management.config.password_hasher.hash(CHOSEN_PASSWORD)


@pytest.mark.parametrize("operation", [
    pytest.param(
        lambda m, a, role: m.create_user(a, "new-account", CHOSEN_PASSWORD, role),
        id="create_user",
    ),
    pytest.param(lambda m, a, role: m.change_role(a, "subject", role), id="change_role"),
])
@pytest.mark.parametrize("role", ["admin", "user", "unknown"])
def test_REQ_ADMIN_04_roles_outside_the_configuration_are_refused(
    management: UserManagement, actor: AuthenticatedUser, operation: RoleOperation, role: str,
) -> None:
    with pytest.raises(UnknownRoleError):
        operation(management, actor, role)

    with management.lock.hold():
        assert management.users.count() == 2
    assert management.users.get("subject").role == management.config.user_role
    assert management.audit.user_management_events == []


@pytest.mark.parametrize("operation", ADMIN_OPERATIONS)
@pytest.mark.parametrize("role", ["member", "admin", "unknown"])
def test_REQ_ADMIN_05_only_the_configured_admin_can_run_an_actor_flow(
    management: UserManagement, actor: AuthenticatedUser, operation: AdminOperation, role: str,
) -> None:
    with pytest.raises(NotAnAdminError):
        operation(management, replace(actor, role=role))

    with management.lock.hold():
        assert management.users.count() == 2
    assert management.users.get("subject").role == management.config.user_role
    assert management.users.get("subject").is_active
    assert management.audit.user_management_events == []


@pytest.mark.parametrize("operation", [
    pytest.param(demote_subject, id="change_role"),
    pytest.param(deactivate_subject, id="deactivate_user"),
])
def test_REQ_ADMIN_06_the_last_active_admin_cannot_be_removed(
    management: UserManagement, actor: AuthenticatedUser, operation: AdminOperation,
) -> None:
    with management.lock.hold():
        management.users.update("actor", is_active=False)
        management.users.update("subject", role=management.config.admin_role)

    with pytest.raises(LastAdminError):
        operation(management, actor)

    assert management.users.get("subject").role == management.config.admin_role
    assert management.users.get("subject").is_active
    assert management.audit.user_management_events == []


@pytest.mark.parametrize(("operation", "role_field", "stays_active"), [
    pytest.param(demote_subject, "user_role", True, id="change_role"),
    pytest.param(deactivate_subject, "admin_role", False, id="deactivate_user"),
])
@pytest.mark.parametrize("is_active", [True, False])
def test_an_admin_can_be_removed_when_another_active_admin_remains(
    management: UserManagement, actor: AuthenticatedUser, operation: AdminOperation,
    role_field: str, stays_active: bool, is_active: bool,
) -> None:
    with management.lock.hold():
        management.users.update("subject", role=management.config.admin_role, is_active=is_active)

    operation(management, actor)

    user = management.users.get("subject")
    assert user.role == getattr(management.config, role_field)
    assert user.is_active == (is_active and stays_active)
    with management.lock.hold():
        assert management.users.count_active_admins(management.config.admin_role) == 1


def test_leaving_the_last_admin_in_the_admin_role_is_allowed(
    management: UserManagement, actor: AuthenticatedUser,
) -> None:
    user = management.change_role(actor, actor.id, management.config.admin_role)

    assert user.role == management.config.admin_role
    with management.lock.hold():
        assert management.users.count_active_admins(management.config.admin_role) == 1


def test_REQ_ADMIN_07_an_admin_cannot_deactivate_their_own_account(
    management: UserManagement, actor: AuthenticatedUser,
) -> None:
    with management.lock.hold():
        management.users.update("subject", role=management.config.admin_role)

    with pytest.raises(SelfDeactivationError):
        management.deactivate_user(actor, actor.id)

    assert management.users.get(actor.id).is_active
    assert management.audit.user_management_events == []


@pytest.mark.parametrize(("operation", "initial_role_field", "final_role_field", "kind"), [
    pytest.param(
        deactivate_subject, "user_role", "user_role", "user_deactivated", id="deactivate",
    ),
    pytest.param(promote_subject, "user_role", "admin_role", "role_changed", id="promote"),
    pytest.param(demote_subject, "admin_role", "user_role", "role_changed", id="demote"),
])
def test_REQ_ADMIN_10_role_change_and_deactivation_end_every_subject_session(
    management: UserManagement, actor: AuthenticatedUser,
    stored_sessions: list[FakeSessionRecord],
    operation: AdminOperation, initial_role_field: str, final_role_field: str, kind: str,
) -> None:
    with management.lock.hold():
        management.users.update("subject", role=getattr(management.config, initial_role_field))

    operation(management, actor)

    subject = management.users.get("subject")
    assert subject.is_active == (kind == "role_changed")
    assert subject.role == getattr(management.config, final_role_field)
    assert [asdict(event) for event in management.audit.user_management_events] == [{
        "kind": UserManagementEventKind(kind),
        "actor_id": actor.id,
        "subject_id": "subject",
        "role": subject.role if kind == "role_changed" else None,
        "session_count": 2,
        "session_ref": None,
    }]
    for record in stored_sessions:
        remains = record.user_id != "subject"
        assert (management.sessions.load(record.id) is not None) == remains


@pytest.mark.parametrize("role_field", ["admin_role", "user_role"])
def test_repeating_the_stored_role_keeps_sessions_and_reports_no_event(
    management: UserManagement, actor: AuthenticatedUser,
    stored_sessions: list[FakeSessionRecord], role_field: str,
) -> None:
    role = getattr(management.config, role_field)
    with management.lock.hold():
        subject = management.users.update("subject", role=role)

    assert management.change_role(actor, "subject", role) == subject

    for record in stored_sessions:
        assert management.sessions.load(record.id) == record
    assert management.audit.user_management_events == []


def test_revocation_returns_the_store_count_and_leaves_other_accounts_sessions(
    management: UserManagement, actor: AuthenticatedUser,
    stored_sessions: list[FakeSessionRecord],
) -> None:
    assert management.revoke_user_sessions(actor, "subject") == 2

    for record in stored_sessions:
        remains = record.user_id != "subject"
        assert (management.sessions.load(record.id) is not None) == remains
    assert management.users.get("subject").is_active
    assert management.revoke_user_sessions(actor, "subject") == 0
    assert management.audit.user_management_events[-1].session_count == 0


def test_revocation_can_end_the_admins_own_sessions(
    management: UserManagement, actor: AuthenticatedUser,
) -> None:
    record = management.sessions.create(
        actor.id, datetime(2030, 1, 1, tzinfo=timezone.utc),
        ip_address=CLIENT_ADDRESS, user_agent=CLIENT_USER_AGENT,
    )

    assert management.revoke_user_sessions(actor, actor.id) == 1
    assert management.sessions.load(record.id) is None
    assert management.users.get(actor.id).is_active


def test_listing_keeps_the_stores_order_and_includes_inactive_accounts(
    management: UserManagement,
) -> None:
    with management.lock.hold():
        management.users.update("subject", is_active=False)

    assert management.list_users() == management.users.list()
    assert [user.id for user in management.list_users()] == ["actor", "subject"]
    assert management.audit.user_management_events == []


def test_listing_an_empty_store_returns_no_accounts(empty_management: UserManagement) -> None:
    assert empty_management.list_users() == []


def test_promoting_a_user_changes_the_stored_role(
    management: UserManagement, actor: AuthenticatedUser,
) -> None:
    user = management.change_role(actor, "subject", management.config.admin_role)

    assert user == management.users.get("subject")
    assert user.role == management.config.admin_role
    with management.lock.hold():
        assert management.users.count_active_admins(management.config.admin_role) == 2


@pytest.mark.parametrize("operation", [
    pytest.param(
        lambda m, a, password: m.create_user(a, "new-account", password, m.config.user_role),
        id="create_user",
    ),
    pytest.param(
        lambda m, a, password: complete_first_run_setup(m, "first-admin", password), id="setup",
    ),
])
@pytest.mark.parametrize(("password", "reason"), [
    ("password123", "Password is too common — choose something less predictable"),
    ("aaaaaaaabbbbbbbb", "Password must contain at least 4 unique characters"),
    ("abc", "Password must be at least 8 characters long"),
])
def test_both_password_accepting_flows_reject_weak_passwords_without_writing(
    empty_management: UserManagement, actor: AuthenticatedUser, operation: PasswordOperation,
    password: str, reason: str,
    caplog: pytest.LogCaptureFixture,
) -> None:
    management = empty_management
    with pytest.raises(WeakPasswordError) as error:
        operation(management, actor, password)

    with management.lock.hold():
        assert management.users.count() == 0
    assert management.audit.user_management_events == []
    assert str(error.value) == reason
    assert isinstance(error.value.__cause__, ValueError)
    assert str(error.value.__cause__) == reason
    assert password not in str(error.value)
    assert password not in caplog.text


def test_duplicate_usernames_raise_the_store_error_without_an_event(
    management: UserManagement, actor: AuthenticatedUser,
) -> None:
    with pytest.raises(UsernameTakenError):
        management.create_user(actor, "member", CHOSEN_PASSWORD, management.config.user_role)

    with management.lock.hold():
        assert management.users.count() == 2
    assert management.audit.user_management_events == []


@pytest.mark.parametrize("operation", [
    pytest.param(lambda m, a: m.change_role(a, "missing", m.config.admin_role), id="promote"),
    pytest.param(lambda m, a: m.change_role(a, "missing", m.config.user_role), id="demote"),
    pytest.param(lambda m, a: m.deactivate_user(a, "missing"), id="deactivate_user"),
    pytest.param(lambda m, a: m.revoke_user_sessions(a, "missing"), id="revoke_user_sessions"),
])
def test_an_unknown_subject_is_refused_without_an_event(
    management: UserManagement, actor: AuthenticatedUser, operation: AdminOperation,
) -> None:
    with pytest.raises(UnknownUserError):
        operation(management, actor)

    with management.lock.hold():
        assert management.users.count() == 2
    assert management.audit.user_management_events == []


@pytest.mark.parametrize("operation", ADMIN_OPERATIONS)
def test_authorization_precedes_subject_role_and_password_validation(
    empty_management: UserManagement, actor: AuthenticatedUser, operation: AdminOperation,
) -> None:
    management = replace(
        empty_management, config=replace(empty_management.config, admin_role="root"),
    )

    with pytest.raises(NotAnAdminError):
        operation(management, actor)

    with management.lock.hold():
        assert management.users.count() == 0
    assert management.audit.user_management_events == []


def test_a_non_admin_is_refused_before_weak_password_or_unknown_role_errors(
    management: UserManagement, actor: AuthenticatedUser,
) -> None:
    with pytest.raises(NotAnAdminError):
        management.create_user(replace(actor, role="member"), "new-account", "abc", "unknown")


@pytest.mark.parametrize(
    ("operation", "kind", "role_field", "session_count"),
    [
        pytest.param(
            create_member, "user_created", "user_role", None, id="user_created",
        ),
        pytest.param(
            promote_subject, "role_changed", "admin_role", 2, id="role_changed",
        ),
        pytest.param(
            deactivate_subject, "user_deactivated", None, 2, id="user_deactivated",
        ),
        pytest.param(
            revoke_subject_sessions, "sessions_revoked", None, 2, id="sessions_revoked",
        ),
    ],
)
def test_each_actor_flow_reports_exactly_its_public_event(
    management: UserManagement, actor: AuthenticatedUser,
    stored_sessions: list[FakeSessionRecord], operation: AdminOperation,
    kind: str, role_field: str | None, session_count: int | None,
    caplog: pytest.LogCaptureFixture,
) -> None:

    result = operation(management, actor)

    assert [asdict(event) for event in management.audit.user_management_events] == [{
        "kind": UserManagementEventKind(kind),
        "actor_id": actor.id,
        "subject_id": result.id if kind == "user_created" else "subject",
        "role": getattr(management.config, role_field) if role_field else None,
        "session_count": session_count,
        "session_ref": None,
    }]
    evidence = repr(management.audit.user_management_events) + caplog.text
    for secret in (
        CHOSEN_PASSWORD, management.config.password_hasher.hash(CHOSEN_PASSWORD),
        "new-account", *(record.id for record in stored_sessions),
    ):
        assert secret not in evidence


def test_first_setup_reports_exactly_the_first_admin_event(
    empty_management: UserManagement, caplog: pytest.LogCaptureFixture,
) -> None:
    user = complete_first_run_setup(empty_management, "first-administrator", CHOSEN_PASSWORD)

    assert [asdict(event) for event in empty_management.audit.user_management_events] == [{
        "kind": UserManagementEventKind.FIRST_ADMIN_CREATED,
        "actor_id": None,
        "subject_id": user.id,
        "role": empty_management.config.admin_role,
        "session_count": None,
        "session_ref": None,
    }]
    evidence = repr(empty_management.audit.user_management_events) + caplog.text
    for secret in (CHOSEN_PASSWORD, user.password_hash, user.username):
        assert secret not in evidence


def test_the_public_last_admin_guard_can_protect_a_host_write(
    management: UserManagement,
) -> None:
    with management.lock.hold(), pytest.raises(LastAdminError):
        management.ensure_not_last_admin("actor")

    with management.lock.hold():
        assert management.ensure_not_last_admin("subject") is None
        management.users.update("subject", role=management.config.admin_role)
        assert management.ensure_not_last_admin("actor") is None
        management.users.update("actor", role=management.config.user_role)

    with management.lock.hold():
        assert management.users.count_active_admins(management.config.admin_role) == 1
    assert management.audit.user_management_events == []


def test_the_public_last_admin_guard_refuses_an_unknown_account(management: UserManagement) -> None:
    with management.lock.hold(), pytest.raises(UnknownUserError):
        management.ensure_not_last_admin("missing")


def test_a_helper_without_the_write_lock_is_refused_by_the_store(
    empty_management: UserManagement, monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(empty_management.lock, "hold", nullcontext)

    with pytest.raises(LockNotHeldError):
        complete_first_run_setup(empty_management, "first-admin", CHOSEN_PASSWORD)

    assert empty_management.users.list() == []
    assert empty_management.audit.user_management_events == []


def test_shared_arrangements_supply_the_administration_protocols(
    management: UserManagement,
) -> None:
    assert isinstance(management.users, UserAdministrationStore)
    assert isinstance(management.audit, AuditSink)
    assert isinstance(management.lock, WriteLock)


def test_the_session_arrangement_prunes_only_the_subjects_oldest_sessions(
    management: UserManagement, stored_sessions: list[FakeSessionRecord],
) -> None:
    sessions = management.sessions
    newest = sessions.create(
        "subject", stored_sessions[0].expires_at + timedelta(minutes=5),
        ip_address=CLIENT_ADDRESS, user_agent=CLIENT_USER_AGENT,
    )

    assert set(sessions.prune_overflow("subject", 1)) == {
        record.id for record in stored_sessions if record.user_id == "subject"
    }
    assert sessions.load(newest.id) == newest
    assert sessions.load(stored_sessions[1].id) == stored_sessions[1]
    assert sessions.prune_overflow("subject", 1) == []
    assert sessions.prune_overflow("subject", 0) == [newest.id]


@pytest.mark.parametrize("error_type", [
    UsernameTakenError, UnknownUserError, NotAnAdminError, UnknownRoleError, LastAdminError,
    SelfDeactivationError, WeakPasswordError, SetupAlreadyDoneError, SetupRacedError,
    WrongPasswordError, UnknownSessionError, PasswordlessAccountError,
])
def test_hosts_can_catch_every_management_refusal_through_its_common_base(
    error_type: type[UserManagementError],
) -> None:
    with pytest.raises(UserManagementError):
        raise error_type()


PASSWORD_CHANGES = [
    pytest.param(reset_subject_password, "password_set_by_admin", "actor", id="admin_reset"),
    pytest.param(change_subject_own_password, "password_changed", "subject", id="own_password"),
]
PASSWORD_OPERATIONS = [
    pytest.param(reset_subject_password, id="admin_reset"),
    pytest.param(change_subject_own_password, id="own_password"),
]


@pytest.mark.parametrize(("operation", "kind", "actor_id"), PASSWORD_CHANGES)
def test_REQ_ADMIN_10_password_changes_end_all_subject_sessions_and_report_only_public_fields(
    management: UserManagement, actor: AuthenticatedUser,
    stored_sessions: list[FakeSessionRecord], operation: PasswordOperation,
    kind: str, actor_id: str, caplog: pytest.LogCaptureFixture,
) -> None:
    assert operation(management, actor, NEW_PASSWORD) is None

    subject = management.users.get("subject")
    assert management.config.password_hasher.verify(NEW_PASSWORD, subject.password_hash)
    assert not management.config.password_hasher.verify(CHOSEN_PASSWORD, subject.password_hash)
    assert [asdict(event) for event in management.audit.user_management_events] == [{
        "kind": UserManagementEventKind(kind),
        "actor_id": actor_id,
        "subject_id": "subject",
        "role": None,
        "session_count": 2,
        "session_ref": None,
    }]
    for record in stored_sessions:
        remains = record.user_id != "subject"
        assert (management.sessions.load(record.id) is not None) == remains
    evidence = repr(management.audit.user_management_events) + caplog.text
    for secret in (
        CHOSEN_PASSWORD, NEW_PASSWORD, subject.password_hash, subject.username,
        *(record.id for record in stored_sessions),
    ):
        assert secret not in evidence


@pytest.mark.parametrize("own_change", [True, False])
def test_REQ_ADMIN_10_an_admin_changing_their_own_password_ends_the_current_session(
    management: UserManagement, actor: AuthenticatedUser,
    stored_sessions: list[FakeSessionRecord], own_change: bool,
) -> None:
    current_session = stored_sessions[1]

    if own_change:
        management.change_own_password(actor, CHOSEN_PASSWORD, NEW_PASSWORD)
    else:
        management.set_password(actor, actor.id, NEW_PASSWORD)

    assert management.sessions.load(current_session.id) is None
    assert management.audit.user_management_events[-1].session_count == 1
    assert management.sessions.count_active() == 2


@pytest.mark.parametrize(("current", "new", "error_type"), [
    ("wrong-current-password", NEW_PASSWORD, WrongPasswordError),
    ("wrong-current-password", "password123", WrongPasswordError),
])
def test_REQ_ADMIN_10_refused_own_password_changes_preserve_password_and_every_session(
    management: UserManagement, actor: AuthenticatedUser,
    stored_sessions: list[FakeSessionRecord], current: str, new: str,
    error_type: type[UserManagementError], caplog: pytest.LogCaptureFixture,
) -> None:
    stored_hash = management.users.get(actor.id).password_hash

    with pytest.raises(error_type) as error:
        management.change_own_password(actor, current, new)

    assert management.users.get(actor.id).password_hash == stored_hash
    assert management.sessions.list_active() == stored_sessions
    assert management.audit.user_management_events == []
    evidence = str(error.value) + caplog.text
    for secret in (current, new, stored_hash, *(record.id for record in stored_sessions)):
        assert secret not in evidence


@pytest.mark.parametrize("proposed", [
    pytest.param(NEW_PASSWORD, id="a strong password"),
    pytest.param("password123", id="a weak password"),
])
@pytest.mark.parametrize("operation", PASSWORD_OPERATIONS)
def test_a_passwordless_account_refuses_every_password_change_without_writes(
    management: UserManagement, actor: AuthenticatedUser, operation: PasswordOperation,
    proposed: str,
) -> None:
    subject = PasswordlessUser(id="subject", username="member", role=management.config.user_role)
    management = a_user_management(management.users.get("actor"), subject, config=management.config)
    session = management.sessions.create(
        "subject", datetime(2030, 1, 1, tzinfo=timezone.utc),
        ip_address=CLIENT_ADDRESS, user_agent=CLIENT_USER_AGENT,
    )

    with pytest.raises(PasswordlessAccountError):
        operation(management, actor, proposed)

    assert management.users.get("subject").password_hash is None
    assert management.sessions.list_active() == [session]
    assert management.audit.user_management_events == []


@pytest.mark.parametrize("operation", PASSWORD_OPERATIONS)
def test_REQ_ADMIN_10_password_changes_reject_weak_passwords_without_writes(
    management: UserManagement, actor: AuthenticatedUser,
    stored_sessions: list[FakeSessionRecord], operation: PasswordOperation,
) -> None:
    stored_hash = management.users.get("subject").password_hash

    with pytest.raises(WeakPasswordError):
        operation(management, actor, "password123")

    assert management.users.get("subject").password_hash == stored_hash
    assert management.sessions.list_active() == stored_sessions
    assert management.audit.user_management_events == []


@pytest.mark.parametrize(("hasher", "typed", "admitted", "refused"), [
    pytest.param(
        LegibleHasher(), DECOMPOSED_PASSWORD, [DECOMPOSED_PASSWORD], [COMPOSED_PASSWORD],
        id="injected_hasher_decomposed",
    ),
    pytest.param(
        LegibleHasher(), COMPOSED_PASSWORD, [COMPOSED_PASSWORD], [DECOMPOSED_PASSWORD],
        id="injected_hasher_composed",
    ),
    pytest.param(
        a_cheap_argon2id_hasher(), DECOMPOSED_PASSWORD,
        [DECOMPOSED_PASSWORD, COMPOSED_PASSWORD], [], id="argon2id_decomposed",
    ),
    pytest.param(
        a_cheap_argon2id_hasher(), COMPOSED_PASSWORD,
        [COMPOSED_PASSWORD, DECOMPOSED_PASSWORD], [], id="argon2id_composed",
    ),
])
@pytest.mark.parametrize("operation", PASSWORD_OPERATIONS)
def test_REQ_ADMIN_10_a_changed_password_logs_in_as_its_hasher_matches_the_typed_spelling(
    actor: AuthenticatedUser, operation: PasswordOperation, hasher: PasswordHasher,
    typed: str, admitted: list[str], refused: list[str],
) -> None:
    management = a_management_hashing_with(hasher)

    operation(management, actor, typed)

    subject = management.users.get("subject")
    for spelling in admitted:
        assert judge_credentials(spelling, subject, hasher=hasher) is LoginOutcome.ADMITTED
    for spelling in refused:
        assert judge_credentials(spelling, subject, hasher=hasher) is LoginOutcome.WRONG_PASSWORD
    management.change_own_password(
        the_subject_signed_in(management, actor), typed, NEW_PASSWORD,
    )
    changed = management.users.get("subject")
    assert judge_credentials(NEW_PASSWORD, changed, hasher=hasher) is LoginOutcome.ADMITTED


@pytest.mark.parametrize("own_change", [True, False])
def test_REQ_ADMIN_10_password_changes_refuse_an_unknown_account(
    empty_management: UserManagement, actor: AuthenticatedUser, own_change: bool,
) -> None:
    with pytest.raises(UnknownUserError):
        if own_change:
            empty_management.change_own_password(actor, CHOSEN_PASSWORD, NEW_PASSWORD)
        else:
            empty_management.set_password(actor, "missing", NEW_PASSWORD)

    assert empty_management.audit.user_management_events == []


@pytest.mark.parametrize("operation", [
    pytest.param(lambda m, a: m.set_password(a, "subject", NEW_PASSWORD), id="set_password"),
    pytest.param(
        lambda m, a: m.change_own_password(a, CHOSEN_PASSWORD, NEW_PASSWORD),
        id="change_own_password",
    ),
])
def test_password_writes_require_the_host_lock(
    management: UserManagement, actor: AuthenticatedUser,
    stored_sessions: list[FakeSessionRecord], operation: AdminOperation,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    hashes = [user.password_hash for user in management.users.list()]
    monkeypatch.setattr(management.lock, "hold", nullcontext)

    with pytest.raises(LockNotHeldError):
        operation(management, actor)

    assert [user.password_hash for user in management.users.list()] == hashes
    assert management.sessions.list_active() == stored_sessions
    assert management.audit.user_management_events == []
