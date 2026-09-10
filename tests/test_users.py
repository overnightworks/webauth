"""Account administration through the same ports the hosts implement."""

from __future__ import annotations

from collections.abc import Callable
from contextlib import nullcontext
from dataclasses import FrozenInstanceError, asdict, replace
from datetime import datetime, timedelta, timezone

import pytest
from webauth_arrangement import (
    CLIENT_ADDRESS,
    CLIENT_USER_AGENT,
    Argon2idStyleHasher,
    FakeSessionRecord,
    FakeUser,
    LockNotHeldError,
    UsersWithSetupRace,
    a_session_cache,
    a_session_cache_failing_on,
    a_user_management,
    a_web_auth_config,
)

from webauth.dependencies import AuthenticatedUser
from webauth.ports import (
    AuditSink,
    SessionAdministrationStore,
    UnknownUserError,
    UserAdministrationStore,
    UserManagementError,
    UserManagementEventKind,
    UsernameTakenError,
    UserRecord,
    WriteLock,
)
from webauth.users import (
    LastAdminError,
    NotAnAdminError,
    SelfDeactivationError,
    SessionSummary,
    SetupAlreadyDoneError,
    SetupRacedError,
    UnknownRoleError,
    UnknownSessionError,
    UserManagement,
    WeakPasswordError,
    WrongPasswordError,
    complete_first_run_setup,
    session_reference,
)

CHOSEN_PASSWORD = "River!Lantern92"
NEW_PASSWORD = "Mountain!Beacon83"
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


ADMIN_OPERATIONS = [
    pytest.param(create_member, id="create_user"),
    pytest.param(promote_subject, id="change_role"),
    pytest.param(deactivate_subject, id="deactivate_user"),
    pytest.param(revoke_subject_sessions, id="revoke_user_sessions"),
    pytest.param(lambda m, a: m.set_password(a, "subject", NEW_PASSWORD), id="set_password"),
    pytest.param(lambda m, a: m.revoke_session(a, "unknown"), id="revoke_session"),
]

@pytest.fixture
def management() -> UserManagement:
    config = a_web_auth_config(
        admin_role="operator", user_role="member", password_hasher=Argon2idStyleHasher(),
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
def actor(management: UserManagement) -> AuthenticatedUser:
    return AuthenticatedUser(
        id="actor", username="administrator", role=management.config.admin_role, is_active=True,
    )


@pytest.fixture
def empty_management(management: UserManagement) -> UserManagement:
    return a_user_management(config=management.config)


@pytest.fixture
def cached_management(management: UserManagement) -> UserManagement:
    return replace(management, config=replace(management.config, session_cache=a_session_cache()))


@pytest.fixture
def stored_sessions(cached_management: UserManagement) -> list[FakeSessionRecord]:
    management = cached_management
    cache = management.config.session_cache
    records = []
    for user_id in ("subject", "actor", "subject"):
        record = management.sessions.create(
            user_id,
            datetime(2030, 1, 1, tzinfo=timezone.utc),
            ip_address=CLIENT_ADDRESS,
            user_agent=CLIENT_USER_AGENT,
        )
        cache.store(
            record.id, record.user_id, record.user.username, record.user.role,
            record.user.is_active, record.ip_address, record.user_agent,
            record.expires_at, record.created_at, management.config.session_max_age_seconds,
        )
        records.append(record)
    subject = management.users.get("subject")
    cache.store(
        "cache-only-session", subject.id, subject.username, subject.role, subject.is_active,
        CLIENT_ADDRESS, CLIENT_USER_AGENT, records[0].expires_at, records[0].created_at,
        management.config.session_max_age_seconds,
    )
    return records


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
@pytest.mark.parametrize("with_cache", [True, False])
def test_REQ_ADMIN_10_role_change_and_deactivation_end_every_subject_session(
    cached_management: UserManagement, actor: AuthenticatedUser,
    stored_sessions: list[FakeSessionRecord], with_cache: bool,
    operation: AdminOperation, initial_role_field: str, final_role_field: str, kind: str,
) -> None:
    management = cached_management
    if not with_cache:
        management = replace(management, config=replace(management.config, session_cache=None))

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
        if with_cache:
            assert (management.config.session_cache.get(record.id) is not None) == remains
    if with_cache:
        assert management.config.session_cache.get("cache-only-session") is None


@pytest.mark.parametrize("role_field", ["admin_role", "user_role"])
def test_repeating_the_stored_role_keeps_sessions_and_reports_no_event(
    cached_management: UserManagement, actor: AuthenticatedUser,
    stored_sessions: list[FakeSessionRecord], role_field: str,
) -> None:
    management = cached_management
    role = getattr(management.config, role_field)
    with management.lock.hold():
        subject = management.users.update("subject", role=role)

    assert management.change_role(actor, "subject", role) == subject

    for record in stored_sessions:
        assert management.sessions.load(record.id) == record
        assert management.config.session_cache.get(record.id) is not None
    assert management.config.session_cache.get("cache-only-session") is not None
    assert management.audit.user_management_events == []


def test_revocation_returns_the_store_count_and_removes_cached_sessions_too(
    cached_management: UserManagement, actor: AuthenticatedUser,
    stored_sessions: list[FakeSessionRecord],
) -> None:
    management = cached_management

    assert management.revoke_user_sessions(actor, "subject") == 2

    for record in stored_sessions:
        remains = record.user_id != "subject"
        assert (management.sessions.load(record.id) is not None) == remains
        assert (management.config.session_cache.get(record.id) is not None) == remains
    assert management.config.session_cache.get("cache-only-session") is None
    assert management.users.get("subject").is_active
    assert management.revoke_user_sessions(actor, "subject") == 0
    assert management.audit.user_management_events[-1].session_count == 0


def test_revocation_without_a_cache_can_end_the_admins_own_sessions(
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
    ("abc", "Password must contain at least 4 unique characters"),
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
    cached_management: UserManagement, actor: AuthenticatedUser,
    stored_sessions: list[FakeSessionRecord], operation: AdminOperation,
    kind: str, role_field: str | None, session_count: int | None,
    caplog: pytest.LogCaptureFixture,
) -> None:
    management = cached_management

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
        "new-account", *(record.id for record in stored_sessions), "cache-only-session",
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
    assert isinstance(management.sessions, SessionAdministrationStore)
    assert isinstance(management.audit, AuditSink)
    assert isinstance(management.lock, WriteLock)


def test_the_session_arrangement_prunes_only_the_subjects_oldest_sessions(
    cached_management: UserManagement, stored_sessions: list[FakeSessionRecord],
) -> None:
    sessions = cached_management.sessions
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
    WrongPasswordError, UnknownSessionError,
])
def test_hosts_can_catch_every_management_refusal_through_its_common_base(
    error_type: type[UserManagementError],
) -> None:
    with pytest.raises(UserManagementError):
        raise error_type()


PASSWORD_CHANGES = [
    pytest.param(
        lambda m, a, password: m.set_password(a, "subject", password),
        "password_set_by_admin", "actor", id="admin_reset",
    ),
    pytest.param(
        lambda m, a, password: m.change_own_password(
            replace(a, id="subject", username="member", role=m.config.user_role),
            CHOSEN_PASSWORD, password,
        ),
        "password_changed", "subject", id="own_password",
    ),
]
PASSWORD_OPERATIONS = [
    pytest.param(change.values[0], id=change.id) for change in PASSWORD_CHANGES
]


@pytest.mark.parametrize(("operation", "kind", "actor_id"), PASSWORD_CHANGES)
@pytest.mark.parametrize("with_cache", [True, False])
def test_REQ_ADMIN_10_password_changes_end_all_subject_sessions_and_report_only_public_fields(
    cached_management: UserManagement, actor: AuthenticatedUser,
    stored_sessions: list[FakeSessionRecord], operation: PasswordOperation,
    kind: str, actor_id: str, with_cache: bool, caplog: pytest.LogCaptureFixture,
) -> None:
    management = cached_management
    if not with_cache:
        management = replace(management, config=replace(management.config, session_cache=None))

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
        if with_cache:
            assert (management.config.session_cache.get(record.id) is not None) == remains
    if with_cache:
        assert management.config.session_cache.get("cache-only-session") is None
    evidence = repr(management.audit.user_management_events) + caplog.text
    for secret in (
        CHOSEN_PASSWORD, NEW_PASSWORD, subject.password_hash, subject.username,
        *(record.id for record in stored_sessions), "cache-only-session",
    ):
        assert secret not in evidence


@pytest.mark.parametrize("own_change", [True, False])
def test_REQ_ADMIN_10_an_admin_changing_their_own_password_ends_the_current_session(
    cached_management: UserManagement, actor: AuthenticatedUser,
    stored_sessions: list[FakeSessionRecord], own_change: bool,
) -> None:
    management = cached_management
    current_session = stored_sessions[1]

    if own_change:
        management.change_own_password(actor, CHOSEN_PASSWORD, NEW_PASSWORD)
    else:
        management.set_password(actor, actor.id, NEW_PASSWORD)

    assert management.sessions.load(current_session.id) is None
    assert management.config.session_cache.get(current_session.id) is None
    assert management.audit.user_management_events[-1].session_count == 1
    assert management.sessions.count_active() == 2


@pytest.mark.parametrize(("current", "new", "error_type"), [
    ("wrong-current-password", NEW_PASSWORD, WrongPasswordError),
    ("wrong-current-password", "password123", WrongPasswordError),
])
def test_REQ_ADMIN_10_refused_own_password_changes_preserve_password_and_every_session(
    cached_management: UserManagement, actor: AuthenticatedUser,
    stored_sessions: list[FakeSessionRecord], current: str, new: str,
    error_type: type[UserManagementError], caplog: pytest.LogCaptureFixture,
) -> None:
    management = cached_management
    stored_hash = management.users.get(actor.id).password_hash

    with pytest.raises(error_type) as error:
        management.change_own_password(actor, current, new)

    assert management.users.get(actor.id).password_hash == stored_hash
    assert management.sessions.list_active() == stored_sessions
    for record in stored_sessions:
        assert management.config.session_cache.get(record.id) is not None
    assert management.audit.user_management_events == []
    evidence = str(error.value) + caplog.text
    for secret in (current, new, stored_hash, *(record.id for record in stored_sessions)):
        assert secret not in evidence


@pytest.mark.parametrize("operation", PASSWORD_OPERATIONS)
def test_REQ_ADMIN_10_password_changes_reject_weak_passwords_without_writes(
    cached_management: UserManagement, actor: AuthenticatedUser,
    stored_sessions: list[FakeSessionRecord], operation: PasswordOperation,
) -> None:
    management = cached_management
    stored_hash = management.users.get("subject").password_hash

    with pytest.raises(WeakPasswordError):
        operation(management, actor, "password123")

    assert management.users.get("subject").password_hash == stored_hash
    assert management.sessions.list_active() == stored_sessions
    for record in stored_sessions:
        assert management.config.session_cache.get(record.id) is not None
    assert management.config.session_cache.get("cache-only-session") is not None
    assert management.audit.user_management_events == []


@pytest.mark.parametrize("operation", PASSWORD_OPERATIONS)
def test_REQ_ADMIN_10_password_changes_delete_from_the_store_before_a_cache_failure(
    cached_management: UserManagement, actor: AuthenticatedUser,
    stored_sessions: list[FakeSessionRecord], operation: PasswordOperation,
) -> None:
    management = replace(cached_management, config=replace(
        cached_management.config, session_cache=a_session_cache_failing_on("smembers"),
    ))

    with pytest.raises(ConnectionError):
        operation(management, actor, NEW_PASSWORD)

    assert management.sessions.list_active() == [stored_sessions[1]]
    assert management.audit.user_management_events == []


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


@pytest.mark.parametrize(("offset", "limit"), [(0, None), (1, 1), (1, None), (0, 0), (9, 2)])
def test_REQ_ADMIN_12_listing_returns_only_public_fields_in_the_stores_page_order(
    cached_management: UserManagement, stored_sessions: list[FakeSessionRecord],
    offset: int, limit: int | None, caplog: pytest.LogCaptureFixture,
) -> None:
    management = cached_management

    summaries = management.list_sessions(offset, limit)

    page = stored_sessions[offset:None if limit is None else offset + limit]
    assert [asdict(summary) for summary in summaries] == [{
        "session_ref": session_reference(record.id),
        "user_id": record.user_id,
        "username": record.user.username,
        "ip_address": record.ip_address,
        "user_agent": record.user_agent,
    } for record in page]
    assert management.sessions.count_active() == len(stored_sessions)
    assert management.audit.user_management_events == []
    evidence = repr(summaries) + caplog.text
    for secret in (
        CHOSEN_PASSWORD, management.users.get("subject").password_hash,
        *(record.id for record in stored_sessions), "cache-only-session",
    ):
        assert secret not in evidence


def test_REQ_ADMIN_12_an_empty_store_has_no_session_summaries(
    empty_management: UserManagement,
) -> None:
    assert empty_management.list_sessions() == []
    assert empty_management.sessions.count_active() == 0


@pytest.mark.parametrize("with_cache", [True, False])
@pytest.mark.parametrize("session_index", [0, 1, 2])
def test_REQ_ADMIN_12_an_admin_revokes_one_listed_session_without_its_raw_token(
    cached_management: UserManagement, actor: AuthenticatedUser,
    stored_sessions: list[FakeSessionRecord], with_cache: bool, session_index: int,
    caplog: pytest.LogCaptureFixture,
) -> None:
    management = cached_management
    if not with_cache:
        management = replace(management, config=replace(management.config, session_cache=None))
    summary = management.list_sessions(offset=session_index, limit=1)[0]

    assert management.revoke_session(actor, summary.session_ref) is None

    for index, record in enumerate(stored_sessions):
        remains = index != session_index
        assert (management.sessions.load(record.id) is not None) == remains
        if with_cache:
            assert (management.config.session_cache.get(record.id) is not None) == remains
    if with_cache:
        assert management.config.session_cache.get("cache-only-session") is not None
    assert management.sessions.count_active() == 2
    assert [asdict(event) for event in management.audit.user_management_events] == [{
        "kind": UserManagementEventKind.SESSION_REVOKED,
        "actor_id": actor.id,
        "subject_id": summary.user_id,
        "role": None,
        "session_count": None,
        "session_ref": summary.session_ref,
    }]
    evidence = repr(management.audit.user_management_events) + caplog.text
    for secret in (
        CHOSEN_PASSWORD, management.users.get("subject").password_hash,
        summary.username, *(record.id for record in stored_sessions),
    ):
        assert secret not in evidence


def test_REQ_ADMIN_12_revoking_a_consumed_reference_is_refused_without_another_event(
    cached_management: UserManagement, actor: AuthenticatedUser,
    stored_sessions: list[FakeSessionRecord],
) -> None:
    management = cached_management
    summary = management.list_sessions(limit=1)[0]
    management.revoke_session(actor, summary.session_ref)

    with pytest.raises(UnknownSessionError):
        management.revoke_session(actor, summary.session_ref)

    assert management.sessions.list_active() == stored_sessions[1:]
    assert len(management.audit.user_management_events) == 1


def test_REQ_ADMIN_12_revoking_a_session_deletes_from_the_store_before_a_cache_failure(
    cached_management: UserManagement, actor: AuthenticatedUser,
    stored_sessions: list[FakeSessionRecord],
) -> None:
    management = replace(cached_management, config=replace(
        cached_management.config, session_cache=a_session_cache_failing_on("pipeline"),
    ))
    record = stored_sessions[0]
    summary = management.list_sessions(limit=1)[0]

    with pytest.raises(ConnectionError):
        management.revoke_session(actor, summary.session_ref)

    assert management.sessions.load(record.id) is None
    assert management.audit.user_management_events == []


@pytest.mark.parametrize("reference", ["unknown", "", "é", "session-1", "0" * 64])
def test_REQ_ADMIN_12_unknown_or_raw_session_references_preserve_every_session(
    cached_management: UserManagement, actor: AuthenticatedUser,
    stored_sessions: list[FakeSessionRecord], reference: str, caplog: pytest.LogCaptureFixture,
) -> None:
    management = cached_management

    with pytest.raises(UnknownSessionError) as error:
        management.revoke_session(actor, reference)

    assert management.sessions.list_active() == stored_sessions
    for record in stored_sessions:
        assert management.config.session_cache.get(record.id) is not None
        assert record.id not in str(error.value) + caplog.text
    assert management.audit.user_management_events == []


@pytest.mark.parametrize("operation", [
    pytest.param(lambda m, a: m.set_password(a, "subject", NEW_PASSWORD), id="set_password"),
    pytest.param(
        lambda m, a: m.change_own_password(a, CHOSEN_PASSWORD, NEW_PASSWORD),
        id="change_own_password",
    ),
    pytest.param(
        lambda m, a: m.revoke_session(a, m.list_sessions()[0].session_ref), id="revoke_session",
    ),
])
def test_password_and_session_writes_require_the_host_lock(
    cached_management: UserManagement, actor: AuthenticatedUser,
    stored_sessions: list[FakeSessionRecord], operation: AdminOperation,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    management = cached_management
    hashes = [user.password_hash for user in management.users.list()]
    monkeypatch.setattr(management.lock, "hold", nullcontext)

    with pytest.raises(LockNotHeldError):
        operation(management, actor)

    assert [user.password_hash for user in management.users.list()] == hashes
    assert management.sessions.list_active() == stored_sessions
    assert management.audit.user_management_events == []


@pytest.mark.parametrize(("session_id", "reference"), [
    ("", "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"),
    ("abc", "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"),
    ("é", "4a99557e4033c3539de2eb65472017cad5f9557f7a0625a09f1c3f6e2ba69c4c"),
])
def test_REQ_ADMIN_12_session_references_are_the_sha256_hex_of_utf8_identifiers(
    session_id: str, reference: str,
) -> None:
    assert session_reference(session_id) == reference


def test_REQ_ADMIN_12_session_summaries_are_immutable(
    cached_management: UserManagement, stored_sessions: list[FakeSessionRecord],
) -> None:
    summary = cached_management.list_sessions()[0]

    assert isinstance(summary, SessionSummary)
    with pytest.raises(FrozenInstanceError):
        summary.session_ref = "replacement"
