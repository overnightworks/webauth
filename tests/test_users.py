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
    Argon2idStyleHasher,
    FakeSessionRecord,
    FakeUser,
    LockNotHeldError,
    UsersWithSetupRace,
    a_session_cache,
    a_user_management,
    a_web_auth_config,
)

from webauth.dependencies import AuthenticatedUser
from webauth.ports import (
    AuditSink,
    SessionRecordStore,
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
    SetupAlreadyDoneError,
    SetupRacedError,
    UnknownRoleError,
    UserManagement,
    WeakPasswordError,
    complete_first_run_setup,
)

CHOSEN_PASSWORD = "River!Lantern92"
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
]

@pytest.fixture
def management() -> UserManagement:
    config = a_web_auth_config(
        admin_role="operator", user_role="member", password_hasher=Argon2idStyleHasher(),
    )
    return a_user_management(
        FakeUser(id="actor", username="administrator", role=config.admin_role),
        FakeUser(id="subject", username="member", role=config.user_role),
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


@pytest.mark.parametrize("with_cache", [True, False])
def test_REQ_ADMIN_10_deactivation_ends_every_subject_session_and_keeps_other_users_sessions(
    cached_management: UserManagement, actor: AuthenticatedUser,
    stored_sessions: list[FakeSessionRecord], with_cache: bool,
) -> None:
    management = cached_management
    if not with_cache:
        management = replace(management, config=replace(management.config, session_cache=None))

    management.deactivate_user(actor, "subject")

    assert not management.users.get("subject").is_active
    for record in stored_sessions:
        remains = record.user_id != "subject"
        assert (management.sessions.load(record.id) is not None) == remains
        if with_cache:
            assert (management.config.session_cache.get(record.id) is not None) == remains
    if with_cache:
        assert management.config.session_cache.get("cache-only-session") is None


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
@pytest.mark.parametrize("password", ["password123", "aaaaaaaabbbbbbbb", "abc"])
def test_both_password_accepting_flows_reject_weak_passwords_without_writing(
    empty_management: UserManagement, actor: AuthenticatedUser, operation: PasswordOperation,
    password: str,
    caplog: pytest.LogCaptureFixture,
) -> None:
    management = empty_management
    with pytest.raises(WeakPasswordError) as error:
        operation(management, actor, password)

    with management.lock.hold():
        assert management.users.count() == 0
    assert management.audit.user_management_events == []
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
            promote_subject, "role_changed", "admin_role", None, id="role_changed",
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
    assert isinstance(management.sessions, SessionRecordStore)
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
])
def test_hosts_can_catch_every_management_refusal_through_its_common_base(
    error_type: type[UserManagementError],
) -> None:
    with pytest.raises(UserManagementError):
        raise error_type()
