"""Signing in through the bound issuer, from a host's start and callback routes.

The admission tests drive `admit_identity` on its own: an identity the bound
issuer vouched for becomes, or reuses, an account. The host tests drive a
FastAPI host with a start route and a callback route
through a `TestClient` whose cookie jar is the browser, against a stateful
fake issuer that answers each code once.
"""

from __future__ import annotations

import base64
import logging
import secrets
import threading
import urllib.parse
from collections.abc import Callable, Iterator
from concurrent.futures import ThreadPoolExecutor
from contextlib import AbstractContextManager, contextmanager
from copy import deepcopy
from dataclasses import asdict, dataclass, replace
from datetime import UTC, datetime, timedelta
from typing import NoReturn

import anyio.to_thread
import pytest
from fastapi import Depends, FastAPI, Request, Response
from fastapi.testclient import TestClient
from httpx import Response as HttpxResponse
from oidc_arrangement import (
    ABSENT,
    ISSUED_ACCESS_TOKEN_CANARY,
    ISSUED_REFRESH_TOKEN,
    FakeClock,
    FakeIssuer,
    FakeKeySetEndpoint,
    LogoutPage,
    a_fake_id_token,
    a_logout_token,
    a_token_of_length,
    assert_holds_only_the_refresh_token,
    jws,
    key_set_document,
    public_jwk,
    rs256,
    rsa_key,
)
from pydantic import SecretStr
from webauth_arrangement import (
    ADMIN_ROLE,
    FIXED_INSTANT,
    FIXED_WALL_CLOCK,
    HTTPS_TEST_SERVER,
    MEMBER_ROLE,
    SESSION_IDLE_SECONDS,
    FakeSessionRecord,
    FakeUser,
    RecordingAuditSink,
    SessionRecordsInMemory,
    UsersInMemory,
    UsersWithCaseInsensitiveUsernames,
    UsersWithoutUniqueUsernames,
    WriteLockInMemory,
    _require_held_lock,
    a_web_auth_config,
    an_http_scope,
    seeded_session,
    session_cookie_header,
    signed_without_bound,
)

from webauth.config import WebAuthConfig, install_web_auth_config
from webauth.cookies import (
    MAX_SESSION_COOKIE_CHARS,
    PendingLogin,
    _pending_login_cookie_name,
    _pending_login_cookie_prefix,
    _sign_pending_login,
    _verify_pending_login,
    issue_session_cookies,
    sign_session_id,
)
from webauth.dependencies import current_user_dependency
from webauth.jwt_verification import MAX_TOKEN_CHARACTERS
from webauth.middleware import install_web_auth_middleware
from webauth.oidc import (
    PENDING_LOGIN_MAX_AGE_SECONDS,
    OidcClientConfig,
    OidcIdentity,
    OidcRefusal,
    OidcRelyingParty,
)
from webauth.oidc_login import (
    AdmissionConfig,
    AdmissionRefusal,
    AdmittedLogin,
    AppRole,
    BackchannelLogoutResult,
    EverySubject,
    NoAdmins,
    admit_identity,
    app_role,
    finish_login,
    fresh_access_token,
    log_out,
    open_session,
    receive_backchannel_logout,
    start_login,
)
from webauth.policies import (
    BodySizePolicy,
    BodySizeRule,
    CacheControlRule,
    CsrfPolicy,
    PathRules,
    RateLimitBudget,
    RateLimitPolicy,
    SecurityHeadersPolicy,
)
from webauth.ports import (
    AccountEventKind,
    AuthenticatedUser,
    SessionRecord,
    UserRecord,
)

MAX_PENDING_LOGIN_COOKIE_CHARS = 896
MAX_PENDING_LOGINS = 5

BOUND_ISSUER = "https://id.example/realms/lab"
BOUND_ISSUER_ORIGIN = "https://id.example"
LOGIN_GROUP = "/apps/lab"
ADMIN_GROUP = f"{LOGIN_GROUP}/admin"
ADMISSION = AdmissionConfig(
    bound_issuer=BOUND_ISSUER, login_group=LOGIN_GROUP, admin_group=ADMIN_GROUP,
)
SUBJECT = "5f0c2a1e-7d4b-4c55-9a51-2f8e3c6b1d90"
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
LEGACY_ADMIN = FakeUser(id=SUBJECT, username="lena.legacy", role=ADMIN_ROLE)


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

    account = host.admit(replace(LENA, preferred_username=preferred_username))

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
            bound_issuer=BOUND_ISSUER, login_group=login_group, admin_group=NoAdmins.IN_THIS_APP,
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
            admin_group=admin_group,
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

    account = host.admit(LENA)

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

    account = host.admit(LENA_IN_THE_ADMIN_GROUP)

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

    first = host.admit(LENA)
    second = host.admit(other_lena)

    assert (first.id, second.id) == (LENA.subject, other_lena.subject)
    assert (first.username, second.username) == ("lena", "lena")


NOW = 1_800_000_000
CLIENT_ID = "lab-app <\"&'>"
CALLBACK_PATH = "/auth/callback"
END_SESSION_ENDPOINT = f"{BOUND_ISSUER}/protocol/openid-connect/logout"
LOGOUT_PATH = "/logout"
LOGOUT_BUTTON_LABEL = "Sign <out> & \"go'"
OLD_HINT_COOKIE_NAME = "__Secure-oidc_id_token_hint"  # noqa: S105
OLD_CSRF_COOKIE_NAME = "__Host-csrf_token"  # noqa: S105
BACKCHANNEL_LOGOUT_PATH = "/auth/backchannel-logout"
BACKCHANNEL_LOGOUT_MAX_BODY_BYTES = 32 * 1024
DEFAULT_MAX_BODY_BYTES = 1024


def a_client_config() -> OidcClientConfig:
    return OidcClientConfig(
        issuer=BOUND_ISSUER,
        authorization_endpoint=f"{BOUND_ISSUER}/protocol/openid-connect/auth",
        token_endpoint=f"{BOUND_ISSUER}/protocol/openid-connect/token",
        jwks_url=f"{BOUND_ISSUER}/protocol/openid-connect/certs",
        end_session_endpoint=END_SESSION_ENDPOINT,
        client_id=CLIENT_ID,
        client_secret=SecretStr("client-secret"),
        redirect_uri=f"{HTTPS_TEST_SERVER}{CALLBACK_PATH}",
        post_logout_redirect_uri=f"{HTTPS_TEST_SERVER}/",
        leeway_seconds=30,
    )


class CountingWriteLock(WriteLockInMemory):
    def __init__(self) -> None:
        super().__init__()
        self.times_taken = 0

    @contextmanager
    def hold(self) -> Iterator[None]:
        self.times_taken += 1
        with self.hold_uncounted():
            yield

    def hold_uncounted(self) -> AbstractContextManager[None]:
        return super().hold()


@dataclass
class OidcHost:
    """A host application and the browser that visits it."""

    client: TestClient
    issuer: FakeIssuer
    key_set: FakeKeySetEndpoint
    wall_clock: FakeClock
    accounts: UsersInMemory
    sessions: SessionRecordsInMemory
    audit: RecordingAuditSink
    config: WebAuthConfig
    lock: CountingWriteLock
    relying_party: OidcRelyingParty
    issued_id_tokens: list[str]
    returned_to: list[str | None]
    admitted_logins: list[AdmittedLogin]

    def start(self, *, return_to: str | None = None) -> str:
        """Visit the start route; answer the authorization URL it sends the browser to."""
        params = {} if return_to is None else {"next": return_to}
        return self.client.get("/login/oidc", params=params).json()["authorization_url"]

    def sign_in_at_issuer(self, *, return_to: str | None = None) -> str:
        """Start a login and sign in at the issuer; answer the callback query."""
        return self.issuer.authorize(self.start(return_to=return_to))

    def callback(self, query: str, *, cookie: str | None = None) -> HttpxResponse:
        """Return to the callback route, with the browser's cookies or only ``cookie``."""
        if cookie is not None:
            self.client.cookies.clear()
        headers = {} if cookie is None else {"cookie": cookie}
        return self.client.get(f"{CALLBACK_PATH}?{query}", headers=headers)

    def pending_cookie_names(self) -> set[str]:
        prefix = _pending_login_cookie_prefix(secure=self.config.cookie_secure)
        return {name for name in self.client.cookies if name.startswith(prefix)}

    def pending_cookie_name(self, query: str) -> str:
        [state] = urllib.parse.parse_qs(query)["state"]
        return _pending_login_cookie_name(state, secure=self.config.cookie_secure)

    def pending_cookie(self, query: str) -> str:
        """The ``name=value`` the browser holds for the login of ``query``."""
        name = self.pending_cookie_name(query)
        return f"{name}={self.client.cookies[name]}"


def an_id_token(nonce: str, wall_clock: FakeClock, groups_claim: object, padding: str = "") -> str:
    now = int(wall_clock.now)
    claims = {
        "iss": BOUND_ISSUER,
        "aud": CLIENT_ID,
        "sub": SUBJECT,
        "exp": now + 300,
        "iat": now - 10,
        "nonce": nonce,
        "preferred_username": "lena",
        "groups": groups_claim,
    }
    header = {"alg": "RS256", "kid": "issuer-key", "typ": "JWT"}
    if padding:
        header["padding"] = padding
    return jws(header, claims, rs256(rsa_key("issuer")))


def a_logout_token_of_the_issuer(
    *, claims: dict[str, object] | None = None, header: dict[str, object] | None = None,
    key_name: str = "issuer",
) -> str:
    return a_logout_token(
        issuer=BOUND_ISSUER,
        audience=CLIENT_ID,
        subject=SUBJECT,
        now=NOW,
        key_id="issuer-key",
        key_name=key_name,
        claims=claims,
        header=header,
    )


def an_oidc_host(
    *users: FakeUser,
    groups_claim: object = (LOGIN_GROUP,),
    address_budget: int | None = None,
    max_sessions: int | None = None,
    root_path: str = "",
    **config_overrides: object,
) -> OidcHost:
    config = a_web_auth_config(**config_overrides)
    lock = CountingWriteLock()
    accounts = UsersInMemory(*users, lock=lock)
    sessions = SessionRecordsInMemory(users=accounts, lock=lock)
    audit = RecordingAuditSink()
    wall_clock = FakeClock(float(NOW))
    issued_id_tokens: list[str] = []
    returned_to: list[str | None] = []
    admitted_logins: list[AdmittedLogin] = []

    def mint_id_token(nonce: str) -> str:
        issued_id_tokens.append(an_id_token(nonce, wall_clock, groups_claim))
        return issued_id_tokens[-1]

    issuer = FakeIssuer(mint_id_token=mint_id_token)
    key_set = FakeKeySetEndpoint(key_set_document(public_jwk(rsa_key("issuer"), "issuer-key")))
    relying_party = OidcRelyingParty(
        a_client_config(),
        post_token_request=issuer,
        fetch_key_set=key_set,
        wall_clock=wall_clock,
        monotonic_clock=FakeClock(5_000.0),
    )
    authenticated: list[AuthenticatedUser] = []
    dependencies = current_user_dependency(
        session_store=lambda: sessions,
        on_authenticated=authenticated.append,
    )

    backchannel_path = PathRules(exact=frozenset({BACKCHANNEL_LOGOUT_PATH}))
    app = FastAPI()
    install_web_auth_config(app, config)
    install_web_auth_middleware(
        app,
        security_headers=SecurityHeadersPolicy(
            content_security_policy="default-src 'self'",
            cache_control_rules=(CacheControlRule(paths=backchannel_path, value="no-store"),),
        ),
        body_size=BodySizePolicy(
            default_max_bytes=DEFAULT_MAX_BODY_BYTES,
            rules=(BodySizeRule(
                paths=backchannel_path, max_bytes=BACKCHANNEL_LOGOUT_MAX_BODY_BYTES,
            ),),
        ),
        rate_limit=None if address_budget is None else RateLimitPolicy(
            default=RateLimitBudget("host", address_budget, 60), exempt=backchannel_path,
        ),
        csrf_origin=CsrfPolicy(exempt=backchannel_path),
    )

    @app.get("/login/oidc")
    def start(
        request: Request, response: Response, next: str | None = None,  # noqa: A002
    ) -> dict[str, str]:
        return {"authorization_url": start_login(
            relying_party, request, response, config, return_to=next,
        )}

    @app.get(CALLBACK_PATH)
    def callback(request: Request, response: Response) -> dict[str, str]:
        outcome = finish_login(
            relying_party, request, response, config,
            admission=ADMISSION, accounts=accounts, lock=lock, audit=audit,
        )
        if isinstance(outcome, OidcRefusal):
            response.status_code = 403
            return {"refusal": outcome.reason.value}
        if isinstance(outcome, AdmissionRefusal):
            response.status_code = 403
            return {"refusal": outcome.value}
        returned_to.append(outcome.return_to)
        admitted_logins.append(outcome)
        with sessions.transaction():
            session = open_session(
                request, config, outcome, sessions=sessions, lock=lock,
                max_sessions=max_sessions, keeps_id_token=True,
            )
        issue_session_cookies(response, session.id, config)
        return {"username": outcome.account.username}

    @app.post(LOGOUT_PATH)
    def form_logout(request: Request) -> Response:
        return log_out(
            relying_party, request, config,
            sessions=sessions, lock=lock, button_label=LOGOUT_BUTTON_LABEL,
        )

    def end_the_sessions_of(form_body: bytes, content_type: str | None) -> BackchannelLogoutResult:
        with sessions.transaction():
            return receive_backchannel_logout(
                relying_party, form_body, content_type,
                accounts=accounts, sessions=sessions, lock=lock, audit=audit,
            )

    @app.post(BACKCHANNEL_LOGOUT_PATH)
    async def backchannel_logout(request: Request) -> Response:
        form_body = await request.body()
        content_type = request.headers.get("content-type")
        try:
            result = await anyio.to_thread.run_sync(end_the_sessions_of, form_body, content_type)
        except Exception:
            logging.getLogger(__name__).exception("back-channel logout failed")
            return Response(status_code=400)
        return Response(
            status_code=200 if result is BackchannelLogoutResult.ACCEPTED else 400,
        )

    @app.get("/admin")
    def admin(user: AuthenticatedUser = Depends(dependencies.admin_user)) -> dict[str, str]:
        return {"username": user.username}

    @app.get("/me")
    def me(user: AuthenticatedUser = Depends(dependencies.current_user)) -> dict[str, str]:
        return {"username": user.username}

    return OidcHost(
        client=TestClient(
            app, base_url=HTTPS_TEST_SERVER, cookies={}, root_path=root_path,
        ),
        issuer=issuer,
        key_set=key_set,
        wall_clock=wall_clock,
        accounts=accounts,
        sessions=sessions,
        audit=audit,
        config=config,
        lock=lock,
        relying_party=relying_party,
        issued_id_tokens=issued_id_tokens,
        returned_to=returned_to,
        admitted_logins=admitted_logins,
    )


def set_cookies(response: HttpxResponse) -> dict[str, set[str]]:
    """Each cookie the response sets or clears, by name, with its attributes
    lower-cased and without the clock-dependent ``Expires``."""
    cookies: dict[str, set[str]] = {}
    for header, value in response.headers.multi_items():
        if header == "set-cookie":
            pair, *attributes = value.split("; ")
            cookies[pair.partition("=")[0]] = {
                attribute.lower()
                for attribute in attributes
                if not attribute.lower().startswith("expires=")
            }
    return cookies


def is_cleared(response: HttpxResponse, name: str) -> bool:
    return "max-age=0" in set_cookies(response).get(name, set())


@pytest.mark.parametrize(("cookie_secure", "prefix", "secure_attribute"), [
    pytest.param(True, "__Host-oidc_pending_", {"secure"}, id="secure"),
    pytest.param(False, "oidc_pending_", set(), id="insecure-development"),
])
def test_a_start_sets_one_lax_http_only_pending_cookie_and_answers_the_issuer_url(
    *, cookie_secure: bool, prefix: str, secure_attribute: set[str],
) -> None:
    host = an_oidc_host(cookie_secure=cookie_secure)

    response = host.client.get("/login/oidc")

    url = response.json()["authorization_url"]
    assert url.startswith(a_client_config().authorization_endpoint + "?")
    name = host.pending_cookie_name(urllib.parse.urlsplit(url).query)
    assert name.startswith(prefix)
    assert set_cookies(response) == {
        name: {
            "httponly",
            f"max-age={PENDING_LOGIN_MAX_AGE_SECONDS}",
            "path=/",
            "samesite=lax",
            *secure_attribute,
        },
    }


def test_an_admitted_callback_signs_the_browser_in_with_the_configured_cookies() -> None:
    host = an_oidc_host()

    response = host.callback(host.sign_in_at_issuer())

    configured = {"path=/", f"max-age={host.config.session_lifetime.absolute_max_age_seconds}",
                  f"samesite={host.config.cookie_samesite}", "secure"}
    assert response.status_code == 200
    assert set_cookies(response)[host.config.session_cookie_name] == configured | {"httponly"}
    assert set(host.client.cookies) == {host.config.session_cookie_name}
    assert host.client.get("/me").json() == {"username": "lena"}


def test_an_admitted_callback_stores_the_refresh_token_and_nothing_of_the_access_token() -> None:
    host = an_oidc_host()

    response = host.callback(host.sign_in_at_issuer())

    record = host.sessions.record
    assert record is not None
    assert stored_refresh_tokens(host) == [ISSUED_REFRESH_TOKEN]
    [admitted] = host.admitted_logins
    visible = (
        repr(record) + repr(host.sessions.list_active()) + repr(admitted)
        + str(response.headers)
    )
    assert ISSUED_ACCESS_TOKEN_CANARY not in visible
    assert ISSUED_REFRESH_TOKEN not in visible
    assert_holds_only_the_refresh_token(admitted)
    assert_holds_only_the_refresh_token(record)


@pytest.mark.parametrize(("members", "stored"), [
    pytest.param({"refresh_token": ABSENT}, [], id="an-answer-without-a-refresh-token"),
    pytest.param(
        {"access_token": ABSENT, "token_type": ABSENT}, [ISSUED_REFRESH_TOKEN],
        id="an-answer-without-an-access-token",
    ),
    pytest.param({"refresh_token": " ~"}, [" ~"], id="a-refresh-token-at-the-grammars-ends"),
])
def test_an_admitted_callback_stores_what_the_code_answer_issued(
    members: dict[str, object], stored: list[str],
) -> None:
    host = an_oidc_host()
    host.issuer.code_answer_members.update(members)

    response = host.callback(host.sign_in_at_issuer())

    assert response.status_code == 200
    assert stored_refresh_tokens(host) == stored
    assert host.sessions.count_active() == 1


@pytest.mark.parametrize("refresh_token", [
    pytest.param("", id="empty"),
    pytest.param(42, id="a-number"),
    pytest.param(None, id="null"),
    pytest.param("rt\x00", id="with-a-nul"),
    pytest.param("rt\r", id="with-a-carriage-return"),
    pytest.param("rt\n", id="with-a-line-feed"),
    pytest.param("rt\x7f", id="with-a-del"),
    pytest.param("rté", id="non-ascii"),
    pytest.param("rt\ud800", id="a-lone-surrogate"),
])
def test_a_refresh_token_outside_the_grammar_refuses_the_login_and_provisions_nothing(
    refresh_token: object,
) -> None:
    host = an_oidc_host()
    host.issuer.code_answer_members["refresh_token"] = refresh_token

    response = host.callback(host.sign_in_at_issuer())

    assert (response.status_code, response.json()) == (403, {"refusal": "token-endpoint-failed"})
    assert host.sessions.count_active() == 0
    assert host.accounts.list() == []


@pytest.mark.parametrize(("seconds_into_the_instant", "seconds_per_reading"), [
    pytest.param(0.0, 0.0, id="a fixed clock"),
    pytest.param(0.9, 0.4, id="an advancing clock"),
])
def test_an_admitted_callback_opens_the_session_for_one_idle_from_one_whole_second_reading(
    seconds_into_the_instant: float, seconds_per_reading: float,
) -> None:
    clock = FakeClock(FIXED_INSTANT.timestamp() + seconds_into_the_instant, seconds_per_reading)
    host = an_oidc_host(wall_clock=clock)

    host.callback(host.sign_in_at_issuer())

    record = host.sessions.record
    assert record is not None
    assert (record.created_at, record.expires_at) == (
        FIXED_INSTANT, FIXED_INSTANT + timedelta(seconds=SESSION_IDLE_SECONDS),
    )
    assert host.client.get("/me").json() == {"username": "lena"}


@pytest.mark.parametrize("cookie_secure", [True, False])
def test_the_callback_hands_the_browser_no_id_token_and_each_login_replaces_the_rows_token(
    *, cookie_secure: bool,
) -> None:
    host = an_oidc_host(cookie_secure=cookie_secure)
    host.callback(host.sign_in_at_issuer())

    response = host.callback(host.sign_in_at_issuer())

    first, second = host.issued_id_tokens
    [login] = host.admitted_logins[1:]
    shown = " ".join([
        repr(host.sessions.list_active()),
        repr(login),
        *(value for _, value in response.headers.multi_items()),
    ])
    assert first != second
    assert second not in shown
    assert not [name for name in set_cookies(response) if "id_token" in name]
    assert stored_id_tokens(host) == [second]


def test_an_id_token_of_the_verifiers_longest_length_is_stored_and_sent_whole() -> None:
    host = an_oidc_host()
    host.issuer.mint_id_token = lambda nonce: a_token_of_length(
        MAX_TOKEN_CHARACTERS,
        lambda header_padding, groups_padding: an_id_token(
            nonce, host.wall_clock, [LOGIN_GROUP, groups_padding], header_padding,
        ),
    )
    host.callback(host.sign_in_at_issuer())
    [stored] = stored_id_tokens(host)

    response = post_logout(host, SAME_ORIGIN_FORM)

    assert (len(stored), hint_of(response)) == (MAX_TOKEN_CHARACTERS, stored)


@dataclass(frozen=True)
class RefusedCallback:
    """A callback that does not sign in: the callback query the browser brings
    back given the issuer's."""

    refusal: str
    groups_claim: object = (LOGIN_GROUP,)
    returned_query: Callable[[OidcHost, str], str] = lambda _host, query: query


def _with_another_code(_host: OidcHost, query: str) -> str:
    return query.replace("code=", "code=not-issued-")


def _after_the_pending_lifetime(host: OidcHost, query: str) -> str:
    host.wall_clock.now += PENDING_LOGIN_MAX_AGE_SECONDS + 1
    return query


def _with_the_code_twice(_host: OidcHost, query: str) -> str:
    return f"{query}&code=another"


def _with_an_undecodable_parameter(_host: OidcHost, query: str) -> str:
    return f"{query}&note=%ff"


_REFUSED_CALLBACKS = [
    pytest.param(
        RefusedCallback("token-request-refused", returned_query=_with_another_code),
        id="a code the issuer never issued",
    ),
    pytest.param(
        RefusedCallback("pending-login-expired", returned_query=_after_the_pending_lifetime),
        id="a pending login past its lifetime",
    ),
    pytest.param(
        RefusedCallback("malformed-callback", returned_query=_with_the_code_twice),
        id="its one state beside a code named twice",
    ),
    pytest.param(
        RefusedCallback("malformed-callback", returned_query=_with_an_undecodable_parameter),
        id="its one state beside an undecodable parameter",
    ),
    pytest.param(
        RefusedCallback("not-a-member", groups_claim=["/apps/other"]),
        id="a person in another app's group only",
    ),
    pytest.param(
        RefusedCallback("not-a-member", groups_claim=[]),
        id="a person whose groups claim is empty",
    ),
    pytest.param(
        RefusedCallback("invalid-identity-claim", groups_claim="/apps/lab"),
        id="a groups claim that is not a list",
    ),
]


@pytest.mark.parametrize("refused", _REFUSED_CALLBACKS)
def test_a_refused_callback_issues_no_session_leaves_no_account_and_consumes_its_cookie(
    refused: RefusedCallback,
) -> None:
    host = an_oidc_host(groups_claim=refused.groups_claim)
    other_tab = host.sign_in_at_issuer()
    query = host.sign_in_at_issuer()

    response = host.callback(refused.returned_query(host, query))

    assert (response.status_code, response.json()) == (403, {"refusal": refused.refusal})
    assert host.config.session_cookie_name not in set_cookies(response)
    assert host.sessions.count_active() == 0
    assert host.accounts.list() == []
    assert is_cleared(response, host.pending_cookie_name(query))
    assert host.pending_cookie_names() == {host.pending_cookie_name(other_tab)}


def test_a_callback_demotes_a_legacy_admin_without_the_admin_group() -> None:
    host = an_oidc_host(deepcopy(LEGACY_ADMIN))

    response = host.callback(host.sign_in_at_issuer())

    assert (response.status_code, response.json()) == (200, {"username": "lena.legacy"})
    assert host.sessions.count_active() == 1
    assert host.client.get("/me").json() == {"username": "lena.legacy"}
    assert host.client.get("/admin").status_code == 403
    assert [event.kind for event in host.audit.account_events] == [
        AccountEventKind.ROLE_CHANGED,
    ]


def test_a_callback_keeps_a_legacy_admin_in_the_admin_group_as_admin() -> None:
    host = an_oidc_host(deepcopy(LEGACY_ADMIN), groups_claim=[ADMIN_GROUP])

    response = host.callback(host.sign_in_at_issuer())

    assert response.status_code == 200
    assert host.client.get("/admin").json() == {"username": "lena.legacy"}
    assert host.audit.account_events == []


@pytest.mark.parametrize(("before", "after", "status_before", "status_after"), [
    pytest.param([LOGIN_GROUP], [ADMIN_GROUP], 403, 200, id="put into the admin group"),
    pytest.param([ADMIN_GROUP], [LOGIN_GROUP], 200, 403, id="taken out of the admin group"),
])
def test_a_role_changed_at_login_reaches_the_persons_other_open_session_at_once(
    before: list[str], after: list[str], status_before: int, status_after: int,
) -> None:
    groups = list(before)
    host = an_oidc_host(groups_claim=groups)
    host.callback(host.sign_in_at_issuer())
    session_cookie = host.client.cookies[host.config.session_cookie_name]
    assert host.client.get("/admin").status_code == status_before

    groups[:] = after
    host.client.cookies.clear()
    host.callback(host.sign_in_at_issuer())
    host.client.cookies.clear()
    host.client.cookies.set(host.config.session_cookie_name, session_cookie)

    assert host.client.get("/admin").status_code == status_after


@pytest.mark.parametrize(("asked_for", "returned"), [
    pytest.param("/albums/42", "/albums/42", id="a deep link"),
    pytest.param("//evil.example", None, id="another host"),
])
def test_a_login_returns_only_a_path_of_this_app_and_otherwise_the_default_page(
    asked_for: str, returned: str | None,
) -> None:
    host = an_oidc_host()

    response = host.callback(host.sign_in_at_issuer(return_to=asked_for))

    assert response.status_code == 200
    assert host.returned_to == [returned]


def test_a_login_started_without_a_return_path_lands_on_the_default_page() -> None:
    host = an_oidc_host()

    host.callback(host.sign_in_at_issuer())

    assert host.returned_to == [None]


@pytest.mark.parametrize("signed", ["//evil.example", "/albums/42#top"])
def test_a_return_path_signed_by_another_build_is_judged_again_at_the_callback(
    signed: str,
) -> None:
    host = an_oidc_host()
    query = host.sign_in_at_issuer()
    name = host.pending_cookie_name(query)
    pending = _verify_pending_login(host.client.cookies[name], host.config.signing_key)
    assert pending is not None
    resigned = _sign_pending_login(
        replace(pending, return_to=signed), host.config.signing_key,
    )

    response = host.callback(query, cookie=f"{name}={resigned}")

    assert response.status_code == 200
    assert host.returned_to == [None]


def test_the_return_path_of_a_refused_login_is_not_handed_out() -> None:
    host = an_oidc_host(groups_claim=())

    response = host.callback(host.sign_in_at_issuer(return_to="/albums/42"))

    assert (response.status_code, host.returned_to) == (403, [])


def test_an_admitted_callback_consumes_its_cookie_and_keeps_the_other_tabs() -> None:
    host = an_oidc_host()
    other_tab = host.sign_in_at_issuer()
    query = host.sign_in_at_issuer()

    response = host.callback(query)

    assert response.json() == {"username": "lena"}
    assert is_cleared(response, host.pending_cookie_name(query))
    assert host.pending_cookie_names() == {host.pending_cookie_name(other_tab)}


def _tampered(host: OidcHost, query: str) -> str:
    cookie = host.pending_cookie(query)
    return cookie[:-1] + ("0" if cookie[-1] != "0" else "1")


def _signed_under_another_key(host: OidcHost, query: str) -> str:
    return _forged(host, query, NOW, secret=b"k" * 64)


def _signed_as_a_session(host: OidcHost, query: str) -> str:
    name, _, value = host.pending_cookie(query).partition("=")
    payload = value.rpartition(".")[0]
    return f"{name}={signed_without_bound(payload, host.config.signing_key)}"


def _oversized(host: OidcHost, query: str) -> str:
    return host.pending_cookie(query) + "0" * MAX_PENDING_LOGIN_COOKIE_CHARS


def _of_another_version(host: OidcHost, query: str) -> str:
    return host.pending_cookie(query).replace("=v2.", "=v3.", 1)


def _with_a_return_path_added_after_signing(host: OidcHost, query: str) -> str:
    name, _, value = host.pending_cookie(query).partition("=")
    *signed_fields, _return_path, signature = value.split(".")
    altered_path = base64.urlsafe_b64encode(b"/albums/42").decode().rstrip("=")
    return f"{name}={'.'.join([*signed_fields, altered_path, signature])}"


def _twice(host: OidcHost, query: str) -> str:
    cookie = host.pending_cookie(query)
    return f"{cookie}; {cookie}"


def _absent(_host: OidcHost, _query: str) -> str:
    return "unrelated=1"


def _another_logins_under_this_name(host: OidcHost, query: str) -> str:
    other_value = host.pending_cookie(host.sign_in_at_issuer()).partition("=")[2]
    return f"{host.pending_cookie_name(query)}={other_value}"


def _forged(host: OidcHost, query: str, issued_at: int, *, secret: bytes | None = None) -> str:
    """A pending login for the callback's state that the host never began."""
    [state] = urllib.parse.parse_qs(query)["state"]
    pending = PendingLogin(
        state=state,
        nonce=secrets.token_urlsafe(32),
        code_verifier=secrets.token_urlsafe(32),
        issued_at=issued_at,
    )
    value = _sign_pending_login(pending, secret or host.config.signing_key)
    return f"{host.pending_cookie_name(query)}={value}"


@pytest.mark.parametrize(("pending_cookie", "refusal"), [
    pytest.param(_absent, "state-mismatch", id="no pending cookie for the state"),
    pytest.param(_tampered, "state-mismatch", id="a tampered signature"),
    pytest.param(_signed_under_another_key, "state-mismatch", id="signed under another key"),
    pytest.param(_signed_as_a_session, "state-mismatch", id="signed as a session cookie"),
    pytest.param(_oversized, "state-mismatch", id="oversized"),
    pytest.param(_of_another_version, "state-mismatch", id="another version"),
    pytest.param(
        _with_a_return_path_added_after_signing, "state-mismatch",
        id="a return path altered after signing",
    ),
    pytest.param(_twice, "state-mismatch", id="the genuine cookie twice"),
    pytest.param(
        _another_logins_under_this_name, "state-mismatch",
        id="another login's genuine cookie under this state's name",
    ),
    pytest.param(
        lambda host, query: _forged(host, query, NOW - PENDING_LOGIN_MAX_AGE_SECONDS - 1),
        "pending-login-expired",
        id="signed but issued before the lifetime",
    ),
    pytest.param(
        lambda host, query: _forged(host, query, NOW + 1),
        "pending-login-expired",
        id="signed but dated in the future",
    ),
])
def test_an_invalid_pending_cookie_is_refused_before_any_token_request_and_cleared(
    pending_cookie: Callable[[OidcHost, str], str], refusal: str,
) -> None:
    host = an_oidc_host()
    query = host.sign_in_at_issuer()
    cookie = pending_cookie(host, query)

    response = host.callback(query, cookie=cookie)

    assert (response.status_code, response.json()) == (403, {"refusal": refusal})
    assert host.issuer.requests == []
    assert is_cleared(response, host.pending_cookie_name(query))
    assert host.accounts.list() == []


@pytest.mark.parametrize(("returned_query", "refusal"), [
    pytest.param(lambda query: query.replace("state=", "other="), "state-mismatch",
                 id="without a state"),
    pytest.param(lambda query: f"{query}&{query.partition('&')[0]}", "malformed-callback",
                 id="naming its state twice"),
    pytest.param(lambda query: query.replace("state=", "state=&other=", 1), "state-mismatch",
                 id="naming an empty state"),
    pytest.param(lambda query: query.replace("state=", "state=%ff", 1), "malformed-callback",
                 id="naming an undecodable state"),
])
def test_a_callback_without_one_state_is_refused_and_selects_no_cookie(
    returned_query: Callable[[str], str], refusal: str,
) -> None:
    host = an_oidc_host()
    query = host.sign_in_at_issuer()

    response = host.callback(returned_query(query))

    assert (response.status_code, response.json()) == (403, {"refusal": refusal})
    assert host.issuer.requests == []
    assert set_cookies(response) == {}
    assert host.pending_cookie_names() == {host.pending_cookie_name(query)}


def test_a_pending_login_is_single_use() -> None:
    host = an_oidc_host()
    query = host.sign_in_at_issuer()
    kept_cookie = host.pending_cookie(query)
    host.callback(query)

    replayed_by_the_browser = host.callback(query)
    replayed_with_a_kept_cookie = host.callback(query, cookie=kept_cookie)

    assert replayed_by_the_browser.json() == {"refusal": "state-mismatch"}
    assert replayed_with_a_kept_cookie.json() == {"refusal": "token-request-refused"}
    assert len(host.issuer.requests) == 2
    assert host.sessions.count_active() == 1


def test_a_concurrent_replay_of_one_callback_signs_in_exactly_once() -> None:
    host = an_oidc_host()
    query = host.sign_in_at_issuer()
    cookie = host.pending_cookie(query)
    host.issuer.before_exchange = threading.Barrier(2, timeout=10).wait

    with ThreadPoolExecutor(max_workers=2) as pool:
        responses = list(pool.map(lambda _: host.callback(query, cookie=cookie), range(2)))

    assert sorted(response.status_code for response in responses) == [200, 403]
    assert {"refusal": "token-request-refused"} in [response.json() for response in responses]
    assert host.sessions.count_active() == 1
    assert len(host.accounts.list()) == 1


@pytest.mark.parametrize("second_returns_first", [False, True], ids=["in order", "reversed"])
def test_two_tabs_both_sign_in_and_the_later_session_replaces_the_earlier(
    *, second_returns_first: bool,
) -> None:
    host = an_oidc_host()
    tabs = [host.sign_in_at_issuer(), host.sign_in_at_issuer()]
    if second_returns_first:
        tabs.reverse()

    first, second = (host.callback(query) for query in tabs)

    assert first.json() == {"username": "lena"}
    assert second.json() == {"username": "lena"}
    assert host.sessions.count_active() == 1
    assert host.pending_cookie_names() == set()


def test_starts_beyond_the_cap_evict_the_oldest_pending_cookie_and_keep_the_session() -> None:
    host = signed_in_host()
    queries = []
    for _ in range(MAX_PENDING_LOGINS + 1):
        queries.append(host.sign_in_at_issuer())
        host.wall_clock.now += 1

    assert host.pending_cookie_names() == {host.pending_cookie_name(q) for q in queries[1:]}
    assert set(host.client.cookies) >= {host.config.session_cookie_name}
    assert host.client.get("/me").json() == {"username": "lena"}
    assert host.callback(queries[0]).json() == {"refusal": "state-mismatch"}


def _a_forged_pending_cookie(host: OidcHost) -> str:
    name = f"{_pending_login_cookie_prefix(secure=True)}{'f' * 16}"
    host.client.cookies.set(name, "v2.forged", domain="testserver.local", path="/")
    return name


def _the_newest_genuine_pending_cookie_twice(host: OidcHost) -> str:
    name = host.pending_cookie_name(host.sign_in_at_issuer())
    value = host.client.cookies[name]
    host.client.cookies.set(name, value, domain="testserver.local", path="/login")
    return name


@pytest.mark.parametrize("unranked_cookie", [
    pytest.param(_a_forged_pending_cookie, id="a forged value"),
    pytest.param(_the_newest_genuine_pending_cookie_twice, id="a name sent twice"),
])
def test_a_start_at_the_cap_evicts_an_unranked_pending_cookie_before_any_genuine_one(
    unranked_cookie: Callable[[OidcHost], str],
) -> None:
    host = an_oidc_host()
    for _ in range(MAX_PENDING_LOGINS - 1):
        host.sign_in_at_issuer()
        host.wall_clock.now += 1
    unranked = unranked_cookie(host)

    response = host.client.get("/login/oidc")

    assert [name for name in set_cookies(response) if is_cleared(response, name)] == [unranked]


def test_a_start_at_the_cap_leaves_a_prefixed_cookie_of_another_shape_alone() -> None:
    host = an_oidc_host()
    genuine = {host.pending_cookie_name(host.sign_in_at_issuer()) for _ in range(4)}
    stranger = f"{_pending_login_cookie_prefix(secure=True)}a@b"
    host.client.cookies.set(stranger, "x", domain="testserver.local", path="/")

    response = host.client.get("/login/oidc")

    newest = host.pending_cookie_name(
        urllib.parse.urlsplit(response.json()["authorization_url"]).query
    )
    assert host.pending_cookie_names() == genuine | {stranger, newest}


SAME_ORIGIN_FORM = {
    "origin": HTTPS_TEST_SERVER,
    "sec-fetch-site": "same-origin",
    "content-type": "application/x-www-form-urlencoded",
}


def signed_in_host(**config_overrides: object) -> OidcHost:
    host = an_oidc_host(**config_overrides)
    host.callback(host.sign_in_at_issuer())
    assert stored_refresh_tokens(host) == [ISSUED_REFRESH_TOKEN]
    return host


def post_logout(host: OidcHost, headers: dict[str, str]) -> HttpxResponse:
    return host.client.post(LOGOUT_PATH, headers=headers, follow_redirects=False)


def content_security_policy_of(response: HttpxResponse) -> dict[str, list[str]]:
    directives = (
        directive.split() for directive in response.headers["content-security-policy"].split("; ")
    )
    return {name: sources for name, *sources in directives}


def test_the_logout_page_posts_the_client_and_the_hint_to_the_end_session_endpoint() -> None:
    host = signed_in_host()

    response = post_logout(host, SAME_ORIGIN_FORM)

    page = LogoutPage(response.text)
    assert response.status_code == 200
    assert response.headers["content-type"] == "text/html; charset=utf-8"
    assert page.attributes_of("form") == [{"method": "post", "action": END_SESSION_ENDPOINT}]
    assert page.attributes_of("input") == [
        {"type": "hidden", "name": "client_id", "value": CLIENT_ID},
        {
            "type": "hidden",
            "name": "post_logout_redirect_uri",
            "value": a_client_config().post_logout_redirect_uri,
        },
        {"type": "hidden", "name": "id_token_hint", "value": host.issued_id_tokens[-1]},
    ]
    assert page.attributes_of("button") == [{"type": "submit"}]
    assert (page.texts["button"], page.texts["title"]) == (LOGOUT_BUTTON_LABEL, LOGOUT_BUTTON_LABEL)
    assert {tag for tag, _ in page.elements} == {
        "html", "head", "meta", "title", "body", "form", "input", "button", "script",
    }


def test_the_logout_policy_admits_the_one_inline_script_by_hash_and_posts_to_two_origins() -> None:
    host = signed_in_host()

    response = post_logout(host, SAME_ORIGIN_FORM)

    page = LogoutPage(response.text)
    policy = content_security_policy_of(response)
    assert policy["script-src"] == [page.script_source]
    assert policy["form-action"] == [BOUND_ISSUER_ORIGIN, HTTPS_TEST_SERVER]
    assert [name for _, attributes in page.elements for name in attributes
            if name.startswith("on")] == []


def hint_of(response: HttpxResponse) -> str | None:
    return LogoutPage(response.text).hidden_fields.get("id_token_hint")


def test_after_back_channel_logout_no_stored_row_holds_the_login_token() -> None:
    host = signed_in_host()

    post_logout_token(host, a_logout_token_of_the_issuer())

    assert host.issued_id_tokens[-1] not in stored_id_tokens(host)


def test_rotation_and_renewal_keep_the_logins_id_token_for_the_logout() -> None:
    session_clock = FakeClock(float(NOW))
    host = signed_in_host(wall_clock=session_clock)
    login_token = host.issued_id_tokens[-1]
    host.issuer.refresh_answer_members = {"id_token": a_fake_id_token("issued-by-the-refresh")}
    [session] = host.sessions.list_active()
    expiry_before_renewal = session.expires_at
    session_clock.now += SESSION_IDLE_SECONDS / 2

    renewed = host.client.get("/me")
    rotated = fresh_access_token(
        host.relying_party, session.id,
        session_transaction=host.sessions.in_transaction, config=host.config,
    )
    held_after_rotation = stored_id_tokens(host)
    response = post_logout(host, SAME_ORIGIN_FORM)

    assert (renewed.status_code, isinstance(rotated, SecretStr)) == (200, True)
    assert session.expires_at > expiry_before_renewal
    assert held_after_rotation == [login_token]
    assert hint_of(response) == login_token


def the_session_cookie_is_cleared(host: OidcHost, response: HttpxResponse) -> bool:
    return is_cleared(response, host.config.session_cookie_name)


def test_the_answer_carries_the_rows_token_ends_the_row_and_sets_only_clearings() -> None:
    host = signed_in_host()
    record = host.sessions.record
    assert record is not None
    record.id_token = SecretStr(a_fake_id_token("held-by-the-row"))
    [rows_token] = stored_id_tokens(host)

    response = post_logout(host, SAME_ORIGIN_FORM)

    header_values = " ".join(value for _, value in response.headers.multi_items())
    assert set(set_cookies(response)) == {host.config.session_cookie_name}
    assert the_session_cookie_is_cleared(host, response)
    assert "location" not in response.headers
    assert rows_token not in header_values
    assert hint_of(response) == rows_token
    assert (host.sessions.count_active(), stored_id_tokens(host), stored_refresh_tokens(host)) == (
        0, [], [],
    )


def _no_session(_host: OidcHost) -> dict[str, str]:
    return {}


def _forged_session_cookie(host: OidcHost) -> dict[str, str]:
    name = host.config.session_cookie_name
    forged = f"{name}={host.client.cookies[name]}tampered"
    host.client.cookies.clear()
    return {"cookie": forged}


def _session_cookie_dropped(host: OidcHost) -> dict[str, str]:
    host.client.cookies.delete(host.config.session_cookie_name)
    return {}


def _session_ended_in_the_store(host: OidcHost) -> dict[str, str]:
    host.sessions.delete_for_user(SUBJECT)
    return {}


def _session_expired_but_stored(host: OidcHost) -> dict[str, str]:
    record = host.sessions.record
    assert record is not None
    record.expires_at = datetime.now(UTC) - timedelta(days=1)
    return {}


def _row_stored_before_the_upgrade(host: OidcHost) -> dict[str, str]:
    record = host.sessions.record
    assert record is not None
    record.id_token = None
    return {}


@pytest.mark.parametrize(("arrange", "sessions_kept", "hint_sent", "lock_taken"), [
    pytest.param(_no_session, 0, False, False, id="no-session"),
    pytest.param(_forged_session_cookie, 1, False, False, id="forged-cookie-ends-nothing"),
    pytest.param(_session_cookie_dropped, 1, False, False, id="session-cookie-gone"),
    pytest.param(_session_ended_in_the_store, 0, False, True, id="session-already-ended"),
    pytest.param(_session_expired_but_stored, 0, True, True, id="session-expired-but-stored"),
    pytest.param(_row_stored_before_the_upgrade, 0, False, True, id="stored-before-upgrade"),
])
def test_a_same_origin_logout_still_answers_the_page(
    arrange: Callable[[OidcHost], dict[str, str]],
    sessions_kept: int,
    *,
    hint_sent: bool,
    lock_taken: bool,
) -> None:
    host = an_oidc_host()
    if arrange is not _no_session:
        host.callback(host.sign_in_at_issuer())
    extra_headers = arrange(host)
    taken_before = host.lock.times_taken

    response = post_logout(host, {**SAME_ORIGIN_FORM, **extra_headers})

    page = LogoutPage(response.text)
    assert response.status_code == 200
    assert page.attributes_of("form") == [{"method": "post", "action": END_SESSION_ENDPOINT}]
    assert hint_of(response) == (host.issued_id_tokens[-1] if hint_sent else None)
    assert the_session_cookie_is_cleared(host, response)
    assert host.sessions.count_active() == sessions_kept
    assert host.lock.times_taken - taken_before == lock_taken


@pytest.mark.parametrize("old_cookie_name", [OLD_HINT_COOKIE_NAME, OLD_CSRF_COOKIE_NAME])
@pytest.mark.parametrize("signed_in", [True, False])
def test_an_old_cookie_changes_no_decision_and_is_neither_read_nor_cleared(
    *, signed_in: bool, old_cookie_name: str,
) -> None:
    def decisions(*, carrying_old_cookie: bool) -> tuple[int, object, int, int, int]:
        host = signed_in_host() if signed_in else an_oidc_host()
        if carrying_old_cookie:
            host.client.cookies.set(old_cookie_name, a_fake_id_token("set-before-the-upgrade"))
        refused = post_logout(host, {**SAME_ORIGIN_FORM, "sec-fetch-site": "cross-site"})
        refusal = (refused.status_code, refused.json(), host.sessions.count_active())
        reply = post_logout(host, SAME_ORIGIN_FORM)
        assert old_cookie_name not in set_cookies(reply)
        assert hint_of(reply) == (host.issued_id_tokens[-1] if signed_in else None)
        return (*refusal, reply.status_code, host.sessions.count_active())
    expected = (403, {"detail": "Cross-origin request rejected"}, int(signed_in), 200, 0)
    assert decisions(carrying_old_cookie=True) == decisions(carrying_old_cookie=False) == expected


@pytest.mark.parametrize("headers", [
    pytest.param({"sec-fetch-site": "cross-site"}, id="cross-site-fetch-metadata"),
    pytest.param({"origin": "https://evil.test"}, id="foreign-origin"),
    pytest.param({}, id="form-with-neither-header"),
])
def test_a_cross_site_logout_is_refused_and_ends_nothing(headers: dict[str, str]) -> None:
    host = signed_in_host()

    response = post_logout(host, {"content-type": "application/x-www-form-urlencoded", **headers})

    assert response.status_code == 403
    assert host.sessions.count_active() == 1
    assert set_cookies(response) == {}


def test_a_logout_reaches_no_issuer_endpoint() -> None:
    host = signed_in_host()
    exchanges_before = len(host.issuer.requests)
    fetches_before = len(host.key_set.fetched_urls)

    def unreachable() -> None:
        raise OSError("the issuer is down")

    host.issuer.before_exchange = unreachable
    host.key_set.before_answer = unreachable

    response = post_logout(host, SAME_ORIGIN_FORM)

    assert hint_of(response) == host.issued_id_tokens[-1]
    assert host.sessions.count_active() == 0
    assert len(host.issuer.requests) == exchanges_before
    assert len(host.key_set.fetched_urls) == fetches_before


def test_the_logout_form_carries_the_configured_values_whatever_the_request_names() -> None:
    host = signed_in_host()
    query = urllib.parse.urlencode({
        "post_logout_redirect_uri": "https://evil.test/",
        "redirect": "https://evil.test/",
        "client_id": "someone-else",
    })

    response = host.client.post(
        f"{LOGOUT_PATH}?{query}", headers=SAME_ORIGIN_FORM, content=query,
    )

    assert LogoutPage(response.text).hidden_fields == {
        "client_id": CLIENT_ID,
        "post_logout_redirect_uri": a_client_config().post_logout_redirect_uri,
        "id_token_hint": host.issued_id_tokens[-1],
    }


OTHER_SUBJECT = "0b6f1d7e-3c8a-4e0b-8d52-6a1f9e4c7b23"
FORM_MEDIA_TYPE = "application/x-www-form-urlencoded"
FORM = {"content-type": FORM_MEDIA_TYPE}


def a_host_with_sessions(
    *, subject_sessions: int, other_sessions: int = 0, address_budget: int | None = None,
    max_sessions: int | None = None,
) -> OidcHost:
    host = an_oidc_host(
        FakeUser(id=SUBJECT, username="lena"), FakeUser(id=OTHER_SUBJECT, username="omar"),
        address_budget=address_budget, max_sessions=max_sessions,
    )
    open_sessions(host, SUBJECT, subject_sessions)
    open_sessions(host, OTHER_SUBJECT, other_sessions)
    return host


def stored_refresh_tokens(host: OidcHost) -> list[str]:
    return [record.refresh_token.get_secret_value()
            for record in host.sessions.list_active() if record.refresh_token is not None]


def stored_id_tokens(host: OidcHost) -> list[str]:
    return [record.id_token.get_secret_value()
            for record in host.sessions.list_active() if record.id_token is not None]


def open_sessions(host: OidcHost, user_id: str, count: int) -> None:
    first_created_at = datetime.now(UTC) - timedelta(minutes=30)
    for minute in range(count):
        created_at = first_created_at + timedelta(minutes=minute)
        seeded_session(
            host.sessions, host.lock.hold_uncounted(), user_id,
            created_at, created_at + timedelta(seconds=SESSION_IDLE_SECONDS),
            SecretStr(f"{user_id}-refresh-token-{minute}"),
        )


def sessions_of(host: OidcHost, user_id: str) -> int:
    return len(host.sessions.sessions_of(user_id))


def post_backchannel_logout(
    host: OidcHost, content: bytes | Iterator[bytes], headers: dict[str, str] = FORM,
) -> HttpxResponse:
    return host.client.post(BACKCHANNEL_LOGOUT_PATH, content=content, headers=headers)


def a_form_of(logout_token: str, **other_fields: str) -> bytes:
    return urllib.parse.urlencode({"logout_token": logout_token, **other_fields}).encode()


def post_logout_token(host: OidcHost, logout_token: str, **other_fields: str) -> HttpxResponse:
    return post_backchannel_logout(host, a_form_of(logout_token, **other_fields))


def test_a_valid_logout_token_ends_every_session_of_its_subject_and_keeps_anothers() -> None:
    host = a_host_with_sessions(subject_sessions=3, other_sessions=2)

    response = post_logout_token(host, a_logout_token_of_the_issuer())

    assert response.status_code == 200
    assert (sessions_of(host, SUBJECT), sessions_of(host, OTHER_SUBJECT)) == (0, 2)
    assert not [token for token in stored_refresh_tokens(host) if token.startswith(SUBJECT)]


def the_cookie_header_of(host: OidcHost, session_id: str) -> dict[str, str]:
    return {"cookie": session_cookie_header(sign_session_id(session_id, host.config.signing_key))}


def _logged_out_holding_the_second_session(host: OidcHost, session_ids: list[str]) -> None:
    headers = {**SAME_ORIGIN_FORM, **the_cookie_header_of(host, session_ids[1])}
    assert post_logout(host, headers).status_code == 200


def _logged_out_by_the_issuer(host: OidcHost, _session_ids: list[str]) -> None:
    assert post_logout_token(host, a_logout_token_of_the_issuer()).status_code == 200


def _logged_in_again_at_the_cap(host: OidcHost, _session_ids: list[str]) -> None:
    assert host.callback(host.sign_in_at_issuer()).status_code == 200


@pytest.mark.parametrize(("ending", "ended"), [
    pytest.param(_logged_out_holding_the_second_session, {1}, id="logout-route"),
    pytest.param(_logged_out_by_the_issuer, {0, 1, 2}, id="back-channel-logout-route"),
    pytest.param(_logged_in_again_at_the_cap, {0}, id="login-at-the-session-cap"),
])
def test_after_a_session_ends_its_cookie_is_refused_and_every_other_sessions_cookie_still_works(
    ending: Callable[[OidcHost, list[str]], None], ended: set[int],
) -> None:
    host = a_host_with_sessions(subject_sessions=3, other_sessions=1, max_sessions=3)
    session_ids = [record.id for record in host.sessions.list_active()]
    ended_tokens = [
        host.sessions.list_active()[index].refresh_token.get_secret_value() for index in ended
    ]

    ending(host, session_ids)

    statuses = [
        host.client.get("/me", headers=the_cookie_header_of(host, session_id)).status_code
        for session_id in session_ids
    ]
    assert statuses == [401 if index in ended else 200 for index in range(len(session_ids))]
    assert not set(ended_tokens) & set(stored_refresh_tokens(host))


def test_a_logout_for_an_unknown_subject_is_accepted_without_provisioning_an_account() -> None:
    host = an_oidc_host(FakeUser(id=OTHER_SUBJECT, username="omar"))
    open_sessions(host, OTHER_SUBJECT, 1)

    response = post_logout_token(host, a_logout_token_of_the_issuer())

    assert response.status_code == 200
    assert [account.id for account in host.accounts.list()] == [OTHER_SUBJECT]
    assert sessions_of(host, OTHER_SUBJECT) == 1
    assert host.audit.account_events == []


def test_a_logout_for_a_subject_without_sessions_is_accepted_and_audits_nothing() -> None:
    host = a_host_with_sessions(subject_sessions=0, other_sessions=1)

    response = post_logout_token(host, a_logout_token_of_the_issuer())

    assert (response.status_code, sessions_of(host, OTHER_SUBJECT)) == (200, 1)
    assert host.audit.account_events == []


def test_a_logout_that_ended_sessions_audits_one_event_for_the_account_and_no_actor() -> None:
    host = a_host_with_sessions(subject_sessions=3)

    post_logout_token(host, a_logout_token_of_the_issuer())

    assert [asdict(event) for event in host.audit.account_events] == [{
        "kind": AccountEventKind.BACKCHANNEL_LOGOUT,
        "actor_id": None,
        "subject_id": SUBJECT,
        "role": None,
        "previous_role": None,
    }]


def test_an_accepted_logout_takes_the_lock_once_and_calls_no_issuer_endpoint() -> None:
    host = a_host_with_sessions(subject_sessions=1)
    exchanges_before = len(host.issuer.requests)

    post_logout_token(host, a_logout_token_of_the_issuer())

    assert host.lock.times_taken == 1
    assert len(host.issuer.requests) == exchanges_before


@pytest.mark.parametrize("logout_token", [
    pytest.param(a_logout_token_of_the_issuer(key_name="forger"), id="forged-signature"),
    pytest.param("not-a-token", id="malformed"),
])
def test_a_logout_token_that_does_not_hold_is_refused_before_the_lock_and_ends_nothing(
    logout_token: str,
) -> None:
    host = a_host_with_sessions(subject_sessions=2)

    response = post_logout_token(host, logout_token)

    assert (response.status_code, response.content) == (400, b"")
    assert sessions_of(host, SUBJECT) == 2
    assert host.lock.times_taken == 0
    assert host.audit.account_events == []


def test_an_id_token_posted_as_a_logout_token_ends_nothing() -> None:
    host = a_host_with_sessions(subject_sessions=1)

    response = post_logout_token(host, an_id_token("nonce", host.wall_clock, [LOGIN_GROUP]))

    assert (response.status_code, sessions_of(host, SUBJECT)) == (400, 1)


@pytest.mark.parametrize(("body", "content_type"), [
    pytest.param(b"", FORM_MEDIA_TYPE, id="empty-body"),
    pytest.param(b"other=1", FORM_MEDIA_TYPE, id="token-missing"),
    pytest.param(b"logout_token=", FORM_MEDIA_TYPE, id="token-empty"),
    pytest.param(b"logout_token", FORM_MEDIA_TYPE, id="field-without-a-value"),
    pytest.param(b"logout_token=%ff", FORM_MEDIA_TYPE, id="undecodable-token"),
    pytest.param(b"logout_token=a&logout_token=b", FORM_MEDIA_TYPE, id="token-twice"),
    pytest.param(b"\xff\xfe", FORM_MEDIA_TYPE, id="body-not-utf-8"),
    pytest.param(
        a_form_of(a_logout_token_of_the_issuer()), "application/json", id="json-media-type",
    ),
    pytest.param(a_form_of(a_logout_token_of_the_issuer()), "text/plain", id="text-media-type"),
    pytest.param(
        a_form_of(a_logout_token_of_the_issuer()), "multipart/form-data", id="multipart-media-type",
    ),
    pytest.param(a_form_of(a_logout_token_of_the_issuer()), None, id="no-media-type"),
])
def test_the_library_refuses_what_is_not_one_well_formed_logout_token_form_before_it_locks(
    body: bytes, content_type: str | None,
) -> None:
    host = a_host_with_sessions(subject_sessions=1)

    result = receive_in_a_transaction(host, body, content_type)

    assert result is BackchannelLogoutResult.REFUSED
    assert (sessions_of(host, SUBJECT), host.lock.times_taken) == (1, 0)


@pytest.mark.parametrize("content_type", [
    pytest.param(f"{FORM_MEDIA_TYPE}; charset=UTF-8", id="media-type-with-parameter"),
    pytest.param(FORM_MEDIA_TYPE.upper(), id="media-type-in-capitals"),
])
def test_a_form_media_type_with_a_parameter_or_in_capitals_is_read(content_type: str) -> None:
    host = a_host_with_sessions(subject_sessions=1)

    result = receive_in_a_transaction(
        host, a_form_of(a_logout_token_of_the_issuer()), content_type,
    )

    assert result is BackchannelLogoutResult.ACCEPTED
    assert sessions_of(host, SUBJECT) == 0


def receive_in_a_transaction(
    host: OidcHost, body: bytes, content_type: str | None,
) -> BackchannelLogoutResult:
    with host.sessions.transaction():
        return receive_backchannel_logout(
            host.relying_party, body, content_type,
            accounts=host.accounts, sessions=host.sessions, lock=host.lock, audit=host.audit,
        )


def test_a_malformed_logout_token_form_gets_an_empty_400() -> None:
    host = a_host_with_sessions(subject_sessions=1)

    response = post_backchannel_logout(host, b"logout_token")

    assert (response.status_code, response.content) == (400, b"")


def test_two_logout_tokens_in_one_form_are_refused_even_when_one_is_valid() -> None:
    host = a_host_with_sessions(subject_sessions=1)
    form = urllib.parse.urlencode([
        ("logout_token", a_logout_token_of_the_issuer()), ("logout_token", "another"),
    ])

    response = post_backchannel_logout(host, form.encode())

    assert (response.status_code, sessions_of(host, SUBJECT)) == (400, 1)


def test_an_unknown_form_field_beside_a_valid_token_is_ignored_past_the_default_limit() -> None:
    host = a_host_with_sessions(subject_sessions=1)

    response = post_logout_token(
        host, a_logout_token_of_the_issuer(), unknown="x" * (2 * DEFAULT_MAX_BODY_BYTES),
    )

    assert (response.status_code, sessions_of(host, SUBJECT)) == (200, 0)


def an_oversized_streamed_body() -> Iterator[bytes]:
    for _ in range(BACKCHANNEL_LOGOUT_MAX_BODY_BYTES // 1024 + 1):
        yield b"x" * 1024


@pytest.mark.parametrize("body", [
    pytest.param(b"x" * (BACKCHANNEL_LOGOUT_MAX_BODY_BYTES + 1), id="declared"),
    pytest.param(an_oversized_streamed_body(), id="streamed"),
])
def test_an_oversized_logout_body_is_refused_and_ends_nothing(
    body: bytes | Iterator[bytes],
) -> None:
    host = a_host_with_sessions(subject_sessions=1)

    response = post_backchannel_logout(host, body)

    assert (response.status_code, sessions_of(host, SUBJECT)) == (413, 1)


@pytest.mark.parametrize("path", [
    pytest.param(f"{BACKCHANNEL_LOGOUT_PATH}/", id="trailing-slash"),
    pytest.param(f"{BACKCHANNEL_LOGOUT_PATH}-other", id="longer-name"),
    pytest.param(LOGOUT_PATH, id="the-browser-logout"),
])
def test_a_path_next_to_the_callback_stays_csrf_protected(path: str) -> None:
    host = signed_in_host()

    response = host.client.post(path, headers=FORM, content=b"logout_token=x")

    assert (response.status_code, host.sessions.count_active()) == (403, 1)


def fails_with_the_store_down(*_arguments: object, **_keywords: object) -> NoReturn:
    raise ConnectionError("the store is down")


@pytest.mark.parametrize("failing_part", [
    pytest.param("sessions.delete_for_user", id="deletion-fails"),
    pytest.param("audit.account_event", id="audit-fails-after-deletion"),
    pytest.param("sessions.commit_failure", id="commit-fails"),
])
def test_a_store_audit_or_commit_failure_answers_400_and_leaves_every_session_in_place(
    failing_part: str, monkeypatch: pytest.MonkeyPatch,
) -> None:
    host = a_host_with_sessions(subject_sessions=2)
    owner, _, part = failing_part.partition(".")
    if part == "commit_failure":
        host.sessions.commit_failure = ConnectionError("the commit failed")
    else:
        monkeypatch.setattr(getattr(host, owner), part, fails_with_the_store_down)

    response = post_logout_token(host, a_logout_token_of_the_issuer())

    answer = (response.status_code, response.headers["cache-control"])
    assert (answer, sessions_of(host, SUBJECT)) == ((400, "no-store"), 2)


@pytest.mark.parametrize(("other_keys", "status", "sessions_left"), [
    pytest.param(0, 200, 0, id="sole-key"),
    pytest.param(1, 400, 1, id="several-keys"),
])
def test_a_logout_token_without_kid_is_verified_only_against_a_sole_issuer_key(
    other_keys: int, status: int, sessions_left: int,
) -> None:
    host = a_host_with_sessions(subject_sessions=1)
    host.key_set.response = key_set_document(
        public_jwk(rsa_key("issuer"), "issuer-key", kid=ABSENT),
        *(public_jwk(rsa_key(f"other-{index}"), f"other-{index}") for index in range(other_keys)),
    )

    response = post_logout_token(host, a_logout_token_of_the_issuer(header={"kid": ABSENT}))

    assert (response.status_code, sessions_of(host, SUBJECT)) == (status, sessions_left)


def test_the_callback_bypasses_an_exhausted_address_budget() -> None:
    host = a_host_with_sessions(subject_sessions=1, address_budget=1)
    host.client.get("/me")
    assert host.client.get("/me").status_code == 429

    response = post_logout_token(host, a_logout_token_of_the_issuer())

    assert (response.status_code, sessions_of(host, SUBJECT)) == (200, 0)


@pytest.mark.parametrize(("body", "status"), [
    pytest.param(None, 200, id="accepted"),
    pytest.param(b"logout_token=x", 400, id="refused"),
    pytest.param(b"x" * (BACKCHANNEL_LOGOUT_MAX_BODY_BYTES + 1), 413, id="oversized"),
])
def test_every_answer_of_the_callback_carries_no_store(body: bytes | None, status: int) -> None:
    host = a_host_with_sessions(subject_sessions=1)
    content = (
        a_form_of(a_logout_token_of_the_issuer()) if body is None else body
    )

    response = post_backchannel_logout(host, content)

    assert (response.status_code, response.headers["cache-control"]) == (status, "no-store")


def test_the_callback_needs_neither_an_origin_nor_a_cookie() -> None:
    host = a_host_with_sessions(subject_sessions=1)
    assert not host.client.cookies

    response = post_logout_token(host, a_logout_token_of_the_issuer())

    assert (response.status_code, "origin" in response.request.headers) == (200, False)


ACCOUNT = FakeUser(id=SUBJECT, username="lena")
BYSTANDER = FakeUser(id=OTHER_SUBJECT, username="omar")
FIRST_EXPIRY = datetime(2030, 1, 1, tzinfo=UTC)
FIRST_CREATED_AT = FIXED_INSTANT - timedelta(hours=1)
IDLE = timedelta(seconds=SESSION_IDLE_SECONDS)
OPENING_CONFIG = a_web_auth_config(wall_clock=FIXED_WALL_CLOCK)


class StoreDown(Exception):
    pass


@dataclass
class OpeningStore:
    """Sessions of ``ACCOUNT`` and ``BYSTANDER`` the way a host's store holds them."""

    sessions: SessionRecordsInMemory
    lock: WriteLockInMemory

    @classmethod
    def holding_session_named(cls, session_id: str) -> OpeningStore:
        lock = WriteLockInMemory()
        record = FakeSessionRecord(
            id=session_id, user=ACCOUNT, created_at=FIRST_EXPIRY, expires_at=FIRST_EXPIRY,
        )
        users = UsersInMemory(ACCOUNT, BYSTANDER, lock=lock)
        return cls(SessionRecordsInMemory(record, users=users, lock=lock), lock)

    @classmethod
    def holding(cls, *owners: FakeUser) -> OpeningStore:
        """One session per owner, each created a minute after the one before."""
        lock = WriteLockInMemory()
        users = UsersInMemory(ACCOUNT, BYSTANDER, lock=lock)
        sessions = SessionRecordsInMemory(users=users, lock=lock)
        store = cls(sessions, lock)
        for minute, owner in enumerate(owners):
            store.create_for(owner, FIRST_CREATED_AT + timedelta(minutes=minute))
        return store

    def create_for(self, owner: FakeUser, now: datetime) -> str:
        return seeded_session(self.sessions, self.lock.hold(), owner.id, now, now + IDLE).id

    def ids(self) -> list[str]:
        return [record.id for record in self.sessions.list_active()]

    def open_session(
        self, *cookie_values: str, max_sessions: int | None = None,
        refresh_token: SecretStr | None = None,
        id_token: SecretStr | None = None,
    ) -> SessionRecord:
        app = FastAPI()
        install_web_auth_config(app, OPENING_CONFIG)
        headers: list[tuple[bytes, bytes]] = []
        if cookie_values:
            headers.append((b"cookie", session_cookie_header(*cookie_values).encode()))
        return open_session(
            Request(an_http_scope(app, headers=headers)), OPENING_CONFIG,
            AdmittedLogin(
                account=ACCOUNT, return_to=None, refresh_token=refresh_token,
                id_token=id_token or SecretStr("id-token-of-the-login"),
            ),
            sessions=self.sessions, lock=self.lock,
            max_sessions=max_sessions, keeps_id_token=True,
        )


def signed(session_id: str) -> str:
    return sign_session_id(session_id, OPENING_CONFIG.signing_key)


def test_a_new_session_holds_the_refresh_token_and_id_token_of_the_admitted_login() -> None:
    store = OpeningStore.holding()

    session = store.open_session(refresh_token=SecretStr("rt-1"), id_token=SecretStr("id-1"))

    assert (session.refresh_token, session.id_token) == (SecretStr("rt-1"), SecretStr("id-1"))
    assert store.sessions.load(session.id) == session


def test_a_new_session_has_a_fresh_id() -> None:
    store = OpeningStore.holding(ACCOUNT)
    [replaced] = store.ids()

    session = store.open_session(signed(replaced))

    assert session.id != replaced
    assert store.ids() == [session.id]
    assert (session.user.id, session.created_at, session.expires_at) == (
        ACCOUNT.id, FIXED_INSTANT, FIXED_INSTANT + IDLE,
    )


@pytest.mark.parametrize(("cookie_values_of", "ended"), [
    pytest.param(lambda ids: [signed(ids[0])], [0], id="verified-same-account"),
    pytest.param(lambda ids: [signed(ids[1])], [1], id="verified-other-account"),
    pytest.param(lambda ids: [f"{ids[0]}.{'0' * 64}"], [], id="forged"),
    pytest.param(lambda ids: [ids[0]], [], id="unsigned"),
    pytest.param(lambda ids: [signed(ids[0]), signed(ids[0])], [], id="duplicated"),
])
def test_only_the_session_a_verified_cookie_names_is_ended_whoever_it_belongs_to(
    cookie_values_of: Callable[[list[str]], list[str]], ended: list[int],
) -> None:
    store = OpeningStore.holding(ACCOUNT, BYSTANDER)
    before = store.ids()

    session = store.open_session(*cookie_values_of(before))

    assert store.ids() == [
        *(session_id for index, session_id in enumerate(before) if index not in ended),
        session.id,
    ]


@pytest.mark.parametrize(("cookie_chars", "ended"), [
    pytest.param(MAX_SESSION_COOKIE_CHARS, True, id="at-the-bound"),
    pytest.param(MAX_SESSION_COOKIE_CHARS + 1, False, id="above-the-bound"),
])
def test_a_signed_cookie_longer_than_the_bound_ends_nothing_though_the_store_holds_its_session(
    cookie_chars: int, ended: bool,
) -> None:
    signature_chars = len(signed("x")) - 1
    long_id = "x" * (cookie_chars - signature_chars)
    store = OpeningStore.holding_session_named(long_id)
    cookie = signed_without_bound(long_id, OPENING_CONFIG.signing_key)
    assert len(cookie) == cookie_chars

    session = store.open_session(cookie)

    assert store.ids() == ([] if ended else [long_id]) + [session.id]


@pytest.mark.parametrize(("existing", "cookie", "max_sessions", "surviving"), [
    pytest.param(2, 1, 2, [0], id="the-replaced-session-never-counts-against-the-cap"),
    pytest.param(3, None, 2, [2], id="the-oldest-above-the-cap-are-ended"),
    pytest.param(2, None, 1, [], id="a-cap-of-one-keeps-only-the-new-session"),
    pytest.param(1, None, 3, [0], id="a-session-below-the-cap-is-kept"),
    pytest.param(3, None, None, [0, 1, 2], id="no-cap-prunes-nothing"),
])
def test_the_account_holds_at_most_its_cap_afterwards_with_the_oldest_ended(
    existing: int, cookie: int | None, max_sessions: int | None, surviving: list[int],
) -> None:
    store = OpeningStore.holding(*[ACCOUNT] * existing)
    bystander = store.create_for(BYSTANDER, FIRST_CREATED_AT)
    before = store.ids()
    cookie_values = [] if cookie is None else [signed(before[cookie])]

    session = store.open_session(*cookie_values, max_sessions=max_sessions)

    assert sorted(store.ids()) == sorted(
        [*(before[index] for index in surviving), bystander, session.id],
    )


@pytest.mark.parametrize("max_sessions", [
    pytest.param(0, id="zero"),
    pytest.param(-1, id="negative"),
    pytest.param(True, id="bool"),
    pytest.param("2", id="text"),
    pytest.param(2.0, id="float"),
])
def test_a_cap_that_is_not_a_positive_whole_number_is_refused_before_anything_is_written(
    max_sessions: object,
) -> None:
    store = OpeningStore.holding(ACCOUNT)
    before = store.ids()
    cookie = signed(before[0])

    with pytest.raises(ValueError, match="max_sessions"):
        store.open_session(cookie, max_sessions=max_sessions)

    assert store.ids() == before


def test_a_failed_host_commit_after_open_session_keeps_the_replaced_session_only() -> None:
    store = OpeningStore.holding(ACCOUNT)
    before = store.ids()
    store.sessions.commit_failure = StoreDown()
    cookie = signed(before[0])

    with pytest.raises(StoreDown), store.sessions.transaction():
        store.open_session(cookie)

    assert store.ids() == before


def test_a_create_that_raises_after_the_delete_leaves_the_replaced_session(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    store = OpeningStore.holding(ACCOUNT)
    before = store.ids()

    def store_down(*_: object, **__: object) -> NoReturn:
        raise StoreDown

    monkeypatch.setattr(store.sessions, "create", store_down)
    cookie = signed(before[0])

    with pytest.raises(StoreDown), store.sessions.transaction():
        store.open_session(cookie)

    assert store.ids() == before


def test_two_same_tick_logins_at_a_cap_of_one_both_succeed_and_the_later_remains() -> None:
    store = OpeningStore.holding()

    first = store.open_session(max_sessions=1)
    second = store.open_session(max_sessions=1)

    assert first.created_at == second.created_at
    assert store.ids() == [second.id]


def test_a_second_login_in_the_same_browser_replaces_the_first_session() -> None:
    host = signed_in_host()
    [first] = [record.id for record in host.sessions.list_active()]

    host.callback(host.sign_in_at_issuer())

    assert [record.id for record in host.sessions.list_active()] != [first]
    assert host.sessions.count_active() == 1


def test_a_failed_commit_after_the_login_issues_no_cookie_and_keeps_the_replaced_session() -> None:
    host = signed_in_host()
    before = [record.id for record in host.sessions.list_active()]
    cookie_before = host.client.cookies[host.config.session_cookie_name]
    host.sessions.commit_failure = StoreDown()
    query = host.sign_in_at_issuer()

    with pytest.raises(StoreDown):
        host.callback(query)

    assert [record.id for record in host.sessions.list_active()] == before
    assert host.client.cookies[host.config.session_cookie_name] == cookie_before
