"""Signing in through the bound issuer, from a host's start and callback routes.

The admission tests drive `admit_identity` on its own: an identity the bound
issuer vouched for becomes, or reuses, an account. The host tests drive a
FastAPI host with a start route and a callback route
through a `TestClient` whose cookie jar is the browser, against a stateful
fake issuer that answers each code once.
"""

from __future__ import annotations

import secrets
import threading
import urllib.parse
from collections.abc import Callable, Iterator
from concurrent.futures import ThreadPoolExecutor
from contextlib import AbstractContextManager, contextmanager
from copy import deepcopy
from dataclasses import asdict, dataclass, replace
from datetime import UTC, datetime, timedelta

import pytest
from fastapi import Depends, FastAPI, Request, Response
from fastapi.testclient import TestClient
from httpx import Response as HttpxResponse
from oidc_arrangement import (
    FakeClock,
    FakeIssuer,
    FakeKeySetEndpoint,
    jws,
    key_set_document,
    public_jwk,
    rs256,
    rsa_key,
)
from pydantic import SecretStr
from webauth_arrangement import (
    ADMIN_ROLE,
    CLIENT_ADDRESS,
    CLIENT_USER_AGENT,
    HTTPS_TEST_SERVER,
    MEMBER_ROLE,
    SESSION_MAX_AGE_SECONDS,
    FakeUser,
    RecordingAuditSink,
    SessionRecordsInMemory,
    UsersInMemory,
    UsersWithCaseInsensitiveUsernames,
    WriteLockInMemory,
    _require_held_lock,
    a_web_auth_config,
    signed_without_bound,
)

from webauth.config import WebAuthConfig, install_web_auth_config
from webauth.cookies import (
    MAX_PENDING_LOGIN_COOKIE_CHARS,
    PendingLogin,
    issue_session_cookies,
    pending_login_cookie_name,
    pending_login_cookie_prefix,
    sign_pending_login,
)
from webauth.dependencies import AuthenticatedUser, current_user_dependency
from webauth.middleware import install_web_auth_middleware
from webauth.oidc import (
    PENDING_LOGIN_MAX_AGE_SECONDS,
    OidcClientConfig,
    OidcIdentity,
    OidcRefusal,
    OidcRelyingParty,
)
from webauth.oidc_login import (
    MAX_PENDING_LOGINS,
    AdmissionConfig,
    AdmissionRefusal,
    EverySubject,
    NoAdmins,
    admit_identity,
    finish_login,
    log_out,
    start_login,
)
from webauth.policies import CsrfPolicy, PathRules, SecurityHeadersPolicy
from webauth.ports import SubjectUserStore, UserManagementEventKind, UserRecord

BOUND_ISSUER = "https://id.example/realms/lab"
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
)


@dataclass
class LegacyPasswordUser(FakeUser):
    """A host model that still carries the field the library no longer reads."""

    # Proves a host model still carrying the old password field works
    password_hash: str = "legacy-hash"  # noqa: S105


LENA_IN_THE_ADMIN_GROUP = replace(LENA, groups=(ADMIN_GROUP,))
LEGACY_ADMIN = FakeUser(id=SUBJECT, username="lena.legacy", role=ADMIN_ROLE)
LEGACY_ADMIN_WITH_PASSWORD_FIELD = LegacyPasswordUser(
    id=SUBJECT, username="lena.legacy", role=ADMIN_ROLE,
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


def a_host(*users: FakeUser, store: type[UsersInMemory] = UsersInMemory) -> Host:
    lock = WriteLockInMemory()
    return Host(store(*users, lock=lock), RecordingAuditSink(), lock)


def test_the_in_memory_store_supplies_the_subject_port() -> None:
    assert isinstance(a_host().accounts, SubjectUserStore)


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

    assert (account.id, account.username, account.role, account.is_active) == (
        SUBJECT, username, MEMBER_ROLE, True,
    )
    assert host.accounts.list() == [account]
    assert [asdict(event) for event in host.audit.user_management_events] == [{
        "kind": UserManagementEventKind.USER_CREATED,
        "actor_id": None,
        "subject_id": SUBJECT,
        "role": MEMBER_ROLE,
        "session_ref": None,
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
    assert len(host.audit.user_management_events) == 1


class UntouchableAccounts(UsersInMemory):
    def get(self, user_id: str) -> FakeUser | None:
        raise AssertionError("a refusal must not read an account")

    def get_by_username(self, username: str) -> FakeUser | None:
        raise AssertionError("a refusal must not read an account")


class UntouchableLock(WriteLockInMemory):
    def hold(self) -> AbstractContextManager[None]:
        raise AssertionError("a refusal must not take the write lock")


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
def test_a_refusal_before_any_account_takes_no_lock_reads_no_account_and_audits_nothing(
    identity: OidcIdentity, admission: AdmissionConfig, refusal: AdmissionRefusal,
) -> None:
    host = Host(UntouchableAccounts(), RecordingAuditSink(), UntouchableLock())

    assert host.admit(identity, admission) is refusal
    assert host.audit.user_management_events == []


def test_a_person_outside_the_group_is_refused_before_a_deactivated_account_is_read() -> None:
    host = a_host(FakeUser(id=SUBJECT, username="lena", is_active=False))

    assert host.admit(replace(LENA, groups=())) is AdmissionRefusal.NOT_A_MEMBER


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


@pytest.mark.parametrize("legacy", [
    pytest.param(LEGACY_ADMIN, id="an admin account created outside admission"),
    pytest.param(
        LEGACY_ADMIN_WITH_PASSWORD_FIELD, id="an account whose model carries a password field",
    ),
])
def test_a_stored_admin_outside_the_admin_group_is_demoted_and_audited_at_login(
    legacy: FakeUser,
) -> None:
    host = a_host(deepcopy(legacy))

    account = host.admit(LENA)

    assert account is host.accounts.get(SUBJECT)
    assert (account.username, account.role) == ("lena.legacy", MEMBER_ROLE)
    assert [asdict(event) for event in host.audit.user_management_events] == [{
        "kind": UserManagementEventKind.ROLE_CHANGED,
        "actor_id": None,
        "subject_id": SUBJECT,
        "role": MEMBER_ROLE,
        "session_ref": None,
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
    kinds = [event.kind for event in host.audit.user_management_events]
    expected = [UserManagementEventKind.ROLE_CHANGED] if case.changed else (
        [] if case.stored_role else [UserManagementEventKind.USER_CREATED]
    )
    assert kinds == expected


def test_a_role_change_audit_event_carries_the_roles_and_no_username() -> None:
    host = a_host(FakeUser(id=SUBJECT, username="lena.private", role=MEMBER_ROLE))

    host.admit(LENA_IN_THE_ADMIN_GROUP)

    [event] = host.audit.user_management_events
    assert (event.actor_id, event.subject_id, event.previous_role, event.role) == (
        None, SUBJECT, MEMBER_ROLE, ADMIN_ROLE,
    )
    assert "lena.private" not in repr(event)


def test_a_deactivated_admin_is_refused_before_any_role_is_written() -> None:
    host = a_host(FakeUser(id=SUBJECT, username="lena", role=ADMIN_ROLE, is_active=False))

    assert host.admit(LENA) is AdmissionRefusal.ACCOUNT_DEACTIVATED
    assert host.accounts.get(SUBJECT).role == ADMIN_ROLE
    assert host.audit.user_management_events == []


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

    assert host.audit.user_management_events == []


def test_a_role_that_does_not_change_is_written_by_no_second_login() -> None:
    host = a_host(store=UsersRejectingNeedlessRoleWrites)
    host.admit(LENA_IN_THE_ADMIN_GROUP)

    host.admit(LENA_IN_THE_ADMIN_GROUP)

    assert [event.kind for event in host.audit.user_management_events] == [
        UserManagementEventKind.USER_CREATED,
    ]


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
        replace(LENA, issuer="https://other.example/realms/lab"),
        [LEGACY_ADMIN],
        AdmissionRefusal.FOREIGN_ISSUER,
        id="another issuer's identity whose subject names a legacy admin",
    ),
    pytest.param(
        LENA, [FakeUser(id=SUBJECT, username="lena", is_active=False)],
        AdmissionRefusal.ACCOUNT_DEACTIVATED,
        id="a deactivated account",
    ),
    pytest.param(
        LENA, [replace(LEGACY_ADMIN_WITH_PASSWORD_FIELD, is_active=False)],
        AdmissionRefusal.ACCOUNT_DEACTIVATED,
        id="a deactivated account whose model carries a password field",
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
    assert host.audit.user_management_events == []


def test_a_username_the_store_refuses_on_create_is_taken_and_nothing_is_written() -> None:
    stored = [FakeUser(id="user-7", username="Lena")]
    host = a_host(*deepcopy(stored), store=UsersWithCaseInsensitiveUsernames)

    assert host.admit(LENA) is AdmissionRefusal.USERNAME_TAKEN
    assert host.accounts.list() == stored
    assert host.audit.user_management_events == []


NOW = 1_800_000_000
CLIENT_ID = "lab-app"
CALLBACK_PATH = "/auth/callback"
END_SESSION_ENDPOINT = f"{BOUND_ISSUER}/protocol/openid-connect/logout"
FORM_LOGOUT_PATH = "/logout"
FETCH_LOGOUT_PATH = "/logout/fetch"


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
        with super().hold():
            yield


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

    def start(self) -> str:
        """Visit the start route; answer the authorization URL it sends the browser to."""
        return self.client.get("/login/oidc").json()["authorization_url"]

    def sign_in_at_issuer(self) -> str:
        """Start a login and sign in at the issuer; answer the callback query."""
        return self.issuer.authorize(self.start())

    def callback(self, query: str, *, cookie: str | None = None) -> HttpxResponse:
        """Return to the callback route, with the browser's cookies or only ``cookie``."""
        if cookie is not None:
            self.client.cookies.clear()
        headers = {} if cookie is None else {"cookie": cookie}
        return self.client.get(f"{CALLBACK_PATH}?{query}", headers=headers)

    def pending_cookie_names(self) -> set[str]:
        prefix = pending_login_cookie_prefix(secure=self.config.cookie_secure)
        return {name for name in self.client.cookies if name.startswith(prefix)}

    def pending_cookie_name(self, query: str) -> str:
        [state] = urllib.parse.parse_qs(query)["state"]
        return pending_login_cookie_name(state, secure=self.config.cookie_secure)

    def pending_cookie(self, query: str) -> str:
        """The ``name=value`` the browser holds for the login of ``query``."""
        name = self.pending_cookie_name(query)
        return f"{name}={self.client.cookies[name]}"


def an_id_token(nonce: str, wall_clock: FakeClock, groups_claim: object) -> str:
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
    return jws(header, claims, rs256(rsa_key("issuer")))


def an_oidc_host(
    *users: FakeUser, store_max_age_seconds: int = SESSION_MAX_AGE_SECONDS,
    groups_claim: object = (LOGIN_GROUP,),
    **config_overrides: object,
) -> OidcHost:
    config = a_web_auth_config(**config_overrides)
    lock = CountingWriteLock()
    accounts = UsersInMemory(*users, lock=lock)
    sessions = SessionRecordsInMemory(
        max_age_seconds=store_max_age_seconds, users=accounts, lock=lock,
    )
    audit = RecordingAuditSink()
    wall_clock = FakeClock(float(NOW))
    issuer = FakeIssuer(mint_id_token=lambda nonce: an_id_token(nonce, wall_clock, groups_claim))
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
        audit_sink=lambda: audit,
        on_authenticated=authenticated.append,
    )

    def open_session(account: UserRecord, response: Response) -> dict[str, str]:
        record = sessions.create(
            account.id,
            datetime.now(UTC) + timedelta(seconds=sessions.max_age_seconds),
            ip_address=CLIENT_ADDRESS,
            user_agent=CLIENT_USER_AGENT,
        )
        issue_session_cookies(response, record.id, config)
        return {"username": account.username}

    app = FastAPI()
    install_web_auth_config(app, config)
    install_web_auth_middleware(
        app,
        security_headers=SecurityHeadersPolicy(content_security_policy="default-src 'self'"),
        csrf_origin=CsrfPolicy(),
        csrf_token=CsrfPolicy(
            token_exempt=PathRules(exact=frozenset({FORM_LOGOUT_PATH, FETCH_LOGOUT_PATH})),
        ),
    )

    @app.get("/login/oidc")
    def start(request: Request, response: Response) -> dict[str, str]:
        return {"authorization_url": start_login(relying_party, request, response, config)}

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
        return open_session(outcome, response)

    @app.post(FORM_LOGOUT_PATH)
    def form_logout(request: Request) -> Response:
        response = Response(status_code=303)
        response.headers["location"] = log_out(
            relying_party, request, response, config, sessions=sessions, lock=lock,
        )
        return response

    @app.post(FETCH_LOGOUT_PATH)
    def fetch_logout(request: Request, response: Response) -> dict[str, str]:
        return {
            "logout_url": log_out(
                relying_party, request, response, config, sessions=sessions, lock=lock,
            ),
        }

    @app.get("/admin")
    def admin(user: AuthenticatedUser = Depends(dependencies.admin_user)) -> dict[str, str]:
        return {"username": user.username}

    @app.get("/me")
    def me(user: AuthenticatedUser = Depends(dependencies.current_user)) -> dict[str, str]:
        return {"username": user.username}

    return OidcHost(
        client=TestClient(
            app, base_url=HTTPS_TEST_SERVER, cookies={},
            headers={"user-agent": CLIENT_USER_AGENT},
        ),
        issuer=issuer,
        key_set=key_set,
        wall_clock=wall_clock,
        accounts=accounts,
        sessions=sessions,
        audit=audit,
        config=config,
        lock=lock,
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

    configured = {"path=/", f"max-age={host.config.cookie_max_age_seconds}",
                  f"samesite={host.config.cookie_samesite}", "secure"}
    assert response.status_code == 200
    assert set_cookies(response)[host.config.session_cookie_name] == configured | {"httponly"}
    assert set_cookies(response)[host.config.csrf_cookie_name] == configured
    assert host.client.get("/me").json() == {"username": "lena"}


def test_an_admitted_callback_expires_the_session_by_the_stores_lifetime() -> None:
    store_max_age_seconds = 1_200
    host = an_oidc_host(store_max_age_seconds=store_max_age_seconds)

    response = host.callback(host.sign_in_at_issuer())

    record = host.sessions.record
    assert record is not None
    expires_in = (record.expires_at - datetime.now(UTC)).total_seconds()
    assert expires_in == pytest.approx(store_max_age_seconds, abs=60)
    session_cookie = set_cookies(response)[host.config.session_cookie_name]
    assert f"max-age={host.config.cookie_max_age_seconds}" in session_cookie
    assert host.client.get("/me").json() == {"username": "lena"}


@dataclass(frozen=True)
class RefusedCallback:
    """A callback that does not sign in: the accounts the host holds, and
    the callback query the browser brings back given the issuer's."""

    refusal: str
    stored: tuple[FakeUser, ...] = ()
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
        RefusedCallback(
            "account-deactivated",
            stored=(replace(LEGACY_ADMIN_WITH_PASSWORD_FIELD, is_active=False),),
        ),
        id="an identity whose legacy account is deactivated",
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
    host = an_oidc_host(*deepcopy(refused.stored), groups_claim=refused.groups_claim)
    other_tab = host.sign_in_at_issuer()
    query = host.sign_in_at_issuer()

    response = host.callback(refused.returned_query(host, query))

    assert (response.status_code, response.json()) == (403, {"refusal": refused.refusal})
    assert host.config.session_cookie_name not in set_cookies(response)
    assert host.sessions.count_active() == 0
    assert host.accounts.list() == list(refused.stored)
    assert is_cleared(response, host.pending_cookie_name(query))
    assert host.pending_cookie_names() == {host.pending_cookie_name(other_tab)}


def test_a_callback_demotes_a_legacy_admin_without_the_admin_group() -> None:
    host = an_oidc_host(deepcopy(LEGACY_ADMIN))

    response = host.callback(host.sign_in_at_issuer())

    assert (response.status_code, response.json()) == (200, {"username": "lena.legacy"})
    assert host.sessions.count_active() == 1
    assert host.client.get("/me").json() == {"username": "lena.legacy"}
    assert host.client.get("/admin").status_code == 403
    assert [event.kind for event in host.audit.user_management_events] == [
        UserManagementEventKind.ROLE_CHANGED,
    ]


def test_a_callback_keeps_a_legacy_admin_in_the_admin_group_as_admin() -> None:
    host = an_oidc_host(deepcopy(LEGACY_ADMIN), groups_claim=[ADMIN_GROUP])

    response = host.callback(host.sign_in_at_issuer())

    assert response.status_code == 200
    assert host.client.get("/admin").json() == {"username": "lena.legacy"}
    assert host.audit.user_management_events == []


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
    host.callback(host.sign_in_at_issuer())
    host.client.cookies.clear()
    host.client.cookies.set(host.config.session_cookie_name, session_cookie)

    assert host.client.get("/admin").status_code == status_after


def test_the_password_account_refusal_is_no_longer_an_admission_refusal() -> None:
    with pytest.raises(ValueError):
        AdmissionRefusal("subject-held-by-password-account")


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
    return host.pending_cookie(query).replace("=v1.", "=v2.", 1)


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
    value = sign_pending_login(pending, secret or host.config.signing_key)
    return f"{host.pending_cookie_name(query)}={value}"


@pytest.mark.parametrize(("pending_cookie", "refusal"), [
    pytest.param(_absent, "state-mismatch", id="no pending cookie for the state"),
    pytest.param(_tampered, "state-mismatch", id="a tampered signature"),
    pytest.param(_signed_under_another_key, "state-mismatch", id="signed under another key"),
    pytest.param(_signed_as_a_session, "state-mismatch", id="signed as a session cookie"),
    pytest.param(_oversized, "state-mismatch", id="oversized"),
    pytest.param(_of_another_version, "state-mismatch", id="another version"),
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
def test_two_tabs_both_sign_in_whichever_returns_first(*, second_returns_first: bool) -> None:
    host = an_oidc_host()
    tabs = [host.sign_in_at_issuer(), host.sign_in_at_issuer()]
    if second_returns_first:
        tabs.reverse()

    first, second = (host.callback(query) for query in tabs)

    assert first.json() == {"username": "lena"}
    assert second.json() == {"username": "lena"}
    assert host.sessions.count_active() == 2
    assert host.pending_cookie_names() == set()


def test_starts_beyond_the_cap_evict_the_oldest_pending_cookie_and_keep_the_session() -> None:
    host = an_oidc_host()
    host.callback(host.sign_in_at_issuer())
    queries = []
    for _ in range(MAX_PENDING_LOGINS + 1):
        queries.append(host.sign_in_at_issuer())
        host.wall_clock.now += 1

    assert host.pending_cookie_names() == {host.pending_cookie_name(q) for q in queries[1:]}
    assert {host.config.session_cookie_name, host.config.csrf_cookie_name} <= set(
        host.client.cookies
    )
    assert host.client.get("/me").json() == {"username": "lena"}
    assert host.callback(queries[0]).json() == {"refusal": "state-mismatch"}


def _a_forged_pending_cookie(host: OidcHost) -> str:
    name = f"{pending_login_cookie_prefix(secure=True)}{'f' * 16}"
    host.client.cookies.set(name, "v1.forged", domain="testserver.local", path="/")
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
    stranger = f"{pending_login_cookie_prefix(secure=True)}a@b"
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


def signed_in_host() -> OidcHost:
    host = an_oidc_host()
    host.callback(host.sign_in_at_issuer())
    assert host.sessions.count_active() == 1
    return host


def post_logout(
    host: OidcHost, headers: dict[str, str], path: str = FORM_LOGOUT_PATH,
) -> HttpxResponse:
    return host.client.post(path, headers=headers, follow_redirects=False)


def is_the_issuers_logout_url(url: str) -> bool:
    parts = urllib.parse.urlsplit(url)
    return (
        f"{parts.scheme}://{parts.netloc}{parts.path}" == END_SESSION_ENDPOINT
        and urllib.parse.parse_qs(parts.query, keep_blank_values=True) == {
            "client_id": [CLIENT_ID],
            "post_logout_redirect_uri": [a_client_config().post_logout_redirect_uri],
        }
    )


def both_session_cookies_are_cleared(host: OidcHost, response: HttpxResponse) -> bool:
    return is_cleared(response, host.config.session_cookie_name) and is_cleared(
        response, host.config.csrf_cookie_name,
    )


def a_logout_by_form(host: OidcHost) -> tuple[HttpxResponse, str]:
    response = post_logout(host, SAME_ORIGIN_FORM)
    assert response.status_code == 303
    return response, response.headers["location"]


def a_logout_by_fetch(host: OidcHost) -> tuple[HttpxResponse, str]:
    token = host.client.cookies[host.config.csrf_cookie_name]
    response = post_logout(
        host, {**SAME_ORIGIN_FORM, host.config.csrf_header_name: token}, FETCH_LOGOUT_PATH,
    )
    assert response.status_code == 200
    return response, response.json()["logout_url"]


@pytest.mark.parametrize("log_out_through", [
    pytest.param(a_logout_by_form, id="form-303"),
    pytest.param(a_logout_by_fetch, id="fetch-json"),
])
def test_a_logout_ends_the_session_clears_both_cookies_and_sends_the_browser_to_the_issuer(
    log_out_through: Callable[[OidcHost], tuple[HttpxResponse, str]],
) -> None:
    host = signed_in_host()

    response, logout_url = log_out_through(host)

    assert is_the_issuers_logout_url(logout_url)
    assert both_session_cookies_are_cleared(host, response)
    assert host.sessions.count_active() == 0


@dataclass(frozen=True)
class LogoutShape:
    path: str
    status_code: int
    url_of: Callable[[HttpxResponse], str]


LOGOUT_SHAPES = [
    pytest.param(
        LogoutShape(FORM_LOGOUT_PATH, 303, lambda response: response.headers["location"]),
        id="form-303",
    ),
    pytest.param(
        LogoutShape(FETCH_LOGOUT_PATH, 200, lambda response: response.json()["logout_url"]),
        id="fetch-json",
    ),
]


def _no_session(_host: OidcHost) -> dict[str, str]:
    return {}


def _forged_session_cookie(host: OidcHost) -> dict[str, str]:
    name = host.config.session_cookie_name
    forged = f"{name}={host.client.cookies[name]}tampered"
    host.client.cookies.clear()
    return {"cookie": forged}


def _session_ended_in_the_store(host: OidcHost) -> dict[str, str]:
    host.sessions.delete_for_user(SUBJECT)
    return {}


def _session_expired_but_stored(host: OidcHost) -> dict[str, str]:
    record = host.sessions.record
    assert record is not None
    record.expires_at = datetime.now(UTC) - timedelta(days=1)
    return {}


@pytest.mark.parametrize(("arrange", "sessions_kept"), [
    pytest.param(_no_session, 0, id="no-session"),
    pytest.param(_forged_session_cookie, 1, id="forged-cookie-ends-nothing"),
    pytest.param(_session_ended_in_the_store, 0, id="session-already-ended"),
    pytest.param(_session_expired_but_stored, 0, id="session-expired-but-stored"),
])
@pytest.mark.parametrize("shape", LOGOUT_SHAPES)
def test_a_same_origin_logout_needs_no_csrf_token_and_still_reaches_the_issuer(
    shape: LogoutShape, arrange: Callable[[OidcHost], dict[str, str]], sessions_kept: int,
) -> None:
    host = an_oidc_host()
    if arrange is not _no_session:
        host.callback(host.sign_in_at_issuer())
    extra_headers = arrange(host)

    response = post_logout(host, {**SAME_ORIGIN_FORM, **extra_headers}, shape.path)

    assert response.status_code == shape.status_code
    assert is_the_issuers_logout_url(shape.url_of(response))
    assert both_session_cookies_are_cleared(host, response)
    assert host.sessions.count_active() == sessions_kept


@pytest.mark.parametrize("shape", LOGOUT_SHAPES)
def test_a_logout_without_a_session_takes_no_lock(shape: LogoutShape) -> None:
    host = an_oidc_host()

    post_logout(host, SAME_ORIGIN_FORM, shape.path)

    assert host.lock.times_taken == 0


@pytest.mark.parametrize("shape", LOGOUT_SHAPES)
@pytest.mark.parametrize("headers", [
    pytest.param({"sec-fetch-site": "cross-site"}, id="cross-site-fetch-metadata"),
    pytest.param({"origin": "https://evil.test"}, id="foreign-origin"),
    pytest.param({}, id="form-with-neither-header"),
])
def test_a_cross_site_logout_is_refused_and_ends_nothing(
    shape: LogoutShape, headers: dict[str, str],
) -> None:
    host = signed_in_host()

    response = post_logout(
        host, {"content-type": "application/x-www-form-urlencoded", **headers}, shape.path,
    )

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

    response, logout_url = a_logout_by_form(host)

    assert is_the_issuers_logout_url(logout_url)
    assert host.sessions.count_active() == 0
    assert len(host.issuer.requests) == exchanges_before
    assert len(host.key_set.fetched_urls) == fetches_before
    assert both_session_cookies_are_cleared(host, response)


def test_the_logout_url_ignores_any_target_the_request_names() -> None:
    host = signed_in_host()
    query = urllib.parse.urlencode({
        "post_logout_redirect_uri": "https://evil.test/",
        "redirect": "https://evil.test/",
        "client_id": "someone-else",
    })

    response = host.client.post(
        f"{FORM_LOGOUT_PATH}?{query}",
        headers=SAME_ORIGIN_FORM,
        content=query,
        follow_redirects=False,
    )

    assert is_the_issuers_logout_url(response.headers["location"])
