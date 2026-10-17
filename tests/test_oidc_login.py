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
from collections.abc import Callable
from concurrent.futures import ThreadPoolExecutor
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
from webauth.oidc import (
    PENDING_LOGIN_MAX_AGE_SECONDS,
    OidcClientConfig,
    OidcIdentity,
    OidcRefusal,
    OidcRelyingParty,
)
from webauth.oidc_login import (
    MAX_PENDING_LOGINS,
    AdmissionRefusal,
    admit_identity,
    finish_login,
    start_login,
)
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
class LegacyPasswordUser(FakeUser):
    """A host model that still carries the field the library no longer reads."""

    # Proves a host model still carrying the old password field works
    password_hash: str = "legacy-hash"  # noqa: S105


LEGACY_ADMIN = FakeUser(id=SUBJECT, username="lena.legacy", role=ADMIN_ROLE)
LEGACY_ADMIN_WITH_PASSWORD_FIELD = LegacyPasswordUser(
    id=SUBJECT, username="lena.legacy", role=ADMIN_ROLE,
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
    }]


@pytest.mark.parametrize("legacy", [
    pytest.param(LEGACY_ADMIN, id="an admin account created outside admission"),
    pytest.param(
        LEGACY_ADMIN_WITH_PASSWORD_FIELD, id="an account whose model carries a password field",
    ),
])
def test_a_stored_account_whose_id_is_the_subject_signs_in_as_it_is(legacy: FakeUser) -> None:
    host = a_host(deepcopy(legacy))

    account = host.admit(LENA)

    assert account is host.accounts.get(SUBJECT)
    assert (account.username, account.role) == ("lena.legacy", ADMIN_ROLE)
    assert host.accounts.list() == [legacy]
    assert host.audit.user_management_events == []


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


def a_client_config() -> OidcClientConfig:
    return OidcClientConfig(
        issuer=BOUND_ISSUER,
        authorization_endpoint=f"{BOUND_ISSUER}/protocol/openid-connect/auth",
        token_endpoint=f"{BOUND_ISSUER}/protocol/openid-connect/token",
        jwks_url=f"{BOUND_ISSUER}/protocol/openid-connect/certs",
        client_id=CLIENT_ID,
        client_secret=SecretStr("client-secret"),
        redirect_uri=f"{HTTPS_TEST_SERVER}{CALLBACK_PATH}",
        leeway_seconds=30,
    )


@dataclass
class OidcHost:
    """A host application and the browser that visits it."""

    client: TestClient
    issuer: FakeIssuer
    wall_clock: FakeClock
    accounts: UsersInMemory
    sessions: SessionRecordsInMemory
    config: WebAuthConfig

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


def an_id_token(nonce: str, wall_clock: FakeClock) -> str:
    now = int(wall_clock.now)
    claims = {
        "iss": BOUND_ISSUER,
        "aud": CLIENT_ID,
        "sub": SUBJECT,
        "exp": now + 300,
        "iat": now - 10,
        "nonce": nonce,
        "preferred_username": "lena",
    }
    header = {"alg": "RS256", "kid": "issuer-key", "typ": "JWT"}
    return jws(header, claims, rs256(rsa_key("issuer")))


def an_oidc_host(
    *users: FakeUser, store_max_age_seconds: int = SESSION_MAX_AGE_SECONDS,
    **config_overrides: object,
) -> OidcHost:
    config = a_web_auth_config(**config_overrides)
    lock = WriteLockInMemory()
    accounts = UsersInMemory(*users, lock=lock)
    sessions = SessionRecordsInMemory(
        max_age_seconds=store_max_age_seconds, users=accounts, lock=lock,
    )
    audit = RecordingAuditSink()
    wall_clock = FakeClock(float(NOW))
    issuer = FakeIssuer(mint_id_token=lambda nonce: an_id_token(nonce, wall_clock))
    relying_party = OidcRelyingParty(
        a_client_config(),
        post_token_request=issuer,
        fetch_key_set=FakeKeySetEndpoint(
            key_set_document(public_jwk(rsa_key("issuer"), "issuer-key"))
        ),
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

    @app.get("/login/oidc")
    def start(request: Request, response: Response) -> dict[str, str]:
        return {"authorization_url": start_login(relying_party, request, response, config)}

    @app.get(CALLBACK_PATH)
    def callback(request: Request, response: Response) -> dict[str, str]:
        outcome = finish_login(
            relying_party, request, response, config,
            bound_issuer=BOUND_ISSUER, accounts=accounts, lock=lock, audit=audit,
        )
        if isinstance(outcome, OidcRefusal):
            response.status_code = 403
            return {"refusal": outcome.reason.value}
        if isinstance(outcome, AdmissionRefusal):
            response.status_code = 403
            return {"refusal": outcome.value}
        return open_session(outcome, response)

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
        wall_clock=wall_clock,
        accounts=accounts,
        sessions=sessions,
        config=config,
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
]


@pytest.mark.parametrize("refused", _REFUSED_CALLBACKS)
def test_a_refused_callback_issues_no_session_leaves_no_account_and_consumes_its_cookie(
    refused: RefusedCallback,
) -> None:
    host = an_oidc_host(*deepcopy(refused.stored))
    other_tab = host.sign_in_at_issuer()
    query = host.sign_in_at_issuer()

    response = host.callback(refused.returned_query(host, query))

    assert (response.status_code, response.json()) == (403, {"refusal": refused.refusal})
    assert host.config.session_cookie_name not in set_cookies(response)
    assert host.sessions.count_active() == 0
    assert host.accounts.list() == list(refused.stored)
    assert is_cleared(response, host.pending_cookie_name(query))
    assert host.pending_cookie_names() == {host.pending_cookie_name(other_tab)}


def test_a_callback_for_a_legacy_admin_signs_in_as_that_admin() -> None:
    host = an_oidc_host(deepcopy(LEGACY_ADMIN))

    response = host.callback(host.sign_in_at_issuer())

    assert (response.status_code, response.json()) == (200, {"username": "lena.legacy"})
    assert host.sessions.count_active() == 1
    assert host.sessions.record is not None
    assert host.sessions.record.user_id == SUBJECT
    assert host.client.get("/me").json() == {"username": "lena.legacy"}
    assert host.client.get("/admin").json() == {"username": "lena.legacy"}
    assert host.accounts.list() == [LEGACY_ADMIN]


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
