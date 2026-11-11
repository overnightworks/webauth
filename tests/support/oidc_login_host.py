"""The OIDC host the login tests drive: a FastAPI host, a fake issuer and its stores."""

from __future__ import annotations

import enum
import urllib.parse
from collections.abc import Callable, Iterator
from contextlib import AbstractContextManager, contextmanager
from dataclasses import dataclass, replace
from typing import Any

import anyio
import pytest
from fastapi import Depends, FastAPI, Request, Response
from fastapi.responses import JSONResponse
from fastapi.testclient import TestClient
from httpx import Response as HttpxResponse
from pydantic import SecretStr

from tests.support.account_arrangement import (
    FakeUser,
    UsersInMemory,
    WriteLockInMemory,
    require_held_lock,
)
from tests.support.oidc_arrangement import (
    ABSENT,
    ISSUED_REFRESH_TOKEN,
    FakeClock,
    FakeIssuer,
    FakeKeySetEndpoint,
    LogoutPage,
    a_key_set_endpoint,
    a_realm_client_config,
    a_relying_party,
    an_id_token_claims,
    jws,
    rs256,
    rsa_key,
)
from tests.support.session_store_arrangement import FakeSessionRecord, SessionRecordsInMemory
from tests.support.webauth_arrangement import (
    ADMIN_ROLE,
    HTTPS_TEST_SERVER,
    RecordingAuditSink,
    a_web_auth_config,
    an_http_scope,
    drive,
)
from webauth.admission import AdmissionConfig, EverySubject, NoAdmins
from webauth.config import WebAuthConfig, install_web_auth_config, web_auth_config
from webauth.cookies import (
    _pending_login_cookie_name,
    _pending_login_cookie_prefix,
)
from webauth.dependencies import account_language_of_session, current_user_dependency
from webauth.middleware import install_web_auth_middleware
from webauth.oidc import (
    OidcClientConfig,
    OidcRefusal,
    OidcRelyingParty,
)
from webauth.policies import (
    BodySizePolicy,
    CsrfPolicy,
    RateLimitBudget,
    RateLimitPolicy,
    SecurityHeadersPolicy,
)
from webauth.ports import (
    AccountKind,
    AuthenticatedUser,
    SignInStores,
    UsernameTakenError,
)
from webauth.sign_in_routes import (
    LogoutPageText,
    SignInPaths,
    SignInRefusal,
    install_sign_in_routes,
)

BOUND_ISSUER = "https://id.example/realms/lab"
LOGIN_GROUP = "/apps/lab"
ADMIN_GROUP = f"{LOGIN_GROUP}/admin"
ADMISSION = AdmissionConfig(
    bound_issuer=BOUND_ISSUER,
    login_group=LOGIN_GROUP,
    admin_group=ADMIN_GROUP,
)
EVERYONE = replace(ADMISSION, login_group=EverySubject.OF_THE_BOUND_ISSUER)
NO_ADMINS = replace(ADMISSION, admin_group=NoAdmins.IN_THIS_APP)
EVERYONE_WITH_ADMIN_GROUP = replace(EVERYONE, admin_group="/apps/other/admin")
SUBJECT = "5f0c2a1e-7d4b-4c55-9a51-2f8e3c6b1d90"
LEGACY_ADMIN = FakeUser(id=SUBJECT, username="lena.legacy", role=ADMIN_ROLE)


NOW = 1_800_000_000
CLIENT_ID = "lab-app <\"&'>"
START_PATH = "/login/oidc"
CALLBACK_PATH = "/auth/callback"
LOGOUT_PATH = "/logout"
LANGUAGE_PATH = "/language"
END_SESSION_ENDPOINT = f"{BOUND_ISSUER}/protocol/openid-connect/logout"
LOGOUT_BUTTON_LABEL = "Sign <out> & \"go'"
LOGOUT_LANGUAGE = "en-US"
LOGOUT_PAGE_TEXT = LogoutPageText(language=LOGOUT_LANGUAGE, button_label=LOGOUT_BUTTON_LABEL)
BACKCHANNEL_LOGOUT_PATH = "/auth/backchannel-logout"
SIGN_IN_PATHS = SignInPaths(
    start=START_PATH,
    callback=CALLBACK_PATH,
    logout=LOGOUT_PATH,
    backchannel_logout=BACKCHANNEL_LOGOUT_PATH,
)
BACKCHANNEL_LOGOUT_MAX_BODY_BYTES = 32 * 1024
DEFAULT_MAX_BODY_BYTES = 1024


def a_client_config() -> OidcClientConfig:
    return a_realm_client_config(
        issuer=BOUND_ISSUER,
        authorization_endpoint=f"{BOUND_ISSUER}/protocol/openid-connect/auth",
        token_endpoint=f"{BOUND_ISSUER}/protocol/openid-connect/token",
        jwks_url=f"{BOUND_ISSUER}/protocol/openid-connect/certs",
        end_session_endpoint=END_SESSION_ENDPOINT,
        client_id=CLIENT_ID,
        client_secret=SecretStr("client-secret"),
        redirect_uri=f"{HTTPS_TEST_SERVER}{CALLBACK_PATH}",
        post_logout_redirect_uri=f"{HTTPS_TEST_SERVER}/",
        scopes=("openid",),
    )


class TransactionKind(enum.Enum):
    """What the host's ``SignInTransaction`` does when its block fails."""

    PER_CALL = "serializes only: every store call stands whatever happens later"
    ROLLING_BACK = "restores accounts, sessions and audit events when the block or its exit fails"


class UsersWithCaseInsensitiveUsernames(UsersInMemory):
    """A store whose unique index ignores case."""

    def create_for_subject(
        self, subject: str, username: str, role: str, kind: AccountKind
    ) -> FakeUser:
        if any(user.username.casefold() == username.casefold() for user in self.list()):
            raise UsernameTakenError("Username is already taken")
        return super().create_for_subject(subject, username, role, kind)


class UsersWithoutUniqueUsernames(UsersInMemory):
    """A store with no unique index on the username."""

    def create_for_subject(
        self, subject: str, username: str, role: str, kind: AccountKind
    ) -> FakeUser:
        require_held_lock(self._lock)
        user = FakeUser(id=subject, username=username, role=role, kind=kind)
        self._users[subject] = user
        return user


class UsersWithSnapshots(UsersInMemory):
    """Accounts that can be put back as they were."""

    def snapshot(self) -> Callable[[], None]:
        users, usernames = dict(self._users), dict(self._usernames)
        stored = [(user, user.role, user.kind) for user in users.values()]

        def restore() -> None:
            self._users, self._usernames = dict(users), dict(usernames)
            for user, role, kind in stored:
                user.role = role
                user.kind = kind

        return restore


class UsersWithSnapshotsAndNoUniqueUsernames(UsersWithSnapshots, UsersWithoutUniqueUsernames):
    """Accounts that can be put back as they were, in a store with no unique username index."""


class UsersWithSnapshotsAndCaseInsensitiveUsernames(
    UsersWithSnapshots, UsersWithCaseInsensitiveUsernames
):
    """Accounts that can be put back as they were, in a store whose unique index ignores case."""


class _WindowClosedError(AssertionError):
    """A record was used after the transaction's exit."""


class _Window:
    def __init__(self) -> None:
        self.open = True


class _Guarded:
    """A record, or a store handing out guarded records, that fails once its window closed."""

    def __init__(self, wrapped: Any, window: _Window) -> None:  # noqa: ANN401
        self._wrapped = wrapped
        self._window = window

    def __getattr__(self, name: str) -> Any:  # noqa: ANN401
        if not self._window.open:
            raise _WindowClosedError(f"{name} used after the sign-in transaction's exit")
        member = getattr(self._wrapped, name)
        if callable(member):
            return lambda *args, **kwargs: self._guard(member(*args, **kwargs))
        return self._guard(member)

    def _guard(self, value: object) -> object:
        return (
            value
            if value is None or isinstance(value, (bool, int, str))
            else (_Guarded(value, self._window))
        )


class RecordingSignInTransaction:
    """The host's ``SignInTransaction`` over the host's stores and its one lock.

    It counts its entries and refuses to be entered again from inside its own block.
    ``strict`` hands the route stores whose records fail once the block is left.
    ``exit_failure`` is raised after a clean block, as an exit that fails to commit;
    ``entry_failure`` is raised when the transaction is entered."""

    def __init__(
        self,
        kind: TransactionKind,
        *,
        accounts: UsersWithSnapshots,
        sessions: SessionRecordsInMemory,
        audit: RecordingAuditSink,
        lock: WriteLockInMemory,
        strict: bool,
    ) -> None:
        self.kind = kind
        self.entries = 0
        self.exit_failure: Exception | None = None
        self.entry_failure: Exception | None = None
        self.cleanup_failure: Exception | None = None
        self._accounts = accounts
        self._sessions = sessions
        self._audit = audit
        self._lock = lock
        self._strict = strict
        self._open = 0

    def __call__(self) -> AbstractContextManager[SignInStores]:
        if self.entry_failure is not None:
            raise self.entry_failure
        return self._entered()

    @contextmanager
    def _entered(self) -> Iterator[SignInStores]:
        with self._lock.hold():
            if self._open:
                raise AssertionError("the sign-in transaction was entered from inside its block")
            self.entries += 1
            self._open += 1
            window = _Window()
            try:
                with self._failing_as_the_kind_does():
                    yield self._stores(window)
                    if self.exit_failure is not None:
                        raise self.exit_failure
            except BaseException:
                if self.cleanup_failure is not None:
                    raise self.cleanup_failure from None
                raise
            finally:
                window.open = False
                self._open -= 1

    @contextmanager
    def _failing_as_the_kind_does(self) -> Iterator[None]:
        if self.kind is TransactionKind.PER_CALL:
            yield
            return
        restore_accounts = self._accounts.snapshot()
        events = list(self._audit.account_events)
        try:
            with self._sessions.transaction():
                yield
        except BaseException:
            restore_accounts()
            self._audit.account_events[:] = events
            raise

    def _stores(self, window: _Window) -> SignInStores:
        if not self._strict:
            return SignInStores(self._accounts, self._sessions, self._audit)
        return SignInStores(
            _Guarded(self._accounts, window),  # pyright: ignore[reportArgumentType]
            _Guarded(self._sessions, window),  # pyright: ignore[reportArgumentType]
            self._audit,
        )


class StoreDown(Exception):
    pass


def failing(owner: object, name: str, monkeypatch: pytest.MonkeyPatch) -> None:
    """Make ``owner.name`` raise ``StoreDown`` until the monkeypatch is undone."""

    def down(*_arguments: object, **_keywords: object) -> None:
        raise StoreDown

    monkeypatch.setattr(owner, name, down)


def _the_refusal_as_json(_request: Request, refusal: SignInRefusal) -> Response:
    cause = refusal.cause
    reason = cause.reason.value if isinstance(cause, OidcRefusal) else cause.value
    return JSONResponse({"refusal": reason}, status_code=403)


@dataclass
class OidcHost:
    """A host application and the browser that visits it."""

    client: TestClient
    issuer: FakeIssuer
    key_set: FakeKeySetEndpoint
    wall_clock: FakeClock
    accounts: UsersWithSnapshots
    sessions: SessionRecordsInMemory
    audit: RecordingAuditSink
    config: WebAuthConfig
    lock: WriteLockInMemory
    relying_party: OidcRelyingParty
    transaction: RecordingSignInTransaction
    issued_id_tokens: list[str]
    refusals: list[SignInRefusal]
    answer_refusals: Callable[[Request, SignInRefusal], Response] = _the_refusal_as_json
    """What the host's refusal hook answers; a test replaces it."""
    relying_party_of: Callable[[Request], OidcRelyingParty] | None = None
    """What the host's relying-party callable answers; a test replaces it."""

    def read_relying_party(self, request: Request) -> OidcRelyingParty:
        if self.relying_party_of is None:
            return self.relying_party
        return self.relying_party_of(request)

    def start(self, *, return_to: str | None = None) -> str:
        """Visit the start route; answer the authorization URL it redirects the browser to."""
        params = {} if return_to is None else {"next": return_to}
        return self.client.get(START_PATH, params=params).headers["location"]

    def drive_start(self) -> tuple[list[dict[str, object]], BaseException | None]:
        """Visit the start route below the test client: the ASGI messages it sent and the
        exception it raised, if any."""
        app: FastAPI = self.client.app  # pyright: ignore[reportAssignmentType]
        scope = an_http_scope(app, START_PATH, headers=[(b"host", b"testserver")])
        messages, raised = anyio.run(lambda: drive(app, scope, body_chunks=[]))
        return [dict(message) for message in messages], raised

    def sign_in_at_issuer(self, *, return_to: str | None = None) -> str:
        """Start a login and sign in at the issuer; answer the callback query."""
        return self.issuer.authorize(self.start(return_to=return_to))

    def callback(self, query: str, *, cookie: str | None = None) -> HttpxResponse:
        """Return to the callback route, with the browser's cookies or only ``cookie``."""
        if cookie is not None:
            self.client.cookies.clear()
        headers = {} if cookie is None else {"cookie": cookie}
        return self.client.get(f"{CALLBACK_PATH}?{query}", headers=headers)

    def account_language(self) -> str | None:
        """What the host's page route answers from the browser's session cookie."""
        return self.client.get(LANGUAGE_PATH).json()["language"]

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


def an_id_token(
    nonce: str,
    wall_clock: FakeClock,
    groups_claim: object,
    padding: str = "",
    *,
    locale_claim: object = ABSENT,
) -> str:
    claims = an_id_token_claims(
        int(wall_clock.now),
        issuer=BOUND_ISSUER,
        audience=CLIENT_ID,
        subject=SUBJECT,
        nonce=nonce,
        preferred_username="lena",
        groups=groups_claim,
        locale=locale_claim,
    )
    claims = {name: value for name, value in claims.items() if value is not ABSENT}
    header = {"alg": "RS256", "kid": "issuer-key", "typ": "JWT"}
    if padding:
        header["padding"] = padding
    return jws(header, claims, rs256(rsa_key("issuer")))


def _install_the_host_middleware(
    app: FastAPI,
    config: WebAuthConfig,
    address_budget: int | None,
) -> None:
    install_web_auth_config(app, config)
    install_web_auth_middleware(
        app,
        sign_in_paths=SIGN_IN_PATHS,
        security_headers=SecurityHeadersPolicy(content_security_policy="default-src 'self'"),
        body_size=BodySizePolicy(default_max_bytes=DEFAULT_MAX_BODY_BYTES),
        rate_limit=None
        if address_budget is None
        else RateLimitPolicy(default=RateLimitBudget("host", address_budget, 60)),
        csrf_origin=CsrfPolicy(),
    )


def _add_the_login_routes(
    app: FastAPI,
    *,
    host: Callable[[], OidcHost],
    transaction: RecordingSignInTransaction,
    max_sessions: int | None,
    keeps_id_token: bool,
    admission: AdmissionConfig,
    logout_page_text: Callable[[Request], LogoutPageText],
    ui_language: Callable[[Request], str | None],
) -> None:
    def refused(request: Request, refusal: SignInRefusal) -> Response:
        current = host()
        current.refusals.append(refusal)
        return current.answer_refusals(request, refusal)

    install_sign_in_routes(
        app,
        paths=SIGN_IN_PATHS,
        relying_party=lambda request: host().read_relying_party(request),
        admission=admission,
        transaction=transaction,
        refused=refused,
        keeps_id_token=keeps_id_token,
        max_sessions=max_sessions,
        logout_page_text=logout_page_text,
        ui_language=ui_language,
    )


def _add_the_signed_in_routes(app: FastAPI, sessions: SessionRecordsInMemory) -> None:
    dependencies = current_user_dependency(
        session_store=lambda: sessions,
        on_authenticated=lambda _user: None,
    )

    @app.get("/admin")
    def admin(user: AuthenticatedUser = Depends(dependencies.admin_user)) -> dict[str, str]:
        return {"username": user.username}

    @app.get("/me")
    def me(user: AuthenticatedUser = Depends(dependencies.current_user)) -> dict[str, str]:
        return {"username": user.username}

    @app.get(LANGUAGE_PATH)
    def language(request: Request) -> dict[str, str | None]:
        return {
            "language": account_language_of_session(
                request, sessions=sessions, config=web_auth_config(request)
            )
        }


def _an_issuer_side(
    wall_clock: FakeClock,
    groups_claim: object,
    locale_claim: object,
) -> tuple[FakeIssuer, FakeKeySetEndpoint, OidcRelyingParty, list[str]]:
    issued_id_tokens: list[str] = []

    def mint_id_token(nonce: str) -> str:
        issued_id_tokens.append(
            an_id_token(nonce, wall_clock, groups_claim, locale_claim=locale_claim)
        )
        return issued_id_tokens[-1]

    issuer = FakeIssuer(mint_id_token=mint_id_token)
    key_set = a_key_set_endpoint("issuer")
    relying_party = a_relying_party(
        config=a_client_config(),
        post_token_request=issuer,
        fetch_key_set=key_set,
        wall_clock=wall_clock,
    )
    return issuer, key_set, relying_party, issued_id_tokens


@dataclass(frozen=True)
class _HostStores:
    """The host's accounts, sessions, audit and sign-in transaction over one write lock."""

    lock: WriteLockInMemory
    accounts: UsersWithSnapshots
    sessions: SessionRecordsInMemory
    audit: RecordingAuditSink
    transaction: RecordingSignInTransaction


def _the_stores_of_a_host(
    users: tuple[FakeUser, ...],
    stored_session: FakeSessionRecord | None,
    transaction_kind: TransactionKind,
    strict_records: bool,
    account_store: type[UsersWithSnapshots],
) -> _HostStores:
    lock = WriteLockInMemory()
    accounts = account_store(*users, lock=lock)
    sessions = SessionRecordsInMemory(stored_session, users=accounts, lock=lock)
    audit = RecordingAuditSink()
    transaction = RecordingSignInTransaction(
        transaction_kind,
        accounts=accounts,
        sessions=sessions,
        audit=audit,
        lock=lock,
        strict=strict_records,
    )
    return _HostStores(lock, accounts, sessions, audit, transaction)


def _a_host_app(
    config: WebAuthConfig, address_budget: int | None, behind_base_http_middleware: bool
) -> FastAPI:
    app = FastAPI()
    _install_the_host_middleware(app, config, address_budget)
    if behind_base_http_middleware:
        app.middleware("http")(_pass_through)
    return app


def _a_client_of(app: FastAPI, root_path: str) -> TestClient:
    return TestClient(
        app,
        base_url=HTTPS_TEST_SERVER,
        cookies={},
        root_path=root_path,
        follow_redirects=False,
        raise_server_exceptions=False,
    )


def an_oidc_host(
    *users: FakeUser,
    groups_claim: object = (LOGIN_GROUP,),
    locale_claim: object = ABSENT,
    address_budget: int | None = None,
    max_sessions: int | None = None,
    root_path: str = "",
    transaction_kind: TransactionKind = TransactionKind.PER_CALL,
    strict_records: bool = False,
    behind_base_http_middleware: bool = False,
    stored_session: FakeSessionRecord | None = None,
    keeps_id_token: bool = True,
    admission: AdmissionConfig = ADMISSION,
    account_store: type[UsersWithSnapshots] = UsersWithSnapshots,
    logout_page_text: Callable[[Request], LogoutPageText] = lambda _request: LOGOUT_PAGE_TEXT,
    ui_language: Callable[[Request], str | None] = lambda _request: None,
    **config_overrides: object,
) -> OidcHost:
    config = a_web_auth_config(**config_overrides)
    stores = _the_stores_of_a_host(
        users, stored_session, transaction_kind, strict_records, account_store
    )
    wall_clock = FakeClock(float(NOW))
    issuer, key_set, relying_party, issued_id_tokens = _an_issuer_side(
        wall_clock, groups_claim, locale_claim
    )
    app = _a_host_app(config, address_budget, behind_base_http_middleware)
    holder: list[OidcHost] = []
    _add_the_login_routes(
        app,
        host=lambda: holder[0],
        transaction=stores.transaction,
        max_sessions=max_sessions,
        keeps_id_token=keeps_id_token,
        admission=admission,
        logout_page_text=logout_page_text,
        ui_language=ui_language,
    )
    _add_the_signed_in_routes(app, stores.sessions)
    holder.append(
        OidcHost(
            client=_a_client_of(app, root_path),
            issuer=issuer,
            key_set=key_set,
            wall_clock=wall_clock,
            accounts=stores.accounts,
            sessions=stores.sessions,
            audit=stores.audit,
            config=config,
            lock=stores.lock,
            relying_party=relying_party,
            transaction=stores.transaction,
            issued_id_tokens=issued_id_tokens,
            refusals=[],
        )
    )
    return holder[0]


async def _pass_through(request: Request, call_next: Callable[[Request], Any]) -> Response:
    return await call_next(request)


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


SAME_ORIGIN_FORM = {
    "origin": HTTPS_TEST_SERVER,
    "sec-fetch-site": "same-origin",
    "content-type": "application/x-www-form-urlencoded",
}


def after_signing_in(host: OidcHost) -> OidcHost:
    host.callback(host.sign_in_at_issuer())
    assert stored_refresh_tokens(host) == [ISSUED_REFRESH_TOKEN]
    return host


def post_logout(host: OidcHost, headers: dict[str, str]) -> HttpxResponse:
    return host.client.post(LOGOUT_PATH, headers=headers, follow_redirects=False)


def hint_of(response: HttpxResponse) -> str | None:
    return LogoutPage(response.text).hidden_fields.get("id_token_hint")


OTHER_SUBJECT = "0b6f1d7e-3c8a-4e0b-8d52-6a1f9e4c7b23"


def stored_refresh_tokens(host: OidcHost) -> list[str]:
    return [
        record.refresh_token.get_secret_value()
        for record in host.sessions.list_active()
        if record.refresh_token is not None
    ]


def stored_id_tokens(host: OidcHost) -> list[str]:
    return [
        record.id_token.get_secret_value()
        for record in host.sessions.list_active()
        if record.id_token is not None
    ]
