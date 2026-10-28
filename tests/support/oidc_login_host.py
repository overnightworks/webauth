"""The OIDC host the login tests drive: a FastAPI host, a fake issuer and its stores."""

from __future__ import annotations

import enum
import logging
import urllib.parse
from collections.abc import Callable, Iterator
from contextlib import AbstractContextManager, contextmanager
from dataclasses import dataclass
from typing import Any

import anyio.to_thread
from fastapi import Depends, FastAPI, Request, Response
from fastapi.responses import JSONResponse
from fastapi.testclient import TestClient
from httpx import Response as HttpxResponse
from pydantic import SecretStr

from tests.support.oidc_arrangement import (
    ISSUED_REFRESH_TOKEN,
    FakeClock,
    FakeIssuer,
    FakeKeySetEndpoint,
    LogoutPage,
    jws,
    key_set_document,
    public_jwk,
    rs256,
    rsa_key,
)
from tests.support.webauth_arrangement import (
    ADMIN_ROLE,
    HTTPS_TEST_SERVER,
    FakeSessionRecord,
    FakeUser,
    RecordingAuditSink,
    SessionRecordsInMemory,
    UsersInMemory,
    WriteLockInMemory,
    a_web_auth_config,
)
from webauth.config import WebAuthConfig, install_web_auth_config
from webauth.cookies import (
    _pending_login_cookie_name,
    _pending_login_cookie_prefix,
)
from webauth.dependencies import current_user_dependency
from webauth.middleware import install_web_auth_middleware
from webauth.oidc import (
    OidcClientConfig,
    OidcRefusal,
    OidcRelyingParty,
)
from webauth.oidc_login import (
    AdmissionConfig,
    BackchannelLogoutResult,
    log_out,
    receive_backchannel_logout,
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
    AuthenticatedUser,
    SignInStores,
)
from webauth.sign_in_routes import SignInPaths, SignInRefusal, install_sign_in_routes

BOUND_ISSUER = "https://id.example/realms/lab"
LOGIN_GROUP = "/apps/lab"
ADMIN_GROUP = f"{LOGIN_GROUP}/admin"
ADMISSION = AdmissionConfig(
    bound_issuer=BOUND_ISSUER, login_group=LOGIN_GROUP, admin_group=ADMIN_GROUP,
)
SUBJECT = "5f0c2a1e-7d4b-4c55-9a51-2f8e3c6b1d90"
LEGACY_ADMIN = FakeUser(id=SUBJECT, username="lena.legacy", role=ADMIN_ROLE)


NOW = 1_800_000_000
CLIENT_ID = "lab-app <\"&'>"
START_PATH = "/login/oidc"
CALLBACK_PATH = "/auth/callback"
SIGN_IN_PATHS = SignInPaths(start=START_PATH, callback=CALLBACK_PATH)
END_SESSION_ENDPOINT = f"{BOUND_ISSUER}/protocol/openid-connect/logout"
LOGOUT_PATH = "/logout"
LOGOUT_BUTTON_LABEL = "Sign <out> & \"go'"
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


class TransactionKind(enum.Enum):
    """What the host's ``SignInTransaction`` does when its block fails."""

    PER_CALL = "serializes only: every store call stands whatever happens later"
    ROLLING_BACK = "restores accounts, sessions and audit events when the block or its exit fails"


class UsersWithSnapshots(UsersInMemory):
    """Accounts that can be put back as they were."""

    def snapshot(self) -> Callable[[], None]:
        users, usernames = dict(self._users), dict(self._usernames)
        roles = [(user, user.role) for user in users.values()]

        def restore() -> None:
            self._users, self._usernames = dict(users), dict(usernames)
            for user, role in roles:
                user.role = role

        return restore


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
        return value if value is None or isinstance(value, (bool, int, str)) else (
            _Guarded(value, self._window)
        )


class RecordingSignInTransaction:
    """The host's ``SignInTransaction`` over the host's stores and its one lock.

    It counts its entries and refuses to be entered again from inside its own block.
    ``strict`` hands the route stores whose records fail once the block is left."""

    def __init__(
        self,
        kind: TransactionKind,
        *,
        accounts: UsersWithSnapshots,
        sessions: SessionRecordsInMemory,
        audit: RecordingAuditSink,
        lock: CountingWriteLock,
        strict: bool,
    ) -> None:
        self.kind = kind
        self.entries = 0
        self._accounts = accounts
        self._sessions = sessions
        self._audit = audit
        self._lock = lock
        self._strict = strict
        self._open = 0

    def __call__(self) -> AbstractContextManager[SignInStores]:
        return self._entered()

    @contextmanager
    def _entered(self) -> Iterator[SignInStores]:
        with self._lock.hold_uncounted():
            if self._open:
                raise AssertionError("the sign-in transaction was entered from inside its block")
            self.entries += 1
            self._open += 1
            window = _Window()
            try:
                with self._failing_as_the_kind_does():
                    yield self._stores(window)
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
    lock: CountingWriteLock
    relying_party: OidcRelyingParty
    transaction: RecordingSignInTransaction
    issued_id_tokens: list[str]
    refusals: list[SignInRefusal]
    answer_refusals: Callable[[Request, SignInRefusal], Response] = _the_refusal_as_json
    """What the host's refusal hook answers; a test replaces it."""

    def start(self, *, return_to: str | None = None) -> str:
        """Visit the start route; answer the authorization URL it redirects the browser to."""
        params = {} if return_to is None else {"next": return_to}
        return self.client.get(START_PATH, params=params).headers["location"]

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


def _install_the_host_middleware(
    app: FastAPI, config: WebAuthConfig, address_budget: int | None,
) -> None:
    backchannel_path = PathRules(exact=frozenset({BACKCHANNEL_LOGOUT_PATH}))
    install_web_auth_config(app, config)
    install_web_auth_middleware(
        app,
        security_headers=SecurityHeadersPolicy(
            content_security_policy="default-src 'self'",
            cache_control_rules=(
                SIGN_IN_PATHS.cache_control_rule,
                CacheControlRule(paths=backchannel_path, value="no-store"),
            ),
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


def _add_the_login_routes(
    app: FastAPI,
    relying_party: OidcRelyingParty,
    *,
    host: Callable[[], OidcHost],
    transaction: RecordingSignInTransaction,
    max_sessions: int | None,
    keeps_id_token: bool,
    admission: AdmissionConfig,
) -> None:
    def refused(request: Request, refusal: SignInRefusal) -> Response:
        current = host()
        current.refusals.append(refusal)
        return current.answer_refusals(request, refusal)

    install_sign_in_routes(
        app,
        paths=SIGN_IN_PATHS,
        relying_party=lambda _request: relying_party,
        admission=admission,
        transaction=transaction,
        refused=refused,
        keeps_id_token=keeps_id_token,
        max_sessions=max_sessions,
    )


def _add_the_logout_routes(
    app: FastAPI,
    relying_party: OidcRelyingParty,
    config: WebAuthConfig,
    *,
    accounts: UsersInMemory,
    sessions: SessionRecordsInMemory,
    lock: CountingWriteLock,
    audit: RecordingAuditSink,
) -> None:
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


def _an_issuer_side(
    wall_clock: FakeClock, groups_claim: object,
) -> tuple[FakeIssuer, FakeKeySetEndpoint, OidcRelyingParty, list[str]]:
    issued_id_tokens: list[str] = []

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
    return issuer, key_set, relying_party, issued_id_tokens


def an_oidc_host(
    *users: FakeUser,
    groups_claim: object = (LOGIN_GROUP,),
    address_budget: int | None = None,
    max_sessions: int | None = None,
    root_path: str = "",
    transaction_kind: TransactionKind = TransactionKind.PER_CALL,
    strict_records: bool = False,
    behind_base_http_middleware: bool = False,
    stored_session: FakeSessionRecord | None = None,
    keeps_id_token: bool = True,
    admission: AdmissionConfig = ADMISSION,
    **config_overrides: object,
) -> OidcHost:
    config = a_web_auth_config(**config_overrides)
    lock = CountingWriteLock()
    accounts = UsersWithSnapshots(*users, lock=lock)
    sessions = SessionRecordsInMemory(stored_session, users=accounts, lock=lock)
    audit = RecordingAuditSink()
    wall_clock = FakeClock(float(NOW))
    issuer, key_set, relying_party, issued_id_tokens = _an_issuer_side(wall_clock, groups_claim)
    transaction = RecordingSignInTransaction(
        transaction_kind, accounts=accounts, sessions=sessions, audit=audit, lock=lock,
        strict=strict_records,
    )
    app = FastAPI()
    _install_the_host_middleware(app, config, address_budget)
    if behind_base_http_middleware:
        app.middleware("http")(_pass_through)
    holder: list[OidcHost] = []
    _add_the_login_routes(
        app, relying_party, host=lambda: holder[0], transaction=transaction,
        max_sessions=max_sessions, keeps_id_token=keeps_id_token, admission=admission,
    )
    _add_the_logout_routes(
        app, relying_party, config, accounts=accounts, sessions=sessions, lock=lock, audit=audit,
    )
    _add_the_signed_in_routes(app, sessions)
    holder.append(OidcHost(
        client=TestClient(
            app, base_url=HTTPS_TEST_SERVER, cookies={}, root_path=root_path,
            follow_redirects=False, raise_server_exceptions=False,
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
        transaction=transaction,
        issued_id_tokens=issued_id_tokens,
        refusals=[],
    ))
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
    return [record.refresh_token.get_secret_value()
            for record in host.sessions.list_active() if record.refresh_token is not None]


def stored_id_tokens(host: OidcHost) -> list[str]:
    return [record.id_token.get_secret_value()
            for record in host.sessions.list_active() if record.id_token is not None]
