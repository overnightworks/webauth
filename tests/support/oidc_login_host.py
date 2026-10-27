"""The OIDC host the login tests drive: a FastAPI host, a fake issuer and its stores."""

from __future__ import annotations

import logging
import urllib.parse
from collections.abc import Iterator
from contextlib import AbstractContextManager, contextmanager
from dataclasses import dataclass, replace

import anyio.to_thread
from fastapi import Depends, FastAPI, Request, Response
from fastapi.testclient import TestClient
from httpx import Response as HttpxResponse
from pydantic import SecretStr

from tests.support.oidc_arrangement import (
    ISSUED_REFRESH_TOKEN,
    FakeClock,
    FakeIssuer,
    FakeKeySetEndpoint,
    LogoutPage,
    a_fake_id_token,
    a_logout_token,
    jws,
    key_set_document,
    public_jwk,
    rs256,
    rsa_key,
)
from tests.support.webauth_arrangement import (
    ADMIN_ROLE,
    HTTPS_TEST_SERVER,
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
    issue_session_cookies,
)
from webauth.dependencies import current_user_dependency
from webauth.middleware import install_web_auth_middleware
from webauth.oidc import (
    OidcClientConfig,
    OidcIdentity,
    OidcRefusal,
    OidcRelyingParty,
)
from webauth.oidc_login import (
    AdmissionConfig,
    AdmissionRefusal,
    AdmittedLogin,
    BackchannelLogoutResult,
    finish_login,
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
    AuthenticatedUser,
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


def _install_the_host_middleware(
    app: FastAPI, config: WebAuthConfig, address_budget: int | None,
) -> None:
    backchannel_path = PathRules(exact=frozenset({BACKCHANNEL_LOGOUT_PATH}))
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


def _add_the_login_routes(
    app: FastAPI,
    relying_party: OidcRelyingParty,
    config: WebAuthConfig,
    *,
    accounts: UsersInMemory,
    sessions: SessionRecordsInMemory,
    lock: CountingWriteLock,
    audit: RecordingAuditSink,
    max_sessions: int | None,
    returned_to: list[str | None],
    admitted_logins: list[AdmittedLogin],
) -> None:
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
    app = FastAPI()
    _install_the_host_middleware(app, config, address_budget)
    _add_the_login_routes(
        app, relying_party, config, accounts=accounts, sessions=sessions, lock=lock, audit=audit,
        max_sessions=max_sessions, returned_to=returned_to, admitted_logins=admitted_logins,
    )
    _add_the_logout_routes(
        app, relying_party, config, accounts=accounts, sessions=sessions, lock=lock, audit=audit,
    )
    _add_the_signed_in_routes(app, sessions)
    return OidcHost(
        client=TestClient(app, base_url=HTTPS_TEST_SERVER, cookies={}, root_path=root_path),
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


FORM_MEDIA_TYPE = "application/x-www-form-urlencoded"


FORM = {"content-type": FORM_MEDIA_TYPE}


def stored_refresh_tokens(host: OidcHost) -> list[str]:
    return [record.refresh_token.get_secret_value()
            for record in host.sessions.list_active() if record.refresh_token is not None]


def stored_id_tokens(host: OidcHost) -> list[str]:
    return [record.id_token.get_secret_value()
            for record in host.sessions.list_active() if record.id_token is not None]


def post_backchannel_logout(
    host: OidcHost, content: bytes | Iterator[bytes], headers: dict[str, str] = FORM,
) -> HttpxResponse:
    return host.client.post(BACKCHANNEL_LOGOUT_PATH, content=content, headers=headers)


def a_form_of(logout_token: str, **other_fields: str) -> bytes:
    return urllib.parse.urlencode({"logout_token": logout_token, **other_fields}).encode()


def post_logout_token(host: OidcHost, logout_token: str, **other_fields: str) -> HttpxResponse:
    return post_backchannel_logout(host, a_form_of(logout_token, **other_fields))
