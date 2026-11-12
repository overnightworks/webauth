"""A resource app whose gate's relying party posts to a fake token endpoint, and the routes that
exchange the token the resource admitted."""

from __future__ import annotations

from dataclasses import dataclass, field, replace
from threading import get_ident
from typing import TYPE_CHECKING, Any

from fastapi import Request, WebSocket
from fastapi.responses import JSONResponse
from starlette.middleware import Middleware

from tests.support.gate_arrangement import (
    MACHINE_PREFIX,
    PERSON_PATHS,
    PERSON_PREFIX,
    BearerApp,
    ScopeRelay,
    a_bearer_app,
    a_known_person,
    a_resource,
    an_interactive_agent_token,
    relayed,
)
from tests.support.oidc_arrangement import (
    REALM_ISSUER,
    FakeTokenEndpoint,
    a_realm_client_config,
    a_relying_party,
    changed,
    token_endpoint_answer,
)
from webauth.middleware import (
    BearerGate,
    BearerGateMiddleware,
    MarkedRoute,
    ProtectedResource,
    exchanged_access_token,
)
from webauth.oidc import (
    ExchangedAccess,
    OidcRefusal,
    OidcRelyingParty,
    TokenEndpointAnswer,
    TokenRequest,
)

if TYPE_CHECKING:
    from collections.abc import Callable

EXCHANGE_PATH = "/exchange"
PERSON_EXCHANGE_PATH = f"{PERSON_PREFIX}exchange"
MACHINE_EXCHANGE_PATH = f"{MACHINE_PREFIX}exchange"
EXCHANGE_SOCKET_PATH = "/exchange-socket"
EXCHANGED_TOKEN = "exchanged-token-canary-never-shown"  # noqa: S105
ACCESS_TOKEN_TYPE = "urn:ietf:params:oauth:token-type:access_token"  # noqa: S105
EXCHANGED_LIFETIME_SECONDS = 300
EXCHANGE_SCOPES = ("calendar:read", "calendar:write")
OTHER_ISSUER = "https://other-login.example.org/realms/workshop"
EXCHANGE_ROUTE = MarkedRoute("GET", EXCHANGE_PATH)


def an_exchange_answer(**changes: Any) -> TokenEndpointAnswer:
    """The issuer's accepted answer to a token exchange; `changes` replace its members, and
    `ABSENT` removes one."""
    document = {
        "access_token": EXCHANGED_TOKEN,
        "issued_token_type": ACCESS_TOKEN_TYPE,
        "token_type": "Bearer",
        "expires_in": EXCHANGED_LIFETIME_SECONDS,
    }
    return token_endpoint_answer(200, changed(document, changes))


@dataclass
class ExchangeIssuer(FakeTokenEndpoint):
    """A token endpoint that keeps the thread of each post and the end of it in `events`, and
    runs `before_answer` while the post is in flight."""

    threads: list[int] = field(default_factory=list)
    events: list[str] = field(default_factory=list)
    before_answer: Callable[[], None] = lambda: None

    def __call__(self, request: TokenRequest) -> TokenEndpointAnswer:
        self.threads.append(get_ident())
        try:
            self.before_answer()
            return super().__call__(request)
        finally:
            self.events.append("post-ended")


@dataclass
class ExchangeApp:
    """The resource app, its issuer and what its exchange routes saw.

    The routes ask for `scopes`, which a test changes; `outcomes` are the results of the calls
    and `raised` the exceptions they raised."""

    app: BearerApp
    issuer: ExchangeIssuer
    resource: ProtectedResource
    relying_party: OidcRelyingParty
    relay: ScopeRelay
    issuer_url: str = REALM_ISSUER
    scopes: Any = EXCHANGE_SCOPES
    outcomes: list[ExchangedAccess | OidcRefusal] = field(default_factory=list)
    raised: list[Exception] = field(default_factory=list)
    route_threads: list[int] = field(default_factory=list)

    def exchange(
        self,
        path: str = EXCHANGE_PATH,
        *,
        token: str | None = None,
        cookie: bool = False,
        **request: Any,
    ) -> Any:
        """A request to an exchange route, bearing `token` (default: the resource's token)."""
        bearing_token = self.admitted_token() if token is None and not cookie else token
        authorization = () if bearing_token is None else (f"Bearer {bearing_token}",)
        return self.app.ask(path, authorization=authorization, cookie=cookie, **request)

    @property
    def token_endpoint(self) -> str:
        return _token_endpoint_of(self.issuer_url)

    def admitted_token(self) -> str:
        return an_interactive_agent_token(self.resource, iss=self.issuer_url)

    def moving_the_clock_during_the_post(self, seconds: float) -> None:
        def move() -> None:
            self.app.clock.now += seconds

        self.issuer.before_answer = move


def _exchange_route(exchange: ExchangeApp) -> Callable[[Request], Any]:
    async def route(request: Request) -> JSONResponse:
        exchange.route_threads.append(get_ident())
        try:
            outcome = await exchanged_access_token(request, scopes=exchange.scopes)
        except (RuntimeError, ValueError) as error:
            exchange.raised.append(error)
            return JSONResponse({"raised": type(error).__name__})
        exchange.outcomes.append(outcome)
        return JSONResponse({"answered": type(outcome).__name__})

    return route


def _add_exchange_routes(exchange: ExchangeApp) -> None:
    app = exchange.app.auth.app
    route = _exchange_route(exchange)
    for path in (EXCHANGE_PATH, PERSON_EXCHANGE_PATH, MACHINE_EXCHANGE_PATH):
        app.add_api_route(path, route, methods=["GET", "POST"])

    @app.websocket(EXCHANGE_SOCKET_PATH)
    async def socket(websocket: WebSocket) -> None:
        await websocket.accept()
        try:
            await exchanged_access_token(websocket, scopes=EXCHANGE_SCOPES)
        except RuntimeError as error:
            exchange.raised.append(error)
        await websocket.send_json({"raised": len(exchange.raised)})
        await websocket.close()


def _token_endpoint_of(issuer_url: str) -> str:
    return f"{issuer_url}/protocol/openid-connect/token"


def _posting_to(app: BearerApp, issuer: ExchangeIssuer, issuer_url: str) -> OidcRelyingParty:
    """Replaces the app's gate by one over `issuer_url` whose relying party posts to `issuer`
    and whose resource marks `EXCHANGE_ROUTE`, which `a_bearer_app` leaves to the host."""
    entry = next(m for m in app.auth.app.user_middleware if m.cls is BearerGateMiddleware)
    gate = entry.kwargs["policy"]
    assert isinstance(gate, BearerGate)
    assert gate.resource is not None
    party = a_relying_party(
        config=a_realm_client_config(
            issuer=issuer_url, token_endpoint=_token_endpoint_of(issuer_url)
        ),
        post_token_request=issuer,
        fetch_key_set=app.key_sets,
        wall_clock=app.clock,
    )
    admission = replace(gate.admission, bound_issuer=issuer_url)
    resource = replace(gate.resource, marked_routes=frozenset({EXCHANGE_ROUTE}))
    entry.kwargs["policy"] = replace(
        gate, relying_party=party, admission=admission, resource=resource
    )
    return party


def an_exchange_app(
    answer: TokenEndpointAnswer | Exception | None = None,
    *,
    issuer_url: str = REALM_ISSUER,
    inner_middleware: tuple[Middleware, ...] = (),
) -> ExchangeApp:
    """An app whose resource admits `an_interactive_agent_token`s and whose gate exchanges at
    `issuer_url`, which answers `answer` (default `an_exchange_answer()`).

    `EXCHANGE_PATH` is a marked route of the resource, `PERSON_EXCHANGE_PATH` is on a person path,
    `MACHINE_EXCHANGE_PATH` on a machine path and `EXCHANGE_SOCKET_PATH` is a WebSocket; each
    calls `exchanged_access_token` for `ExchangeApp.scopes`.
    """
    resource = a_resource()
    issuer = ExchangeIssuer(answer or an_exchange_answer())
    app = a_bearer_app(
        resource=resource,
        person_paths=PERSON_PATHS,
        known_accounts=(a_known_person(),),
        inner_middleware=inner_middleware,
    )
    relying_party = _posting_to(app, issuer, issuer_url)
    exchange = ExchangeApp(
        app, issuer, resource, relying_party, relayed(app.auth), issuer_url=issuer_url
    )
    _add_exchange_routes(exchange)
    return exchange
