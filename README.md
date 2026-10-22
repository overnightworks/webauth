# webauth

OpenID Connect login and session authentication for FastAPI applications. It is
built for [Keycloak](https://www.keycloak.org/); any OpenID Connect issuer that
signs ID tokens with RS256 and publishes static endpoints works. The host serves
a start and a callback route. webauth runs the flow, then keeps the session:
sessions the store decides on every request, HMAC-signed cookies, CSRF
double-submit, admin checks, per-address rate limits, and the audit events they
raise. The client is a confidential client: it authenticates at the token
endpoint with HTTP Basic and sends PKCE with the `S256` method.

Distribution `overnightworks-webauth`, import package `webauth`. [Install](#install) names
where the wheel comes from.

## Quick start

```python
import os

from fastapi import Depends, FastAPI
from pydantic import SecretStr

from webauth.config import SessionLifetime, WebAuthConfig, install_web_auth_config
from webauth.dependencies import current_user_dependency
from webauth.middleware import install_web_auth_middleware
from webauth.policies import CsrfPolicy, SecurityHeadersPolicy, default_content_security_policy
from webauth.ports import AuthenticatedUser
from webauth.proxies import TrustedProxies
from webauth.rate_limit import SingleProcessRateLimitBackend

app = FastAPI()
config = WebAuthConfig(
    session_secret=SecretStr(os.environ["SESSION_SECRET"]),
    trusted_proxies=TrustedProxies.parse("10.0.0.0/8"),
    rate_limits=SingleProcessRateLimitBackend(),
    allowed_hosts_exact=frozenset({"app.example.com"}),
    allowed_hosts_patterns=(),
    session_lifetime=SessionLifetime(idle_seconds=43200, absolute_max_age_seconds=43200),
)
install_web_auth_config(app, config)
install_web_auth_middleware(
    app,
    security_headers=SecurityHeadersPolicy(
        content_security_policy=default_content_security_policy(),
    ),
    csrf_origin=CsrfPolicy(),
    csrf_token=CsrfPolicy(),
)
auth = current_user_dependency(
    session_store=the_hosts_session_store,
    on_authenticated=bind_the_hosts_log_context,
)


@app.get("/me")
def me(user: AuthenticatedUser = Depends(auth.current_user)) -> AuthenticatedUser:
    return user
```

`current_user_dependency` returns an `AuthDependencies` (`current_user`,
`admin_user`, `verified_session_id`) and its docstring says what `session_store`
and `on_authenticated` are. `trusted_proxies` names the peers whose
`X-Forwarded-For` and `X-Forwarded-Proto` are believed, and it decides alone only
when the ASGI server does not rewrite the client address or scheme from those
headers, so the host turns the server's own forwarded-header handling off (uvicorn's
`proxy_headers`, on by default: `proxy_headers=False` or `--no-proxy-headers`). The
sign-in routes are under [OpenID Connect login](#openid-connect-login); [`tests/typing/oidc_host.py`](tests/typing/oidc_host.py)
is a complete host, checked in CI against the built wheel.

## Testing a host

A test that needs a signed-in person needs no issuer. It creates the account and
a session inside the configured lifetime in the host's own store, calls
`issue_session_cookies(response, session_id, config)` from `webauth.cookies` on
a `Response` and copies both cookies it sets into its client. A state-changing
request also sends the CSRF cookie's value in the header named
`config.csrf_header_name` and passes the origin check ([CSRF origin](#csrf-origin)).
When the client keeps the cookies' attributes and `cookie_secure` is on, use an
`https` base URL.

A test of the host's own start, callback and logout routes gives
`OidcRelyingParty` its own `post_token_request` (a `TokenRequestPost`, from
`webauth.oidc`) and `fetch_key_set` (a `KeySetFetch`, from
`webauth.jwt_verification`) instead of the HTTPS ones. The host owns that stub.

The sign-in flow itself is proven against a real issuer: `e2e/oidc/` drives
Keycloak in a real browser and is webauth's own proof. A host proves its own
sign-in against an issuer of its choosing. webauth ships no fake issuer, because
one that mints tokens does not belong in every production install.

## Security model

Who the library defends against, and what it trusts. Where a line has an
owning section, it links there.

1. **Browser to library** (cookies, [CSRF](#csrf-origin), Origin, [return path](#the-return-path), body size, [the session gate](#the-session-gate), [rate limit](#rate-limiting-and-the-optional-redis-extra), [WebSocket handshake](#websocket-handshakes)): any browser or cross-site attacker is in scope. A network attacker below TLS is out of scope; the host's TLS, HSTS and `cookie_secure` own that ([Configuration](#configuration)).
2. **Library to issuer:** the configured issuer is trusted for what it signs and serves over TLS, and gets no defence beyond the JOSE and OpenID Connect specifications and PyJWT.
   - In scope: anyone presenting a token that lacks the issuer's signature or carries the wrong `alg`, `aud`, `iss`, type or time.
   - In scope: a network attacker against TLS. The library speaks https only, verifies the issuer's certificate against the system's trusted CAs and follows no redirect ([The relying party](#the-relying-party)).
   - Availability: every connection and read is bounded.
3. **Host configuration to library:** the host developer and the operator are trusted but fallible. The library checks the values whose mistake would silently weaken security or stick: secret length, the bools behind `Secure` and HSTS, a single string where a collection belongs, https URLs, group paths, ranges, and structure-breaking characters. It does not re-check a type that pyright proves unless the wrong type would pass construction silently, nor a grammar the browser already parses fail-closed.
4. **Host store to library (ports):** the store is trusted to keep its Protocol docstring duties ([`webauth.ports`](src/webauth/ports.py)): id entropy, exact comparison, atomicity, and raising on a missing row. The library re-derives every decision it owns from the record's fields, so a wrong `expires_at` is refused ([Session lifetime](#session-lifetime)). It does not detect a store that breaks a duty. The store holds the session's refresh token in plain text, and a dump of it holds no credential usable on its own: the issuer renews it only with the client secret.
5. **Host infrastructure** (`WallClock`, `WriteLock`, Redis, the logging pipeline): trusted. The library itself never logs a token, secret, cookie or session id, and keeps urllib3 from logging during its exchanges.
6. **The back-channel logout route:** anyone who can reach it is untrusted. The token signature is the control; reachability is the host's duty ([Back-channel logout](#back-channel-logout)).
7. **Named residues:**
   - with a `WriteLock` that is released before the host commits (an in-process lock), a back-channel logout of the same account that runs between `finish_login`'s admission and the host's commit after `open_session` deletes nothing of that login, so the session it opens survives; a lock that the request's first `hold` takes and only the host's commit or rollback releases (a transaction-scoped lock) closes that window;
   - a node whose clock runs more than 60 s behind the node that last renewed a session, or a clock that steps back more than 60 s, refuses that session until its clock catches up; the session is not ended ([Session lifetime](#session-lifetime));
   - a clock reading past year 9999 fails closed;
   - name resolution is bounded by the system resolver, not by the library; connecting is bounded per resolved address, outside the total deadline ([The relying party](#the-relying-party));
   - an access token that [`fresh_access_token`](#the-persons-access-token) handed out stays valid at the service it is sent to, and at the issuer's own endpoints, until its own `exp`, even after a logout or an expiry that lands once the call has decided; webauth revokes nothing;
   - with a store that commits every statement, a session deleted between `fresh_access_token`'s second `load` and the end of its block is seen only through `replace_refresh_token` answering `False`, and an issuer that echoes or omits the refresh token never reaches that call, so the call then hands out a token for the session deleted in that window.

To report a vulnerability, see [SECURITY.md](SECURITY.md).

## OpenID Connect login

The host names the issuer's authorization, token, key-set and end-session
URLs itself; the library does no discovery.

### What every app gets

Every app that signs people in through Keycloak behaves the same way, unless it
names `EverySubject` or `NoAdmins` under
[Admitting an identity](#admitting-an-identity). The details are in the
sections linked below.

**Who gets in.** Only members of the app's `login_group`, such as
`/apps/notes`, get in. Members of its `admin_group`, such as
`/apps/notes/admin`, are admins. Both are decided again at every login, so a
change in Keycloak takes effect at the person's next sign-in; an app session
that is already open keeps its access until it ends; a changed admin role
reaches every open session at the person's next sign-in. See
[Admitting an identity](#admitting-an-identity).

**When Keycloak is down.** People who are already signed in keep working until
their app session ends, because the app checks a session in its own store and
never asks Keycloak. A new sign-in fails at Keycloak: the app sends the browser
to Keycloak's sign-in page, which does not load, so the person sees the
browser's or the proxy's error page, not the app's. Only when Keycloak fails
during the sign-in, or the browser reaches Keycloak but the app does not, does
the sign-in stop at the app's callback, on the host's refusal page. webauth
offers no local fallback login. See
[The store decides every request](#the-store-decides-every-request).

**Signing out.** Signing out of an app ends its session in that browser at once
and takes the browser to Keycloak, which ends the person's Keycloak session in
that browser without asking anything. Keycloak then tells each app the
person signed in to through that Keycloak session, and each of those apps ends
all of the person's sessions, on every device. An app they used only on another
device is not told and keeps them signed in there. On their other devices, the
next sign-in asks for no password while that device's own Keycloak session
lasts. If the app cannot send the ID token of the browser's latest Keycloak
sign-in, Keycloak asks once to confirm instead; if the realm key that signed
that token has been deleted since, Keycloak shows an error page instead. See
[The ID token hint](#the-id-token-hint), [Logging out](#logging-out) and
[Back-channel logout](#back-channel-logout).

#### Signed out and refused

Every app shows signed-out and refused people the same way. This is the rule
every app follows; [the session gate](#the-session-gate) enforces it, and a
host without the gate follows it itself.

- **A page without a session** sends the browser straight to the app's start
  route, with `next` naming the page, so the person lands there after signing
  in. The host passes `next` to `start_login` as `return_to`, and
  `finish_login` hands back the same-origin path or `None`. An API call without a session gets
  401, and the app's UI then navigates to its start route. See
  [The host's start, callback and logout routes](#the-hosts-start-callback-and-logout-routes)
  and, for the rule `return_to` must pass,
  [The return path](#the-return-path). For a
  server-rendered host, `LoginRedirect` makes the redirect-or-401 split; see
  [Reading the session](#reading-the-session).
- **Public paths** are the exception. Each app names its own, and they need
  no session and do not redirect.
- **The page after signing out** is the app's `post_logout_redirect_uri`. It
  never redirects by itself. See [Logging out](#logging-out).
- **Which refusal shows which page.** "No access" is for
  `AdmissionRefusal.NOT_A_MEMBER`; "Login failed" is for an `OidcRefusal`
  and for `AdmissionRefusal.FOREIGN_ISSUER` and `USERNAME_TAKEN`, which are
  setup errors, not missing rights.
  Both types are returned by `finish_login`, see
  [The host's start, callback and logout routes](#the-hosts-start-callback-and-logout-routes).
  A refusal carries no identity, so the page shows no name. A
  `NOT_A_MEMBER` login sets no ID token hint, so signing out from "no
  access" makes Keycloak ask once, unless the browser still holds a hint from
  an earlier sign-in (see
  [The ID token hint](#the-id-token-hint)).
- **Look.** The three pages (logged out, no access, login failed), their
  wording and their ways out are the sign-in pattern of
  [ui-console](https://github.com/overnightworks/ui-console); each app takes
  the colours from its own tokens.

### The host's start, callback and logout routes

The host serves three routes over its one `OidcRelyingParty`: start
(`start_login`), callback (`finish_login`, then `open_session`) and logout
(`log_out`). `webauth.oidc_login` carries the pending login in a signed cookie of
its own, one per login, so the host keeps no server-side store and
`WebAuthConfig` knows nothing of OpenID Connect. Each function's docstring holds
its contract, the `webauth.oidc_login` and `webauth.cookies` module docstrings
hold the login and its cookies, and `build_app` in
[`e2e/oidc/host_app.py`](e2e/oidc/host_app.py) is the worked set of routes,
type-checked and run against a real issuer.

The library never commits: the host commits an admitted login before it issues
the cookies. A pending login is single-use because its cookie is cleared and the
issuer accepts a code once; webauth keeps no replay store. The `finish_login`
docstring holds the callback's outcomes and the host's duties.

#### The return path

The path a person was headed to travels through the login as `return_to`. Only a
same-origin path of this app comes back from `finish_login`; anything else comes
back as `None`, the host's default page, and the login still succeeds. The
`start_login` docstring holds the rule.

#### Logging out

`log_out` is the whole logout sequence in one call: it ends the session, clears
the cookies and returns the issuer's end-session URL, so the issuer ends its own
session too. It makes no outbound call, so an issuer that is down still leaves
the person signed out of the app. Its docstring holds the rest.

#### The ID token hint

`finish_login` hands the browser the login's ID token in a cookie of its own,
and `log_out` passes it to Keycloak as `id_token_hint`, so Keycloak can end its
session without asking the person to confirm. The hint is never a credential:
webauth does not sign, decode, verify or log it, and Keycloak judges it. Its
cookie name, scope and flags are in the `webauth.cookies` module docstring.

### Back-channel logout

When a person's session ends at the issuer, the issuer posts a Logout Token to
every client that session signed in to.
`webauth.oidc_login.receive_backchannel_logout` reads that form, has
`OidcRelyingParty.verify_logout_token` check the token, and ends every session
of its subject, in every browser. The host owns the route and the transaction;
the route answers 200 only after its commit. The token's signature is the only
control, so the route must be reachable by the issuer alone. The docstrings of
those two names hold the token rules and the setup the route needs.

### The relying party

`webauth.oidc.OidcRelyingParty` runs the authorization-code flow with PKCE for
one client at one issuer, described by an `OidcClientConfig` that the host
builds with its secrets from its own secret channel. Every outbound call goes
through the two transports the host injects
(`webauth.oidc_transport.post_token_request_over_https` and
`webauth.https_client.fetch_key_set_over_https`), which speak https only, bound
every request in time and size, follow no redirect and log nothing.

### The person's access token

`webauth.oidc_login.fresh_access_token` turns a signed-in session into a new
access token for one call to another service, in memory only. It answers a
`SecretStr`, or an `AccessTokenRefusal` whose `AccessTokenRefusalReason` says
what the host does. A token handed out stays valid until its own `exp` after a
later logout, and webauth makes no revocation call
([Security model](#security-model), item 7). `OidcRelyingParty.workload_access_token`
answers the client's own token.

### Admitting an identity

`admit_identity` turns a verified identity into the account it signs in as, and
`finish_login` takes the same `AdmissionConfig`. The host's store is bound to one
issuer, so an account's `id` is the issuer's subject. Members of `login_group`
come in, members of `admin_group` get the admin role, and `EverySubject` and
`NoAdmins` state on purpose that there is no group to require or no admin. A
second service that verifies the issuer's token itself calls `app_role`.

## Reading the session

`current_user_dependency` binds the host's session store into the route
dependencies `current_user`, `admin_user` and `verified_session_id`. A missing
or dead session answers 401, or, for a browser navigation on a server-rendered
host that names a `LoginRedirect`, a redirect to its login page.
`session_id_from_request` reads the signed session cookie and `admit_session`
decides a session id that the host read itself.

## The session gate

`install_web_auth_middleware(..., session_gate=SessionGate(...))` makes the rule
of "Signed out and refused" hold for every route: a request needs a live
session unless the host names it, so a route that forgets a dependency is gated,
not public. `admitted_user` reads the gate's admission where no dependency is
used.

## WebSocket handshakes

A browser sends the session cookie on a cross-site WebSocket handshake too.
`authenticate_websocket` is the one check a host runs at the handshake: it
decides the `Origin` first, then the session. A socket does not end when its
session does, so the host checks again while it streams.

## Configuration

The host builds one `WebAuthConfig` by keyword and installs it with
`install_web_auth_config`; no module reads an environment variable or a global.
Its docstring says what each field decides and what construction refuses.
`cookie_secure` is the one switch for transport security: it alone decides
whether both cookies carry `Secure` and whether HSTS is sent, whatever the
request's scheme, so a host serving plain http (local development) turns it off
for that environment and nowhere else. `SecurityHeadersPolicy` names the headers
every response carries, the library's own refusals and the 500 among them, and
`default_content_security_policy()` builds the policy a host gives it.

## The store decides every request

The library caches no sessions: `SessionRecordStore` is asked on every
authenticated request, so a session the host ended is refused on its next one.
The library alone decides whether a loaded session still stands; the store
writes the expiry it is given.

## Session lifetime

`SessionLifetime` holds the two numbers that decide how long someone stays
signed in: an idle window and an absolute cap from the session's creation. An
open session is not re-checked, so the cap is also the worst-case delay before a
removal from the host's login group takes effect. The recommended policy for a
host that admits by `login_group` is a 12-hour cap with an idle window of the
same length. Every login checks the group again, and the issuer's SSO session
turns that login into a redirect the person does not notice. A removal takes
effect at once only by disabling the user at the issuer together with
[Back-channel logout](#back-channel-logout).

## Middleware order

`install_web_auth_middleware` adds the library's middleware in one order,
outermost first, and refuses a stack that would break it: security headers, body
size limit, per-address rate limit, CSRF origin, CSRF token, session gate. Install
it once and add no library middleware yourself. Its docstring holds the reason
for each position and where a host's own middleware goes. A host
whose own middleware is the session authority answers a request without a
session with `webauth.dependencies.unauthenticated_response`.

## CSRF origin

`CsrfOriginMiddleware` refuses a state-changing request that a foreign page
originated, by `Sec-Fetch-Site` where a browser sends it and otherwise by
comparing `Origin` (or `Referer`) with the hosts in `WebAuthConfig`. `CsrfPolicy`
decides which paths are checked and defaults to fail-closed.

## Rate limiting, and the optional Redis extra

`WebAuthConfig.rate_limits` is a `webauth.ports.RateLimitBackend`, and the host
names its budgets in a `webauth.policies.RateLimitPolicy`. A backend that cannot
answer raises, so the middleware fails the request closed.
`webauth.rate_limit.RedisRateLimitBackend` shares one window across processes and
needs the optional extra, `overnightworks-webauth[redis]`;
`webauth.rate_limit.SingleProcessRateLimitBackend` serves a single-node host that
runs one worker and needs no Redis.

## Audit events

The library reports an account operation (a user created, a role changed, a
back-channel logout) to the host's `AuditSink.account_event`, which maps it to
the host's audit system or does nothing. An event carries no session identifier
or username.

## What it owns, and what it leaves to the host

It owns the machinery an application should not rebuild:

| Module | Owns |
|---|---|
| `webauth.config` | The deployment facts every other module reads, installed on the app |
| `webauth.cookies` | The signed session cookie, the CSRF token bound to it, the pending-login cookie and the ID token hint cookie, issued and cleared |
| `webauth.dependencies` | Turning a signed cookie, or a session id, into the account that made the request or opened a WebSocket handshake |
| `webauth.policies` | Which requests are exempt, cacheable, or rate-limited, and how |
| `webauth.proxies` | Which peers may name a client, and the client identity that follows |
| `webauth.rate_limit` | The sliding-window backends a per-address budget is measured with, Redis or in-process |
| `webauth.ports` | What the host supplies, as Protocols, and `AuthenticatedUser`, which the library hands out |
| `webauth.middleware` | Body-size, CSRF, rate-limit, security-header and session-gate middleware, and `install_web_auth_middleware`, which installs them in the one order |
| `webauth.jwt_verification` | Whether an RS256 token from a remote issuer holds, against the issuer's cached key set |
| `webauth.https_client` | The one owner of outbound HTTPS: the key-set fetch and the token-request form POST |
| `webauth.oidc` | Logging a browser in at an OpenID Connect issuer: the authorization URL with PKCE, the callback judged, the code exchanged, the ID token verified, and the refresh and client-credentials grants |
| `webauth.oidc_login` | The login from the host's routes: admission and role, `open_session`, `log_out`, `fresh_access_token` and `receive_backchannel_logout` |
| `webauth.oidc_transport` | `post_token_request_over_https`, the production `TokenRequestPost` |

It leaves the application everything that touches the application's own truth:

- **Users and roles.** It has no user model and no role names beyond the
  configured ones; the one thing it writes to an account is the role admission
  derives from the issuer's groups, and it decides no authorisation beyond the
  admin check.
- **Persistence.** It holds no schema and no ORM; what it needs reaches it
  through the Protocols in `webauth.ports`.
- **Transactions.** The library commits nothing. Whether a request that fails
  leaves the auth machinery's writes behind is the host's: a transaction that
  rolls back on an exception leaves none, a store that applies each call keeps
  them, and the rate-limit budget counts attempts either way. Behind
  [the session gate](#the-session-gate), the renewal is durable before the route
  runs.
- **Routes.** It defines none. The only responses it writes are its own
  refusals: 401, 403, 413, 429, 503 and the 500, and the 302 to the host's login
  path.
- **Identity.** It issues no access or ID tokens: it is no identity provider, and
  it verifies the ID tokens an issuer made.
- **HTTP framing** is the ASGI server's job. uvicorn's two parsers, h11 and
  httptools, answer some framing conflicts differently, and HTTP allows either
  answer. webauth never re-parses framing: its body-size limit counts the
  streamed bytes whatever the headers say.

## Install

`overnightworks-webauth` is not on PyPI: it installs only from the wheel
published as an asset on each tag's release. Take the version from the
[Releases page](https://github.com/overnightworks/webauth/releases) and put it in
place of `X.Y.Z`, in a `pyproject.toml`:

```toml
dependencies = [
    "overnightworks-webauth @ https://github.com/overnightworks/webauth/releases/download/vX.Y.Z/overnightworks_webauth-X.Y.Z-py3-none-any.whl",
]
```

Tags are never moved; a broken release gets the next patch tag.

## Versioning

The version follows [semantic versioning](https://semver.org/). While it is 0.x,
a minor release may break a public contract and says so under **Breaking** in the
[CHANGELOG](CHANGELOG.md); a patch release never does. Only the latest minor
release receives security fixes, as [SECURITY.md](SECURITY.md) says.

A module's public names are the names its `__all__` lists. Every other name it
defines starts with an underscore, and a module whose name starts with one (such
as `webauth._validation`) is private as a whole, as the Python typing
specification defines it. A name a module only imports is public there only when
its `__all__` re-exports it. Anything private may change or disappear in any
release.

## Development

[AGENTS.md](AGENTS.md) holds the repository's rules, the checks a change must
pass and how a release is made. The commands live under `scripts/`:

- `scripts/check.sh` runs every static check CI's `checks` job runs;
- `scripts/regenerate-build-constraints.sh` regenerates the hash-pinned build
  constraints from the setuptools floor in `pyproject.toml`;
- `scripts/verify-release.sh` downloads a release and checks the checksums and
  build-provenance attestations of its wheel and sdist.

The proof runs against a real issuer are described in
[`e2e/oidc/README.md`](e2e/oidc/README.md).

## Licence

MIT — see [LICENSE](LICENSE).
