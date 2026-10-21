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

`current_user_dependency` returns an `AuthDependencies` with three fields:
`current_user`, `admin_user` and `verified_session_id`. `session_store` is the
host's own FastAPI dependency. `on_authenticated` binds the account into the
host's log context. `login_redirect` is optional ([Reading the session](#reading-the-session)).
`trusted_proxies` names the peers whose `X-Forwarded-For` and `X-Forwarded-Proto`
are believed. The logout route is `token_exempt` ([Logging out](#logging-out)); the
sign-in routes are under [OpenID Connect login](#openid-connect-login).
[`tests/typing/oidc_host.py`](tests/typing/oidc_host.py) is a complete host,
checked in CI against the built wheel.

## Testing a host

A test that needs a signed-in person needs no issuer. It creates the account and
a session inside the configured lifetime in the host's own store, then calls
`issue_session_cookies(response, session_id, config)` from `webauth.cookies` on
a `Response` and copies both cookies it sets (read them from
`response.headers.getlist("set-cookie")`) into its client. The cookies cover a
read-only request; a state-changing request also sends the value of the CSRF
cookie in the header named `config.csrf_header_name`, and a form POST also needs
`Sec-Fetch-Site: same-origin`, or an `Origin` the config allows ([CSRF
origin](#csrf-origin)); a JSON POST needs neither. When the client keeps the
cookies' attributes and `cookie_secure` is on, use an `https` base URL.

A test of the host's own start, callback and logout routes gives
`OidcRelyingParty` its own `post_token_request` (a `TokenRequestPost`, from
`webauth.oidc`) and `fetch_key_set` (a `KeySetFetch`, from
`webauth.jwt_verification`) instead of the HTTPS ones, with the clocks as in
[The relying party](#the-relying-party). The host owns that stub.

The sign-in flow itself is proven against a real issuer: `e2e/oidc/` drives
Keycloak in a real browser, run by hand, and is webauth's own proof. A host
proves its own sign-in against a real issuer of its choosing. webauth ships no
fake issuer, because one that mints tokens does not belong in every production
install.

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
   - with a `WriteLock` that is released before the host commits (an in-process lock), a session that a login has created but not yet committed survives a back-channel logout of the same account that runs in between; a lock held until the transaction commits closes that window;
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

`webauth.oidc_login` carries the pending login for the host in a signed cookie
of its own, so the host keeps no server-side store and `WebAuthConfig` knows
nothing of OpenID Connect. The host serves three routes over its one
`OidcRelyingParty`: start (`start_login`), callback (`finish_login`, then
`open_session`) and logout (`log_out`). Each function's docstring holds its
contract, and `build_app` in
[`e2e/oidc/host_app.py`](e2e/oidc/host_app.py) is the worked set of routes,
type-checked and run against a real issuer; `config` is the `WebAuthConfig`
built under [Session lifetime](#session-lifetime) and the relying party is built
under [The relying party](#the-relying-party). See also
[Admitting an identity](#admitting-an-identity).

The host answers the callback with the `response` it passed to `finish_login` on
every outcome, refusals included, because that response carries the header that
clears the pending-login cookie. `finish_login` answers an `AdmittedLogin`, or
the `OidcRefusal` or `AdmissionRefusal` that stopped it; the host then opens
the session, commits, and only then issues the cookies, so a cookie never names
a session that was rolled back.

#### The return path

The path a person was headed to before signing in travels through the login as
`return_to`: the host hands it to `start_login`, and `finish_login` answers it
again after judging it a second time. Only a same-origin path of this app comes
back, so a login can never send a browser to another site; anything else comes
back as `None`, the host's default page, and the login still succeeds. The
rule, including how `root_path` is read, is in the `start_login` docstring.

#### Opening a session

`open_session` is the whole sequence between admission and the cookies: under
the host's write lock it ends the session the request's cookie names, prunes the
account to the host's cap and creates the new session, holding the login's
refresh token. It never commits and sets no cookie; the host commits, then calls
`issue_session_cookies`. See its docstring for the order and the cap.

#### Logging out

`log_out` is the whole logout sequence in one call: it ends the session the
request's cookie names, clears the session and CSRF cookies and returns the
issuer's end-session URL, so Keycloak ends its own session too, without asking
when it receives the ID token hint. It makes no outbound call and never
commits, so an issuer that is down still leaves the person signed out of the
app. The logout route is protected by the origin check, not by the CSRF token,
which is why it is listed in `token_exempt`; the `log_out` docstring says how a
form and a `fetch` logout differ and what the host's policy needs. The
post-logout redirect URI must be registered at the issuer (see
`OidcClientConfig`), and a form logout needs the issuer's origin in
`form-action` (see [Content-Security-Policy](#content-security-policy)).

The pending login travels in a cookie per login, so two tabs never overwrite
each other. Its name, flags, value and cap are in the `webauth.cookies` module
docstring.

#### The ID token hint

`finish_login` hands the browser the login's ID token in a cookie of its own,
and `log_out` passes it to Keycloak as `id_token_hint`, so Keycloak can end its
session without asking the person to confirm. The hint is never a credential:
webauth does not sign, decode, verify or log it, and Keycloak judges it. The
cookie is scoped to the `logout_path` of the `OidcClientConfig`; its name,
flags and bound, and what a changed `logout_path` leaves behind, are in the
`webauth.cookies` module docstring.

The callback names its pending login by state, and `finish_login` clears that
login's cookie on every outcome while every other tab's stays. A pending login
is single-use because its cookie is cleared and the issuer accepts its
authorization code once; webauth keeps no replay store, so a copied cookie is
stopped by the issuer refusing the spent code (`TOKEN_REQUEST_REFUSED`). The
callback matrix, which refusal answers which malformed callback, is in the
`finish_login` docstring.

### Back-channel logout

When a person's session ends at the issuer, for example after they sign out of
one app, the issuer posts a Logout Token to every client that session signed in
to. `webauth.oidc_login.receive_backchannel_logout` reads that form, has
`OidcRelyingParty.verify_logout_token` check the token, and ends every session
of its subject, in every browser. The host owns the route and the transaction;
the route answers 200 only after its commit. The worked route is `build_app`
in `e2e/oidc/host_app.py`. The token's signature is the only control, so the
route must be reachable by the issuer alone. The docstrings of those two
names hold the token rules, the order of the steps, and the CSRF, rate-limit,
body-size and reachability setup the route needs.

### The host's duties at login

The library never commits, so these belong to the host's callback route:
redirect to `admitted.return_to` or to a fixed local path, commit the
transaction `open_session` wrote into before it issues the cookies, and give the
`WriteLock` a second hold in the same request. The `finish_login` and
`open_session` docstrings hold the detail.

### The relying party

`webauth.oidc.OidcRelyingParty` runs the authorization-code flow with PKCE for
one client at one issuer, described by an `OidcClientConfig` that the host
builds with its secrets from its own secret channel. `begin_login` starts a
login, `complete_login` turns the callback into an `OidcIdentity` or an
`OidcRefusal`, `renew_access` and `workload_access_token` post a refresh and a
client-credentials grant, and `verify_logout_token` judges a Logout Token.
Every outbound call goes through the two transports the host injects
(`webauth.oidc_transport.post_token_request_over_https` and
`webauth.https_client.fetch_key_set_over_https`), which speak https only, bound
every request in time and size, follow no redirect and log nothing.
`build_app` in `e2e/oidc/host_app.py` composes them in a worked host. The docstrings of those names hold the order in which a callback is
judged, the token rules and the transports' bounds.

### The person's access token

`webauth.oidc_login.fresh_access_token` turns a signed-in session into a new
access token for one call to another service (an agent service, say). The
session holds only the refresh token, so a call that finds a standing session
with a refresh token is one refresh grant, and the access token goes to the
host in memory only. It answers a `SecretStr`, or an `AccessTokenRefusal` whose
`AccessTokenRefusalReason` says what the host does: treat the person as signed
out, send them to sign in again, or fail the call. A slow issuer holds only the
caller's thread, never a session row, a login or a logout. A token handed out
stays valid until its own `exp` after a later logout, and webauth makes no
revocation call ([Security model](#security-model), item 7). The docstrings of
`fresh_access_token` and the reasons hold the phases, the host's duties and the
realm's assumptions.

### Admitting an identity

`admit_identity` turns a verified identity into the account it signs in as, and
`finish_login` takes the same `AdmissionConfig`, which the host builds once at
startup. The host's store is bound to one issuer, so an account's `id` is the
issuer's subject. The app names a group path such as `/apps/notes`:
members come in, members of `admin_group` get the admin role, and both are
decided again at every login, so a change at the issuer takes effect at the
next sign-in while an open session runs on. Only the issuer's groups decide the
role. `EverySubject` states on purpose that admission needs no group, and `NoAdmins`
that the app has no admins; `EverySubject` leaves `admin_group` deciding who is
admin. A second service that verifies the issuer's token
itself calls `app_role` instead of copying the rule.

The rules, the order of refusals, and what is written are in the docstrings of
`AdmissionConfig`, `admit_identity` and `app_role`, and in the
`webauth.oidc_login` module docstring.

## Reading the session

`current_user_dependency` binds the host's session store into the route
dependencies `current_user`, `admin_user` and `verified_session_id`. A missing
or dead session answers 401, or, for a browser navigation on a server-rendered
host that names a `LoginRedirect`, a redirect to its login page.
`session_id_from_request` is the one reader of the signed session cookie, and
`admit_session` decides a session id that the host read itself. Both, and the
rule that bounds a stored expiry, are documented on the functions.

## The session gate

`install_web_auth_middleware(..., session_gate=SessionGate(...))` makes the rule
of "Signed out and refused" hold for every route: a request needs a live
session unless the host names it, so a route that forgets a dependency is gated,
not public. `SessionGate` names the public and optional paths and the host's
`SessionTransaction`; behind it the dependencies return the gate's admission
instead of admitting a second time, and `admitted_user` reads it where no
dependency is used.

## WebSocket handshakes

A browser sends the session cookie on a cross-site WebSocket handshake too, and
the middlewares pass WebSocket scopes through. `authenticate_websocket` is the
one check a host runs at the handshake: it decides the `Origin` first, then the
session, and answers the account or a `ConnectionRefusal`. A socket does not end
when its session does, so the host checks again while it streams.

## Configuration

The host builds one `WebAuthConfig` by keyword and installs it with
`install_web_auth_config`; no module reads an environment variable or a global.
It holds the deployment facts: the session secret, trusted proxies, rate-limit
backend, allowed hosts, session lifetime, cookie and header names, roles, the
clock and the IPv6 rate-limit prefix. Its docstring says what each field
decides, and refuses what the library cannot honour at construction.

`cookie_secure` is the one switch for transport security. It alone decides
whether both cookies carry `Secure` and whether `SecurityHeadersMiddleware`
sends HSTS, whatever the request's scheme, so a host serving plain http
(local development) turns it off for that environment and nowhere else.

`SecurityHeadersPolicy` names the headers every response carries, the
Permissions-Policy and Cache-Control rules among them, and the library's own
refusals and the 500 carry them too (see [Middleware order](#middleware-order)).

### The cookie-name rule

The session and CSRF cookies default to `__Host-` names, which only this exact
host can set, and to plain names when `cookie_secure=False`. A name a host
chooses is held to a rule that stops a login loop or a clash with a cookie the
library sets itself; `WebAuthConfig` lists it and refuses a breach when it is
built. The defaults are the constants in `webauth.cookies`. The ID token hint
cookie is described under [The ID token hint](#the-id-token-hint).

### Content-Security-Policy

`default_content_security_policy()` builds the policy a host gives
`SecurityHeadersPolicy`: nothing loads unless this origin serves it, and no page
may frame it. It holds no host fact; a host adds its own sources per
`CspDirective` through `added_sources` without copying the string. Its
docstring holds the default directives, how sources are written and checked, and
the `form-action` case for a form that posts or redirects to an issuer.

## The store decides every request

The library caches no sessions: `SessionRecordStore` is asked on every
authenticated request, so a session the host ended is refused on its next one.
The library alone decides whether a loaded session still stands; the store
writes the expiry it is given.

## Session lifetime

`SessionLifetime` holds the two numbers that decide how long someone stays
signed in: an idle window and an absolute cap from the session's creation. The
library owns the rule; `admit_session` documents it. The session, CSRF and
ID-token hint cookies live as long as the cap, issued once at login and never
reissued (`issue_session_cookies`), so the cap is also the worst-case delay
before a removal from the host's login group takes effect: an open session is
not re-checked. The recommended policy for a host that admits by `login_group`
is a 12-hour cap with an idle window of the same length. Every login checks the
group again, and the issuer's SSO session turns that login into a redirect the
person does not notice. A removal takes effect at once only by disabling the
user at the issuer together with the back-channel logout ("Back-channel logout"
above); without it, an open app session stays valid until it expires.

## Ending a session

Ending a session is a call on the host's store: `delete`, `delete_for_user` or
`prune_overflow`. The library makes it in `log_out`, `open_session` and
back-channel logout only, and a host that signs in through OpenID Connect ends a
session with [`log_out`](#logging-out).

## Middleware order

`install_web_auth_middleware(app, *, security_headers, body_size=None,
rate_limit=None, csrf_origin=None, csrf_token=None, session_gate=None)` adds the library's
middleware in the one order below, outermost first. Starlette inserts at the
front, so the installer adds them in reverse.

1. `SecurityHeadersMiddleware` (required): outside everything, so the
   library's own refusals carry the headers: the 413s, the
   429 and 503 with `Retry-After`, the CSRF 403s, and the 500.
2. `BodySizeLimitMiddleware`: a body whose Content-Length is over the limit
   is refused before it costs a rate-limit budget or a session lookup. A
   streamed body found over the limit while the route reads it comes after the
   session gate's admission.
3. `IpRateLimitMiddleware`: outside CSRF, so forged requests spend the
   address's budget.
4. `CsrfOriginMiddleware`.
5. `CsrfTokenMiddleware`.
6. `SessionGateMiddleware`: innermost, so a request the others refuse before
   admission never costs a session lookup, and a forged state-changing request is refused
   before it renews a session.

`csrf_origin` and `csrf_token` take separate `CsrfPolicy` values. The
installer refuses, before it touches the app, three things:

- A `csrf_token` without a `csrf_origin` (`ValueError`).
- A `csrf_token` whose `token_exempt` paths the origin check does not fully
  cover (`ValueError`): login routes skip the token on the promise that the
  origin check protects them. An exact path must require the origin check; a
  prefix must have every path below it checked, so an origin exemption inside
  it, or an origin policy that protects only the prefix string, is refused;
  shapes and patterns are refused as unverifiable.
- An app that already carries any of the six library middleware or a
  subclass of one, from an earlier installer call or added by hand
  (`RuntimeError`).

Install once, and add no library middleware yourself.

**Placement of host middleware.** Added before the call, a host middleware
sits inside the library stack: a request the library refuses early (413 by
Content-Length, 429, 503, the CSRF 403s, the session gate's 302 and 401)
never reaches it.
Added after the call, it sits outside: it sees every library refusal with the
headers already set. Put a middleware that must see only admitted requests
(session lookups, audit) before the call; put one that must observe every
response (access logs, metrics) after it. A response or exception produced by a host
middleware added after the call (outside the stack) does not carry the
library headers. A host `BaseHTTPMiddleware` or `@app.middleware("http")` makes a
response that fails mid-stream look complete wherever it sits, and added before
the call it also turns the 413 for a streamed body the route reads into the
library 500; write a middleware that must see admitted requests as pure ASGI.
The library middlewares run the app in the caller's task, so a `ContextVar` that
the app or an inner middleware sets is visible to an outer host middleware after
the call returns; a host that relied on `BaseHTTPMiddleware`'s task isolation
restores its own context, for example by resetting the token it set.

**Budget semantics.** When the limiter is enabled, the path is not exempt and
the limiter is reached:

| Refusal | Rate budget |
|---|---|
| 413 by Content-Length | spends nothing |
| 413 for a streamed body the route reads | spends one |
| CSRF 403 | spends one |
| library 500 | spends one; a missing-config 500 fails before rate admission |

**A body over the limit.**

| Body | Answer | Rate budget |
|---|---|---|
| Any Content-Length header over the limit | 413 before the route | spends nothing |
| Streamed (no Content-Length), and the response has already started when the limit trips: a streaming response that reads the body, or any `StreamingResponse` under ASGI spec < 2.4 (uvicorn reports 2.3), whose disconnect listener reads it | Never a second start and never a 413: the response is cut off at its next await, and one that already finished stays complete. The `RequestBodyTooLarge` error reaches the server either way | spends one |
| Streamed (no Content-Length), read by the route through `request.body()` or `request.stream()` before the response starts | 413 with the headers | spends one |
| Streamed, parsed by FastAPI (a typed body, `Form()`, `File()`/`UploadFile`) | FastAPI's 400 "There was an error parsing the body" through the host's `HTTPException` handler; the route never runs | spends one |
| Streamed, never read, and the response is not a `StreamingResponse` under spec < 2.4 | Not size-checked; answers normally | spends one |

The library sends a response's start whole: a cancellation inside the app waits until the start is sent, and so does a host deadline that cancels through an anyio cancel scope outside the stack; asyncio cancellation (`asyncio.timeout`, server shutdown) still interrupts it. The wait is bounded: a start the app hands over that has not been sent after `BodySizePolicy.start_send_seconds` (default 10 seconds) is cut off with an error that reaches the server; no 413 and no second start follow.

**The 500 cases.**

| Cause | Response | Budget |
|---|---|---|
| A route raises | The library 500 with the headers; the exception still reaches the server | spends one |
| No `WebAuthConfig` installed | The library 500 with the headers (no HSTS); the exception still reaches the server | spends nothing |

## CSRF origin

`CsrfOriginMiddleware` reads `Sec-Fetch-Site` first on a state-changing
request: the header overrides the Origin allowlist for `same-origin`
(passes) and `cross-site` (refused), while `same-site` is decided by the
allowlist; when the header is absent the allowlist decides.
When both are absent, a form POST is refused — a JSON POST with neither
header still passes. An `Origin` or `Referer` that is `null`, empty, has no
host, carries userinfo or a non-numeric port, or cannot be parsed is refused
like a foreign origin; an empty `Origin` is not replaced by the `Referer`.
An exact host matches the parsed host with or without a numeric port. A
configured host pattern is matched against the whole host plus numeric port,
so anchor it and allow the port, e.g. `app\.example(:\d+)?`.

`CsrfPolicy` defaults to fail-closed: with `protected` left unset, every
state-changing request is checked, and `exempt` names the path prefixes that
carry no session and therefore no token — a sessionless payment-provider
webhook, say. A deployment that lists every mutating route in
`protected` has exactly those routes checked and must leave
`exempt` empty: combining an explicit `protected` list with any exemption is
refused at startup, because the exemption cannot change that list.

`webauth.dependencies.unauthenticated_response(request, login_redirect)`
answers what `current_user_dependency` answers for a request without a usable
session cookie — the login redirect or the 401 `Authentication required` — as a
real `Response` rather than a raised exception, for a host whose own middleware
is the session authority and cannot rely on FastAPI's dependency-injection or
exception-handling machinery to reach it. For a forged, doubled or ended
session the dependency and the session gate answer `Invalid session` or
`Session expired`, with the same redirect.

## Rate limiting, and the optional Redis extra

`WebAuthConfig` requires a `rate_limits`, a `webauth.ports.RateLimitBackend`
with one method — `is_allowed(key, *, limit, window_seconds) -> bool` — that
counts the current event against a sliding window and raises rather than
guessing when it cannot answer, so the middleware fails the request closed.

The middleware calls `is_allowed` from a worker thread, so a slow limiter does
not stall the event loop, and calls may overlap: a backend of your own must be
thread-safe (both backends below are). A check holds its worker thread until the
backend gives up, so give a Redis client short timeouts and few retries; the
client defaults can hold a thread for a minute.

The host names its budgets in a `webauth.policies.RateLimitPolicy`. Exempt
paths spend nothing. The first `RateLimitRule` whose paths match decides which
budget a request spends from, and every other path spends from `default`. A
budget name starts with a lowercase letter, holds only lowercase letters,
digits, `-` and `_`, and is unique in the policy. The limiter key is
`<name>:<address>` inside the Redis `key_prefix`, so renaming a budget starts
it fresh. A budget whose `max_requests` or `window_seconds` is not a positive
whole number is refused at construction. A backend of your own receives only
such values: `limit` and `window_seconds` are positive integers, excluding
booleans, and the caller validates them before invoking the backend.

```python
from webauth.policies import PathRules, RateLimitBudget, RateLimitPolicy, RateLimitRule

RateLimitPolicy(
    default=RateLimitBudget("api", max_requests=300, window_seconds=60),
    rules=(
        RateLimitRule(
            paths=PathRules(prefixes=("/files/",)),
            budget=RateLimitBudget("downloads", max_requests=1200, window_seconds=60),
        ),
    ),
    exempt=PathRules(exact=frozenset({"/robots.txt"}), prefixes=("/static/",)),
)
```

Two backends implement `RateLimitBackend`:

- `webauth.rate_limit.RedisRateLimitBackend` shares one window across every
  process that reaches the same Redis. It needs the client library, so a host
  that uses it installs `overnightworks-webauth[redis]`. It measures the
  window on the Redis server's own clock (`TIME`), so hosts with differing
  clocks share one budget, and it needs Redis 5.0 or later, or Valkey: the
  script reads `TIME` and so relies on script effects replication. If the
  server refuses the script, the middleware answers every rate-limited request
  with 503, failing closed.
- `webauth.rate_limit.SingleProcessRateLimitBackend` keeps the window in this
  process's memory and needs no Redis — for a single-node host that runs one
  worker. Two processes or two hosts count independently, so a multi-worker
  deployment uses the Redis backend instead.

Redis is therefore an optional dependency: a deployment that supplies the
in-process backend installs `overnightworks-webauth` without the `redis` extra.

## Audit events

Map `AuditSink.account_event(event)` to the host's audit system, or
explicitly implement a no-op. Every event carries `kind`, `actor_id`, and
`subject_id`; optional fields default to `None`:

| Event kind | Additional fields |
|---|---|
| `user_created` | `role` |
| `role_changed` | `previous_role`, `role` |
| `backchannel_logout` | none; `subject_id` is the account whose sessions the issuer ended |

Events contain no raw session identifiers or usernames. An admission event
with `actor_id=None` means the issuer's groups decided, not a person.

## What it owns, and what it leaves to the host

It owns the machinery an application should not rebuild:

| Module | Owns |
|---|---|
| `webauth.config` | The deployment facts every other module reads, installed on the app |
| `webauth.cookies` | The signed session cookie, the CSRF token bound to it, the pending-login cookie and the ID token hint cookie, issued and cleared |
| `webauth.dependencies` | Turning a signed cookie into the account that made the request or opened a WebSocket handshake (`authenticate_websocket`), and a session id into that account without a request (`admit_session`) |
| `webauth.policies` | Which requests are exempt, cacheable, or rate-limited, and how |
| `webauth.proxies` | Which peers may name a client, and the client identity that follows |
| `webauth.rate_limit` | The sliding-window backends a per-address budget is measured with — Redis or in-process |
| `webauth.ports` | What the host supplies, as Protocols, and what the library hands out (`AuthenticatedUser`) or reads from the host (`WallClock`): the record shapes `UserRecord` and `SessionRecord`, the stores `SubjectUserStore` and `SessionRecordStore`, and `SessionTransaction`, `WriteLock`, `AuditSink` and `RateLimitBackend` |
| `webauth.middleware` | Body-size, CSRF, rate-limit, security-header and session-gate middleware, and `install_web_auth_middleware`, which installs them in the one order |
| `webauth.jwt_verification` | Whether an RS256 token from a remote issuer holds: PyJWT reads the token behind a bound of 8,192 characters on the token and 512 on its header segment (longer is `TOKEN_TOO_LONG` or `MALFORMED_TOKEN`), its signature against the issuer's cached key set, issuer, audience and time claims. A key set may publish at most `MAX_KEY_SET_KEYS` (10) RS256 signing keys; keys for other purposes are passed over, bounded only by the key set's size. A token without a `kid` member verifies against the key set's only RS256 verification key, which may lack `kid`, and is refused as `INVALID_KEY_ID` against several eligible keys; a key without `kid` beside others is admitted but unreachable, `MAX_KEY_SET_KEYS` counts it, an explicit `"kid": null` or a `kid` that is not a string is malformed, and a rotation of a sole key, or a change between one and several keys, can stay unseen until the one-hour TTL expires, unless a token naming an unfamiliar `kid` triggers an earlier refresh. A token naming an unknown `kid` is refused as `KEY_SET_UNAVAILABLE` when the key-set refresh it triggered failed or is cooling down after a failure, and as `UNKNOWN_KEY_ID` only when the refresh succeeded without that key. |
| `webauth.https_client` | The one owner of outbound HTTPS: the key-set fetch and the form POST the token request is sent with, under per-operation timeouts and a total deadline, a size cap, no redirect followed and the system's trusted certificates |
| `webauth.oidc` | Logging a browser in at an OpenID Connect issuer: the authorization URL with PKCE, the callback judged, the code exchanged and the ID token verified into an identity, and the refresh and client-credentials grants answering a fresh access token |
| `webauth.oidc_login` | Whether a verified identity of the bound issuer becomes, reuses, or is refused an account, the role that account holds (`admin_role` or `user_role`, set from the admin group at every login) and `app_role`, the same rule as a pure function for a second service, `open_session`, which ends the replaced session, prunes the account to its cap and then creates the new one, holding the login's refresh token, at the configured clock's instant, `log_out`, which ends the browser's session and returns the issuer's end-session URL, `fresh_access_token`, which turns a live session into a new access token for one call and stores the issuer's rotated refresh token, and `receive_backchannel_logout`, which reads the back-channel form and ends every session of the subject its verified Logout Token names. Takes its identity from `webauth.oidc` |
| `webauth.oidc_transport` | `post_token_request_over_https`, the production `TokenRequestPost`: the token request sent through `webauth.https_client` |

It leaves the application everything that touches the application's own truth:

- **Users and roles.** It has no user model and no role names beyond the
  configured ones; the one thing it writes to an account is the role admission
  derives from the issuer's groups (`admin_role` or `user_role`), and it
  decides no authorisation beyond the admin check.
- **Persistence.** It holds no schema and no ORM, and an import-linter contract
  keeps it that way. What it needs reaches it through the Protocols in
  `webauth.ports`.
- **Transactions.** The library commits nothing; a store either applies each of
  its calls at once or writes into a transaction the host commits. Whether a
  request that fails leaves the auth machinery's writes behind is the host's: a
  transaction that rolls back on an exception leaves none, a store that applies
  each call keeps them, and the rate-limit budget counts attempts either way.
  Behind [the session gate](#the-session-gate), the gate makes the session
  renewal durable through the host's `SessionTransaction` before the route runs,
  so a route that fails afterwards does not undo it.
  [`fresh_access_token`](#the-persons-access-token) opens and leaves two short
  transactions through the same `SessionTransaction`, neither held across the
  issuer's grant.
- **Routes.** It defines none. The only responses it writes are its own
  refusals: 401, 403, 413, 429, 503 and the 500, and the 302 to the host's login
  path. Once a response has started it writes nothing more: a streamed body over
  the limit then raises `RequestBodyTooLarge` to the server.
- **Identity.** It issues no access or ID tokens: it is no identity provider, and
  it verifies the ID tokens an issuer made.
- **HTTP framing** is the ASGI server's job. uvicorn's two parsers, h11 and
  httptools, answer some framing conflicts differently, and HTTP allows either
  answer. webauth never re-parses framing: its body-size limit counts the
  streamed bytes whatever the headers say.

## Install

`overnightworks-webauth` is not on PyPI: it installs only from the wheel
published as an asset on each tag's release. Take the version
from the [Releases page](https://github.com/overnightworks/webauth/releases)
and put it in place of `X.Y.Z`:

```bash
uv pip install "overnightworks-webauth @ https://github.com/overnightworks/webauth/releases/download/vX.Y.Z/overnightworks_webauth-X.Y.Z-py3-none-any.whl"
```

In a `pyproject.toml`:

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

The checks a change must pass, and the commands that run them, are in
[AGENTS.md](AGENTS.md) under "Checks".

## Licence

MIT — see [LICENSE](LICENSE).
