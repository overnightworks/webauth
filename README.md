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

`webauth.oidc_login` carries the pending login for the host, so the host
keeps no server-side store and `WebAuthConfig` knows nothing of OpenID
Connect. The host serves three routes over its one `OidcRelyingParty`:
start, callback and logout. In the example, `config` is the
`WebAuthConfig` built under [Session lifetime](#session-lifetime) and
`relying_party` is built under [The relying party](#the-relying-party); see
also [Admitting an identity](#admitting-an-identity).

```python
from fastapi import Request, Response

from webauth.cookies import issue_session_cookies
from webauth.oidc import OidcRefusal
from webauth.oidc_login import (
    AdmissionConfig,
    AdmissionRefusal,
    finish_login,
    open_session,
    start_login,
)

admission = AdmissionConfig(
    bound_issuer=client_config.issuer,
    login_group="/apps/notes",
    admin_group="/apps/notes/admin",
)


@app.get("/login/oidc")
def start(request: Request, next: str | None = None) -> Response:
    response = Response(status_code=303)
    response.headers["location"] = start_login(
        relying_party, request, response, config, return_to=next,
    )
    return response


@app.get("/auth/callback")
def callback(request: Request, response: Response) -> dict[str, str]:
    outcome = finish_login(
        relying_party, request, response, config,
        admission=admission, accounts=accounts, lock=lock, audit=audit,
    )
    if isinstance(outcome, (OidcRefusal, AdmissionRefusal)):
        response.status_code = 403
        return describe_the_hosts_refusal(outcome)
    session = open_session(
        request, config, outcome,
        sessions=sessions, lock=lock,
        max_sessions=3,
    )
    commit_the_hosts_transaction()
    issue_session_cookies(response, session.id, config)
    response.status_code = 303
    response.headers["location"] = outcome.return_to or "/"
    ...
```

`start_login(relying_party, request, response, config, *, return_to)` begins a
login, sets its pending-login cookie on `response` and returns the
authorization URL. The keyword is required, so a host cannot forget it; pass
`None` for none.
`finish_login(...)` answers an `AdmittedLogin` (the `account` to open a session
for, the `return_to` path or `None`, and the login's `refresh_token` or `None`), or the `OidcRefusal` or `AdmissionRefusal` that stopped it;
on an `AdmittedLogin` the host calls [`open_session`](#opening-a-session), commits, and
only then issues the cookies. `finish_login`
sets the header that clears the pending-login cookie on `response`, so the
host answers with that response on every outcome, refusals included: FastAPI
copies an injected `response`'s headers only when the route returns a value
that is not itself a `Response`; a returned `JSONResponse` is sent as-is and a
raised `HTTPException` gets a new response, so neither carries them, which
would leave the pending cookie in the browser.

#### The return path

`return_to` is the raw path and raw query as the app sees them, `root_path`
included, never the percent-decoded `request.url.path`; `LoginRedirect` builds
its `next` the same way. The library keeps it in the pending-login cookie and
returns it from `finish_login`, after judging it again. It is a same-origin
path of this app, ASCII only (non-ASCII characters are percent-encoded) and, once
percent-encoded, at most 512 bytes, or `None`; `None` means the host's default
page, and the login still succeeds. These never come back: a path a browser
reads as another host (`//x`, `/\x`, tab, CR or LF between the slashes), an
absolute URL, a bare host, any control character, the empty string, anything
over 512 bytes, and, under a `root_path`, a path outside it. A `root_path` with
a character other than ASCII letters, digits, `-._~` and `/` keeps no return
path. A `.` or `..` segment (also as `%2e`) is refused too, because a browser
resolves it before sending a request, and so is a literal `#`, which a request
never carries.

`start_login` keeps a `return_to` only when it already lies under `root_path` at
a segment boundary, as Starlette's router reads it, and prepends nothing: with
`root_path="/app"`, `/app/albums/42` is kept and `/albums/42` comes back `None`.
Only the address `LoginRedirect` builds from the request gets `root_path`
prepended, unless the raw path already carries it at a segment boundary. A login
route inside a mounted sub-app is judged against that mount's `root_path`. The
fragment is lost, because browsers never send it.

#### Opening a session

`open_session(request, config, admitted, sessions=..., lock=...,
max_sessions=...)` is the whole sequence between admission and the cookies. It
reads `WebAuthConfig.wall_clock` once, as the same whole seconds the session
decision reads, and inside one `lock.hold()` it ends the session the request's
cookie names (signed, sole and within the length bound, whichever account it
belongs to; any other cookie ends nothing), then, with a cap, ends all but the
account's newest `max_sessions - 1` sessions, then creates the account's new
session through `create(user_id, *, now, expires_at, refresh_token)`
with `created_at` equal to that `now`, `expires_at` one idle period later and the
`refresh_token` of `admitted`, a `SecretStr` or `None`.
The host passes no expiry, and the store writes the instants and the token it is given.
The store writes the token with `get_secret_value()` into one nullable text column of the session
row; the library bounds it only by the 64 KiB token response, so the column takes no smaller
length. A session stored before the host held refresh tokens answers `None`. The
new session is created last, so it is never the one the cap ends, and the
replaced session never counts against the cap. With a cap of 2 and sessions
`{S1, S2}`, a login whose cookie names `S2` leaves `{S1, S3}`; two logins in
the same clock tick at a cap of 1 both succeed and leave the later one.
`max_sessions=None` states that the host sets no cap; any other value must be
a positive whole number, or `ValueError` is raised before anything is written.
It answers the new `SessionRecord`.

It never commits and sets no cookie: the host commits, then calls
`issue_session_cookies(response, session.id, config)`, so a cookie never names a
session that was rolled back. It records no audit event, like `log_out`. The
host's `WriteLock` must allow a second hold in the same request: one for
admission, one for `open_session`.

#### Logging out

`log_out(relying_party, request, response, config, sessions=..., lock=...)` is
the whole logout sequence in one call, so no host rebuilds its order: it ends
the session the request's cookie names (when there is one) under the write
lock, clears the session and CSRF cookies on `response` and returns the
issuer's end-session URL. That URL carries the client ID, the configured
`post_logout_redirect_uri` and the `id_token_hint` that `finish_login` handed
the browser at sign-in (see [The ID token hint](#the-id-token-hint)), so
Keycloak ends the session without asking the person to confirm. Without a
usable hint the URL leaves it out and Keycloak asks once. While the session lives, its row
holds the refresh token; no logout step sends it to Keycloak, and deleting the row removes it. The logout is a GET to Keycloak, so the hint lands in that
device's browser history and is visible to a TLS-terminating edge; in the
fetch shape it also reaches the page's own script. Once the session has
ended, the hint has no logout power left. `log_out` makes no outbound call
and never commits, so an issuer that is down still leaves the person signed
out of the app. A request with no usable session (a
missing, expired-and-deleted, forged, oversized or duplicated cookie) still
gets the URL and the cookie clearing, so the issuer's session ends too. A
forged or duplicated cookie ends no stored session: a duplicated cookie's
session lasts until it expires.

A form logs out through a route that builds the `Response` itself and passes
it in. Never return a `RedirectResponse` here: FastAPI sends a returned
`Response` as is, so the cookie deletions on an injected `response` would be
lost.

```python
from webauth.oidc_login import log_out


@app.post("/logout")
def logout(request: Request) -> Response:
    response = Response(status_code=303)
    response.headers["location"] = log_out(
        relying_party, request, response, config, sessions=sessions, lock=lock,
    )
    commit_the_hosts_transaction()
    return response
```

A page that logs out through `fetch` returns the URL as JSON through the
injected `response` and navigates itself, because `fetch` would follow a
cross-origin 303: `return {"logout_url": log_out(...)}`, then
`location.assign(logout_url)`. Neither route uses `Depends(current_user)`.

The logout is protected by the origin check, not by the CSRF token. The token
is bound to the session, so it fails once the session has expired, and a plain
form cannot send the token header. Install the stack with
`csrf_origin=CsrfPolicy()` and
`csrf_token=CsrfPolicy(token_exempt=PathRules(exact=frozenset({"/logout"})))`.
The host lists its own logout route's exact path, whichever shape it uses: a
fetch logout at `/logout/fetch` lists `"/logout/fetch"` instead.
Keep the route POST only, because the origin check runs only on mutating
methods; name the path exactly in `token_exempt`, never in `exempt` and never
as a prefix, so no other route falls under it.

A logout form redirects the browser to the issuer, and Chromium checks
`form-action` on that redirect. A host whose logout is a form adds the
end-session endpoint's origin to `form-action` in its policy (see
[Content-Security-Policy](#content-security-policy)). A page that logs out
through `fetch` is not subject to `form-action`.

Register each app's post-logout redirect URI at the issuer: Keycloak checks
`post_logout_redirect_uri` against the client's `post.logout.redirect.uris`.

An issuer on another registrable domain than the app needs
`cookie_samesite="lax"`. With the default `"strict"` the browser withholds the
session cookie from the first page after the callback redirect, and that page
is signed out. An issuer on the same site works with either value.

The pending login travels in a cookie of its own, one per login, so two tabs
never overwrite each other:

- **Name:** the pending-login prefix `__Host-oidc_pending_` followed by the
  first 16 hex characters of the SHA-256 of the login's state. With
  `cookie_secure=False` the name is the plain `oidc_pending_…` form and the
  cookie is not `Secure`. That is for plain http, a host's own session login
  or a test stack whose two app URLs are http on a loopback host, where a
  sibling host or a network observer can set or read it.
- **Flags:** `HttpOnly`, `Path=/`, `Max-Age=600`, and `Secure` following
  `cookie_secure`. It is always `SameSite=Lax`, whatever `cookie_samesite`
  says: the callback is a top-level navigation from the issuer's site, which a
  `Strict` cookie would not accompany.
- **Value:** `v2.` followed by the state, nonce, verifier, `issued_at` and the
  base64url-encoded return path (empty when there is none), each bounded to the
  exact shape `begin_login` mints or `return_to` allows, and an HMAC-SHA256
  signature under the session signing key with an `oidc-pending:` prefix no
  other cookie uses; the whole value is at most 896 characters, and the
  signature is compared in constant time.
- **Cap:** a browser holds at most five pending-login cookies. A start beyond
  them clears the oldest by `issued_at` — a cookie that does not verify, or
  whose name appears twice, counts as oldest — so repeated starts never crowd
  out the session and CSRF cookies. Only names of the exact pending-login
  shape, the prefix and 16 lowercase hex characters, count; any other cookie
  whose name merely starts with the prefix is neither counted nor cleared.

#### The ID token hint

`finish_login` also hands the browser the login's ID token in a cookie of its
own, so that `log_out` can pass it to Keycloak as `id_token_hint`:

- **Name:** `__Secure-oidc_id_token_hint`, or the plain `oidc_id_token_hint`
  with `cookie_secure=False`. It cannot be a `__Host-` cookie, because that
  prefix demands `Path=/`.
- **Flags:** `HttpOnly`, `SameSite=Strict` always, `Max-Age` as the session
  cookie (the session cap), `Secure` following `cookie_secure`, and `Path` set to the
  `logout_path` of the `OidcClientConfig`. The browser sends it to every path
  beneath that prefix, so set `logout_path` to the narrowest prefix that covers
  the logout routes: with `/logout` only `/logout` and the paths under it carry
  the hint, while `/` sends it with every request.
- **Set only on an admitted login:** a refused callback sets none, and a new
  login overwrites the old one. An ID token longer than
  `MAX_ID_TOKEN_HINT_CHARS` (3072) is not kept and the old cookie is cleared
  instead; the person is still signed in, and their logout asks. Keycloak
  asks once whenever the browser holds no ID token from its latest Keycloak
  sign-in: a token over the bound, a hint cookie the browser no longer holds, or a
  token of another Keycloak session.
- **Never a credential:** the hint is not signed by webauth, and it is never
  decoded, verified, logged or accepted as a session. Keycloak judges it. The
  reader passes on only a sole cookie of that name that has the shape of a
  compact JWS within the bound; anything else counts as missing.
- **Cleared on every logout.** `log_out` clears the cookie whether or not it
  could use the hint.
- **`logout_path`** is the browser-visible path of the host's logout route, or
  a parent of all its logout routes, such as `/logout` for `/logout` and
  `/logout/fetch`. Behind a path-rewriting proxy it is the path the browser
  sees. Changing it between deployments leaves the
  cookie of the old path in the browser, and `log_out` clears only the new
  path. Where the old path still matches the logout route, as `/` does for
  `/logout`, a new login adds a second cookie of the same name; a logout that
  finds two omits the hint, so Keycloak keeps asking until the old cookie
  expires or the person removes it.
  After a realm signing key is deleted, an old hint gives Keycloak's
  error page instead of a confirmation.

`finish_login` reads the state from the callback, selects exactly the cookie
that state names and clears it on every outcome — admitted or refused —
while every other tab's cookie stays. A callback names a usable state when it
carries `state` exactly once, non-empty and decodable.

- With a usable state, a malformed rest (a parameter named twice, one that
  does not decode, or a pair that strict query parsing refuses, such as a
  trailing `&` or a name without `=`) still clears that state's cookie. It is
  refused as `MALFORMED_CALLBACK` when that cookie is genuine and as
  `STATE_MISMATCH` otherwise.
- Without a usable state no cookie is selected. The callback is refused as
  `MALFORMED_CALLBACK` when it holds a parameter named twice, one that does
  not decode, or a pair that strict query parsing refuses, such as a trailing
  `&` or a name without `=`, and as `STATE_MISMATCH` otherwise.
- With a well-formed rest, a missing, forged, oversized, unknown-version or
  duplicated cookie, or a genuine cookie of another login, is
  `STATE_MISMATCH`.

Every one of these is refused before any token request.

**Single use, stated honestly.** A pending login is single-use because its
cookie is cleared on every outcome and the issuer accepts its authorization
code once. webauth keeps no server-side replay store: a copy of the cookie
taken before the callback is stopped by the issuer refusing the spent code
(`TOKEN_REQUEST_REFUSED`), not by webauth remembering it.

### Back-channel logout

When a person's Keycloak session ends, for example after they sign out of
one app, Keycloak posts a Logout Token to the `backchannel.logout.url` of
every client that session signed in to. `receive_backchannel_logout(relying_party,
form_body, content_type, *, accounts, sessions, lock, audit)` reads the POSTed
form (one non-empty `logout_token` field, `application/x-www-form-urlencoded`),
verifies the token and ends every session of its subject, in every browser, and
answers `BackchannelLogoutResult.ACCEPTED` or `REFUSED`; a malformed form is
`REFUSED` before anything is verified or locked. The host's route passes the
raw body and the content type:

```python
import logging

import anyio.to_thread
from fastapi import Request, Response

from webauth.oidc_login import BackchannelLogoutResult, receive_backchannel_logout

logger = logging.getLogger(__name__)


def end_the_sessions_of(form_body: bytes, content_type: str | None) -> BackchannelLogoutResult:
    with the_hosts_transaction() as work:
        return receive_backchannel_logout(
            relying_party, form_body, content_type,
            accounts=work.accounts, sessions=work.sessions, lock=work.lock, audit=work.audit,
        )


@app.post("/auth/backchannel-logout")
async def backchannel_logout(request: Request) -> Response:
    form_body = await request.body()
    content_type = request.headers.get("content-type")
    try:
        result = await anyio.to_thread.run_sync(end_the_sessions_of, form_body, content_type)
    except Exception:
        logger.exception("back-channel logout failed")
        return Response(status_code=400)
    return Response(status_code=200 if result is BackchannelLogoutResult.ACCEPTED else 400)
```

`the_hosts_transaction()` opens the host's stores on one connection and
commits when the block ends. The verification, the lock and the stores are
synchronous, so they run in a worker thread and create and use their stores
there. The route answers 200 only after the commit; a refusal or a failure,
the commit's included, leaves every session in place and answers 400.

The function runs in this order. It reads the form, then verifies the token
before it takes the lock; a malformed form or a refusal does nothing more. Under `lock.hold()` it looks up
`accounts.get(subject)`. An unknown subject is accepted and creates no
account. A known subject loses every session
through the store's `delete_for_user`, and one `backchannel_logout` audit event with
`actor_id=None` is emitted when at least one session ended. It never commits,
clears a cookie or calls Keycloak.

`OidcRelyingParty.verify_logout_token(logout_token)` answers a
`VerifiedLogout(subject)` or an `OidcRefusal`. It is stricter than the OpenID
Connect Back-Channel Logout profile asks, and it never returns the token, its
claims or its `sid`, so no session id is stored. The token must be:

- RS256, signed by a key of the configured issuer, with the JOSE header
  `typ` exactly `logout+jwt` (`JwtVerifier.verify(token, expected_type=...)`);
- for exactly this client: `aud` is the client ID, as a string or an array of
  one;
- issued no more than `LOGOUT_TOKEN_MAX_AGE_SECONDS` (120) plus the
  configured leeway ago, and not in the future beyond the leeway, with an
  integer `iat`;
- unexpired, with an `exp` after its `iat`;
- carrying `events` with exactly the key
  `http://schemas.openid.net/event/backchannel-logout`, whose value is an
  object;
- carrying a non-empty `sub`, so a token naming only a `sid` is refused, and
  no `nonce`, not even `null`.

There is no replay store: a copy of a valid token ends the subject's sessions
again, as the first did, for at most those two minutes plus the leeway. A
person who signed in again in that time is signed out once more.

Set the route up so that only the issuer can reach it:

- **Body.** A `BodySizeRule` of 32 KiB for the exact path in `body_size`,
  under a smaller default.
- **Headers.** A `CacheControlRule` for the exact path with `no-store`, so
  every answer, 400 and 413 included, carries it.
- **CSRF.** Keycloak sends neither an Origin nor a cookie: list the exact path
  in `exempt` of both `csrf_origin` and `csrf_token`. Never a prefix, and
  `/logout` stays `token_exempt` only.
- **Rate limit.** List the exact path in `RateLimitPolicy.exempt`, because
  Keycloak posts from shared server addresses and one budget would otherwise
  refuse a real logout.
- **Reachability.** Register `backchannel.logout.url` on the client by an
  internal name, never through the public hostname or a Cloudflare Access
  application.

### The host's duties at login

The library never commits, so these belong to the host's OIDC
callback route, around [`open_session`](#opening-a-session):

- **Return path:** redirect to `admitted.return_to`, or to a fixed local path
  when it is `None`. The library has already judged it (see
  [The return path](#the-return-path)).
- **Commit before cookies:** commit the transaction `open_session` wrote
  into, then call `issue_session_cookies`.
- **Second hold:** the `WriteLock` must allow a second hold in the same
  request, one for admission and one for `open_session`.
- **Entropy:** see `SessionRecordStore.create`.

### The relying party

`webauth.oidc.OidcRelyingParty` runs the authorization-code flow with PKCE
for one client at one issuer, described by an `OidcClientConfig` whose issuer URLs
are all https and whose `client_secret` is a `SecretStr`. The two app URLs,
`redirect_uri` and `post_logout_redirect_uri`, may instead be http on a loopback host
(`localhost`, `127.0.0.1` or `[::1]`) for local and CI test stacks; every issuer URL
stays https. Browsers differ in whether they keep a `Secure` cookie over http on a
loopback host, so a stack that must work in each runs with
[`cookie_secure=False`](#configuration) and the plain cookie names. `begin_login()`
answers the URL to send the browser to and a `PendingLogin` — its state,
nonce and PKCE verifier, and `issued_at`, the wall-clock second it began.
`complete_login(pending, callback_query)` takes that pending login and the
callback's raw query string and answers an `OidcIdentity` (subject, issuer,
full group paths, `sid`, `preferred_username`, the verified `id_token`
as received, which stays out of its repr, and the `refresh_token` the code exchange
issued as a `SecretStr`, or `None` when the issuer gave none) or an `OidcRefusal` naming its
reason. The state is checked before anything else the callback says; then
the pending login's age: one older than `PENDING_LOGIN_MAX_AGE_SECONDS`
(600) or dated in the future is `PENDING_LOGIN_EXPIRED`, and no token
request is sent. An error the issuer reports is carried as its short error
code only, never its description, and a `code` longer than
`MAX_AUTHORIZATION_CODE_CHARS` (2048) is `MALFORMED_CALLBACK`. A token answer
that names a member twice keeps its last value. The code is exchanged through
the `post_token_request` the host injects, and the ID token is verified by a
`JwtVerifier` whose one accepted audience is the client ID, then checked for
the pending nonce and an authorized party: a token for several audiences must
name the client as its `azp`, and any `azp` a token names must be the client. The exchange's access token is never read
or kept. A `refresh_token` in the answer must be a string of RFC 6749 Appendix A.17's
`1*VSCHAR` (printable ASCII); anything else, `null` included, is
`TOKEN_ENDPOINT_FAILED`.

Two more calls post a grant to the same token endpoint, with the same Basic
authorization, no cache and no lock, so each call is one POST and a fresh
token. `renew_access(refresh_token)` posts `grant_type=refresh_token` with the
refresh token a `SecretStr` holds and answers a `RenewedAccess`: the new
`access_token` and the `refresh_token` the issuer rotated to, or `None` when it
sent none. `workload_access_token()` posts `grant_type=client_credentials` and
nothing else, so the issuer applies the client's default scopes, and answers
the client's own access token. Both answers need a `token_type` that is
`Bearer` in ASCII, any case, and an `access_token` of RFC 6750's `b64token`
shape, so it can sit in an `Authorization` header; anything else is
`TOKEN_ENDPOINT_FAILED`. A refresh token outside the grammar above, sent or
received, is `TOKEN_ENDPOINT_FAILED` too, and a sent one reaches no request.
An issuer's `error` on a 400 or 401 is `TOKEN_REQUEST_REFUSED` carrying
`idp_error`, as in the code exchange (`invalid_grant` for a refresh token the
issuer no longer accepts, `unauthorized_client` for a client with no service
account); any other failure is `TOKEN_ENDPOINT_FAILED`. Neither call decodes
a token: its claims are for whoever receives it to judge. The realm must give
the client a service account holding the role the receiver demands; that is
the realm's duty, not the library's.

For a Keycloak client the host builds one `OidcClientConfig`. The client id and secret come
from the host's secret channel, never from source:

```python
import os

from pydantic import SecretStr

from webauth.oidc import OidcClientConfig

realm = "https://auth.example.test/realms/example"
client_config = OidcClientConfig(
    issuer=realm,
    authorization_endpoint=f"{realm}/protocol/openid-connect/auth",
    token_endpoint=f"{realm}/protocol/openid-connect/token",
    jwks_url=f"{realm}/protocol/openid-connect/certs",
    end_session_endpoint=f"{realm}/protocol/openid-connect/logout",
    client_id=os.environ["OIDC_CLIENT_ID"],
    client_secret=SecretStr(os.environ["OIDC_CLIENT_SECRET"]),
    redirect_uri="https://app.example.test/auth/callback",
    post_logout_redirect_uri="https://app.example.test/",
    logout_path="/logout",
    leeway_seconds=30,
)
```

In production both outbound calls go through `webauth.https_client`, the one
module that imports urllib3:

```python
import time

from webauth.https_client import fetch_key_set_over_https
from webauth.oidc import OidcRelyingParty
from webauth.oidc_transport import post_token_request_over_https

relying_party = OidcRelyingParty(
    client_config,
    post_token_request=post_token_request_over_https,
    fetch_key_set=fetch_key_set_over_https,
    wall_clock=time.time,
    monotonic_clock=time.monotonic,
)
```

Each request is HTTPS only, under the system's trusted certificates
(`SSL_CERT_FILE` included), with a connect and a read timeout of five seconds
each and a total deadline of ten seconds — `KEY_SET_FETCH_DEADLINE_SECONDS`
and `TOKEN_EXCHANGE_DEADLINE_SECONDS` — over the TLS handshake and the
whole answer, so an origin that drips its answer is cut off as a timeout;
connecting, which urllib3 bounds by the connect timeout once per resolved
address, and the host name lookup, which the resolver offers no way to bound,
run outside it. No retry, no redirect followed and
no content decoding. The key-set
fetch reads at most one byte past `MAX_KEY_SET_BYTES` and refuses any answer
but 200. The token POST is a form POST with the client's Basic authorization
and `Accept: application/json`; it hands back any answer but a redirect —
an issuer's `400 invalid_grant` included — and raises `TokenEndpointError`
for a redirect, an answer past `MAX_TOKEN_RESPONSE_BYTES`, a TLS failure, a
timeout or an unreachable origin. Its message is the library's own and never
quotes the URL, the client secret, the code, the verifier or a refresh token. urllib3 logs
nothing during either call, since its records quote the URL and whatever
malformed header text the origin sends back. A `timeout_seconds` or
`deadline_seconds` of zero or less raises `ValueError`, and
`post_token_request_over_https` raises `ValueError` when `timeout_seconds`
exceeds `deadline_seconds` instead of capping it. `TokenEndpointError.failure`
names the `ExchangeFailure` that ended the request, so a caller can tell
`TIMED_OUT` from other transport failures.

### The person's access token

`webauth.oidc_login.fresh_access_token(relying_party, session_id, *,
session_transaction, config)` turns a signed-in session into a new access token
for one call to another service (an agent service, say). It answers a
`SecretStr`, or an `AccessTokenRefusal` whose `reason` is one of three:

| `AccessTokenRefusalReason` | Meaning | The host |
|---|---|---|
| `SESSION_ENDED` | The session is gone or outside its lifetime: the person is signed out. | Treats the person as signed out, as it does after a refused request. |
| `SIGN_IN_AGAIN` | The session holds no refresh token (it began before the host stored them, or the issuer gave none), or the issuer refused it as `invalid_grant`. | Sends the person to sign in again. The app session itself still stands: only this call is refused. |
| `ISSUER_UNAVAILABLE` | The issuer is unreachable, answered something unusable, or refused for another reason. `issuer_refusal` carries the `OidcRefusal`, so `invalid_client` shows its cause. | Fails the call and logs `issuer_refusal`; the person stays signed in. |

The session holds only the refresh token; the access token is never stored. Each
call costs one refresh grant at the issuer and hands the new access token to the
host in memory, for the one call it serves. Keep it nowhere. When the issuer
answers a refresh token different from the one the call sent, the call
stores it with `SessionRecordStore.replace_refresh_token`. It renews nothing:
asking for a token is not the person's request, so the session's expiry does not
move.

The call has four phases, and admission's own decision judges the session in
the first and the third:

1. **Read.** In one `session_transaction`, `load` the session. No row, or one
   outside its lifetime, is `SESSION_ENDED`; a row without a refresh token is
   `SIGN_IN_AGAIN`. Either way the issuer is not asked. The block is left,
   which releases every row lock `load` took.
2. **Grant.** With no transaction and no `WriteLock` open, send the stored
   refresh token. `invalid_grant` is `SIGN_IN_AGAIN`; every other refusal is
   `ISSUER_UNAVAILABLE`. A refusal writes nothing.
3. **Decide.** In a second `session_transaction`, `load` the session again at a
   new clock reading. A session that is gone or outside its lifetime now is
   `SESSION_ENDED` and the token is dropped, whatever refresh token the issuer
   returned. Otherwise a refresh token that differs from the one **sent**
   (not the one re-read) is stored; `replace_refresh_token` answering `False`
   is `SESSION_ENDED`.
4. **Return.** The token is handed out only after the second block was left
   without an exception.

So a slow issuer holds only the host's worker thread, never a session row, a login
or a logout. That thread is bounded as [The relying party](#the-relying-party)
describes for the token POST. A logout, a back-channel logout, an overflow prune
or a lifetime expiry that happens during the grant is seen in phase 3.

What it cannot do: the final decision is the last check. A token it authorized may
be returned after a logout or an expiry that lands later, and it stays valid at the
service it is sent to, and at the issuer's own endpoints, until its own `exp`
(300 s in a Keycloak realm with the default access-token lifespan). webauth makes no revocation call. With a store that
commits every statement, a deletion landing between the second `load` and the end of
the block is seen only through `replace_refresh_token` answering `False`, so an issuer
that echoes or omits the refresh token leaves that window open ([Security
model](#security-model), item 7).

The host's duties:

- Call it from a worker thread (a sync route, or `run_in_threadpool`), outside any
  open session transaction and outside its `WriteLock`.
- Pass an id the cookie reader bounded, or bound it first, as `admit_session` asks.
- Pass the `SessionTransaction` it hands the session gate, or
  `lambda: nullcontext(store)` for a store that commits each statement. The call
  commits nothing beyond the two transactions it opens and leaves, neither held
  across the grant.
- Store the refresh token in the session row and answer `replace_refresh_token` with
  a strict `bool`: `True` when the stored row now holds the token, `False` when the
  row is gone. It only updates an existing row, never creates one.

Two assumptions follow from the realm. The app session and the realm's SSO session
end separately: an app session that outlives the realm's SSO session (the realm sets
its idle and maximum lifetimes, for example 7 days and 30 days) gets `SIGN_IN_AGAIN`
for these calls while the person stays signed in to the app. And the issuer lets a refresh token be used again
after it issued a new one (Keycloak's `revokeRefreshToken` unset): two overlapping
calls for one session each get a valid token, and the later write wins. If the issuer
revokes a refresh token on use, the second of two overlapping calls is refused as
`invalid_grant` and answers a false `SIGN_IN_AGAIN`.

### Admitting an identity

`webauth.oidc_login.admit_identity(identity, *, admission, accounts, lock,
audit, config)` turns that identity into the account it signs in as, and
`finish_login` takes the same `admission`. It is an
`AdmissionConfig(bound_issuer=..., login_group=..., admin_group=...)` the host builds once at
startup. The host binds its store to one issuer — the `issuer` of its
`OidcClientConfig` — and passes it as `bound_issuer`; changing the issuer is a
migration of the host's accounts, never a configuration change. `login_group`
is required: the app's Keycloak group path, such as `/apps/notes`. A host
that leaves it out gets a `TypeError`; one whose value is not a group path (no
leading `/`, a trailing `/`, an empty segment, whitespace around a segment, a
control, format or line-separator character) gets a `ValueError`, both at startup. Whether the group
exists in Keycloak is not checked here. `accounts` is a `SubjectUserStore`
(`get`, `create_for_subject(subject, username, role)`,
which adds an account whose `id` is the subject, so a back-channel logout names
the account directly, and `set_role(user_id, role)`, which changes an account's
role in the caller's transaction, never commits, and returns the record). Any
stored account whose `id` equals the subject character for character is that
subject's account, whatever created it, and keeps its username; its role
follows the groups (below). A host that
migrates legacy accounts makes sure that no legacy `id` can equal a subject of
the bound issuer. After the issuer, membership is checked, before any lock or account:

- A person is a member when one of the identity's groups is `login_group` or
  below it, compared character for character and by path segment:
  `/apps/notes/admin` counts for `/apps/notes`, `/apps/notes2` and
  a bare `notes` do not. A missing or empty `groups` claim means no
  membership; a malformed one is refused as `INVALID_IDENTITY_CLAIM`. The
  check runs on every login, after `FOREIGN_ISSUER` and before any account is
  looked up or created, so a refusal writes nothing and sets no session
  cookie. What the refused person sees is the host's page.
- Taking someone out of the group refuses them at their next login; their
  account and data stay, and putting them back returns them to the same
  account. A session that is already open runs on until the host's session
  lifetime (below) ends it.

After that, admission holds `lock.hold()` and never commits:

- A new subject gets an account with the issuer's `preferred_username` (or the
  subject when it suggests none, or only whitespace) and `config.user_role`
  (or `admin_role`, for a member of `admin_group`), and the audit sink hears
  `user_created` with `actor_id=None`.
- A known subject reuses its account, even when its suggested username
  changed. No username is looked up, so a second subject whose
  `preferred_username` another account holds is admitted by a store without a
  unique username; disabling a person is done at the issuer.
- The role comes from `admin_group`, a required setting: a group path strictly
  below `login_group`, such as `/apps/notes/admin`, or
  `NoAdmins.IN_THIS_APP` when the app has no admins. A missing `admin_group`
  is a `TypeError`; a malformed path, or one not below `login_group`,
  is a `ValueError`, both at startup (under `EverySubject`, any group path is
  allowed). A person who is in `admin_group` or below it gets `admin_role`;
  everyone else, and everyone under `NoAdmins`, gets `user_role`. This holds at
  every login, for new and known accounts alike: a known account whose stored
  role differs is rewritten with `set_role` and the audit sink hears
  `role_changed`; a stored role other than `admin_role` or `user_role` is
  overwritten to `user_role` (unless the identity belongs to `admin_group`,
  which gives `admin_role`). The issuer's groups are the only source of admin:
  a person taken out of the group is a plain user from their next login, on
  every device at once, since the role lives on the account, while a session
  that is already open keeps the old role until then. Only the derived role is
  stored, never the groups. Migrating from a store with its own admins: put them
  into the admin group first, or they are demoted at their next login.
- Otherwise it answers an `AdmissionRefusal` and writes nothing:
  `FOREIGN_ISSUER` for an identity from another issuer, `NOT_A_MEMBER` for a
  person outside `login_group`, and `USERNAME_TAKEN` when a store that enforces
  a unique username raises `UsernameTakenError` from `create_for_subject`.

`login_group` may instead be `EverySubject.OF_THE_BOUND_ISSUER`, which admits
without looking at groups. It admits every subject of the realm, the users of
other apps included, so a host says it on purpose and only when the issuer
already limits who can sign in.

The issuer must send full group paths: in Keycloak the group membership mapper
needs `full.path` on. Without it the claim holds bare names, no group path
matches and everyone is refused, which fails safe.

A second service that verifies the issuer's token itself, such as an API behind
the app, calls `webauth.oidc_login.app_role(groups, admission)` with the same
`AdmissionConfig` instead of copying the rule. It answers `AppRole.ADMIN` for
`admin_group` or a path below it, `AppRole.USER` for any other member, and
`None` for a person outside `login_group`; `EverySubject` makes every set of
groups a member and `NoAdmins` never yields `ADMIN`. The answer is the kind of
role, not the host's spelling of it. It reads nothing but its arguments, so
checking that the groups come from `bound_issuer` stays with the caller, and so
does checking that the claim is a list of strings: webauth's login refuses any
other shape, and so should the caller.

## Reading the session

`webauth.dependencies.current_user_dependency` answers 401 for a missing or
dead session by default. A server-rendered host instead passes
`login_redirect=LoginRedirect(path="/login", redirect_query_param="next")` —
`path` must be a same-origin absolute path, never a scheme or `//` address, nor a backslash or tab/CR/LF form a browser reads as one —
and a browser navigation (`Accept` rating `text/html` above
`application/json` by q-value) with no live session then answers 302 to that
path, with the raw path and query string it asked for under the query key it
named, while every other request still gets 401. A dependency can only raise
an `HTTPException`, so the 302 still carries FastAPI's default JSON body
(`{"detail":"Found"}`) alongside its `Location` header.

`webauth.dependencies.session_id_from_request(connection, config)` is the one
reader of the session cookie: it parses the raw `Cookie` headers and returns
the verified session identifier, or `None` when the cookie is missing, longer
than `MAX_SESSION_COOKIE_CHARS` (200 characters, defined in `webauth.cookies`),
forged, or present more than once. The limit holds even for a correctly signed
cookie, so `issue_session_cookies` raises `ValueError` for an identifier whose
signed cookie would exceed it (identifiers up to 135 characters fit) or that is empty. The signature is an HMAC-SHA256 over `session:` and the identifier, so a signature made for a CSRF token or a pending login is no session cookie, and a cookie issued by 0.14.x or earlier is refused. A sibling
subdomain can set a second cookie of the same name, so a request carrying two
is refused rather than resolved to either: `current_user_dependency` answers
401 (`Invalid session`) and `CsrfTokenMiddleware` 403. A host that reads the
session cookie itself calls this function instead of `request.cookies`.

A host that reads the session id itself, for example through
`session_id_from_request` or its own socket layer, decides it with
`webauth.dependencies.admit_session(session_id, *, sessions, config)`. It needs
no request and sets no cookie. It returns the `webauth.ports.AuthenticatedUser`
after renewing the session, or `ConnectionRefusal.SESSION_ENDED_OR_EXPIRED`
for an unknown id, a session outside its lifetime, or a `touch` that answers
`False`; a refused session is not renewed. A failing store, or a `touch` that
does not answer a `bool`, raises.

`admit_session` decides the session alone and checks no `Origin`. A host that
admits a WebSocket handshake with it instead of `authenticate_websocket` checks
the `Origin` first, as "WebSocket handshakes" describes. A host that reads the
id other than through `session_id_from_request` bounds its length itself, because
`admit_session` hands the id to `SessionRecordStore.load` as given. Like the
other entry points it never commits: the host finishes its transaction right
after the call.

## The session gate

`install_web_auth_middleware(..., session_gate=SessionGate(...))` makes the rule
of "Signed out and refused" hold for every route: a request needs a live
session unless the host names it. A route that forgets a dependency is gated,
not public.

```python
SessionGate(
    session_transaction=lambda: nullcontext(sessions),
    login_redirect=LoginRedirect(path="/login", redirect_query_param="next"),
    public=(PublicRule(PathRules(exact=frozenset({"/login", "/health"}))),),
    optional=PathRules(exact=frozenset({"/privacy"})),
)
```

- **Fail closed.** `public` rules (`PublicRule`, by path and optionally by
  `methods`) let a request through untouched, with no store read. `optional`
  paths admit and renew a live session and let every other request through as
  signed out. A `methods` set opens only the methods it names: `HEAD` and
  `OPTIONS` stay gated unless listed.
- **Paths.** Gate rules are router paths, written as the routes are:
  `root_path` is stripped when it starts the path at a segment boundary. The
  CSRF, rate-limit and security-header rules are full paths, `root_path`
  included. A host under a `root_path` keeps each rule in its own convention.
  A path with a `.` or `..` segment is never public or optional.
- **WebSocket and lifespan scopes** pass; `authenticate_websocket` decides a
  handshake.
- **`SessionTransaction`** is the host's transaction around the gate's store
  calls: one call from construction to exit, on one worker thread, with
  concurrent calls for concurrent requests. A clean exit makes the renewal
  durable before the route runs (`lambda: nullcontext(store)` for a store that
  commits each call); rolling back on an exception is the host's decision. A
  failing store or commit answers the library 500, on optional paths too, and a
  route that fails afterwards leaves the renewal in place.
- **Refusals** are what `current_user_dependency` answers, under FastAPI's
  default exception handler: the 302 to `login_redirect` for a navigation,
  otherwise 401 `Authentication required`, `Invalid session` or
  `Session expired`.
- **Behind the gate**, `current_user`, `admin_user` and `verified_session_id`
  return the gate's admission for the request's own session cookie, so a
  request costs one `load` and one `touch`. A public route that uses them admits
  by itself, and so does a mounted app with another `WebAuthConfig` instance.
  The admission vouches for one request: host code that carries it into another
  request with the same cookie carries that request's decision along, which the
  library does not defend against ([Security model](#security-model), item 3).
- **`webauth.middleware.admitted_user(request)`** returns the account where no
  dependency is used, and `None` on public paths and on optional paths without a
  live session. It raises `RuntimeError` when no gate decided the request. For
  the session id use `session_id_from_request`.

## WebSocket handshakes

A browser sends the session cookie on a cross-site WebSocket handshake too,
and the webauth middlewares pass WebSocket scopes through untouched.
`webauth.dependencies.authenticate_websocket(connection, *, sessions)`
is the one check a host runs at the handshake. It answers the
`webauth.ports.AuthenticatedUser`, or a `ConnectionRefusal`:

| Refusal | Value | When |
|---|---|---|
| `MISSING_ORIGIN` | `missing-origin` | no `Origin` header |
| `FOREIGN_ORIGIN` | `foreign-origin` | an `Origin` that is empty, repeated, `null`, unparsable or not an allowed host |
| `NO_SESSION` | `no-session` | the session cookie is missing, empty or longer than `MAX_SESSION_COOKIE_CHARS` |
| `INVALID_SESSION` | `invalid-session` | the cookie is forged or present more than once |
| `SESSION_ENDED_OR_EXPIRED` | `session-ended-or-expired` | the store does not know the session, its stored expiry is outside the session lifetime, or `touch` answers `False` |

The `Origin` is decided first, before the store is touched, so a refused
handshake neither renews a session nor writes anything. Exactly one
`Origin` must name a host the configured allowlist admits (`allowed_hosts_exact`
and `allowed_hosts_patterns`, the same matching as "CSRF origin"; `WebAuthConfig`
refuses both empty, so local development lists
`allowed_hosts_exact={"localhost", "127.0.0.1"}`). There is no `Referer` fallback, and
`Sec-Fetch-Site` does not decide: a client that is not a browser must send an
allowed `Origin` too. The `Origin` keeps a foreign page from using a visitor's
cookie; it is no credential.

Then the session is decided exactly as `current_user_dependency` decides it
for a request, by `admit_session`: an admitted handshake renews the session.
A failing store, or a `touch` that does not answer a `bool`, raises instead of
refusing, and an exception never accepts the socket.

```python
from fastapi import WebSocket
from starlette.concurrency import run_in_threadpool

from webauth.dependencies import ConnectionRefusal, authenticate_websocket
from webauth.ports import AuthenticatedUser


@app.websocket("/room")
async def room(websocket: WebSocket) -> None:
    def authenticate() -> AuthenticatedUser | ConnectionRefusal:
        with the_hosts_unit_of_work() as unit:
            return authenticate_websocket(websocket, sessions=unit.sessions)

    outcome = await run_in_threadpool(authenticate)
    if isinstance(outcome, ConnectionRefusal):
        await websocket.close(code=1008)
        return
    await websocket.accept()
    ...
```

- Authenticate, and finish the transaction, before `accept` and before waiting
  for a message. A transactional store holds the session's row until its
  transaction ends, so a transaction kept open for the socket's life would block
  a logout.
- A refusal closes with code 1008 before `accept`. A real server answers the
  handshake with HTTP 403; the browser does not receive a close frame.
- A synchronous store runs in a worker, as above, not in the receive loop.
- A host may wrap the plain function in its own dependency: FastAPI resolves a
  parameter annotated `HTTPConnection` on a WebSocket route.
- After a successful check, `session_id_from_request(websocket, config)` names
  the session on the same handshake.

A socket does not end when its session does: a logout, a host's own revocation
through its store, and `webauth.oidc_login.receive_backchannel_logout` delete the stored
session and cannot signal an open socket. The host calls the same helper again, in a fresh
transaction, before protected work and on its own schedule while a stream runs,
and on a refusal closes the socket and stops the protected work. A successful
re-check counts as activity like a request does: it renews the session, so a
socket that keeps being re-checked stays signed in, and it stays signed in only
until the absolute cap of `SessionLifetime`, which bounds a socket's life.

## Configuration

The host builds one `WebAuthConfig` by keyword and installs it. The
`session_secret` must be at least 32 characters; a shorter one is refused.
Fields a host may leave out:

| Field | Default | Values |
|---|---|---|
| `cookie_samesite` | `"strict"` | `"strict"` or `"lax"`; `None` is refused (a cross-site cookie is not what this library issues) |
| `cookie_secure` | `True` | `True` or `False`; any other value is refused |
| `session_cookie_name` | `"__Host-session_id"`, or `"session_id"` with `cookie_secure=False` | a cookie name that obeys [the cookie-name rule](#the-cookie-name-rule) |
| `csrf_header_name` | `"x-csrf-token"` | the request header that carries the CSRF token |
| `csrf_cookie_name` | `"__Host-csrf_token"`, or `"csrf_token"` with `cookie_secure=False` | a cookie name that obeys [the cookie-name rule](#the-cookie-name-rule) |
| `admin_role` | `"admin"` | a role name; empty, whitespace-only, or equal to `user_role` is refused |
| `user_role` | `"user"` | a role name; empty, whitespace-only, or equal to `admin_role` is refused |
| `wall_clock` | `time.time` | a `webauth.ports.WallClock`, seconds since the epoch; the one reading of now behind every HTTP and WebSocket session decision, so a test fixes it |
| `ipv6_budget_prefix` | `64` | `32` to `128`; every IPv6 address in one network of this prefix shares one rate-limit budget, so users behind one `/64` limit each other. IPv4 (mapped or not) keeps a budget per address. Anything outside the range is refused |

`cookie_secure` alone decides whether both cookies carry `Secure` — when they
are set and when they are cleared — and whether `SecurityHeadersMiddleware`
sends HSTS. The request's scheme does not decide it, so a deployment behind
a TLS proxy it has not listed in `trusted_proxies` still gets both. A browser
does not send a `Secure` cookie back over plain http, so a host's own session
login over plain http works only with `cookie_secure=False` in that
environment's configuration, which drops `Secure` and HSTS together. An
OpenID Connect sign-in needs an https issuer whatever it is set to, because
`OidcClientConfig` refuses an issuer URL that is not https. With it off,
`SecurityHeadersMiddleware` also removes an HSTS header a route set itself.

The HSTS value is fixed at `max-age=31536000; includeSubDomains`; the policy has
no field for it.

`SecurityHeadersMiddleware` sends the `Permissions-Policy` its
`SecurityHeadersPolicy` names in `permissions_policy`. The field defaults to
`DEFAULT_PERMISSIONS_POLICY` (`"camera=(), microphone=(), geolocation=()"`),
so a host that leaves it out keeps every one of those features off. The value
replaces the whole header, so a host that records audio names every feature it
still wants off, for example
`permissions_policy="camera=(), microphone=(self), geolocation=()"`. A value
may hold visible ASCII, and space and tab only between visible characters; anything
else, such as an empty value, a space or tab at either end, CR, LF, NUL, DEL or a
non-ASCII character, is refused when the policy or the rule is built. `content_security_policy`
and the `value` of a `CacheControlRule` are held to the same bound.

A `__Host-` cookie carries `Secure` and `Path=/` and no `Domain`, so only
this exact host can set it: a sibling subdomain cannot plant one with
`Domain=parent`. Browsers drop a `__Host-` cookie without `Secure`, so an
unnamed cookie falls back to its plain name when `cookie_secure=False`, and a
`__Host-` or `__Secure-` name a host sets itself with `cookie_secure=False` is refused when
the configuration is built rather than ending in a silent login loop.

`SecurityHeadersMiddleware` is a pure ASGI middleware: the 500 of an unhandled exception
carries the security headers and the exception still reaches the server. A host's 500
handler runs, but the response it returns is not sent, and with `debug=True` Starlette's
traceback page is not sent either: the client gets the library 500 with the headers.
`install_web_auth_middleware` (see [Middleware order](#middleware-order)) installs the
whole stack in the order that makes every library refusal carry the headers. What changed
in each release is in the [CHANGELOG](CHANGELOG.md).

The cookies' default names are the public constants `DEFAULT_SESSION_COOKIE_NAME` and
`DEFAULT_CSRF_COOKIE_NAME` in `webauth.cookies` (the `__Host-` names) and
`PLAIN_SESSION_COOKIE_NAME` and `PLAIN_CSRF_COOKIE_NAME` (the names with `cookie_secure=False`).
A client that reads the CSRF cookie by name reads `config.csrf_cookie_name`.
A request that reaches the library in an app without `install_web_auth_config` raises
`RuntimeError`.

### The cookie-name rule

`session_cookie_name` and `csrf_cookie_name` are refused at construction unless
each is:

- an RFC 6265 token: ASCII letters, digits and ``!#$%&'*+-.^_`\|~`` (empty,
  spaces, `;`, `=`, `,`, quotes and non-ASCII are refused);
- different from the other cookie's name;
- not a `__Host-` or `__Secure-` name with `cookie_secure=False`;
- not a name webauth's own cookies use: the pending-login cookies (names
  starting `__Host-oidc_pending_`, or `oidc_pending_` with
  `cookie_secure=False`) and the ID token hint cookie
  (`__Secure-oidc_id_token_hint`, or `oidc_id_token_hint`), in both variants
  whatever `cookie_secure` is;
- not `None`.

The OpenID Connect ID token hint cookie is described under
[The ID token hint](#the-id-token-hint).

### Content-Security-Policy

`default_content_security_policy()` holds no host fact: `default-src 'none'` with
`'self'` for scripts, styles, connections, fonts, manifests and workers, `data:` and
`blob:` besides for images, `blob:` for media, `base-uri 'self'`, `form-action 'self'` and
`frame-ancestors 'none'`. A host
adds its own sources to one directive through `added_sources`, without copying the
string. A framework that writes style attributes, for example, needs inline style, and
that is the host's choice, so the host names it:

```python
from webauth.policies import CspDirective, default_content_security_policy

default_content_security_policy(
    added_sources={CspDirective.STYLE_SRC: ["'unsafe-inline'"]},
)
```

Callers supply complete source expressions: keywords, nonces and hashes in their
quotes, hosts and schemes bare. Only `script_hashes` takes bare `sha256-<base64>`
values and quotes them. A source is one token of printable ASCII without space, `;` or `,`,
and is kept verbatim; anything else is a `ValueError` when the policy is built. A non-empty
addition to `frame-ancestors` replaces its `'none'`, while an addition to `form-action` extends
its `'self'`. `base-uri 'self'` is fixed and not extendable. The library does not check that a
token is a valid CSP source, so a host that writes `'selff'` gets what it wrote.

A form may submit only to this origin. A host whose form posts to another origin names
it, for example an issuer such as Keycloak:

```python
default_content_security_policy(
    added_sources={CspDirective.FORM_ACTION: ["https://id.example.test"]},
)
```

This writes `form-action 'self' https://id.example.test`.

Browsers differ on redirects: MDN's compatibility data records that Chromium and Safari
also check `form-action` on the redirect that answers a form submission, and Firefox does not
([MDN `form-action`](https://developer.mozilla.org/en-US/docs/Web/HTTP/Reference/Headers/Content-Security-Policy/form-action),
its compatibility table row `blocks_redirects`; [w3c/webappsec-csp#8](https://github.com/w3c/webappsec-csp/issues/8);
[CSP3 `form-action`](https://w3c.github.io/webappsec-csp/#directive-form-action)).
A host whose form POST is answered by a redirect to another origin, such as an issuer's
logout endpoint, adds that origin. Add the origin, not a path: after a redirect the path
is ignored ([CSP3, Paths and Redirects](https://w3c.github.io/webappsec-csp/#source-list-paths-and-redirects)).

## The store decides every request

The library caches no sessions. Every authenticated request costs one
`SessionRecordStore.load` and one `touch`, so a session the host ended is
refused on its next request, with 401 or the login redirect. The exception is a
gated request whose route runs in a mounted app with another `WebAuthConfig`:
[the session gate](#the-session-gate) admits it under each. Whether a loaded
session still stands is decided by the library alone, against
`WebAuthConfig.session_lifetime` (see "Session lifetime"). `SessionRecordStore.touch`
takes the session id and the `expires_at` the library computed; the store writes it
and computes none of its own.
`SessionRecordStore.touch` returns a strict `bool`: `True` when a stored row was
renewed, `False` when the session is gone, which refuses the request like an
expired session.

## Session lifetime

Two numbers decide how long someone stays signed in. The library owns the
session's lifetime; the host's store only writes the expiry it is given. The
session, CSRF and ID-token hint cookies live as long as the cap: they are issued
once at login and never reissued, so the browser keeps them exactly as long as
the session may last. An open WebSocket captured the cookie at its handshake and
runs on after the browser drops it; the absolute cap and the host's re-checks
bound a socket (see "WebSocket handshakes").

- `SessionLifetime.idle_seconds` is how long a session stands without a request.
- `SessionLifetime.absolute_max_age_seconds` is how long a session may live from
  its `created_at`, however recently it was used. The idle window is at most
  the cap, and the cap is at most 400 days (`MAX_SESSION_LIFETIME_SECONDS`), the
  longest a browser keeps a cookie.

`WebAuthConfig.session_lifetime` is required. The library reads `config.wall_clock`
once per request, as whole seconds, and admits a loaded session only when
`now <= expires_at <= min(now + idle + 60 s, created_at + cap)`: the stored expiry
is neither past nor further out than the lifetime allows, with 60 seconds of
tolerance for the idle window and none for the cap. A session outside that is refused as
`SESSION_ENDED_OR_EXPIRED` and not renewed. An admitted session is renewed to
`min(now + idle, created_at + cap)`, so it never outlives its cap. A session
created more than 60 seconds in the future is refused too. A stored
timestamp without an offset is read as UTC.

Every lifetime — `idle_seconds` and
`absolute_max_age_seconds` — must be a positive whole number of seconds; `0`, a negative
value, a `float`, a string or a `bool` is refused when the object is built.

The recommended policy for a host that admits by `login_group` is a 12-hour
cap, with an idle window of the same length. The cap
sets the worst-case delay before a removal from the group takes effect, because
an open session is not re-checked. Every login checks the group again, and
the issuer's SSO session turns that login into a
redirect the person does not notice. A removal takes effect at once only by disabling
the user at the issuer together with the back-channel logout ("Back-channel logout"
above); without it, an open app session stays valid until it expires.

```python
import re

from pydantic import SecretStr

from webauth.config import SessionLifetime, WebAuthConfig
from webauth.proxies import TrustedProxies
from webauth.rate_limit import SingleProcessRateLimitBackend

TWELVE_HOURS = 12 * 3600

config = WebAuthConfig(
    session_secret=SecretStr("a-secret-of-at-least-thirty-two-characters"),
    trusted_proxies=TrustedProxies.parse("10.0.0.0/8"),
    rate_limits=SingleProcessRateLimitBackend(),
    allowed_hosts_exact=frozenset({"app.example.com"}),
    allowed_hosts_patterns=(re.compile(r"^.+\.example\.com$"),),
    session_lifetime=SessionLifetime(
        idle_seconds=TWELVE_HOURS, absolute_max_age_seconds=TWELVE_HOURS,
    ),
)
```

## Ending a session

The refresh token is part of the session row: whatever ends the row ends it, and no other row
or table holds it. Ending a session is a call on the host's store: `delete(session_id)`,
`delete_for_user(user_id)` or `prune_overflow(user_id, keep_newest)`, where `0` keeps none. The
library makes that call in three places only: [`log_out`](#logging-out),
[`open_session`](#opening-a-session) (the session an incoming cookie replaced,
and all but the newest ones under the cap) and back-channel logout. A host that signs in
through OpenID Connect ends a session with `log_out`. The next request carrying
an ended session's cookie is refused.

## Middleware order

`install_web_auth_middleware` adds the library's middleware in one order,
outermost first, and refuses a stack that would break it:

1. `SecurityHeadersMiddleware` (required): outside everything, so the library's
   own refusals (the 413s, the 429 and 503, the CSRF 403s and the 500) carry
   the headers.
2. `BodySizeLimitMiddleware`: a body declared too large is refused before it
   costs a rate-limit budget or a session lookup.
3. `IpRateLimitMiddleware`: outside CSRF, so forged requests spend the
   address's budget.
4. `CsrfOriginMiddleware`.
5. `CsrfTokenMiddleware`.
6. `SessionGateMiddleware`: innermost, so a request refused before admission
   never costs a session lookup, and a forged state-changing request is refused
   before it renews a session.

Install it once and add no library middleware yourself. Where a host's own
middleware goes, what each refusal spends from the rate-limit budget, and the
cases of a body over the limit are in the docstrings of
`install_web_auth_middleware`, `IpRateLimitMiddleware` and
`BodySizeLimitMiddleware`. A host whose own middleware is the session authority
answers a request without a session with `webauth.dependencies.unauthenticated_response`.

## CSRF origin

`CsrfOriginMiddleware` refuses a state-changing request that a foreign page
originated. It trusts `Sec-Fetch-Site` where a browser sends it and otherwise
compares `Origin` (or `Referer`) with the hosts in `WebAuthConfig`. A request
that names no origin passes when it is a JSON POST and is refused when it is a
form. `CsrfPolicy` decides which paths are checked and defaults to fail-closed;
the middleware's docstring holds how a malformed origin and an allowed host
pattern are matched.

## Rate limiting, and the optional Redis extra

`WebAuthConfig.rate_limits` is a `webauth.ports.RateLimitBackend`: a sliding
window per key that counts the current event and raises rather than guessing
when it cannot answer, so the middleware fails the request closed. The host
names its budgets in a `webauth.policies.RateLimitPolicy`: a default budget,
rules that give some paths another, and paths that spend nothing.

Two backends implement the port. `webauth.rate_limit.RedisRateLimitBackend`
shares one window across every process that reaches the same Redis and needs
the optional extra, `overnightworks-webauth[redis]`.
`webauth.rate_limit.SingleProcessRateLimitBackend` keeps the window in this
process's memory, for a single-node host that runs one worker, and needs no
Redis.

## Audit events

The library reports an account operation (a user created, a role changed, a
back-channel logout) to the host's `AuditSink.account_event`. The host maps it
to its audit system or implements a no-op. An event carries no session
identifier or username; the fields each `AccountEventKind` adds are in its
docstring.

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
