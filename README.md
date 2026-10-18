# webauth

OpenID Connect login and session authentication for FastAPI applications. It is
built for [Keycloak](https://www.keycloak.org/); any OpenID Connect issuer that
signs ID tokens with RS256 and publishes static endpoints works. The host serves
a start and a callback route. webauth runs the flow, then keeps the session:
sessions the store decides on every request, HMAC-signed cookies, CSRF
double-submit, admin checks, per-address rate limits, and the audit events they
raise. The client is a confidential client: it authenticates at the token
endpoint with HTTP Basic and sends PKCE with the `S256` method.

Distribution `overnightworks-webauth`, import package `webauth`. The login needs
the `jwt` extra, which [Install](#install) names.

## OpenID Connect login

The host names the issuer's authorization, token, key-set and end-session
URLs itself; the library does no discovery.

### What every app gets

Every app that signs people in through Keycloak behaves the same way, unless it
names `EverySubject` or `NoAdmins` under
[Admitting an identity](#admitting-an-identity). The details are in the
sections linked below.

**Who gets in.** Only members of the app's `login_group`, such as
`/apps/songmaker`, get in. Members of its `admin_group`, such as
`/apps/songmaker/admin`, are admins. Both are decided again at every login, so a
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
lasts. If the browser holds no ID token from its latest Keycloak sign-in,
Keycloak asks once to confirm instead. See [Logging out](#logging-out) and
[Back-channel logout](#back-channel-logout).

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
from webauth.oidc_login import AdmissionConfig, AdmissionRefusal, finish_login, start_login

admission = AdmissionConfig(
    bound_issuer=client_config.issuer,
    login_group="/apps/songmaker",
    admin_group="/apps/songmaker/admin",
)


@app.get("/login/oidc")
def start(request: Request) -> Response:
    response = Response(status_code=303)
    response.headers["location"] = start_login(relying_party, request, response, config)
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
    session = open_the_hosts_session(outcome)
    issue_session_cookies(response, session.id, config)
    ...
```

`start_login(relying_party, request, response, config)` begins a login, sets
its pending-login cookie on `response` and returns the authorization URL.
`finish_login(...)` answers the `UserRecord` to open a session for, or the `OidcRefusal` or `AdmissionRefusal` that stopped it;
the host commits on an account and opens the session itself. `finish_login`
sets the header that clears the pending-login cookie on `response`, so the
host answers with that response on every outcome, refusals included: FastAPI
copies an injected `response`'s headers only when the route returns a value
that is not itself a `Response`; a returned `JSONResponse` is sent as-is and a
raised `HTTPException` gets a new response, so neither carries them, which
would leave the pending cookie in the browser.

#### Logging out

`log_out(relying_party, request, response, config, sessions=..., lock=...)` is
the whole logout sequence in one call, so no host rebuilds its order: it ends
the session the request's cookie names (when there is one) under the write
lock, clears the session and CSRF cookies on `response` and returns the
issuer's end-session URL. That URL carries the client ID, the configured
`post_logout_redirect_uri` and the `id_token_hint` that `finish_login` handed
the browser at sign-in (see [The ID token hint](#the-id-token-hint)), so
Keycloak ends the session without asking the person to confirm. Without a
usable hint the URL leaves it out and Keycloak asks once; the app stores no
Keycloak token. The logout is a GET to Keycloak, so the hint lands in that
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
  cookie is not `Secure`; that is for local development over http only, where
  a sibling host or a network observer can set or read it.
- **Flags:** `HttpOnly`, `Path=/`, `Max-Age=600`, and `Secure` following
  `cookie_secure`. It is always `SameSite=Lax`, whatever `cookie_samesite`
  says: the callback is a top-level navigation from the issuer's site, which a
  `Strict` cookie would not accompany.
- **Value:** `v1.` followed by the state, nonce, verifier and `issued_at`,
  each bounded to the exact shape `begin_login` mints, and an HMAC-SHA256
  signature under the session signing key with an `oidc-pending:` prefix no
  other cookie uses; the whole value is at most 256 characters, and the
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
  cookie, `Secure` following `cookie_secure`, and `Path` set to the
  `logout_path` of the `OidcClientConfig`. The browser sends it to every path
  beneath that prefix, so set `logout_path` to the narrowest prefix that covers
  the logout routes: with `/logout` only `/logout` and the paths under it carry
  the hint, while `/` sends it with every request.
- **Set only on an admitted login:** a refused callback sets none, and a new
  login overwrites the old one. An ID token longer than
  `MAX_ID_TOKEN_HINT_CHARS` (3072) is not kept and the old cookie is cleared
  instead; the person is still signed in, and their logout asks. Keycloak
  asks once whenever the browser holds no ID token from its latest Keycloak
  sign-in: a token over the bound, a sign-in from before the upgrade, or a
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
logout_token, *, accounts, sessions, lock, audit)` verifies it and ends every
session of its subject, in every browser, and answers
`BackchannelLogoutResult.ACCEPTED` or `REFUSED`. The host's route is a POST of
a form with one `logout_token` field:

```python
import logging
import urllib.parse

import anyio.to_thread
from fastapi import Request, Response

from webauth.oidc_login import BackchannelLogoutResult, receive_backchannel_logout

logger = logging.getLogger(__name__)


def the_logout_token_of(request_body: bytes, content_type: str | None) -> str | None:
    media_type = (content_type or "").partition(";")[0].strip().lower()
    if media_type != "application/x-www-form-urlencoded":
        return None
    try:
        fields = urllib.parse.parse_qsl(
            request_body.decode(), keep_blank_values=True, strict_parsing=True, errors="strict",
        )
    except ValueError:
        return None
    tokens = [value for name, value in fields if name == "logout_token"]
    return tokens[0] if len(tokens) == 1 and tokens[0] else None


def end_the_sessions_of(logout_token: str) -> BackchannelLogoutResult:
    with the_hosts_transaction() as work:
        return receive_backchannel_logout(
            relying_party, logout_token,
            accounts=work.accounts, sessions=work.sessions, lock=work.lock, audit=work.audit,
        )


@app.post("/auth/backchannel-logout")
async def backchannel_logout(request: Request) -> Response:
    logout_token = the_logout_token_of(
        await request.body(), request.headers.get("content-type"),
    )
    if logout_token is None:
        return Response(status_code=400)
    try:
        result = await anyio.to_thread.run_sync(end_the_sessions_of, logout_token)
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

The function runs in this order. It verifies the token before it takes the
lock, and a refusal does nothing more. Under `lock.hold()` it looks up
`accounts.get(subject)`. An unknown subject is accepted and creates no
account. A known subject, an inactive account included, loses every session
through `end_user_sessions`, and one `backchannel_logout` audit event with
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

The library never writes, so these belong to the host's OIDC
callback route:

- **`next`:** validate the final decoded value against the rule
  `LoginRedirect.path` enforces: one leading `/`; never `//` or a backslash
  form after browsers strip tab, CR and LF; no scheme. Otherwise fall back to
  a fixed local path.
- **Fresh id:** every successful login mints a fresh session id. Never reuse
  one from an incoming cookie, and never the issuer's `sid`.
- **Replaced session:** when a verified session cookie is present, load its
  record and end it with `end_session(sessions, session_id=<old id>)`, then
  commit that transaction before `issue_session_cookies`.
- **Entropy:** at least 128 bits from a CSPRNG. `secrets.token_urlsafe(32)`
  gives 43 characters, under the 135-character bound.

### The relying party

`webauth.oidc.OidcRelyingParty` runs the authorization-code flow with PKCE
for one client at one issuer, described by an `OidcClientConfig` whose URLs
are all https and whose `client_secret` is a `SecretStr`. `begin_login()`
answers the URL to send the browser to and a `PendingLogin` — its state,
nonce and PKCE verifier, and `issued_at`, the wall-clock second it began.
`complete_login(pending, callback_query)` takes that pending login and the
callback's raw query string and answers an `OidcIdentity` (subject, issuer,
full group paths, `sid`, `preferred_username`, and the verified `id_token`
as received, which stays out of its repr) or an `OidcRefusal` naming its
reason. The state is checked before anything else the callback says; then
the pending login's age: one older than `PENDING_LOGIN_MAX_AGE_SECONDS`
(600) or dated in the future is `PENDING_LOGIN_EXPIRED`, and no token
request is sent. An error the issuer reports is carried as its short error
code only, never its description, and a `code` longer than
`MAX_AUTHORIZATION_CODE_CHARS` (2048) is `MALFORMED_CALLBACK`. A token answer
that names any member twice, at any depth, is `TOKEN_ENDPOINT_FAILED` rather
than letting the last one win. The code is exchanged through the `post_token_request` the host
injects, and the ID token is verified by a
`JwtVerifier` whose one accepted audience is the client ID, then checked for
the pending nonce and an authorized party: a token for several audiences must
name the client as its `azp`, and any `azp` a token names must be the client.

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
from webauth.oidc_login import post_token_request_over_https

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
and `TOKEN_EXCHANGE_DEADLINE_SECONDS` — over connecting, the TLS handshake and
the whole answer, so an origin that drips its answer is cut off as a timeout;
only the host name lookup runs outside it. No retry, no redirect followed and
no content decoding. The key-set
fetch reads at most one byte past `MAX_KEY_SET_BYTES` and refuses any answer
but 200. The token POST is a form POST with the client's Basic authorization
and `Accept: application/json`; it hands back any answer but a redirect —
an issuer's `400 invalid_grant` included — and raises `TokenEndpointError`
for a redirect, an answer past `MAX_TOKEN_RESPONSE_BYTES`, a TLS failure, a
timeout or an unreachable origin. Its message is the library's own and never
quotes the URL, the client secret, the code or the verifier. urllib3 logs
nothing during either call, since its records quote the URL and whatever
malformed header text the origin sends back. A `timeout_seconds` or
`deadline_seconds` of zero or less raises `ValueError`, and
`post_token_request_over_https` raises `ValueError` when `timeout_seconds`
exceeds `deadline_seconds` instead of capping it. `TokenEndpointError.failure`
names the `ExchangeFailure` that ended the request, so a caller can tell
`TIMED_OUT` from other transport failures.

### Admitting an identity

`webauth.oidc_login.admit_identity(identity, *, admission, accounts, lock,
audit, config)` turns that identity into the account it signs in as, and
`finish_login` takes the same `admission`. It is an
`AdmissionConfig(bound_issuer=..., login_group=..., admin_group=...)` the host builds once at
startup. The host binds its store to one issuer — the `issuer` of its
`OidcClientConfig` — and passes it as `bound_issuer`; changing the issuer is a
migration of the host's accounts, never a configuration change. `login_group`
is required: the app's Keycloak group path, such as `/apps/songmaker`. A host
that leaves it out gets a `TypeError`; one whose value is not a group path (no
leading `/`, a trailing `/`, an empty segment, whitespace around a segment, a
control, format or line-separator character) gets a `ValueError`, both at startup. Whether the group
exists in Keycloak is not checked here. `accounts` is a `SubjectUserStore`
(`get`, `get_by_username`, `create_for_subject(subject, username, role)`,
which adds an account whose `id` is the subject, so a back-channel logout names
the account directly, and `set_role(user_id, role)`, which changes an account's
role in the caller's transaction, never commits, and returns the record). Any
stored account whose `id` equals the subject character for character is that
subject's account, whatever created it, and keeps its username; its role
follows the groups (below). The host's `get` must compare exactly: no case, accent or
trailing-space folding, even where its id column's collation folds. A host that
migrates legacy accounts makes sure that no legacy `id` can equal a subject of
the bound issuer. After the issuer, membership is checked, before any lock or account:

- A person is a member when one of the identity's groups is `login_group` or
  below it, compared character for character and by path segment:
  `/apps/songmaker/admin` counts for `/apps/songmaker`, `/apps/songmaker2` and
  a bare `songmaker` do not. A missing or empty `groups` claim means no
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
  changed. A deactivated account is refused before any role is written.
- The role comes from `admin_group`, a required setting: a group path strictly
  below `login_group`, such as `/apps/songmaker/admin`, or
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
  person outside `login_group`, `ACCOUNT_DEACTIVATED`, and
  `USERNAME_TAKEN` when a new subject's username belongs to another account
  — including when the store's own uniqueness is stricter than its lookup
  and `create_for_subject` raises `UsernameTakenError`.

`login_group` may instead be `EverySubject.OF_THE_BOUND_ISSUER`, which admits
without looking at groups. It admits every subject of the realm, the users of
other apps included, so a host says it on purpose and only when the issuer
already limits who can sign in.

The issuer must send full group paths: in Keycloak the group membership mapper
needs `full.path` on. Without it the claim holds bare names, no group path
matches and everyone is refused, which fails safe.

## Reading the session

`webauth.dependencies.current_user_dependency` answers 401 for a missing or
dead session by default. A server-rendered host instead passes
`login_redirect=LoginRedirect(path="/login", redirect_query_param="next")` —
`path` must be a same-origin absolute path, never a scheme or `//` address, nor a backslash or tab/CR/LF form a browser reads as one —
and a browser navigation (`Accept` rating `text/html` above
`application/json` by q-value) with no live session then answers 302 to that
path, with the asked-for address and query string under the query key it
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

## WebSocket handshakes

A browser sends the session cookie on a cross-site WebSocket handshake too,
and the webauth middlewares pass WebSocket scopes through untouched.
`webauth.dependencies.authenticate_websocket(connection, *, sessions, audit)`
is the one check a host runs at the handshake. It answers the
`AuthenticatedUser`, or a `WebSocketRefusal`:

| Refusal | Value | When |
|---|---|---|
| `MISSING_ORIGIN` | `missing-origin` | no `Origin` header |
| `FOREIGN_ORIGIN` | `foreign-origin` | an `Origin` that is empty, repeated, `null`, unparsable or not an allowed host |
| `NO_SESSION` | `no-session` | the session cookie is missing, empty or longer than `MAX_SESSION_COOKIE_CHARS` |
| `INVALID_SESSION` | `invalid-session` | the cookie is forged or present more than once |
| `SESSION_ENDED_OR_EXPIRED` | `session-ended-or-expired` | the store does not know the session, the liveness policy refuses it, or `touch` answers `False` |
| `ACCOUNT_DISABLED` | `account-disabled` | the account behind a live session is inactive |

The `Origin` is decided first, before the store is touched, so a refused
handshake neither renews a session nor writes an audit event. Exactly one
`Origin` must name a host the configured allowlist admits (`allowed_hosts_exact`
and `allowed_hosts_patterns`, the same matching as "CSRF origin"; `localhost`
and `127.0.0.1` when none is configured). There is no `Referer` fallback, and
`Sec-Fetch-Site` does not decide: a client that is not a browser must send an
allowed `Origin` too. The `Origin` keeps a foreign page from using a visitor's
cookie; it is no credential.

Then the session is decided exactly as `current_user_dependency` decides it
for a request, from the same code: an admitted handshake renews the session
and reports a changed address or agent. A failing store, or a `touch` that
does not answer a `bool`, raises instead of refusing, and an exception never
accepts the socket.

```python
from fastapi import WebSocket
from starlette.concurrency import run_in_threadpool

from webauth.dependencies import AuthenticatedUser, WebSocketRefusal, authenticate_websocket


@app.websocket("/room")
async def room(websocket: WebSocket) -> None:
    def authenticate() -> AuthenticatedUser | WebSocketRefusal:
        with the_hosts_unit_of_work() as unit:
            return authenticate_websocket(websocket, sessions=unit.sessions, audit=unit.audit)

    outcome = await run_in_threadpool(authenticate)
    if isinstance(outcome, WebSocketRefusal):
        await websocket.close(code=1008)
        return
    await websocket.accept()
    ...
```

- Authenticate, and finish the transaction, before `accept` and before waiting
  for a message. `load` holds the session against a concurrent deletion until
  the transaction ends, so one kept open for the socket's life would block a
  logout.
- A refusal closes with code 1008 before `accept`. A real server answers the
  handshake with HTTP 403; the browser does not receive a close frame.
- A synchronous store runs in a worker, as above, not in the receive loop.
- A host may wrap the plain function in its own dependency: FastAPI resolves a
  parameter annotated `HTTPConnection` on a WebSocket route.
- After a successful check, `session_id_from_request(websocket, config)` names
  the session on the same handshake.

A socket does not end when its session does: a logout, an administrator's
revocation and `webauth.oidc_login.receive_backchannel_logout` delete the stored
session and cannot signal an open socket. The host calls the same helper again, in a fresh
transaction, before protected work and on its own schedule while a stream runs,
and on a refusal closes the socket and stops the protected work. A successful
re-check counts as activity like a request does: it renews the session, so a
socket that keeps being re-checked stays signed in, and it stays signed in only
until the absolute cap (`ExpiryColumnLiveness(absolute_max_age_seconds)` or
`IdleWindowLiveness(..., absolute_max_age_seconds=...)`), which bounds a
socket's life. A host without an absolute cap sets no end to a socket it keeps
re-checking.

## Configuration

The host builds one `WebAuthConfig` by keyword and installs it. It must state
`cookie_max_age_seconds`, the browser cookie's
`Max-Age`; [Session lifetime](#session-lifetime) states the rule.
Fields a host may leave out:

| Field | Default | Values |
|---|---|---|
| `cookie_samesite` | `"strict"` | `"strict"` or `"lax"`; `None` is refused (a cross-site cookie is not what this library issues) |
| `cookie_secure` | `True` | `True` or `False`; any other value is refused |
| `session_cookie_name` | `"__Host-session_id"`, or `"session_id"` with `cookie_secure=False` | an RFC 6265 token: ASCII letters, digits and ``!#$%&'*+-.^_`\|~`` (empty, spaces, `;`, `=`, `,`, quotes and non-ASCII are refused); must differ from the other cookie's name; a `__Host-` or `__Secure-` name with `cookie_secure=False` is refused; `None` is refused |
| `csrf_header_name` | `"x-csrf-token"` | the request header that carries the CSRF token |
| `csrf_cookie_name` | `"__Host-csrf_token"`, or `"csrf_token"` with `cookie_secure=False` | an RFC 6265 token: ASCII letters, digits and ``!#$%&'*+-.^_`\|~`` (empty, spaces, `;`, `=`, `,`, quotes and non-ASCII are refused); must differ from the other cookie's name; a `__Host-` or `__Secure-` name with `cookie_secure=False` is refused; `None` is refused |
| `admin_role` | `"admin"` | a role name; empty, whitespace-only, or equal to `user_role` is refused |
| `user_role` | `"user"` | a role name; empty, whitespace-only, or equal to `admin_role` is refused |
| `max_user_agent_chars` | `500` | a positive `int`; zero, a negative number, or a `bool` is refused |
| `ipv6_budget_prefix` | `64` | `32` to `128`; every IPv6 address in one network of this prefix shares one rate-limit budget, so users behind one `/64` limit each other. IPv4 (mapped or not) keeps a budget per address; sessions and audit keep the full address. Anything outside the range is refused |

`cookie_secure` alone decides whether both cookies carry `Secure` — when they
are set and when they are cleared — and whether `SecurityHeadersMiddleware`
sends HSTS. The request's scheme no longer decides it, so a deployment behind
a TLS proxy it has not listed in `trusted_proxies` still gets both. A browser
does not send a `Secure` cookie back over plain http, so local development
over http works only with `cookie_secure=False` in that environment's
configuration, which drops `Secure` and HSTS together. With it off,
`SecurityHeadersMiddleware` also removes an HSTS header a route set itself.

`SecurityHeadersMiddleware` sends the `Permissions-Policy` its
`SecurityHeadersPolicy` names in `permissions_policy`. The field defaults to
`DEFAULT_PERMISSIONS_POLICY` (`"camera=(), microphone=(), geolocation=()"`),
so a host that leaves it out keeps every one of those features off. The value
replaces the whole header, so a host that records audio names every feature it
still wants off, for example
`permissions_policy="camera=(), microphone=(self), geolocation=()"`. A value
containing CR or LF is refused when the policy is built.

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
The OpenID Connect ID token hint cookie is described under
[The ID token hint](#the-id-token-hint).
A request that reaches the library in an app without `install_web_auth_config` raises
`RuntimeError`.

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
values and quotes them. Every source is validated against the CSP grammar when the
policy is built, and a malformed one is a `ValueError`. A non-empty addition to
`frame-ancestors` replaces its `'none'`, while an addition to `form-action` extends
its `'self'`. `base-uri 'self'` is fixed and not extendable. Validation covers a declared subset of CSP Level 3: a
well-formed keyword outside it, such as `'trusted-types-eval'`, is refused too, and a host that
needs one writes the whole `SecurityHeadersPolicy` string itself.

A form may submit only to this origin. A host whose form posts to another origin names
it, for example an issuer such as Keycloak:

```python
default_content_security_policy(
    added_sources={CspDirective.FORM_ACTION: ["https://id.example.test"]},
)
```

This writes `form-action 'self' https://id.example.test`. `form-action` takes `'self'`,
scheme sources and host sources, as `frame-ancestors` does; nonces, hashes and other
keywords are a `ValueError`.

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
refused on its next request, with 401 or the login redirect. Whether a loaded
session still stands is decided by `WebAuthConfig.session_liveness`, a
`webauth.ports.SessionLivenessPolicy`, and `webauth.dependencies` alone reads
the wall clock and passes the instant in. `webauth.liveness` ships two:
`ExpiryColumnLiveness`, for a store with `created_at`/`expires_at` columns, and
`IdleWindowLiveness`, for one that keeps `last_seen` (and `created_at` when it
is given an absolute cap).
`SessionRecordStore.touch` returns a strict `bool`: `True` when a stored row was
renewed, `False` when the session is gone, which refuses the request like an
expired session.

## Session lifetime

Three numbers decide how long someone stays signed in, and each has one owner.
The library reads no session lifetime of its own: the session's expiry belongs
to the host's session store.

- `WebAuthConfig.cookie_max_age_seconds` is required and is the browser cookie's
  `Max-Age`. The cookie is issued once at login and never reissued, so it bounds
  the whole sign-in of a client that sends a request at a time. An open
  WebSocket captured the cookie at its handshake and runs on after the browser
  drops it; the absolute cap and the host's re-checks bound a socket (see
  "WebSocket handshakes").
- The idle window — `IdleWindowLiveness`'s idle argument, or the host's
  `expires_at` refresh for `ExpiryColumnLiveness` — refuses a session left unused for longer.
- The absolute cap — `ExpiryColumnLiveness(absolute_max_age_seconds)` or
  `IdleWindowLiveness(idle, absolute_max_age_seconds=...)` — refuses a session
  older than the cap, however recently it was used.

Every lifetime — `cookie_max_age_seconds` and the windows and
caps of both liveness policies — must be a positive whole number of seconds; `0`, a negative
value, a `float`, a string or a `bool` is refused when the object is built.

The recommended policy for a host that admits by `login_group` is a 12-hour
cookie and cap, with the idle window left to the host. The cookie and the cap
set the worst-case delay before a removal from the group takes effect, because
an open session is not re-checked. Every login checks the group again, and
Keycloak's own SSO session (30 days, 7 days idle) turns that login into a
redirect the person does not notice. A removal takes effect at once only with
`edge lock` together with the back-channel logout ("Back-channel logout"
above); without it, an open app session stays valid until it expires.

```python
import re

from pydantic import SecretStr

from webauth.config import WebAuthConfig
from webauth.liveness import IdleWindowLiveness
from webauth.proxies import TrustedProxies
from webauth.rate_limit import SingleProcessRateLimitBackend

TWELVE_HOURS = 12 * 3600

config = WebAuthConfig(
    session_secret=SecretStr("a-secret-of-at-least-thirty-two-characters"),
    trusted_proxies=TrustedProxies.parse("10.0.0.0/8"),
    rate_limits=SingleProcessRateLimitBackend(),
    allowed_hosts_exact=frozenset({"app.example.com"}),
    allowed_hosts_patterns=(re.compile(r"^.+\.example\.com$"),),
    cookie_max_age_seconds=TWELVE_HOURS,
    session_liveness=IdleWindowLiveness(TWELVE_HOURS, absolute_max_age_seconds=TWELVE_HOURS),
)
```

## Ending a session

`webauth.session_ending` is the one place a session ends in the host's store. A
host that signs in through OpenID Connect logs out with
[`log_out`](#logging-out), which calls it; any other route calls
`end_session(sessions, session_id=...)` rather than deleting from the store
itself; `end_user_sessions(sessions, user_id)` ends every session
of an account and returns the store's count, and
`prune_sessions(sessions, user_id, max_sessions)` ends the oldest sessions above
a cap after a login and returns their identifiers. The next request carrying an
ended session's cookie is refused. The `session_administration` helpers
end sessions through the same functions.

## Middleware order

`install_web_auth_middleware(app, *, security_headers, body_size=None,
rate_limit=None, csrf_origin=None, csrf_token=None)` adds the library's
middleware in the one order below, outermost first. Starlette inserts at the
front, so the installer adds them in reverse.

1. `SecurityHeadersMiddleware` (required): outside everything, so the
   library's own refusals carry the headers: the 413s, the
   429 and 503 with `Retry-After`, the CSRF 403s, and the 500.
2. `BodySizeLimitMiddleware`: a body whose Content-Length is over the limit
   is refused before it costs a rate-limit budget or a session lookup.
3. `IpRateLimitMiddleware`: outside CSRF, so forged requests spend the
   address's budget.
4. `CsrfOriginMiddleware`.
5. `CsrfTokenMiddleware`.

`csrf_origin` and `csrf_token` take separate `CsrfPolicy` values. The
installer refuses, before it touches the app, three things:

- A `csrf_token` without a `csrf_origin` (`ValueError`).
- A `csrf_token` whose `token_exempt` paths the origin check does not fully
  cover (`ValueError`): login routes skip the token on the promise that the
  origin check protects them. An exact path must require the origin check; a
  prefix must have every path below it checked, so an origin exemption inside
  it, or an origin policy that protects only the prefix string, is refused;
  shapes and patterns are refused as unverifiable.
- An app that already carries any of the five library middleware or a
  subclass of one, from an earlier installer call or added by hand
  (`RuntimeError`).

Install once, and add no library middleware yourself.

**Placement of host middleware.** Added before the call, a host middleware
sits inside the library stack: a request the library refuses early (413 by
Content-Length, 429, 503, the CSRF 403s) never reaches it.
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
| Streamed (no Content-Length), and the response has already started when the limit trips: a streaming response that reads the body, or any `StreamingResponse` under ASGI spec < 2.4 (uvicorn reports 2.3), whose disconnect listener reads it | Never a second start and never a 413: the response is cut off at its next await, and one that already finished stays complete. The error reaches the server either way | spends one |
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
allowlist; when the header is absent the allowlist is applied as before.
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
webhook, say. A deployment that already lists every mutating route in
`protected` keeps that exact fail-open shape unchanged. It must leave
`exempt` empty: combining an explicit `protected` list with any exemption is
refused at startup, because the exemption cannot change that list.

`webauth.dependencies.unauthenticated_response(request, login_redirect)`
answers exactly what `current_user_dependency` would for the same request —
the same login redirect or the same 401 — as a real `Response` rather than a
raised exception, for a host whose own middleware is the session authority
and cannot rely on FastAPI's dependency-injection or exception-handling
machinery to reach it.

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
in-process backend installs plain `webauth`.

## Session administration

Host developers use [`webauth.session_administration`](src/webauth/session_administration.py)
to list and end sessions without a user store. Construct
`SessionAdministration(sessions, audit, lock, config)` with the host's
`SessionAdministrationStore`, `AuditSink`, `WriteLock` and `WebAuthConfig`.

- `SessionAdministrationStore`: extends `SessionRecordStore` with
  `list_active(*, offset=0, limit=None)`. The host selects
  active records using its liveness rules and owns their order. These reads
  need no write lock; `limit=None` returns all remaining records.
- `WriteLock.hold()`: serializes checks and writes across the supplied stores
  in one host-owned transaction. `revoke_session` acquires it and never
  commits. The host commits on success and rolls back on failure. A
  transaction-scoped lock can remain held until then.

| Helper | Behavior |
|---|---|
| `list_sessions(offset=0, limit=None)` | Returns frozen `SessionSummary` records with `session_ref`, `user_id`, `username`, `ip_address`, and `user_agent` |
| `revoke_session(actor, session_ref)` | Ends the active session identified by a listed reference; raises `UnknownSessionError` if absent |

`revoke_session` requires `config.admin_role` and raises `NotAnAdminError`
otherwise; the host guards `list_sessions` with its admin dependency. Public
references come only from `webauth.cookies.session_reference(session_id)`:
SHA-256 hex of the UTF-8 raw identifier. Lists, the `session_revoked` event, and
`SessionIdentityChanged` (its `session_ref`) expose no raw token; the host reads
any timestamps from its own records. Refusals derive from `webauth.WebAuthError`.
[The session administration tests](tests/test_session_administration.py) verify
the helpers, including REQ-ADMIN-12 for listed references.

## Audit events

Map `AuditSink.account_event(event)` to the host's audit system, or
explicitly implement a no-op. Every event carries `kind`, `actor_id`, and
`subject_id`; optional fields default to `None`:

| Event kind | Additional fields |
|---|---|
| `user_created` | `role` |
| `session_revoked` | `session_ref` |
| `role_changed` | `previous_role`, `role` |
| `backchannel_logout` | none; `subject_id` is the account whose sessions the issuer ended |

Events contain no raw session identifiers or usernames. An admission event
with `actor_id=None` means the issuer's groups decided, not a person.

`AuditSink` has a second method, `session_identity_changed(event)`, which
receives a `SessionIdentityChanged` with `change`, `user_id`, `session_ref`,
`previous`, and `current` when a live session begins arriving from somewhere
else.

## What it owns, and what it leaves to the host

It owns the machinery an application should not rebuild:

| Module | Owns |
|---|---|
| `webauth.config` | The deployment facts every other module reads, installed on the app |
| `webauth.cookies` | The signed session cookie, the CSRF token bound to it, the pending-login cookie and the ID token hint cookie, issued and cleared |
| `webauth.dependencies` | Turning a signed cookie into the account that made the request or opened a WebSocket handshake (`authenticate_websocket`) |
| `webauth.policies` | Which requests are exempt, cacheable, or rate-limited, and how |
| `webauth.proxies` | Which peers may name a client, and the client identity that follows |
| `webauth.rate_limit` | The sliding-window backends a per-address budget is measured with — Redis or in-process |
| `webauth.ports` | What the host supplies, as Protocols: the record shapes `UserRecord` and `SessionRecord`, the stores `SubjectUserStore`, `SessionRecordStore` and `SessionAdministrationStore`, and `SessionLivenessPolicy`, `WriteLock`, `AuditSink` and `RateLimitBackend` |
| `webauth.liveness` | Whether a session still stands: the expiry-column and idle-window policies |
| `webauth.middleware` | Body-size, CSRF, rate-limit, and security-header middleware, and `install_web_auth_middleware`, which installs them in the one order |
| `webauth.session_ending` | The one place a session ends in the host's store |
| `webauth.session_administration` | Listing and revoking sessions by public reference through a host-owned session store, audit sink and write lock |
| `webauth.jwt_verification` | Whether an RS256 token from a remote issuer holds: strict parsing, its signature against the issuer's cached key set, issuer, audience and time claims. A key set may publish at most `MAX_KEY_SET_KEYS` (10) RS256 signing keys; keys for other purposes are passed over, bounded only by the key set's size. A token without a `kid` member verifies against the key set's only RS256 verification key, which may lack `kid`, and is refused as `INVALID_KEY_ID` against several eligible keys; a key without `kid` beside others is admitted but unreachable, `MAX_KEY_SET_KEYS` counts it, an explicit `"kid": null` is malformed, and a rotation of a sole key, or a change between one and several keys, can stay unseen until the one-hour TTL expires, unless a token naming an unfamiliar `kid` triggers an earlier refresh. A token naming an unknown `kid` is refused as `KEY_SET_UNAVAILABLE` when the key-set refresh it triggered failed or is cooling down after a failure, and as `UNKNOWN_KEY_ID` only when the refresh succeeded without that key. Needs `overnightworks-webauth[jwt]` |
| `webauth.https_client` | The one owner of outbound HTTPS: the key-set fetch and the token-endpoint POST, under per-operation timeouts and a total deadline, a size cap, no redirect followed and the system's trusted certificates. Needs `overnightworks-webauth[jwt]` |
| `webauth.oidc` | Logging a browser in at an OpenID Connect issuer: the authorization URL with PKCE, the callback judged, the code exchanged and the ID token verified into an identity. Needs `overnightworks-webauth[jwt]` |
| `webauth.oidc_login` | Whether a verified identity of the bound issuer becomes, reuses, or is refused an account, the role that account holds (`admin_role` or `user_role`, set from the admin group at every login), `log_out`, which ends the browser's session and returns the issuer's end-session URL, `receive_backchannel_logout`, which ends every session of the subject a verified Logout Token names, and `post_token_request_over_https`, the production `TokenRequestPost`. Takes its identity from `webauth.oidc`, so it needs `overnightworks-webauth[jwt]` too |

It leaves the application everything that touches the application's own truth:

- **Users and roles.** It has no user model and no role names beyond the
  configured ones; the one thing it writes to an account is the role admission
  derives from the issuer's groups (`admin_role` or `user_role`), and it
  decides no authorisation beyond the admin check.
- **Persistence.** It holds no schema and no ORM, and an import-linter contract
  keeps it that way. What it needs reaches it through the Protocols in
  `webauth.ports`.
- **Transactions.** None of the stores commits; the caller owns the
  transaction, so a request that fails leaves nothing behind that the auth
  machinery wrote, except the rate-limit budget, which counts attempts whether or
  not the request succeeds.
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

The wheel is published as an asset on each tag's release; take the version
from the [Releases page](https://github.com/overnightworks/webauth/releases)
and put it in place of `X.Y.Z`:

```bash
uv pip install "overnightworks-webauth[jwt] @ https://github.com/overnightworks/webauth/releases/download/vX.Y.Z/overnightworks_webauth-X.Y.Z-py3-none-any.whl"
```

In a `pyproject.toml`:

```toml
dependencies = [
    "overnightworks-webauth[jwt] @ https://github.com/overnightworks/webauth/releases/download/vX.Y.Z/overnightworks_webauth-X.Y.Z-py3-none-any.whl",
]
```

Tags are never moved; a broken release gets the next patch tag.

## Versioning

The version follows [semantic versioning](https://semver.org/). While it is 0.x,
a minor release may break a public contract and says so under **Breaking** in the
[CHANGELOG](CHANGELOG.md); a patch release never does. Only the latest minor
release receives security fixes, as [SECURITY.md](SECURITY.md) says.

A module's public names are the names its `__all__` lists. Any other name, with or
without a leading underscore, may change or disappear in any release.

## Development

```bash
uv sync --extra dev
uv run pytest tests -q
uv run ruff check src tests e2e
uv run lint-imports
uv run --group e2e pyright
tests/typing/check_against_wheel.sh
```

## Licence

MIT — see [LICENSE](LICENSE).
