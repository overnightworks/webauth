# webauth

Session authentication for FastAPI applications: sessions the store decides
on every request, HMAC-signed cookies, CSRF double-submit, admin checks,
per-address rate limits, and the audit events they raise.

Distribution `overnightworks-webauth`, import package `webauth`.

## What it owns, and what it leaves to the host

It owns the machinery an application should not rebuild:

| Module | Owns |
|---|---|
| `webauth.config` | The deployment facts every other module reads, installed on the app |
| `webauth.cookies` | The signed session cookie and the CSRF token bound to it, issued and cleared |
| `webauth.dependencies` | Turning a signed cookie into the account that made the request |
| `webauth.policies` | Which requests are exempt, cacheable, or rate-limited, and how |
| `webauth.proxies` | Which peers may name a client, and the client identity that follows |
| `webauth.rate_limit` | The sliding-window backends a per-address budget is measured with — Redis or in-process |
| `webauth.liveness` | Whether a session still stands: the expiry-column and idle-window policies |
| `webauth.middleware` | Body-size, CSRF, rate-limit, and security-header middleware, and `install_web_auth_middleware`, which installs them in the one order |
| `webauth.session_administration` | Listing and revoking sessions by public reference through a host-owned session store, audit sink and write lock |
| `webauth.jwt_verification` | Whether an RS256 token from a remote issuer holds: strict parsing, its signature against the issuer's cached key set, issuer, audience and time claims. A key set may publish at most `MAX_KEY_SET_KEYS` (10) RS256 signing keys; keys for other purposes are passed over, bounded only by the key set's size. A token naming an unknown `kid` is refused as `KEY_SET_UNAVAILABLE` when the key-set refresh it triggered failed or is cooling down after a failure, and as `UNKNOWN_KEY_ID` only when the refresh succeeded without that key. Needs `overnightworks-webauth[jwt]` |
| `webauth.https_client` | The one owner of outbound HTTPS: the key-set fetch and the token-endpoint POST, under per-operation timeouts and a total deadline, a size cap, no redirect followed and the system's trusted certificates. Needs `overnightworks-webauth[jwt]` |
| `webauth.oidc` | Logging a browser in at an OpenID Connect issuer: the authorization URL with PKCE, the callback judged, the code exchanged and the ID token verified into an identity. Needs `overnightworks-webauth[jwt]` |
| `webauth.oidc_login` | Whether a verified identity of the bound issuer becomes, reuses, or is refused an account, and `post_token_request_over_https`, the production `TokenRequestPost`. Takes its identity from `webauth.oidc`, so it needs `overnightworks-webauth[jwt]` too |

It leaves the application everything that touches the application's own truth:
the user model, configured roles, login routes, and their
transaction boundaries. The library persists nothing itself — it holds no schema
and no ORM, and an import-linter contract keeps it that way. What it needs
reaches it through the Protocols in `webauth.ports`: `SubjectUserStore`, `SessionRecordStore`,
and `AuditSink`.
None of the stores commits; the caller owns the transaction, so a request that
fails leaves nothing behind that the auth machinery wrote, except the rate-limit
budget, which counts attempts whether or not the request succeeds.
`SessionRecordStore.touch` returns a strict `bool`: `True` when a stored row was
renewed, `False` when the session is gone, which refuses the request like an
expired session.

## Configuration

The host builds one `WebAuthConfig` and installs it. Fields a host may name:

| Field | Default | Values |
|---|---|---|
| `cookie_samesite` | `"strict"` | `"strict"` or `"lax"`; `None` is refused (a cross-site cookie is not what this library issues) |
| `cookie_secure` | `True` | `True` or `False`; any other value is refused |
| `session_cookie_name` | `"__Host-session_id"`, or `"session_id"` with `cookie_secure=False` | any cookie name; a `__Host-` or `__Secure-` name with `cookie_secure=False` is refused |
| `csrf_cookie_name` | `"__Host-csrf_token"`, or `"csrf_token"` with `cookie_secure=False` | any cookie name; a `__Host-` or `__Secure-` name with `cookie_secure=False` is refused |
| `cookie_max_age_seconds` | `session_max_age_seconds`, re-derived when `dataclasses.replace` changes it | a positive whole number of seconds; the browser cookie's `Max-Age`, which may outlive the idle window — see [Session lifetime](#session-lifetime) |
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

### Content-Security-Policy

`default_content_security_policy()` holds no host fact: `default-src 'none'` with
`'self'` for scripts, styles, connections, fonts, manifests and workers, `data:` and
`blob:` besides for images, `blob:` for media, and `frame-ancestors 'none'`. A host
adds its own sources to one directive through `added_sources`, without copying the
string. A framework that writes style attributes, for example, needs inline style, and
that is the host's choice, so the host names it:

```python
default_content_security_policy(
    added_sources={CspDirective.STYLE_SRC: ["'unsafe-inline'"]},
)
```

Callers supply complete source expressions: keywords, nonces and hashes in their
quotes, hosts and schemes bare. Only `script_hashes` takes bare `sha256-<base64>`
values and quotes them. Every source is validated against the CSP grammar when the
policy is built, and a malformed one is a `ValueError`. A non-empty addition to
`frame-ancestors` replaces its `'none'`.

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

## Install

The wheel is published as an asset on each tag's release; take the version
from the [Releases page](https://github.com/overnightworks/webauth/releases)
and put it in place of `X.Y.Z`:

```bash
uv pip install https://github.com/overnightworks/webauth/releases/download/vX.Y.Z/overnightworks_webauth-X.Y.Z-py3-none-any.whl
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

## What it does not do

- It persists nothing and holds no schema or ORM.
- It defines no routes; the only responses it writes are its own refusals: 401, 403, 413, 429, 503 and the 500, and the 302 to the host's login path.
- It has no user model and no role names beyond the configured ones.
- It commits no transaction; the caller owns it.
- It issues no access or ID tokens: it is no identity provider, and it verifies the ID tokens an issuer made.
- It decides no authorisation beyond the admin check.

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

`webauth.dependencies.session_id_from_request(request, config)` is the one
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

## Session administration

Host developers use [`webauth.session_administration`](src/webauth/session_administration.py)
to list and end sessions without a user store. Construct
`SessionAdministration(sessions, audit, lock, config)` with the host's
`SessionAdministrationStore`, `AuditSink`, `WriteLock` and `WebAuthConfig`.

- `SessionAdministrationStore`: extends `SessionRecordStore` with
  `list_active(*, offset=0, limit=None)` and `count_active()`. The host selects
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
any timestamps from its own records. Refusals derive from `UserManagementError`.
[The session administration tests](tests/test_session_administration.py) verify
the helpers, including REQ-ADMIN-12 for listed references.

## Audit events

Map `AuditSink.user_management_event(event)` to the host's audit system, or
explicitly implement a no-op. Every event carries `kind`, `actor_id`, and
`subject_id`; optional fields default to `None`:

| Event kind | Additional fields |
|---|---|
| `user_created` | `role` |
| `session_revoked` | `session_ref` |

Events contain no passwords, hashes, raw session identifiers, or usernames.

`AuditSink` has a second method, `session_identity_changed(event)`, which
receives a `SessionIdentityChanged` with `change`, `user_id`, `session_ref`,
`previous`, and `current` when a live session begins arriving from somewhere
else.

## Rate limiting, and the optional Redis extra

`WebAuthConfig` requires a `rate_limits`, a `webauth.ports.RateLimitBackend`
with one method — `is_allowed(key, *, limit, window_seconds) -> bool` — that
counts the current event against a sliding window and raises rather than
guessing when it cannot answer, so the middleware fails the request closed.

Two backends implement it:

- `webauth.rate_limit.RedisRateLimitBackend` shares one window across every
  process that reaches the same Redis. It needs the client library, so a host
  that uses it installs `overnightworks-webauth[redis]`.
- `webauth.rate_limit.SingleProcessRateLimitBackend` keeps the window in this
  process's memory and needs no Redis — for a single-node host that runs one
  worker. Two processes or two hosts count independently, so a multi-worker
  deployment uses the Redis backend instead.

Redis is therefore an optional dependency: a deployment that supplies the
in-process backend installs plain `webauth`.

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

## Session lifetime

Three numbers decide how long someone stays signed in, and each has one owner:

- `WebAuthConfig.cookie_max_age_seconds` is the browser cookie's `Max-Age`. The
  cookie is issued once at login and never reissued, so it bounds the whole
  sign-in. It defaults to `session_max_age_seconds`.
- The idle window — `IdleWindowLiveness`'s idle argument, or the host's
  `expires_at` refresh for `ExpiryColumnLiveness` — refuses a session left unused for longer.
- The absolute cap — `ExpiryColumnLiveness(absolute_max_age_seconds)` or
  `IdleWindowLiveness(idle, absolute_max_age_seconds=...)` — refuses a session
  older than the cap, however recently it was used.

Every lifetime — `session_max_age_seconds`, `cookie_max_age_seconds` and the windows and
caps of both liveness policies — must be a positive whole number of seconds; `0`, a negative
value, a `float`, a string or a `bool` is refused when the object is built.

The recommended policy is a 30-day cookie, a 7-day idle window and a 30-day
absolute cap: someone who comes back at least weekly stays signed in for up to
30 days, and anyone away for more than 7 days signs in again.

```python
SEVEN_DAYS = 7 * 24 * 3600
THIRTY_DAYS = 30 * 24 * 3600

WebAuthConfig(
    ...,
    session_max_age_seconds=SEVEN_DAYS,
    cookie_max_age_seconds=THIRTY_DAYS,
    session_liveness=IdleWindowLiveness(SEVEN_DAYS, absolute_max_age_seconds=THIRTY_DAYS),
)
```

## Ending a session

`webauth.session_ending` is the one place a session ends in the host's store. A
logout route calls `end_session(sessions, session_id=...)` rather than deleting
from the store itself; `end_user_sessions(sessions, user_id)` ends every session
of an account and returns the store's count, and
`prune_sessions(sessions, user_id, max_sessions)` ends the oldest sessions above
a cap after a login and returns their identifiers. The next request carrying an
ended session's cookie is refused. The `session_administration` helpers
end sessions through the same functions.

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

## OpenID Connect login

`webauth.oidc.OidcRelyingParty` runs the authorization-code flow with PKCE
for one client at one issuer, described by an `OidcClientConfig` whose URLs
are all https and whose `client_secret` is a `SecretStr`. `begin_login()`
answers the URL to send the browser to and a `PendingLogin` — its state,
nonce and PKCE verifier, and `issued_at`, the wall-clock second it began.
`complete_login(pending, callback_query)` takes that pending login and the
callback's raw query string and answers an `OidcIdentity` (subject, issuer,
full group paths, `sid`, `preferred_username`) or an `OidcRefusal` naming its
reason. The state is checked before anything else the callback says; then
the pending login's age: one older than `PENDING_LOGIN_MAX_AGE_SECONDS`
(600) or dated in the future is `PENDING_LOGIN_EXPIRED`, and no token
request is sent. An error the issuer reports is carried as its short error
code only, never its description, and a `code` longer than
`MAX_AUTHORIZATION_CODE_CHARS` (2048) is `MALFORMED_CALLBACK`. A token answer
that names any member twice, at any depth, is `TOKEN_ENDPOINT_FAILED` rather
than letting the last one win. The code is exchanged through the `post_token_request` the host
injects, authenticated with HTTP Basic, and the ID token is verified by a
`JwtVerifier` whose one accepted audience is the client ID, then checked for
the pending nonce and an authorized party: a token for several audiences must
name the client as its `azp`, and any `azp` a token names must be the client.

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

`webauth.oidc_login.admit_identity(identity, *, bound_issuer, accounts, lock,
audit, config)` turns that identity into the account it signs in as. The host
binds its store to one issuer — the `issuer` of its `OidcClientConfig` — and
passes it as `bound_issuer`; changing the issuer is a migration of the host's
accounts, never a configuration change. `accounts` is a `SubjectUserStore`
(`get`, `get_by_username`, and `create_for_subject(subject, username, role)`,
which adds an account whose `id` is the subject, so a back-channel logout names
the account directly). Any stored account whose `id` equals the subject
character for character is that subject's account and signs in as it is,
whatever created it. The host's `get` must compare exactly: no case, accent or
trailing-space folding, even where its id column's collation folds. A host that
migrates legacy accounts makes sure that no legacy `id` can equal a subject of
the bound issuer. Admission holds `lock.hold()` and never commits:

- A new subject gets an account with the issuer's `preferred_username` (or the
  subject when it suggests none, or only whitespace) and `config.user_role` (never equal to `admin_role`, so no new account is an admin by accident),
  and the audit sink hears `user_created` with `actor_id=None`.
- A known subject reuses its account unchanged, even when its suggested
  username changed.
- Otherwise it answers an `AdmissionRefusal` and writes nothing:
  `FOREIGN_ISSUER` for an identity from another issuer, `ACCOUNT_DEACTIVATED`, and
  `USERNAME_TAKEN` when a new subject's username belongs to another account
  — including when the store's own uniqueness is stricter than its lookup
  and `create_for_subject` raises `UsernameTakenError`.

### The host's start and callback routes

`webauth.oidc_login` carries the pending login for the host, so the host
keeps no server-side store and `WebAuthConfig` knows nothing of OpenID
Connect. The host serves two routes over its one `OidcRelyingParty`:

```python
@app.get("/login/oidc")
def start(request: Request) -> Response:
    response = Response(status_code=303)
    response.headers["location"] = start_login(relying_party, request, response, config)
    return response


@app.get("/auth/callback")
def callback(request: Request, response: Response) -> dict[str, str]:
    outcome = finish_login(
        relying_party, request, response, config,
        bound_issuer=client_config.issuer, accounts=accounts, lock=lock, audit=audit,
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

`finish_login` reads the state from the callback, selects exactly the cookie
that state names and clears it on every outcome — admitted or refused —
while every other tab's cookie stays. The state is read on its own, so a
callback naming one state beside a malformed rest — another parameter named
twice, or one that does not decode — still clears that state's cookie; it is
refused as `MALFORMED_CALLBACK` when that state's cookie is genuine and as
`STATE_MISMATCH` otherwise. A callback with no state, an empty one, its
state twice or an undecodable one selects no cookie. Every one of these, and
a missing, forged, oversized, unknown-version or duplicated cookie, or a
genuine cookie of another login, is refused before any token request:
`MALFORMED_CALLBACK` for a malformed query that names a single state whose
cookie is genuine, otherwise `STATE_MISMATCH`.

**Single use, stated honestly.** A pending login is single-use because its
cookie is cleared on every outcome and the issuer accepts its authorization
code once. webauth keeps no server-side replay store: a copy of the cookie
taken before the callback is stopped by the issuer refusing the spent code
(`TOKEN_REQUEST_REFUSED`), not by webauth remembering it.

## Development

```bash
uv sync --extra dev
uv run pytest tests -q
uv run ruff check src tests e2e
uv run lint-imports
uvx --no-build pyright@1.1.414 --pythonpath .venv/bin/python tests/typing
```

## Licence

MIT — see [LICENSE](LICENSE).
