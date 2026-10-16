# webauth

Session authentication for FastAPI applications: sessions with Redis-backed
expiry, HMAC-signed cookies, CSRF double-submit, admin checks,
per-address rate limits, and the audit events they raise.

Distribution `overnightworks-webauth`, import package `webauth`.

## What it owns, and what it leaves to the host

It owns the machinery an application should not rebuild:

| Module | Owns |
|---|---|
| `webauth.config` | The deployment facts every other module reads, installed on the app |
| `webauth.cookies` | The signed session cookie and the CSRF token bound to it |
| `webauth.dependencies` | Turning a signed cookie into the account that made the request |
| `webauth.login` | Cookies issued and cleared, the failure budgets, password admission |
| `webauth.passwords` | Password hashing and the strength rules a chosen password must meet |
| `webauth.policies` | Which requests are exempt, cacheable, or rate-limited, and how |
| `webauth.proxies` | Which peers may name a client, and the client identity that follows |
| `webauth.rate_limit` | The sliding-window backends a per-address budget is measured with — Redis or in-process |
| `webauth.session_store` | `RedisSessionCache`, the one `SessionCache` implementation a host may put on its config |
| `webauth.liveness` | Whether a session still stands: the expiry-column and idle-window policies |
| `webauth.middleware` | Body-size, CSRF, rate-limit, and security-header middleware |
| `webauth.users` | User administration and first-run setup through host-owned stores and a write lock |
| `webauth.jwt_verification` | Whether an RS256 token from a remote issuer holds: strict parsing, its signature against the issuer's cached key set, issuer, audience and time claims. A key set may publish at most `MAX_KEY_SET_KEYS` (10) keys, counting the encryption and other keys it passes over. A token naming an unknown `kid` is refused as `KEY_SET_UNAVAILABLE` when the key-set refresh it triggered failed or is cooling down after a failure, and as `UNKNOWN_KEY_ID` only when the refresh succeeded without that key. Needs `overnightworks-webauth[jwt]` |
| `webauth.https_client` | The one owner of outbound HTTPS: the key-set fetch and the token-endpoint POST, under per-operation timeouts and a total deadline, a size cap, no redirect followed and the system's trusted certificates. Needs `overnightworks-webauth[jwt]` |
| `webauth.oidc` | Logging a browser in at an OpenID Connect issuer: the authorization URL with PKCE, the callback judged, the code exchanged and the ID token verified into an identity. Needs `overnightworks-webauth[jwt]` |
| `webauth.oidc_login` | Whether a verified identity of the bound issuer becomes, reuses, or is refused an account, and `post_token_request_over_https`, the production `TokenRequestPost`. Takes its identity from `webauth.oidc`, so it needs `overnightworks-webauth[jwt]` too |

It leaves the application everything that touches the application's own truth:
the user model, configured roles, setup and login routes, and their
transaction boundaries. The library persists nothing itself — it holds no schema
and no ORM, and an import-linter contract keeps it that way. What it needs
reaches it through the Protocols in `webauth.ports`: `UserStore`,
`SubjectUserStore`, `SessionRecordStore`, `LoginAttemptStore`, `AuditSink`,
and `PasswordHasher`.
None of the stores commits; the caller owns the transaction, so a request that
fails leaves nothing behind that the auth machinery wrote.
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

A `__Host-` cookie carries `Secure` and `Path=/` and no `Domain`, so only
this exact host can set it: a sibling subdomain cannot plant one with
`Domain=parent`. Browsers drop a `__Host-` cookie without `Secure`, so an
unnamed cookie falls back to its plain name when `cookie_secure=False`, and a
`__Host-` or `__Secure-` name a host sets itself with `cookie_secure=False` is refused when
the configuration is built rather than ending in a silent login loop.

v0.14.0 makes `SecurityHeadersMiddleware` a pure ASGI middleware: its
`.dispatch`, the `dispatch=` argument and any subclass override of `dispatch`
are gone. The 500 of an unhandled exception now carries the security headers,
and the exception still reaches the server. A host's 500 handler still runs,
but the response it returns is no longer sent. With `debug=True` Starlette's
traceback page is no longer sent either: the client gets the library 500 with
the headers, and the traceback still reaches the server log.

v0.13.0 adds the OpenID Connect relying party (`webauth.oidc` and
`webauth.oidc_login`) with PKCE and the signed pending-login cookie, and the one
HTTPS client `webauth.https_client` that every outbound request goes through,
with a total deadline of ten seconds on top of the per-step timeout. The
verifier rejects a token naming an unknown `kid` as `KEY_SET_UNAVAILABLE` when
the key-set refresh failed, not as `UNKNOWN_KEY_ID`. It also changes
three public contracts: a `deadline_seconds` or `timeout_seconds` of zero or
less raises `ValueError` in `fetch_key_set_over_https`, `post_form_over_https`
and `post_token_request_over_https`;
`TokenEndpointError.failure` is the `ExchangeFailure` that ended the token
request, so a caller can tell `TIMED_OUT` from other transport failures; and
`post_token_request_over_https` takes `deadline_seconds`, raising `ValueError`
when `timeout_seconds` exceeds it instead of capping it silently.

v0.12.0 adds the RS256 verifier `webauth.jwt_verification` (install the
`jwt` extra), a cookie lifetime separate from the idle window
(`cookie_max_age_seconds`), and an absolute cap for `IdleWindowLiveness`
(`absolute_max_age_seconds`) — see [Session lifetime](#session-lifetime). It
also refuses at construction what used to fail later: every lifetime —
`session_max_age_seconds`, `cookie_max_age_seconds`, and the windows and caps
of both liveness policies — must be a positive whole number of seconds, so a
`0`, a negative value, a `float`, a string or a `bool` stops the host from
starting instead of ending in a silent login loop. A capped
`IdleWindowLiveness` names a naive `created_at` instead of failing with a bare
`TypeError`.

v0.10.0 renames the default cookies to `__Host-session_id` and
`__Host-csrf_token`. Browsers still send the old `session_id` cookie, which
no longer authenticates, so every user of a host on the defaults is signed
out once and signs in again; the old cookies and their sessions run out at
their own expiry. A host that names both cookies itself is unaffected (it
may switch to `__Host-` names when it serves over https); a host naming only
one gets the new default for the other. A development setup with
`cookie_secure=False` keeps the plain names. `DEFAULT_SESSION_COOKIE_NAME` and
`DEFAULT_CSRF_COOKIE_NAME` in `webauth.cookies` now hold the `__Host-` names;
the plain ones are `PLAIN_SESSION_COOKIE_NAME` and `PLAIN_CSRF_COOKIE_NAME`. A
client that reads the CSRF cookie by name reads `config.csrf_cookie_name`
instead.

v0.9.0 counts rate-limit budgets per IPv6 network: every IPv6 client in one
`/64` shares one budget by default, and `ipv6_budget_prefix` (32 to 128)
chooses the network size. The IPv6 budget keys change, so existing Redis
counters for IPv6 clients start from zero once after the upgrade.

v0.8.0 refuses a request that carries the session cookie more than once:
`current_user_dependency` answers 401 and `CsrfTokenMiddleware` 403 where
v0.7 picked one of the values. It adds
`webauth.dependencies.session_id_from_request(request, config)`; a host that
reads the session cookie from `request.cookies` itself switches to it.

v0.7.0 changes three public behaviours a host upgrading from v0.6 must act
on: `issue_session_cookies(response, session_id, config)` no longer takes the
`request`; a host reached over plain http now gets `Secure` cookies and HSTS
unless its configuration sets `cookie_secure=False`; and
`SecurityHeadersMiddleware` reads the installed configuration, so an
application without `install_web_auth_config` gets a `RuntimeError` before
its route runs.

v0.3.0 clears the session cookies with the configured SameSite (`"strict"` by
default), where v0.2.0 cleared them with `lax`. A cookie is deleted by name,
domain and path, so the attribute does not affect the clearing.

## Install

The wheel is published as an asset on each tag's release:

```bash
uv pip install https://github.com/overnightworks/webauth/releases/download/v0.1.0/overnightworks_webauth-0.1.0-py3-none-any.whl
```

In a `pyproject.toml`:

```toml
dependencies = [
    "overnightworks-webauth @ https://github.com/overnightworks/webauth/releases/download/v0.1.0/overnightworks_webauth-0.1.0-py3-none-any.whl",
]
```

Tags are never moved; a broken release gets the next patch tag.

## A login route

The suite's `tests/webauth_arrangement.py` builds a complete configuration and
the fake stores, so the shape of a login is visible without a database. Run
this from `tests/`:

```python
from fastapi import FastAPI, Response
from fastapi.testclient import TestClient
from webauth_arrangement import FakeUser, a_web_auth_config

from webauth.config import install_web_auth_config
from webauth.login import (
    LoginOutcome,
    LoginRefusal,
    http_refusal,
    issue_session_cookies,
    judge_credentials,
)
config = a_web_auth_config()
app = FastAPI()
install_web_auth_config(app, config)

alice = FakeUser(password_hash=config.password_hasher.hash("the-correct-password"))

@app.post("/login")
def login(response: Response, password: str) -> dict[str, str]:
    outcome = judge_credentials(password, alice, hasher=config.password_hasher)
    if outcome is not LoginOutcome.ADMITTED:
        raise http_refusal(LoginRefusal(outcome))
    issue_session_cookies(response, "session-1", config)
    return {"status": "ok"}

client = TestClient(app, base_url="https://songmaker.example")
signed_in = client.post("/login", params={"password": "the-correct-password"})
print(signed_in.status_code, signed_in.cookies[config.session_cookie_name])
```

The real application replaces `FakeUser` with a lookup through its `UserStore`,
guards the attempt with `login_attempt_budget` (raising `http_refusal` on the
`LoginRefusal` it returns), and records the failed attempt itself — the library
never writes.

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
signed cookie would exceed it (identifiers up to 135 characters fit) or that is empty. A sibling
subdomain can set a second cookie of the same name, so a request carrying two
is refused rather than resolved to either: `current_user_dependency` answers
401 (`Invalid session`) and `CsrfTokenMiddleware` 403. A host that reads the
session cookie itself calls this function instead of `request.cookies`.

## users

Host developers use [`webauth.users`](src/webauth/users.py) to administer
accounts without moving their model, persistence, or HTTP API into the library.
Construct `UserManagement(users, sessions, audit, lock, config)` with the host's
stores and `WebAuthConfig`. The additional [ports](src/webauth/ports.py) are:

- `UserAdministrationStore`: extends `UserStore` with `list`, `update`, and
  `count_active_admins`. Duplicate usernames raise `UsernameTakenError`;
  updates to missing accounts raise `UnknownUserError`.
- `SessionAdministrationStore`: extends `SessionRecordStore` with
  `list_active(*, offset=0, limit=None)` and `count_active()`. The host selects
  active records using its liveness rules and owns their order. These reads
  need no write lock; `limit=None` returns all remaining records.
- `WriteLock.hold()`: serializes checks and writes across the supplied stores
  in one host-owned transaction. Helpers acquire it for mutations and never
  commit. The host commits on success and rolls back on failure, including
  `SetupRacedError`. A transaction-scoped lock can remain held until then.

`UserManagement` provides these helpers:

| Helper | Behavior |
|---|---|
| `create_user(actor, username, password, role)` | Creates an active account with either configured role |
| `list_users()` | Returns all accounts in store order |
| `change_role(actor, user_id, role)` | Changes the role and ends all sessions; an unchanged role does neither |
| `deactivate_user(actor, user_id)` | Deactivates the account and ends all sessions; refuses self-deactivation |
| `revoke_user_sessions(actor, user_id)` | Ends all account sessions and returns the store's deletion count |
| `set_password(actor, user_id, password)` | Sets a strength-checked password using the configured hasher and ends all sessions |
| `change_own_password(actor, current, new)` | Verifies the current password, replaces it, and ends all sessions |
| `list_sessions(offset=0, limit=None)` | Returns frozen `SessionSummary` records with `session_ref`, `user_id`, `username`, `ip_address`, and `user_agent` |
| `revoke_session(actor, session_ref)` | Ends the active session identified by a listed reference; raises `UnknownSessionError` if absent |
| `ensure_not_last_admin(user_id)` | Guards a host write against removing the last active admin; the caller holds the lock around both |

Every helper taking `actor` first requires `config.admin_role` (which `WebAuthConfig` keeps distinct from `user_role`), except
`change_own_password`, which lets any authenticated user change their own
password. The host authenticates the actor and guards the two list methods
with its admin dependency. A wrong current password raises `WrongPasswordError`;
the host owns the failed-attempt budget. An account without a password signs
in only through its identity provider, so `set_password` and
`change_own_password` refuse it with `PasswordlessAccountError` and write
nothing. Refusals derive from `UserManagementError`, which the host translates
into its own responses.

Both password paths delete every account session from the store, then from
`config.session_cache` when configured, including the current session. The
host opens a new session and issues new cookies afterwards. Single-session
revocation also deletes from the store before the cache. Public references
come only from `webauth.cookies.session_reference(session_id)`: SHA-256 hex of
the UTF-8 raw identifier. Lists, management events, and `SessionIdentityChanged`
(its `session_ref`) expose no raw token; the host reads any timestamps from its
own records.

v0.6.0 renames `SessionIdentityChanged.session_id` to `session_ref`, which
carries the reference rather than the raw identifier, and moves
`session_reference` from `webauth.users` to `webauth.cookies`; v0.5.1 hosts
update both the import and the field name.

`complete_first_run_setup(management, username, password)` creates the first
administrator only while no account exists. Both a setup route and a bootstrap
command can call it; the host supplies bootstrap credentials through its own
configuration and owns the setup surface.

Map `AuditSink.user_management_event(event)` to the host's audit system, or
explicitly implement a no-op. Every event carries `kind`, `actor_id`, and
`subject_id`; setup has `actor_id=None`. Optional fields default to `None`:

| Event kind | Additional fields |
|---|---|
| `user_created`, `first_admin_created` | `role` |
| `role_changed` | `role`, `session_count` |
| `user_deactivated`, `sessions_revoked` | `session_count` |
| `password_set_by_admin`, `password_changed` | `session_count` |
| `session_revoked` | `session_ref` |

Management events contain no passwords, hashes, raw session identifiers, or
usernames. [The users tests](tests/test_users.py) verify the helpers, including
REQ-ADMIN-10 for password invalidation and REQ-ADMIN-12 for listed references.

## PasswordHasher

The library hardcodes no hashing algorithm: `WebAuthConfig` requires a
`password_hasher`, a `webauth.ports.PasswordHasher` with two methods —
`hash(password) -> str` and `verify(password, stored_hash) -> bool`. `verify`
must check even a `None` `stored_hash` against a fixed dummy at full cost, so a
username nobody holds cannot be told from a wrong password by timing.

`webauth.passwords.Argon2idPasswordHasher` is provided and honours that
contract. It normalises every password to Unicode NFC in both `hash` and
`verify`, as `check_password_strength` does before measuring it.
Normalisation is the hasher's job: the library passes the password as typed,
so a host hasher that wants spelling-independence normalises in both `hash`
and `verify`. New hashes use OWASP's
Argon2id costs (m=19 MiB, t=2, p=1), held in `OWASP_ARGON2ID`; a host passes its
own `argon2.Parameters` to the constructor to change them. Those parameters
are the host's one cost profile: `verify` accepts only an Argon2id hash that
encodes exactly them (version, memory, time, parallelism, salt and hash
length), so an unknown username costs the same as any accepted hash. Every
other stored value raises `webauth.passwords.UnknownHashFormatError` instead
of reading as a wrong password — bcrypt, Argon2i, Argon2d, an empty or garbled
string, an Argon2id hash at other costs (a 64 MiB one as much as a cheaper
one), and an Argon2id hash whose salt or digest is not canonical unpadded
base64 of the profile's salt and hash length. A well-formed hash that Argon2
still fails to check, for example under memory or thread exhaustion, raises
Argon2's own `argon2.exceptions.VerificationError` unchanged. After changing the parameters, set each
password anew, for example with `set_password`. A host with another algorithm
supplies its own class implementing the same protocol.

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
in-process backend and no Redis session cache installs plain `webauth`.

## The session cache, or none

`WebAuthConfig.session_cache` is a `webauth.ports.SessionCache` or `None`, and
that single field decides how a live session's idle expiry is owned. With a
cache, Redis TTL owns idle expiry and the host reconciles the store; with
`session_cache=None`, the store's `touch` on every request owns idle expiry and
there is no sync loop. Either way `WebAuthConfig.session_liveness` — a
`webauth.ports.SessionLivenessPolicy` — makes the admit-or-refuse decision, and
`webauth.dependencies` alone reads the wall clock and passes the instant in.
`webauth.liveness` ships two: `ExpiryColumnLiveness`, for a store with
`created_at`/`expires_at` columns, and `IdleWindowLiveness`, for one that keeps
`last_seen` (and `created_at` when it is given an absolute cap). On the cache
path a policy never trusts the cached `expires_at`, which can lag the real TTL
after a refresh — Redis TTL owns idle there, and only a policy's own caps
remain. There is no app-state install: the config carries the cache, so any
code that holds the config — not only a request handler — can reach it.

The Redis `SessionCache` is an expiry-column feature: a cached session carries
`created_at`/`expires_at`, so it pairs only with `ExpiryColumnLiveness`. The
idle-window model is store-only — it keeps `last_seen` (and `created_at` when
it is given an absolute cap) and reads every request from its store — so
`WebAuthConfig` refuses a `session_cache` alongside `IdleWindowLiveness` at
construction rather than failing per request.

`webauth.session_store.RedisSessionCache` is the one implementation shipped
here; it needs the client library, so a host that uses it installs
`overnightworks-webauth[redis]`. A host that supplies its own cache implements the same
protocol.

## Session lifetime

Three numbers decide how long someone stays signed in, and each has one owner:

- `WebAuthConfig.cookie_max_age_seconds` is the browser cookie's `Max-Age`. The
  cookie is issued once at login and never reissued, so it bounds the whole
  sign-in. It defaults to `session_max_age_seconds`.
- The idle window — `session_max_age_seconds` for the cache TTL, the idle
  argument of `IdleWindowLiveness`, or the host's `expires_at` refresh for
  `ExpiryColumnLiveness` — refuses a session left unused for longer.
- The absolute cap — `ExpiryColumnLiveness(absolute_max_age_seconds)` or
  `IdleWindowLiveness(idle, absolute_max_age_seconds=...)` — refuses a session
  older than the cap, however recently it was used.

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

`webauth.session_ending` is the one place a session ends in both the host's
store and `config.session_cache`. A logout route calls
`end_session(sessions, config.session_cache, session_id=..., user_id=...)`
rather than deleting from either itself; `end_user_sessions(sessions, cache,
user_id)` ends every session of an account and returns the store's count, and
`prune_sessions(sessions, cache, user_id, max_sessions)` ends the oldest
sessions above a cap after a login and returns their identifiers. Each deletes
from the store first, then from the cache when one is configured. A cache that
fails to delete raises: the host answers with an error instead of reporting a
logout the cache would still honour. The `users` helpers end sessions through
the same functions.

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
malformed header text the origin sends back.

`webauth.oidc_login.admit_identity(identity, *, bound_issuer, accounts, lock,
audit, config)` turns that identity into the account it signs in as. The host
binds its store to one issuer — the `issuer` of its `OidcClientConfig` — and
passes it as `bound_issuer`; changing the issuer is a migration of the host's
accounts, never a configuration change. `accounts` is a `SubjectUserStore`
(`get`, `get_by_username`, and `create_for_subject(subject, username, role)`,
which adds an account whose `id` is the subject and which has no password, so
a back-channel logout names the account directly). Admission holds
`lock.hold()` and never commits:

- A new subject gets an account with the issuer's `preferred_username` (or the
  subject when it suggests none, or only whitespace) and `config.user_role` (never equal to `admin_role`, so no new account is an admin by accident),
  and the audit sink hears `user_created` with `actor_id=None`.
- A known subject reuses its account unchanged, even when its suggested
  username changed.
- Otherwise it answers an `AdmissionRefusal` and writes nothing:
  `FOREIGN_ISSUER` for an identity from another issuer, `ACCOUNT_DEACTIVATED`,
  `SUBJECT_HELD_BY_PASSWORD_ACCOUNT` when the subject names an existing
  password account (linking the two is the host's migration to decide), and
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
`finish_login(...)` answers the `UserRecord` to open a session for, as after
a password login, or the `OidcRefusal` or `AdmissionRefusal` that stopped it;
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

`UserRecord.password_hash` is a read-only `str | None` property, so a
password-only host whose model types the field `str` keeps satisfying it, and
password login answers `WRONG_PASSWORD` for an account without one after the
same single hash verification a wrong password costs.

## Development

```bash
uv sync --extra dev
uv run pytest tests -q
uv run ruff check src tests
uv run lint-imports
uvx --no-build pyright@1.1.414 --pythonpath .venv/bin/python tests/typing
```

## Licence

MIT — see [LICENSE](LICENSE).
