# webauth

Session authentication for FastAPI applications: sessions with Redis-backed
expiry, HMAC-signed cookies, CSRF double-submit, admin and owner checks,
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
| `webauth.jwt_verification` | Whether an RS256 token from a remote issuer holds: strict parsing, its signature against the issuer's cached key set, issuer, audience and time claims. A key set may publish at most `MAX_KEY_SET_KEYS` (10) keys, counting the encryption and other keys it passes over. Needs `overnightworks-webauth[jwt]` |

It leaves the application everything that touches the application's own truth:
the user model, configured roles, setup and login routes, and their
transaction boundaries. The library persists nothing itself — it holds no schema
and no ORM, and an import-linter contract keeps it that way. What it needs
reaches it through the Protocols in `webauth.ports`: `UserStore`,
`SessionRecordStore`, `LoginAttemptStore`, `AuditSink`, and `PasswordHasher`.
None of the stores commits; the caller owns the transaction, so a request that
fails leaves nothing behind that the auth machinery wrote.

## Configuration

The host builds one `WebAuthConfig` and installs it. Fields a host may name:

| Field | Default | Values |
|---|---|---|
| `cookie_samesite` | `"strict"` | `"strict"` or `"lax"`; `None` is refused (a cross-site cookie is not what this library issues) |
| `cookie_secure` | `True` | `True` or `False`; any other value is refused |
| `session_cookie_name` | `"__Host-session_id"`, or `"session_id"` with `cookie_secure=False` | any cookie name; a `__Host-` name with `cookie_secure=False` is refused |
| `csrf_cookie_name` | `"__Host-csrf_token"`, or `"csrf_token"` with `cookie_secure=False` | any cookie name; a `__Host-` name with `cookie_secure=False` is refused |
| `cookie_max_age_seconds` | `session_max_age_seconds`, re-derived when `dataclasses.replace` changes it | a positive whole number of seconds; the browser cookie's `Max-Age`, which may outlive the idle window — see [Session lifetime](#session-lifetime) |
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
`__Host-` name a host sets itself with `cookie_secure=False` is refused when
the configuration is built rather than ending in a silent login loop.

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
`path` must be a same-origin absolute path, never a scheme or `//` address —
and a browser navigation (`Accept` rating `text/html` above
`application/json` by q-value) with no live session then answers 302 to that
path, with the asked-for address and query string under the query key it
named, while every other request still gets 401. A dependency can only raise
an `HTTPException`, so the 302 still carries FastAPI's default JSON body
(`{"detail":"Found"}`) alongside its `Location` header.

`webauth.dependencies.session_id_from_request(request, config)` is the one
reader of the session cookie: it parses the raw `Cookie` headers and returns
the verified session identifier, or `None` when the cookie is missing, longer
than `MAX_SESSION_COOKIE_CHARS` (200 characters), forged, or present more than
once. The limit holds even for a correctly signed cookie: `issue_session_cookies`
does not cap the session identifier it signs, and an identifier over 135
characters yields a cookie every reader refuses. A sibling
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

Every helper taking `actor` first requires `config.admin_role`, except
`change_own_password`, which lets any authenticated user change their own
password. The host authenticates the actor and guards the two list methods
with its admin dependency. A wrong current password raises `WrongPasswordError`;
the host owns the failed-attempt budget. Refusals derive from
`UserManagementError`, which the host translates into its own responses.

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
header still passes.

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

## Development

```bash
uv sync --extra dev
uv run pytest tests -q
uv run ruff check src tests
uv run lint-imports
```

## Licence

MIT — see [LICENSE](LICENSE).
