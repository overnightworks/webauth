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

It leaves the application everything that touches the application's own truth:
the user model, configured roles, setup and login routes, and their
transaction boundaries. The library persists nothing itself — it holds no schema
and no ORM, and an import-linter contract keeps it that way. What it needs
reaches it through the Protocols in `webauth.ports`: `UserStore`,
`SessionRecordStore`, `LoginAttemptStore`, `AuditSink`, and `PasswordHasher`.
None of the stores commits; the caller owns the transaction, so a request that
fails leaves nothing behind that the auth machinery wrote.

## Configuration

The host builds one `WebAuthConfig` and installs it. Cookie flags a host may name:

| Field | Default | Values |
|---|---|---|
| `cookie_samesite` | `"strict"` | `"strict"` or `"lax"`; `None` is refused (a cross-site cookie is not what this library issues) |

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
from fastapi import FastAPI, Request, Response
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
from webauth.passwords import hash_password

config = a_web_auth_config()
app = FastAPI()
install_web_auth_config(app, config)

alice = FakeUser(password_hash=hash_password("the-correct-password"))

@app.post("/login")
def login(request: Request, response: Response, password: str) -> dict[str, str]:
    outcome = judge_credentials(password, alice, hasher=config.password_hasher)
    if outcome is not LoginOutcome.ADMITTED:
        raise http_refusal(LoginRefusal(outcome))
    issue_session_cookies(response, request, "session-1", config)
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
come only from `session_reference(session_id)`: SHA-256 hex of the UTF-8 raw
identifier. Lists and management events expose no raw token; the host reads
any timestamps from its own records.

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

`webauth.passwords.BcryptPasswordHasher` is provided and honours that contract.
A host that prefers Argon2id supplies its own class implementing the same
protocol.

## Rate limiting, and the optional Redis extra

`WebAuthConfig` requires a `rate_limits`, a `webauth.ports.RateLimitBackend`
with one method — `is_allowed(key, *, limit, window_seconds) -> bool` — that
counts the current event against a sliding window and raises rather than
guessing when it cannot answer, so the middleware fails the request closed.

Two backends implement it:

- `webauth.rate_limit.RedisRateLimitBackend` shares one window across every
  process that reaches the same Redis. It needs the client library, so a host
  that uses it installs `webauth[redis]`.
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
only `last_seen`. On the cache path a policy never trusts the cached
`expires_at`, which can lag the real TTL after a refresh — Redis TTL owns idle
there, and only a policy's own caps remain. There is no app-state install: the
config carries the cache, so any code that holds the config — not only a
request handler — can reach it.

The Redis `SessionCache` is an expiry-column feature: a cached session carries
`created_at`/`expires_at`, so it pairs only with `ExpiryColumnLiveness`. The
idle-window model is store-only — it keeps just `last_seen` and reads every
request from its store — so `WebAuthConfig` refuses a `session_cache` alongside
`IdleWindowLiveness` at construction rather than failing per request.

`webauth.session_store.RedisSessionCache` is the one implementation shipped
here; it needs the client library, so a host that uses it installs
`webauth[redis]`. A host that supplies its own cache implements the same
protocol.

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
