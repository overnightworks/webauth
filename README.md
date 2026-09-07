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

It leaves the application everything that touches the application's own truth:
the user model, roles, first-run setup, and the login route with its
transaction boundary. The library persists nothing itself — it holds no schema
and no ORM, and an import-linter contract keeps it that way. What it needs
reaches it through the Protocols in `webauth.ports`: `UserStore`,
`SessionRecordStore`, `LoginAttemptStore`, `AuditSink`, and `PasswordHasher`.
None of the stores commits; the caller owns the transaction, so a request that
fails leaves nothing behind that the auth machinery wrote.

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

`webauth.session_store.RedisSessionCache` is the one implementation shipped
here; it needs the client library, so a host that uses it installs
`webauth[redis]`. A host that supplies its own cache implements the same
protocol.

## Development

```bash
uv sync --extra dev
uv run pytest tests -q
uv run ruff check src tests
uv run lint-imports
```

## Licence

MIT — see [LICENSE](LICENSE).
