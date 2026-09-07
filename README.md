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
| `webauth.rate_limit` | The sliding-window counter every per-address budget is measured with |
| `webauth.session_store` | The Redis session cache — Redis owns expiry |
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

## Development

```bash
uv sync --extra dev
uv run pytest tests -q
uv run ruff check src tests
uv run lint-imports
```

## Licence

MIT — see [LICENSE](LICENSE).
