# webauth — Claude Code Config

## Project

Session authentication for FastAPI applications: sessions with Redis-backed
expiry, HMAC-signed cookies, CSRF double-submit, admin and owner checks,
per-address rate limits, audit ports. Distribution `overnightworks-webauth`,
import package `webauth`.

**Python**: 3.12+ | **Package manager**: uv | **Library**: `src/webauth/` |
**Suite**: `tests/`

Extracted from [overnightworks/songmaker](https://github.com/overnightworks/songmaker)
(issue #825) with its history; songmaker installs the wheel from this
repository's tagged release.

**Agent policy:** [AGENTS.md](AGENTS.md) is the provider-neutral entrypoint and
owns the layout, boundary, check and release rules. Read it first.

## Setup & Checks

```bash
uv sync --extra dev
uv run pytest tests -q       # the whole suite; no service needed
uv run ruff check src tests
uv run lint-imports
uv build                     # what the release attaches
```

## Code patterns

- **Ports are Protocols, and none of them commits.** A new host obligation is
  a Protocol in `webauth.ports`, never a concrete class and never a query.
- **Deployment facts come from `WebAuthConfig`.** Nothing reads an environment
  variable or a global; the host installs one config on the app and every
  module reads it from there.
- **No inline comments.** Names carry the meaning; a comment explains only a
  non-obvious *why*.
- **Tests name the behaviour they pin** and use the builders in
  `tests/webauth_arrangement.py` rather than a second set of fakes.
