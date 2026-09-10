# Repository agent guidance

`webauth` is a library, not an application: it is installed by host
applications and has no deployment of its own. Every change here is a change
to a public contract that a tag has already frozen somewhere else.

- Before every repository edit, use the globally installed `agent-claim` CLI
  to check the live ledger and claim the exact write scope. Subagents remain
  within their parent's live claim and do not take overlapping claims.
- Keep the shared `main` checkout clean. Build in an isolated external
  worktree, and never `git stash` — the stash stack is shared across
  worktrees.
- `main` is protected: every change lands through a pull request with green
  CI. Nobody pushes to `main`.

## Repository layout

The repository root holds only what a tool must find there — the package
manifest and its lockfile, scanner configuration, the licence — and the entry
documents `README.md`, `AGENTS.md` and `CLAUDE.md`. Everything else lives in
the directory of its owner: the library under `src/webauth/`, its suite under
`tests/`. No catch-all directory (`tooling/`, `misc/`) and no deeper hierarchy
than the owner needs.

## Boundaries

- The library persists nothing. It holds no schema and no ORM; durable state
  reaches it through the Protocols in `webauth.ports`, which the host
  application implements over the persistence it already owns. `.importlinter`
  forbids `sqlalchemy` and `lint-imports` proves it in CI.
- No host application is a dependency. `webauth` depends on FastAPI, Pydantic
  and bcrypt at runtime, and on nothing else. Redis is optional — install
  `webauth[redis]` for the Redis rate-limit and session backends; a single-node
  host that supplies the in-process rate-limit backend needs no Redis at all.
- The user model, schema, configured role names, transaction boundaries, and
  HTTP routes and responses belong to the host. User administration and
  first-run setup are library helpers in `webauth.users` over host-supplied
  ports and a write lock; the host commits or rolls back their work.

## Checks

```bash
uv sync --extra dev
uv run pytest tests -q
uv run ruff check src tests
uv run lint-imports
```

The suite is fast and needs no service: Redis is faked in-process. Run it
whole.

## Releasing

A release is a tag. `.github/workflows/release.yml` builds the wheel on a
`v*` tag and attaches it to the GitHub release; host applications pin that
asset URL. A tag is never moved — a broken release gets the next patch tag —
so the version in `pyproject.toml` and `webauth.__version__` is raised in the
pull request that precedes the tag.
