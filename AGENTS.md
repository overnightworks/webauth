# Repository agent guidance

`webauth` is a library, not an application: it is installed by host
applications and has no deployment of its own. Every change here is a change
to a public contract that a tag has already frozen somewhere else.

- Before every repository edit, use the globally installed `aco` CLI
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
documents `README.md`, `AGENTS.md`, `CLAUDE.md`, `CHANGELOG.md` and `SECURITY.md`. Everything else lives in
the directory of its owner: the library under `src/webauth/`, its suite under
`tests/`. No catch-all directory (`tooling/`, `misc/`) and no deeper hierarchy
than the owner needs.

`e2e/` is the proof harness: real-browser scripts that drive a host application
built on the library against a real issuer. It owns nothing shipped, the
library never imports it, and it is run by hand (`e2e/oidc/README.md`), not in
CI, which only lints it.

## Boundaries

- The library persists nothing. It holds no schema and no ORM; durable state
  reaches it through the Protocols in `webauth.ports`, which the host
  application implements over the persistence it already owns. `.importlinter`
  forbids `sqlalchemy` and `lint-imports` proves it in CI.
- No host application is a dependency. `webauth` depends on FastAPI (with
  Starlette and anyio, which `src` imports) and Pydantic at
  runtime, and on nothing else. Redis is optional — install
  `overnightworks-webauth[redis]` for the Redis rate-limit backend; a single-node
  host that supplies the in-process rate-limit backend needs no Redis at all.
  JWT verification and OpenID Connect login are optional too —
  `overnightworks-webauth[jwt]` adds PyJWT and cryptography, which only
  `webauth.jwt_verification` imports, and urllib3, which only
  `webauth.https_client` imports — the one owner of outbound HTTPS. Only
  `webauth.oidc` imports `webauth.jwt_verification`; only
  `webauth.jwt_verification` and `webauth.oidc_login` import
  `webauth.https_client`. Four `protected` import-linter contracts enforce
  this. A fifth confines `redis` to `webauth.rate_limit`, and
  `tests/test_public_api.py` imports every module with `redis` blocked, so the
  in-process backend never needs the extra.
- The user model, schema, configured role names, transaction boundaries, and
  HTTP routes and responses belong to the host. Session administration
  is a library helper in `webauth.session_administration` over host-supplied
  ports and a write lock; the host commits or rolls back its work.

## Checks

```bash
uv sync --extra dev
uv run pytest tests -q
uv run ruff check src tests e2e
uv run lint-imports
uv run --group e2e pyright
tests/typing/check_against_wheel.sh
```

`tests/typing/` holds a static OIDC-only host. The script type-checks it with
the pinned pyright against the built wheel, from a directory without `src`, so
a port change or an export a host cannot import fails here.

CI runs these in the `checks` job and re-runs the suite at the lowest declared
versions in `lowest-direct`. The shared quality gate
(`overnightworks/quality`, pinned by SHA in `ci.yml`) is the `quality` job; it
needs only `checks`, not `lowest-direct`. The
quality gate's required check is `quality / verdict`; allowances for known
secret false positives live only in `quality/config.toml`.

The suite is fast and needs no service: Redis is faked in-process. Run it
whole.

## Releasing

A release is a tag. `.github/workflows/release.yml` builds the wheel on a
`v*` tag and attaches it to the GitHub release; host applications pin that
asset URL. A tag is never moved — a broken release gets the next patch tag —
so `webauth.__version__` alone is raised in the pull request that precedes the
tag. It stays a plain string literal, which setuptools reads without importing the
package; anything computed makes setuptools import `webauth` inside the isolated
build, where neither the package's own metadata nor its dependencies are
installed. The same pull request turns `## X.Y.Z - Unreleased` in `CHANGELOG.md`
into the released heading, the bare `## X.Y.Z`.

A pull request that changes behaviour a host can see adds its line to
`CHANGELOG.md` under the unreleased version (opening `## X.Y.Z - Unreleased` when
none is open), marked **Breaking** when a public
contract changes.

A tag must sit on a commit of `main` whose CI push run finished green; the
release workflow's `verify` job checks both and refuses anything else. If
`verify` failed only because CI was still running, re-run the release workflow
once CI is green. Never move or re-create the tag (the tag ruleset forbids
updating and deleting tags) and never bump the version for it.

Both builds (`ci.yml` and `release.yml`) run
`uv build --build-constraint .github/requirements-build.txt --require-hashes`, so the
attested wheel is built by the setuptools pinned there, and a hash that does not match
fails the build. Regenerate the file from the repository root with

```bash
echo "setuptools>=77" | uv pip compile - --generate-hashes --python-version 3.12 --no-annotate --custom-compile-command 'See AGENTS.md "Releasing"' --output-file .github/requirements-build.txt
```

The input floor matches the `[build-system]` floor in `pyproject.toml`. A setuptools
bump is an ordinary Dependabot pull request (`pip` entry, directory `/.github`).

The release carries the wheel, the sdist, `SHA256SUMS` and build-provenance
attestations. Check a downloaded file with
`gh attestation verify <file> -R overnightworks/webauth` and
`sha256sum -c --ignore-missing SHA256SUMS`.
