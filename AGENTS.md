# Repository agent guidance

`webauth` is OpenID Connect login for FastAPI applications, with sessions,
CSRF and rate limits: sessions the store decides on every request, HMAC-signed
cookies, CSRF double-submit, admin checks, per-address rate limits, audit
ports. Distribution `overnightworks-webauth`, import package `webauth`, Python
3.12+, managed with uv. It was extracted, with its history, from
[overnightworks/songmaker](https://github.com/overnightworks/songmaker)
(issue #825), and songmaker installs the wheel from this repository's tagged
release.

`webauth` is a library, not an application: it is installed by host
applications and has no deployment of its own. Every change here is a change
to a public contract that a tag has already frozen somewhere else.

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
  Starlette and anyio, which `src` imports), Pydantic and the OpenID Connect
  stack below at runtime, and on nothing else; `deptry src` proves in CI that `src` imports
  nothing undeclared. Redis is optional — install
  `overnightworks-webauth[redis]` for the Redis rate-limit backend; a single-node
  host that supplies the in-process rate-limit backend needs no Redis at all.
  JWT verification and OpenID Connect login are part of the plain install:
  PyJWT and cryptography, which only `webauth.jwt_verification` imports, and
  urllib3, which only `webauth.https_client` imports — the one owner of
  outbound HTTPS — are core dependencies. Only
  `webauth.oidc` imports `webauth.jwt_verification`; only
  `webauth.jwt_verification`, `webauth.oidc` and `webauth.oidc_transport`
  import `webauth.https_client`. Four `protected` import-linter contracts
  enforce this. A fifth confines `redis` to `webauth.rate_limit`, and
  `tests/test_public_api.py` imports every module with `redis` blocked, so the
  in-process backend never needs the extra.
- The user model, schema, configured role names, transaction boundaries and
  HTTP routes belong to the host. The library writes no response except its
  own refusals and the 500 of an unhandled exception; README.md lists them
  under "What it owns, and what it leaves to the host".
- A name is private when it, or a module on its path, starts with `_`. Tests
  and e2e take public names, or the functions and classes a module defines,
  never its private values or the names it only imports, because a value is
  pinned while a function is a unit under test. `tests/test_public_api.py`
  enforces it.

## Code patterns

- Ports are Protocols, and none of them commits. A new host obligation is a
  Protocol in `webauth.ports`, never a concrete class and never a query.
- Deployment facts come from `WebAuthConfig`. Nothing reads an environment
  variable or a global; the host installs one config on the app and every
  module reads it from there.
- No inline comments; a comment explains only a non-obvious why.
- Tests name the behaviour they pin and use the builders in
  `tests/webauth_arrangement.py` and `tests/oidc_arrangement.py` rather than a
  second set of fakes.

## Checks

```bash
uv sync --group dev
uv run pytest tests -q
uv run ruff check src tests e2e
uv run lint-imports
uv run --locked deptry src
uv run --group e2e pyright
tests/typing/check_against_wheel.sh
```

`tests/typing/` holds the static typing hosts. The script type-checks them with
the pinned pyright against the built wheel, from a directory without `src`, so
a port change or an export a host cannot import fails here.

CI runs these in the `checks` job and re-runs the suite at the lowest declared
versions in `lowest-direct`. The shared quality gate
(`overnightworks/quality`, pinned by SHA in `ci.yml`) is the `quality` job; it
needs `checks` and `lowest-direct`, and lists both as mandatory in
`quality/config.toml`. The quality gate's required check is `quality / verdict`;
allowances for known secret false positives live only in `quality/config.toml`.

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
