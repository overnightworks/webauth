# Repository agent guidance

webauth is a library with no deployment of its own; hosts install the tagged wheel. `tests/e2e/` is a hand-run proof harness
(driven through `scripts/run_oidc_proof.sh`, described in `tests/e2e/oidc/README.md`); CI only lints it.

## Boundaries

- Durable state reaches the library only through the Protocols in `webauth.ports`, which the host implements. What the host
  owns and what the library owns is the Building Blocks section of `docs/ARCHITECTURE.md`.
- A host without the `redis` extra must still import everything; `tests/test_webauth_public_api.py` proves it. `lint-imports` and
  `deptry src` enforce the confinement in `.importlinter` and `pyproject.toml`, and run in `scripts/run_static_checks.sh`.
- A name is private when it, or a module on its path, starts with `_`. Tests take public names, or the functions and
  classes a module defines, never its private values or the names it only imports; `tests/test_webauth_public_api.py` enforces it.

## Code patterns

- Ports are Protocols, and none of them commits. A new host obligation is a Protocol in `webauth.ports`.
- Deployment facts come from `WebAuthConfig`. Nothing reads an environment variable or a global.
- Tests use the builders in `tests/support/webauth_arrangement.py`, `tests/support/oidc_arrangement.py` and `tests/support/gate_arrangement.py`, not a second set of fakes.

## Checks

`scripts/run_static_checks.sh` runs every static check CI's `checks` job runs, from any directory, and stops at the first failure.
`tests/fixtures/typing_hosts/` holds the static typing hosts; the script type-checks them with the pinned pyright against the built wheel,
from a directory without `src`, so a port change or an export a host cannot import fails there. The required check is
`quality / verdict`; allowances for known secret false positives live only in `quality/config.toml`.

## Releasing

- A tag is never moved: a broken release gets the next patch tag. The tag ruleset forbids updating and deleting tags.
- `webauth.__version__` alone is raised, in the pull request that precedes the tag, and stays a plain string literal:
  setuptools reads it without importing the package, whose dependencies the isolated build lacks. The same pull request turns
  `## X.Y.Z - Unreleased` in `docs/CHANGELOG.md` into `## X.Y.Z - YYYY-MM-DD`, the date it expects to tag on.
- A pull request that changes behaviour a host can see adds its line to `docs/CHANGELOG.md` under `## X.Y.Z - Unreleased` (open it
  when none is open), marked **Breaking** when a public contract changes.
- If the release workflow's `verify` job failed only because CI was still running, re-run it once CI is green. Never
  re-create the tag, and never bump the version for it.
- The setuptools floor lives in `[build-system]` of `pyproject.toml`; after changing it run
  `scripts/regenerate_build_constraints.sh`. A setuptools bump is an ordinary Dependabot pull request (`pip`, `/.github`).
- `scripts/verify_release.sh TAG` checks a release's checksums and attestations.
