# webauth

## Commands

- `scripts/run_static_checks.sh`: every static check of CI's `checks` job, from any directory; it stops at the first failure.
- `uvx --from "git+https://github.com/overnightworks/quality@<sha>" quality check`, with the sha `.github/workflows/ci.yml` pins: the quality gate's local check.
- `uv run pytest <test module>`: a targeted run of the tests that prove a change.
- `scripts/regenerate_build_constraints.sh`: regenerates `.github/requirements-build.txt` after a change to the setuptools floor in `[build-system]` of `pyproject.toml`.
- `scripts/run_oidc_proof.sh`: the real-browser proofs and the conformance suite in `tests/e2e/oidc/`, run only by hand as `docs/runbooks/` says.

## Rules

- Durable state reaches the library only through a Protocol in `webauth.ports`, which the host implements. A new host obligation is a new Protocol there.
- The library never commits. Durability is the host's: its adapter persists at each store call, or at the exit of a transaction port (`SessionTransaction`, `SignInTransaction`).
- Deployment facts come from `WebAuthConfig`. Nothing reads an environment variable or a global.
- `redis` is imported only under `TYPE_CHECKING`, so a host without the `redis` extra imports every module.
- A name is private when it, or a module on its path, starts with `_`. Tests take public names, or the functions and classes a module defines, never its private values or the names it only imports.
- Tests arrange through the builders in `tests/support/`, never through a second set of fakes.
- An allowance for a known secret false positive lives only in `quality/config.toml`.
- A pull request that changes what a host sees states its **Breaking** line when a public contract changes, and the hosts' migration or "No migration".
- `webauth.__version__` is the one version. It stays a plain string literal and is raised alone, in the pull request before the tag.
- A tag is never moved or re-created; a broken release gets the next patch tag.
- When the release workflow's `verify` job failed only because CI was still running, re-run it once CI is green; never bump the version for it.

## Owners

- The operator rules each release and pushes its tag. The head writes the release page by hand, from the release item that lists every change since the last tag.

## Documents

- `docs/host-contract.md`: read when you change what a host calls, configures or sees.
- `docs/ARCHITECTURE.md`: read when you change what the host or the library owns, or a boundary between modules.
- `docs/VISION.md`: read when you judge whether a capability belongs in webauth.
- `docs/runbooks/`: read when you run, stop or clean up a real-browser proof or the conformance suite, or refresh its pins.
- `README.md`: read when you change how a host installs, pins or wires webauth.
