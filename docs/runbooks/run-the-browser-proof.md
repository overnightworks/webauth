# Runbook: run the browser proof
Purpose: prove login and logout of a webauth host in a real browser against the platform's Keycloak. Run by hand, never in CI; it takes a few minutes. Impact: none on a live platform; the hold has its own compose project and picks free ports, so two runs may share a machine.

## Check
Prerequisites for `prove` and `conformance`:
- Docker is running.
- A platform checkout sits at the commit in `tests/e2e/oidc/platform_sha.txt`, with no change. The run refuses otherwise. `mise` and `probe-run` are on the `PATH`; the run starts the platform's `scripts/keycloak_hold.sh` through `mise exec`.
- Playwright's Chromium, Firefox and WebKit, the relay image and the conformance suite's images are installed. WebKit's system libraries are installed by hand; `prepare` cannot install them.
- The 1-minute load average is at most 1.5 times the cores; `probe-run` waits for it and starts nothing if it stays above for an hour.

## Fix
1. `scripts/run_oidc_proof.sh prepare` installs the browsers and pulls the images. It runs no probe stack; run it first. Expect exit status 0.
2. `scripts/run_oidc_proof.sh prove --platform DIR`, with the platform checkout as `DIR`. It makes its own run directory under `${XDG_STATE_HOME:-~/.local/state}/webauth-e2e-oidc/` and prints `run directory: <path>`; never name that directory yourself.
3. Read the result table the run prints. Every scenario and check is `held`. A measurement that comes out unfavourably prints `FAILED-as-found` and leaves exit status 0: file each such row as a finding. The docstring of `tests/e2e/oidc/prove.py` says which scenarios report it.
4. Expect exit status 0. The run directory then holds `evidence/` only (screenshots and `result-table.txt`); `runtime/` is gone.

Rollback: none needed. A failed or interrupted run ends through its own cleanup; see `stop-a-run.md`.

## Escalate
- A row other than `held` and `FAILED-as-found`, or a non-zero exit, after a second run: open an issue in overnightworks/webauth with the result table.
- The run printed `the browser worker did not stop`: follow `clean-up-after-a-killed-run.md`.
