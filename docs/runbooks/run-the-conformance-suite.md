# Runbook: run the conformance suite
Purpose: run the OpenID Foundation's conformance suite against the same host app as the browser proof. Run by hand, never in CI.

## Check
The prerequisites of `run-the-browser-proof.md` hold, with one difference: no hal checkout is needed. The suite's images come from `prepare`.

## Fix
1. `scripts/run_oidc_proof.sh prepare` as in `run-the-browser-proof.md`. Expect exit status 0.
2. `scripts/run_oidc_proof.sh conformance`. It takes no argument, takes the same lock and load check as `prove`, and prints `run directory: <path>` (named `conformance-`).
3. Read the result table: every module is `held` or `skipped`. A skipped row carries its justification in the expectation table in `tests/e2e/oidc/conformance.py`. Every failure or timeout is a leftover line with its stderr tail, and the table still follows.
4. Expect exit status 0.
5. Keep the plan export in the run directory's `export/` local. It holds the client secret and the suite's private keys: never attach it to an issue, a pull request or a chat.

Rollback: none needed.

## Escalate
- A module that fails twice with the same stderr tail: open an issue in overnightworks/webauth with the result table, without the `export/` directory.
- The run was killed or printed `the browser worker did not stop`: `evidence/` is not trusted; follow `clean-up-after-a-killed-run.md`.
