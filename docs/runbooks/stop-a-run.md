# Runbook: stop a run
Symptom: a `prove` or `conformance` run must end now (wrong checkout, wrong pin, stuck). Impact: after Ctrl-C the probe lock is free at once, so another proof can start while this run's teardown still goes on; only SIGTERM to `timeout` or to python keeps the lock until the teardown ends.

## Check
- `scripts/run_oidc_proof.sh` prints `run directory: <path>` when a run starts; that run is the one to stop.
- Processes that can outlive the driver, and what ends each:
  - The host app dies with the driver; `cleanup` kills any of this checkout that still listens.
  - Relay containers are docker objects; the driver removes them, `cleanup` removes what remains.
  - The browser runs in a session of its own and ends only when its pipe closes after the Playwright driver dies (not measured here). `cleanup` does not stop it.
  - Playwright's driver and the stack's `hold` process end the same way, when the driver dies (not measured here).

## Fix
1. Press Ctrl-C in the terminal of the run. Expect `FAILED: interrupted` and exit status 1, after the teardown of the host app, the stack, `runtime/` and the result table. Further signals during the teardown are ignored.
2. Without the terminal, send SIGTERM to the `timeout` process or to the driver's python process. The run ends the same way, but `flock` keeps the lock until the teardown ends.
3. Wait for the run to exit before starting another (after Ctrl-C the lock does not hold a new proof back): the teardown takes at most 225 s. If it overruns, nothing stops the driver and it runs on without the lock.
4. Run `scripts/run_oidc_proof.sh cleanup` as in `clean-up-after-a-killed-run.md` when the run printed `the browser worker did not stop`, or when any process listed above remains.

Rollback: none needed; start the run again.

## Escalate
- The driver still runs after 240 s: `clean-up-after-a-killed-run.md`, then open an issue in overnightworks/webauth with the last lines of the run.
- The script printed that `setpriv` could not run (flock status 69): nothing ran; fix the host's `setpriv` before any run.
