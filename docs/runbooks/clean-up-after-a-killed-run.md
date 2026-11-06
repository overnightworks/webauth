# Runbook: clean up after a killed run
Symptom: a run ended by SIGKILL, by the cap's kill, or by an out-of-memory kill, so no cleanup ran. Impact: `runtime/` (credentials and keys), the probe stack, suite and relay containers and host apps may remain.

## Check
- The run directory under `${XDG_STATE_HOME:-~/.local/state}/webauth-e2e-oidc/` still holds `runtime/`.
- `evidence/` of this run is not trusted, nor is that of any run that printed `the browser worker did not stop`: a live browser could still write. Its screenshots are deleted.

## Fix
1. `scripts/run_oidc_proof.sh cleanup`. It takes no argument. It removes `runtime/` of the run directories under the state root without following a symlink, and the probe stack, the suite project, the relay containers and the host apps that still listen.
2. Expect exit status 0. The command exits non-zero while anything of the probe remains; run it again.
3. `cleanup` does not stop the browser. If a Chromium, Firefox or WebKit of the run still lives after a minute, end it by hand.
4. Run the proof again for a result; never read the killed run's `evidence/`.

Rollback: none needed; `cleanup` only removes probe objects.

## Escalate
- `cleanup` still exits non-zero after two runs: open an issue in overnightworks/webauth with its output.
- A directory other than the state root holds `runtime/`: stop, it is not the harness's.
