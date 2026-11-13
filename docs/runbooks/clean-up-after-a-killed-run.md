# Runbook: clean up after a killed run
Symptom: a run ended by SIGKILL, by the cap's kill, or by an out-of-memory kill, so no cleanup ran. Impact: `runtime/` (credentials and keys), the held Keycloak, suite and relay containers and host apps may remain.

## Check
- The run directory under `${XDG_STATE_HOME:-~/.local/state}/webauth-e2e-oidc/` still holds `runtime/`.
- `evidence/` of this run is not trusted, nor is that of any run that printed `the browser worker did not stop`: a live browser could still write. Its screenshots are deleted.

## Fix
1. `scripts/run_oidc_proof.sh cleanup`. It takes no argument. Of every run directory under the state root whose recorded driver process no longer lives, it removes `runtime/` without following a symlink, the held Keycloak's project, the suite project, the relay containers and the host apps that still listen. A run that still lives is left alone.
2. Expect exit status 0. The command exits non-zero while anything of a dead run remains; run it again.
3. Run the proof again for a result; never read the killed run's `evidence/`.

Rollback: none needed; `cleanup` only removes objects of runs that no longer live.

## Escalate
- `cleanup` still exits non-zero after two runs: open an issue in overnightworks/webauth with its output.
- A Chromium, Firefox or WebKit of the run still lives after `cleanup` (it does not stop the browser): open an issue in overnightworks/webauth; do not kill browsers by hand.
- A directory other than the state root holds `runtime/`: stop, it is not the harness's.
