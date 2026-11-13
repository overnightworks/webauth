# Runbook: refresh the e2e pins
Purpose: bump a pin of the proof harness safely. Impact: a bump can break what only a real browser, a real Keycloak or the OIDF suite shows, and CI does not run those.

## Check
Pins Dependabot does not own:
- the `==` pins of `playwright` and `uvicorn` in the `e2e` dependency group (Dependabot ignores them);
- `RELAY_IMAGE` in `tests/e2e/oidc/shim.py` and the two images in `tests/e2e/oidc/suite-compose.yaml` (no docker ecosystem watches them);
- `tests/e2e/oidc/platform_sha.txt`, the platform commit whose `scripts/keycloak_hold.sh` and realm the proof runs against, set by hand.

## Fix
1. Change the pin.
2. `scripts/run_oidc_proof.sh prepare` when a browser or image changed. Expect exit status 0.
3. `scripts/run_oidc_proof.sh prove --platform DIR`, then `scripts/run_oidc_proof.sh conformance`, as in `run-the-browser-proof.md` and `run-the-conformance-suite.md`. Expect exit status 0 from both.
4. Land the bump only when both exit 0. The pull request carries both result tables, without the conformance `export/` directory.

Rollback: revert the pin and run `prepare` again.

## Escalate
- A run fails only with the new pin: keep the old pin and open an issue in overnightworks/webauth with the result table and the pin's release notes.
