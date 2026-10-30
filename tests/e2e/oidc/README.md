# How to run the real-browser proof of the OIDC relying party

`prove.py` drives a real Chromium, and `engines.py` also Firefox and WebKit, through a real
login and logout at a real Keycloak (edge's `hold` stack) against a small host
application whose routes are `build_app` in `host_app.py`; `conformance.py` runs the OpenID Foundation's
conformance suite against the same host. The OIDC path is not faked. What each
driver proves, scenario by scenario, is stated in the docstring of `prove.py` and
`conformance.py`; how the browser and Keycloak reach the apps is stated in
`harness.py` and `shim.py`. `bearer.py` is the bearer proof: it plays hal, the machine
caller, against the same Keycloak (scenarios 28 onwards of `prove.py`; scenarios 55 to 60 send
hal's token to the host's person path `/api/me`, where it is the account behind the token); `realm.py` holds the
realm's facts and the admin calls that shape it.

The proof is run by hand, not in CI: it needs Docker, edge's private checkout and a
Playwright browser, and takes a few minutes. CI only lints `tests/e2e/`. Every terminal
step is a verb of `scripts/run_oidc_proof.sh`, which holds the commands, the caps and the lock.

## Prerequisites

- Docker. The probe picks free loopback ports, so the live edge keeps running.
- An edge checkout at the commit in `edge_sha.txt`, with no change in any path its
  probe consumes (`compose.yaml`, `keycloak`, `probe/keycloak`, `src/edge`, `traefik.yml`,
  `dynamic`). The run refuses otherwise.
- Playwright's Chromium, Firefox and WebKit for the pinned version (WebKit needs system
  libraries that `prepare` cannot install), the relay image of the back-channel
  phase (`RELAY_IMAGE` in `shim.py`) and the conformance suite's images. The verb
  `prepare` installs and pulls them; run it first, because it needs no lock.

## Run the browser proof

1. Run the verb `prove --edge DIR` with the edge checkout as `DIR`. The script makes
   the run's directory itself, under `${XDG_STATE_HOME:-~/.local/state}/webauth-e2e-oidc/`
   (named `prove-` and a random suffix), passes it to the driver as `--scratch` and
   prints it when the run starts; a caller never names it. It takes
   `/tmp/probe-stack.lock` (it waits at most 20 minutes for it), refuses to start while the 1-minute load average is above
   1.5 times the cores, and caps the run (the script's comment gives the numbers and
   why).
2. Read the result table the run prints. A scenario or check that is not `held`
   fails the run, with one exception: a measurement that comes out unfavourably is
   reported as `FAILED-as-found` and leaves the exit status 0. File each such row
   as a finding. `prove.py`'s module docstring says which scenarios report it and
   under what condition.

Verify: the exit status is 0; a `FAILED-as-found` row is a finding to file, not a
failed run. The run directory then holds `evidence/` only:
screenshots and `result-table.txt`. It starts empty, and `runtime/` (credentials,
keys, the stack's scratch) is deleted on every exit path.

## Run the conformance suite

Run the verb `conformance`. It takes no argument and runs `conformance.py` in a run
directory made as for `prove` (named `conformance-`), under the same lock, load check
and cap; the suite's images come from `prepare`. It needs no edge checkout. The plan
export in the run directory's `export/` holds the client secret and the suite's
private keys: keep it local, never attach it to anything. A skipped row carries its
justification in the expectation table in `conformance.py`.

Verify: the exit status is 0 and the result table has a `held` or justified `skipped`
row for every module. Every failure or timeout is reported as a leftover line with its
stderr tail, and the result table still follows.

## Stop a run

Send SIGTERM to `timeout` or to the `prove.py` python process. Ctrl-C in the terminal
reaches only `flock` and does not stop the run, because `timeout` runs in its own
process group so that its limit reaches every descendant. The first SIGTERM or SIGINT
ends the run with `FAILED: interrupted` and exit status 1 after an uninterruptible
cleanup (host app, stack, `runtime/`, result table); further signals are ignored.

## Clean up after a killed run

If the run is killed outright (SIGKILL, the `timeout` fallback, an out-of-memory
kill), nothing can clean up. Run the verb `cleanup`, which takes no argument: it
removes `runtime/` (credentials and keys) of the run directories under the state root,
without following a symlink, and the probe stack, the suite project, the relay
containers and the host apps that are still listening. It exits non-zero while anything
of the probe remains. Do not trust `evidence/` of such a run, nor of a run that prints
`the browser worker did not stop`: its screenshots are deleted, because a live browser
could still write.

## Refreshing the pins

Dependabot ignores the `==` pins of `playwright` and `uvicorn` in the `e2e` dependency group, and does not watch the image digests (it has no docker ecosystem here): `RELAY_IMAGE` in `shim.py`, the two images in `suite-compose.yaml`. Only a probe run vouches for them. `edge_sha.txt` is
a hand-set pin as well. A bump of any of them can break what only a real browser, a real
Keycloak or the OIDF suite shows, and CI does not run those.

Bump the pin, run `prepare` for a new image, then one `prove` and one `conformance`
run, and land the bump only when both exit 0. The pull request carries both result tables.
