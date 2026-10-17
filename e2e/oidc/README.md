# Real-browser proof of the OIDC relying party

`prove.py` drives a real Chromium through a real login and logout at a real
Keycloak (edge's `hold` stack) against a small host application built from the
library's README example. The OIDC path is not faked: the browser fills
Keycloak's own form, and the library calls the real token and key-set
endpoints with its production transport.

`harness.py` is the run plumbing every driver here shares (runtime directory,
host process, first-signal handling, browser worker, run record, evidence scan).

The proof is run by hand, not in CI: it needs Docker, edge's private checkout and a
Playwright browser, and takes minutes. CI only lints `e2e/`.

## Prerequisites

- Ports 8081 and 8090 free (stop the live edge first) and Docker.
- An edge checkout at the commit in `EDGE_SHA`, with no change in any path its
  probe consumes (`compose.yaml`, `keycloak`, `probe/keycloak`, `traefik.yml`,
  `dynamic`). The script refuses to run otherwise.
- Playwright's Chromium for the pinned version (`uv run --group e2e playwright
  install chromium` if `~/.cache/ms-playwright` lacks it).

## Run

Read the 1-minute load average first; above 18 on a 12-core machine, wait.

    flock -o /tmp/probe-stack.lock timeout --kill-after=240 900 \
        uv run --extra dev --group e2e python e2e/oidc/prove.py \
        --edge ~/git/edge --scratch EMPTY_DIR

Stopping it: send SIGTERM to `timeout` or to the `prove.py` python process.
`timeout` runs in its own process group (no `--foreground`, so that its limit
reaches every descendant), hence Ctrl-C in the terminal reaches only `flock`
and does not stop the run. The first SIGTERM or SIGINT ends the run with
`FAILED: interrupted` and exit status 1 after an uninterruptible cleanup (host
app, stack, `runtime/`, evidence scan); further signals are ignored. `--kill-after=240`
exceeds the cleanup's worst case: browser worker 15 s, host SIGTERM 15 s, host
SIGKILL 15 s, stack 180 s, together 225 s.

If the run is killed with SIGKILL anyway (the `timeout` fallback, `kill -9`, an
out-of-memory kill), nothing can clean up. By hand: `rm -rf SCRATCH/runtime`
(it holds credentials and keys); remove the stack with edge's README procedure
(`docker ps -a --filter name=edge-kc-probe`); `pkill -f e2e/oidc/host_app.py`
if a listener on a random port remains (the host app dies with its parent,
so this is rarely needed). Do not trust `evidence/` of such a run, nor of a
run that prints `the browser worker did not stop`: its screenshots are deleted
and nothing is scanned, because a live browser could still write.

`--scratch` must be empty. Afterwards it holds `evidence/` only: screenshots,
`network.har` and `result-table.txt`. `runtime/` (credentials, keys, the stack's
scratch) is deleted on every exit path.

## How the browser reaches the stack

The browser keeps the canonical URLs (`https://auth.hallucinai.de`,
`https://demo.hallucinai.de`, port 443); only the connection is redirected.

- `--host-resolver-rules="MAP name 127.0.0.1:port"` sends each name to a TLS
  shim (for Keycloak) or to the host app. The shim forwards to Traefik on
  8081 with `Host: auth.hallucinai.de` and `X-Forwarded-Proto: https`, as
  Cloudflare's tunnel does.
- Trust is per browser process: `--ignore-certificate-errors-spki-list` names
  the hash of the throwaway leaf's public key. Nothing is installed in any
  profile or store. A certificate with another key, signed by a CA nobody
  trusts, is refused (`CHECK untrusted-certificate`).
- The host app process trusts the throwaway CA through `SSL_CERT_FILE`, for its
  own calls to the token and key-set endpoints.

## Evidence rules

The network log is built from allowlisted fields (URL without query values,
header and cookie names, a few harmless header values, cookie attributes), never
redacted from a raw capture. Every credential the run creates or sees is
registered, and `evidence/` is scanned for each in raw, URL-encoded and
form-encoded form before the script ends; a hit deletes the file and fails the
run. Screenshots are taken only at fixed moments of a scenario: the start page,
Keycloak's form with the password filled (or Keycloak's refusal, where Keycloak
clears the field), the result page, the second sign-in of scenario 2, and, in
scenario 5, only the first page, named after the origin and the `cookie_samesite`. A pending-login cookie's name carries a
digest of the login's state; the log keeps `__Host-oidc_pending_*`.

## What it proves

`SCENARIO 1` is the login, `SCENARIO 2` the logout. The logout ends the session
in the app, not Keycloak's SSO session: a second "Sign in" re-logs in silently,
and the table says so.

`SCENARIO 4` is the disabled user: Keycloak's form refuses, no callback reaches
the app; enabled again, the same credentials sign in; an account the host
holds as deactivated is refused at the callback with `account-deactivated`.
`SCENARIO 6` asserts by bounding boxes that the forms and pages lie inside the
window. Scenarios 1, 4 and 6 run at 390x844 (mobile emulation, touch) and
1280x800.

`SCENARIO 5` is the session cookie after the callback redirect. One host
process per `cookie_samesite` serves both app origins; each cell uses a fresh
browser context and is measured on the `GET /` that the `/auth/callback`
redirect leads to: the cookie names it carried, its `Sec-Fetch-Site`, and the
page it rendered. A logged-out first page is `FAILED-as-found`: a finding to
file, not a failed run.

## Conformance run

`conformance.py` runs the OpenID Foundation's conformance suite (release
v5.3.3, server and mongo images pinned by digest in `suite-compose.yaml`) as the
issuer of a relying party. It needs Docker and no edge checkout. The suite's own
nginx is not used: its certificate has no subject alternative name, which
webauth's HTTPS client rightly refuses. The driver puts the `TlsShim` with a
throwaway certificate in front of the server's port, which is published on
`127.0.0.1` only (the dev-mode API has no login).

The run creates `oidcc-client-basic-certification-test-plan` with a throwaway
client secret, prints the plan's modules as the suite names them and drives two
of them with the host app (`host_app.py`) as the relying party under test and a
real Chromium following the redirects: `oidcc-client-test` (webauth must accept)
and `oidcc-client-test-nonce-invalid` (webauth must refuse with
`nonce-mismatch`). It then writes the plan export to `SCRATCH/export/`. The
export is a full protocol transcript with the client secret and the suite's
private keys in it: keep it local, never attach it to anything.

The suite's verdict alone proves nothing: a refusing module passes when no
further request arrives, whatever the reason. So every row sets the suite's
status/result beside webauth's own decision, read from the host's `/state`
(`token_rejection`, `logins_admitted`, `userinfo_calls`, `userinfo_answered`, the last
refusal), and beside the decision
expected, which the table in `conformance.py` takes from the library's enums:

    module | suite status/result | webauth decision | expected | held / FAILED / FAILED-as-found

`held` needs both to agree. `FAILED-as-found` (a finding, not a failed run) is
only for one named known finding, and needs all three: the decision is
`id-token-rejected/key-set-unavailable` (built from `OidcRefusalReason` and
`RejectionReason`), the run counted more keys at the host's own `jwks_url` than
`MAX_KEY_SET_KEYS`, and the suite's result is not `FAILED`. Every other row that
is not `held` fails the run, so a wrong `jwks_url`, a missing CA trust or a clock
skew cannot pass as the finding. Once the library fix lands the finding stops
matching by itself.

The access token never leaves the host process except in the one UserInfo request
through the shim: it reaches no `/state`, log, HAR or table, a token no header can
carry is not sent, and a failing UserInfo call is logged by exception type only.
The host runs with the shipped default `cookie_samesite="strict"`; the pending-login
cookie is lax in any case and the app and suite hosts are same-site.

The suite finishes an accepting module only on a UserInfo request, which webauth
never sends. The host therefore keeps the access token of the token answer in
memory and makes one UserInfo request after, and only after, `finish_login`
admitted the login. `/reset` builds the relying parties again, as a host
restarted per module would, because the suite generates new keys per module.

Last run: both rows are `FAILED-as-found` with `id-token-rejected/key-set-unavailable`:
the suite publishes 13 keys (its regular 8 and 5 deliberately unsupported ones, of
which only 2 pass the RS256 check), more than the library's `MAX_KEY_SET_KEYS` of 10,
which is checked before any single key.

Pull the images first, outside the lock:

    SUITE_HOST=conformance.example.test docker compose -f e2e/oidc/suite-compose.yaml pull

Then, with the 1-minute load average at or below 18:

    flock -o /tmp/probe-stack.lock timeout --kill-after=240 900 \
        uv run --extra dev --group e2e python e2e/oidc/conformance.py --scratch EMPTY_DIR

Stopping works as above (SIGTERM to `timeout` or to the python process; exit
status 1). On every exit path the suite project is taken down with its volumes
and the run lists the containers, volumes and networks still carrying its
compose project label. The `down` always runs (60 s) and the three listings are
independent calls (10 s each), so one failure never hides another kind. The
`down` runs a second time only when the first did not complete cleanly
(interrupted, failed or timed out). Worst case: 15 s worker join + 30 s host
stop + 90 s first teardown + 90 s backstop teardown = 225 s, inside `--kill-after=240`.
Every failure or timeout, with its stderr tail, is reported as a leftover line,
and the result table and evidence scan still follow. After a SIGKILL nothing can clean up: find the project
with `docker ps -a --filter name=d2-suite`, then `docker compose -p NAME -f
e2e/oidc/suite-compose.yaml down -v --remove-orphans` (with `SUITE_HOST` set to
anything), and `rm -rf SCRATCH/runtime`.

The pins are not watched by Dependabot; their freshness is owned by issue #110.

## Last run: session cookie after the redirect

| App origin | `cookie_samesite` | First page | Session cookie sent | `Sec-Fetch-Site` |
|---|---|---|---|---|
| `https://demo.hallucinai.de` (same site as Keycloak) | strict | Signed in | yes | same-site |
| `https://demo.example.test` (cross site) | strict | Signed out (`FAILED-as-found`) | no | cross-site |
| `https://demo.hallucinai.de` | lax | Signed in | yes | same-site |
| `https://demo.example.test` | lax | Signed in | yes | cross-site |

The pull request that last changed this directory carries the full result table.
