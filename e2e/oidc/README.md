# Real-browser proof of the OIDC relying party

`prove.py` drives a real Chromium through a real login and logout at a real
Keycloak (edge's `hold` stack) against a small host application built from the
library's README example. The OIDC path is not faked: the browser fills
Keycloak's own form, and the library calls the real token and key-set
endpoints with its production transport.

It is run by hand, not in CI: it needs Docker, edge's private checkout and a
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
clears the field), and the result page. A pending-login cookie's name carries a
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

## Last run: session cookie after the redirect

| App origin | `cookie_samesite` | First page | Session cookie sent | `Sec-Fetch-Site` |
|---|---|---|---|---|
| `https://demo.hallucinai.de` (same site as Keycloak) | strict | Signed in | yes | same-site |
| `https://demo.example.test` (cross site) | strict | Signed out (`FAILED-as-found`) | no | cross-site |
| `https://demo.hallucinai.de` | lax | Signed in | yes | same-site |
| `https://demo.example.test` | lax | Signed in | yes | cross-site |

The pull request that last changed this directory carries the full result table.
