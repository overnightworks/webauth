# Real-browser proof of the OIDC relying party

`prove.py` drives a real Chromium through a real login and logout at a real
Keycloak (edge's `hold` stack) against a small host application built from the
library's README example. The OIDC path is not faked: the browser fills
Keycloak's own form, and the library calls the real token and key-set
endpoints with its production transport.

`harness.py` is the run plumbing every driver here shares (runtime directory,
host process, first-signal handling, browser worker, run record, evidence scan). It
also owns the pinned Chromium (`launch_pinned_chromium`: each name mapped to a loopback
port, one leaf certificate trusted by its public-key hash) and the recording context
(`recording_context`: requests logged field by field, URL credentials and cookie values
registered).

The proof is run by hand, not in CI: it needs Docker, edge's private checkout and a
Playwright browser, and takes minutes. CI only lints `e2e/`.

## Prerequisites

- Ports 8081 and 8090 free (stop the live edge first) and Docker.
- An edge checkout at the commit in `EDGE_SHA`, with no change in any path its
  probe consumes (`compose.yaml`, `keycloak`, `probe/keycloak`, `traefik.yml`,
  `dynamic`). The script refuses to run otherwise.
- Playwright's Chromium for the pinned version (`uv run --group e2e playwright
  install chromium` if `~/.cache/ms-playwright` lacks it).
- The relay image of the back-channel phase, `RELAY_IMAGE` in `shim.py` (a pinned
  `python:3.12-slim`); Docker pulls it on first use, so pull it first, outside the lock.

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

## How Keycloak reaches the apps

Keycloak's back-channel logout is a request from its container to the app, and the
apps bind loopback, which the browser's host mapping reaches but a container does not.
The machine's firewall also drops a container's TCP to the host, including the
`keycloak` network's gateway on every port (measured with a listener bound to the
gateway and a container on a network of the same shape), so a listener on the host
would never be called. `CallbackBridge` (`shim.py`) therefore puts a relay
container on the stack's `keycloak` network (`stack.py` finds it by the compose
labels and fails on an absent or ambiguous one): it listens on the container
network and passes the bytes to a unix socket in a private directory, where the host
side accepts exactly `POST /auth/backchannel-logout`, at most 32 KiB, and forwards
it to the app's loopback HTTPS endpoint, verifying the throwaway CA. Anything else
(`/state`, `/reset`, `/deactivate`, another path or method) is answered 404 and
reaches nothing. Every answer carries `Connection: close`: Keycloak's HTTP client keeps
connections in a pool and does not retry a POST on one the bridge already closed. Every wait is bounded (10 s), no body or header is logged, and the
relay holds no secret (read-only, no capabilities, the caller's user id). The bridge
is shut down, its container removed, before the held stack is released, and
`edge-kc-probe` leftovers are listed at the end. The container's name stands in for
production's internal DNS name of the app: it shows that the route works behind an
internal name, not that production's name resolves.

## Evidence rules

The network log is built from allowlisted fields (URL without query values,
header and cookie names, a few harmless header values, cookie attributes), never
redacted from a raw capture. Every credential the run creates or sees is
registered, and `evidence/` is scanned for each in raw, URL-encoded and
form-encoded form before the script ends; a hit deletes the file and fails the
run. Screenshots are taken only at fixed moments of a scenario: the start page,
Keycloak's form with the password filled (or Keycloak's refusal, where Keycloak
clears the field), the result page (the refusal page in scenario 7), Keycloak's logout confirmation and the second sign-in of scenarios 2 and 9, in
scenarios 10 to 13 also the other context's or app's result page, and, in
scenario 5, only the first page, named after the origin and the `cookie_samesite`. A pending-login cookie's name carries a
digest of the login's state; the log keeps `__Host-oidc_pending_*`.

## What it proves

`SCENARIO 1` is the login (the plain member `d1-user` gets 403 from `/admin`),
`SCENARIO 2` the logout, at both widths: the host's `#logout` is a plain form
POST that the origin check admits without a CSRF token; the browser reaches
Keycloak's logout confirmation (`#kc-logout`), where the host already holds 0
sessions and the browser no app cookie; after confirming, the app shows "Signed
out", and a second "Sign in" shows Keycloak's form again (a silent sign-in is a
failure). `SCENARIO 9` (1280x800) ends the app session in the host while the
page still shows the button: the logout still reaches Keycloak's confirmation
and the next sign-in shows Keycloak's form.

`SCENARIO 4` is the disabled user: Keycloak's form refuses, no callback reaches
the app; enabled again, the same credentials sign in; an account the host
holds as deactivated is refused at the callback with `account-deactivated`.
`SCENARIO 6` asserts by bounding boxes that the forms and pages lie inside the
window. `SCENARIO 7` is the outsider: `d1-outsider` is in no group, signs in at
Keycloak, reaches the callback and sees "Sign-in refused" with `not-a-member`;
the host holds 0 accounts and 0 sessions and the browser carries no session
cookie. `SCENARIO 8` is `d1-admin`, a member of `/apps/songmaker/admin` only
(the subgroup the run creates, since the pinned realm has none): it is
admitted, `/admin` answers 200 (the host's `admin_group` is that subgroup),
and the host holds 1 account. `CHECK outsider-groups-claim` records,
as a count only, whether Keycloak sends the outsider a `groups` claim at all;
Keycloak leaves the claim out for a person in no group (claim absent).
Scenarios 1, 2, 4, 6 and 7 run at 390x844 (mobile emulation, touch) and 1280x800;
scenarios 8 and 9 run at 1280x800. The host's `login_group` is `/apps/songmaker` and its `admin_group`
`/apps/songmaker/admin`; `conformance.py` states the value of
`EverySubject.OF_THE_BOUND_ISSUER` and of `NoAdmins.IN_THIS_APP`, because the OIDF
suite's tokens carry no `groups` claim. The demotion of a person taken out of the
admin group is proven at the `finish_login` layer, not here: a D1 step would need
an `Admin.delete` in `stack.py`. The run stays inside its 900 s budget.

`SCENARIO 10` to `13` are the back-channel phase, each at 390x844 and 1280x800. They
run against two further hosts, app A on `https://demo.hallucinai.de` and app B on
`https://demo.example.test` (cookie `lax`), each configured independently: its own
Keycloak client (`d1-app-a`, `d1-app-b`), its own session and account stores and its
own signing secret, and each with the README's `/auth/backchannel-logout` route (the
body-size, cache-control and CSRF exemptions the route recipe lists; no rate limit in
this host). Each client carries `frontchannelLogout: false`, `backchannel.logout.url`
(its bridge), `backchannel.logout.session.required: "false"`,
`backchannel.logout.revoke.offline.tokens: "false"`, `id.token.signed.response.alg:
"RS256"` and its `post.logout.redirect.uris`. The `d1-host` client of the scenarios
above has no callback URL, so they are unchanged. The host counts accepted and refused
callbacks beside its sessions, and no scenario calls `/reset` between its sign-in and
its assertions. The evidence is counts, response outcomes and screenshots, never a Logout
Token.

- `SCENARIO 10`, subject-wide: two contexts sign in to app A as the same person. One
  logs out through the host's button and Keycloak's confirmation; at the confirmation
  the host still holds the other session and no callback. Then Keycloak's callback is
  accepted once, the host holds 0 sessions, and the other context's next `/me` is 401
  and its reloaded page says "Signed out".
- `SCENARIO 11`, cross-app: one context signs in to A and B, a second context to B
  (2 sessions). A logout in A calls B back, and both B sessions end.
- `SCENARIO 12`, admin logout: `POST /admin/realms/hallucinai/users/{id}/logout`
  answers 204; both apps are called back and answer `/me` with 401.
- `SCENARIO 13`, disable, then logout: a person signs in to A and B and the account is
  disabled; that alone ends nothing in either app. The person's own logout in A never
  reaches Keycloak's confirmation (it sends the browser straight back) and calls no
  app back: B still holds its session. Keycloak's admin logout
  then calls both apps back and ends every session, and a fresh sign in is refused at
  Keycloak's form. So the logout that ends a disabled account's sessions is the admin
  one: `edge lock` must send it after the disable (#49).

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
client secret, prints the plan's 14 modules as the suite names them (a count other than
14 fails the run), and drives every module the expectation table in `conformance.py`
does not skip with the host app (`host_app.py`) as the relying party under test and a
real Chromium following the redirects. A module without a table row, or a row without a
module, fails the run. It then writes the plan export to `SCRATCH/export/`. The
export is a full protocol transcript with the client secret and the suite's
private keys in it: keep it local, never attach it to anything.

The suite's verdict alone proves nothing: a refusing module passes when no
further request arrives, whatever the reason. So every row sets the suite's
status/result beside webauth's own decision, read from the host's `/state`
(`token_rejection`, `logins_admitted`, `userinfo_calls`, `userinfo_answered`,
`access_tokens_refused`, the last refusal), and beside the decision expected, which the
table takes from the library's enums:

    module | suite status/result | webauth decision | expected | verdict | why

`held` needs the decision and the suite state to agree with the table: an accepting
module is admitted with UserInfo answered, and every module ends in the suite state
its row names (FINISHED/PASSED, or FINISHED/SKIPPED for sig-none). `skipped` is a justified row that is not driven. `FAILED-as-found` (a
finding, not a failed run) is only for a named known finding on its own module, and needs
all three: the decision equals the finding's signature, the key set at the host's
`jwks_url` holds the finding's number of keys that webauth's own RS256 check admits, and the suite is in the state
the finding predicts (WAITING with no result for an accepting module, since the UserInfo
request never comes). Every other row that is not `held` fails the run, so a wrong
`jwks_url`, a missing CA trust or a clock skew cannot pass as the finding.

The access token never leaves the host process except in the one UserInfo request
through the shim: it reaches no `/state`, log, HAR or table, a token no header can
carry is not sent (and counted as refused), and a failing UserInfo call is logged by
exception type only. The registry holds the client secret raw and in its
`client_secret_basic` form (base64 of `client_id:secret`), so the scan finds either in
the Authorization header. The host runs with the shipped default
`cookie_samesite="strict"`; the pending-login cookie is lax in any case and the app and
suite hosts are same-site.

The suite finishes an accepting module only on a UserInfo request, which webauth
never sends. The host therefore keeps the access token of the token answer in
memory and makes one UserInfo request after, and only after, `finish_login`
admitted the login. `/reset` builds the relying parties again, as a host
restarted per module would, because the suite generates new keys per module.

Each expectation is built from the module's class in the suite's sources
(`net/openid/conformance/openid/client` at release-v5.3.3), named in its justification.

### Last run: the whole Basic plan

Verdict: every applicable module is held, and the one skip is justified. 13 modules
driven and held, 1 skipped, no known finding, exit status 0, evidence scan clean:

| Module | Suite | webauth decision | Verdict |
|---|---|---|---|
| `oidcc-client-test` | FINISHED/PASSED | admitted, UserInfo answered | held |
| `oidcc-client-test-invalid-iss` | FINISHED/PASSED | `id-token-rejected/invalid-issuer` | held |
| `oidcc-client-test-missing-sub` | FINISHED/PASSED | `invalid-identity-claim` | held |
| `oidcc-client-test-invalid-aud` | FINISHED/PASSED | `id-token-rejected/invalid-audience` | held |
| `oidcc-client-test-missing-iat` | FINISHED/PASSED | `id-token-rejected/invalid-claim` | held |
| `oidcc-client-test-kid-absent-single-jwks` | FINISHED/PASSED | admitted, UserInfo answered | held |
| `oidcc-client-test-kid-absent-multiple-jwks` | FINISHED/PASSED | `id-token-rejected/invalid-key-id` | held |
| `oidcc-client-test-idtoken-sig-rs256` | FINISHED/PASSED | admitted, UserInfo answered | held |
| `oidcc-client-test-idtoken-sig-none` | FINISHED/SKIPPED | `id-token-rejected/unsupported-algorithm` | held |
| `oidcc-client-test-invalid-sig-rs256` | FINISHED/PASSED | `id-token-rejected/invalid-signature` | held |
| `oidcc-client-test-userinfo-invalid-sub` | not driven | not driven | skipped |
| `oidcc-client-test-nonce-invalid` | FINISHED/PASSED | `nonce-mismatch` | held |
| `oidcc-client-test-scope-userinfo-claims` | FINISHED/PASSED | admitted, UserInfo answered | held |
| `oidcc-client-test-client-secret-basic` | FINISHED/PASSED | admitted, UserInfo answered | held |

Skip:
- `oidcc-client-test-userinfo-invalid-sub`: webauth takes identity only from the verified
  ID token and never reads a UserInfo answer, so there is no sub to compare.

`oidcc-client-test-kid-absent-single-jwks` signs without a `kid` from a key set whose only
RS256-eligible key has none either (6 keys); webauth admits it and UserInfo answers (#160).
`oidcc-client-test-kid-absent-multiple-jwks` offers three kid-less eligible keys: they are
admitted to the set but unreachable, so webauth refuses with `invalid-key-id`.
`oidcc-client-test-idtoken-sig-none` is driven: webauth refuses alg none with
`id-token-rejected/unsupported-algorithm` and the suite ends the module FINISHED/SKIPPED
after its timeout. No known finding is left; the mechanism stays for the next one.

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

The pins are not watched by Dependabot; their freshness is owned by issue #74.

## Last run: session cookie after the redirect

| App origin | `cookie_samesite` | First page | Session cookie sent | `Sec-Fetch-Site` |
|---|---|---|---|---|
| `https://demo.hallucinai.de` (same site as Keycloak) | strict | Signed in | yes | same-site |
| `https://demo.example.test` (cross site) | strict | Signed out (`FAILED-as-found`) | no | cross-site |
| `https://demo.hallucinai.de` | lax | Signed in | yes | same-site |
| `https://demo.example.test` | lax | Signed in | yes | cross-site |

The pull request that last changed this directory carries the full result table.
