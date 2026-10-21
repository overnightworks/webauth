# Real-browser proof of the OIDC relying party

`prove.py` drives a real Chromium through a real login and logout at a real
Keycloak (edge's `hold` stack) against a small host application built from the
library's README example. The OIDC path is not faked: the browser fills
Keycloak's own form, and the library calls the real token and key-set
endpoints with its production transport.

`harness.py` is the run plumbing every driver here shares (runtime directory,
host process, first-signal handling, browser worker, run record, result table). It
also owns the pinned Chromium (`launch_pinned_chromium`: each name mapped to a loopback
port, one leaf certificate trusted by its public-key hash) and the browser context
(`browser_context`).

The proof is run by hand, not in CI: it needs Docker, edge's private checkout and a
Playwright browser, and takes a few minutes. CI only lints `e2e/`.

## Prerequisites

- Docker. The probe picks free loopback ports, so the live edge keeps running.
- An edge checkout at the commit in `EDGE_SHA`, with no change in any path its
  probe consumes (`compose.yaml`, `keycloak`, `probe/keycloak`, `src/edge`, `traefik.yml`,
  `dynamic`). The script refuses to run otherwise.
- Playwright's Chromium for the pinned version (`uv run --group e2e playwright
  install chromium` if `~/.cache/ms-playwright` lacks it).
- The relay image of the back-channel phase, `RELAY_IMAGE` in `shim.py` (a pinned
  `python:3.12-slim`); Docker pulls it on first use, so pull it first, outside the lock.

## Run

Read the 1-minute load average first; above 18 on a 12-core machine, wait.

The cap is 900 s (`timeout 900`). The full run, with the refresh phase, measured 128 s at edge `2b125b8`
(21.10.2026, load 3 to 5; 136 s and 153 s on 19.10.2026), so the cap leaves a factor of about 6 of room.

    flock -o /tmp/probe-stack.lock timeout --kill-after=240 900 \
        uv run --group dev --group e2e python e2e/oidc/prove.py \
        --edge ~/git/edge --scratch EMPTY_DIR

Stopping it: send SIGTERM to `timeout` or to the `prove.py` python process.
`timeout` runs in its own process group (no `--foreground`, so that its limit
reaches every descendant), hence Ctrl-C in the terminal reaches only `flock`
and does not stop the run. The first SIGTERM or SIGINT ends the run with
`FAILED: interrupted` and exit status 1 after an uninterruptible cleanup (host
app, stack, `runtime/`, result table); further signals are ignored. `--kill-after=240`
exceeds the cleanup's worst case: browser worker 15 s, host SIGTERM 15 s, host
SIGKILL 15 s, stack 180 s, together 225 s.

If the run is killed with SIGKILL anyway (the `timeout` fallback, `kill -9`, an
out-of-memory kill), nothing can clean up. By hand: `rm -rf SCRATCH/runtime`
(it holds credentials and keys); remove the stack with edge's README procedure
(`docker ps -a --filter name=edge-kc-probe`); `pkill -f e2e/oidc/host_app.py`
if a listener on a random port remains (the host app dies with its parent,
so this is rarely needed). Do not trust `evidence/` of such a run, nor of a
run that prints `the browser worker did not stop`: its screenshots are deleted,
because a live browser could still write.

`--scratch` must be empty. Afterwards it holds `evidence/` only: screenshots
and `result-table.txt`. `runtime/` (credentials, keys, the stack's
scratch) is deleted on every exit path.

## How the browser reaches the stack

The browser keeps the canonical URLs (`https://auth.hallucinai.de`,
`https://demo.hallucinai.de`, port 443); only the connection is redirected.

- `--host-resolver-rules="MAP name 127.0.0.1:port"` sends each name to a TLS
  shim (for Keycloak) or to the host app. The shim forwards to the probe's Traefik
  at the READY line's `edge_url` with `Host: auth.hallucinai.de` and `X-Forwarded-Proto: https`, as
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
(`/state`, `/reset`, another path) is answered 404 (an unknown method 501) and
reaches nothing. Every answer carries `Connection: close`: Keycloak's HTTP client keeps
connections in a pool and does not retry a POST on one the bridge already closed. Every read waits at most 10 s, no body or header is logged, and the
relay holds no secret (read-only, no capabilities, the caller's user id). The bridge
is shut down, its container removed, before the held stack is released, and
`edge-kc-probe` leftovers are listed at the end. The container's name stands in for
production's internal DNS name of the app: it shows that the route works behind an
internal name, not that production's name resolves.

## Screenshots

Screenshots are taken only at fixed moments of a scenario: the start page,
Keycloak's form with the password filled (or Keycloak's refusal, where Keycloak
clears the field), the result page (the refusal page in scenario 7), the second sign-in of scenarios 2 and 9, the app's page after the logout past the ID token's expiry (21), the app's page after each logout (15, 17, 22 and 23), the cross-site page and the app's answer to it in scenario 22, Keycloak's confirmation page in scenario 23, A's page after the disable and before the admin logout in scenario 13, in
scenarios 10 to 13 also the other context's or app's result page, and, in
scenario 5, only the first page, named after the origin and the `cookie_samesite`. A pending-login cookie's name carries a
digest of the login's state; the result table keeps `__Host-oidc_pending_*`.

## What it proves

`SCENARIO 1` is the login (the plain member `d1-user` gets 403 from `/admin`),
`SCENARIO 2` the logout, at both widths: the host's `#logout` is a plain form
POST that the origin check admits without a CSRF token; the browser reaches
Keycloak's end-session request, where the host already holds 0 sessions and the
browser no app cookie; Keycloak answers with a redirect to the app's `/` and
`#kc-logout` never attaches, because the host sent the login's ID token as
`id_token_hint` (the hint cookie, stored for the `/logout` path, is gone afterwards,
read through `cookies([origin, origin + /logout])`); the app shows "Signed out", and a second "Sign in" shows Keycloak's form again (a silent sign-in is a
failure). `SCENARIO 9` (1280x800) ends the app session in the host while the
page still shows the button: the logout shows no page either, and the next sign-in
shows Keycloak's form.

The hint scenarios: `SCENARIO 14` (the cookie is stored
for `Path=/logout`, HttpOnly, Secure, SameSite=Strict, and no request to `/` or `/me`
carries it), `SCENARIO 15` (a second login and logout show no page), `SCENARIO 17` (the
same on the cross-site origin `demo.example.test`). A refused
sign-in (scenario 7) leaves no hint cookie. `SCENARIO 21`
(1280x800) gives app A's client `access.token.lifespan` 15 s through the admin API (the
previous setting is restored afterwards), signs in, reads the `exp` of the hint cookie's ID
token, waits until the clock is 2 s past it and logs out: the end-session request carries
`id_token_hint`, Keycloak still answers with a redirect to the app, no `#kc-logout` page
appears, the app shows "Signed out", and the next sign-in shows Keycloak's form. This is
the production case: Keycloak's ID token lasts 5 minutes by default, the session cookie 12 hours.

`SCENARIO 22` and `SCENARIO 23` run in the back-channel phase at 1280x800, with the two
apps below. They prove two sentences of the README:

- `SCENARIO 22`, a logout from another site: the browser holds a signed-in session at app A
  (`https://demo.hallucinai.de`). A page on `https://demo.example.test`, which the harness
  fulfils in the browser (the hosts' policies would not let a served page post across origins),
  submits a form to A's `/logout`. A answers 403 `Cross-origin request rejected` from the
  origin check; `/` still says signed in, `/me` answers 200, the host holds 1 session and the
  hint cookie is unchanged. The person's own logout then ends the session with no page.
- `SCENARIO 23`, the hint of another Keycloak session: a person signs in to A (hint T1,
  Keycloak session S1), Keycloak's admin logout ends S1 (A's back-channel call ends A's session,
  its hint cookie stays), a sign-in to B in the same browser opens S2, and A's page, still
  showing its button, posts the logout, which sends T1. Keycloak asks "Do you want to log
  out?" (status 200 and `#kc-logout`), as the README says; after confirming, it ends S2 and
  calls B back.

`SCENARIO 4` is the disabled user: Keycloak's form refuses, no callback reaches
the app; enabled again, the same credentials sign in.
`SCENARIO 24` (1280x800) is the deep link: a browser without a session opens
`/albums/42?page=2`, is sent to Keycloak, signs in and lands on
`/albums/42?page=2`, which says "Album 42".
`SCENARIO 6` asserts by bounding boxes that the forms and pages lie inside the
window. `SCENARIO 7` is the outsider: `d1-outsider` is in no group, signs in at
Keycloak, reaches the callback and sees "Sign-in refused" with `not-a-member`;
the host holds 0 accounts and 0 sessions and the browser carries no session
cookie. `SCENARIO 8` is `d1-admin`, a member of `/apps/songmaker/admin` only
(the subgroup the pinned realm declares under `/apps/songmaker`): it is
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
its assertions. The result is counts, response outcomes and screenshots, never a Logout
Token.

- `SCENARIO 10`, subject-wide: two contexts sign in to app A as the same person. One
  logs out through the host's button, with no confirmation page; when the request
  reaches Keycloak the host still holds the other session and no callback. Then Keycloak's callback is
  accepted once, the host holds 0 sessions, and the other context's next `/me` is 401
  and its reloaded page says "Signed out".
- `SCENARIO 11`, cross-app: one context signs in to A and B, a second context to B
  (2 sessions). A logout in A calls B back, and both B sessions end.
- `SCENARIO 12`, admin logout: `POST /admin/realms/hallucinai/users/{id}/logout`
  answers 204; both apps are called back and answer `/me` with 401.
- `SCENARIO 13`, disable, then admin logout (the lock flow): a person signs in to A and
  B and the account is disabled; that alone ends nothing: both apps still hold 1 session
  with 0 callbacks and A's page still says signed in. Keycloak's admin logout (204) then
  calls each app back exactly once, which also shows the disable sent none; each holds
  0 sessions and answers `/me` with 401. A fresh sign in is refused at Keycloak's form.

`SCENARIO 25` to `27` are the refresh phase, on the default host at 1280x800. The host's
`GET /access-token` calls `fresh_access_token` for the request's session and `GET
/workload-token` calls `workload_access_token`; each answers the outcome only, never a token,
and the first adds how many different refresh tokens the session has stored so far.

- `SCENARIO 25`, rotation: after a sign-in two calls both answer `token`, and the host has
  stored a different refresh token after each (Keycloak rotates the string on every refresh).
- `SCENARIO 26`, the issuer ends the person: Keycloak's admin logout of the user's sessions
  (the `d1-host` client has no back-channel URL, so the app session stands) makes the next call
  answer `sign-in-again` while `/me` still answers 200; after the app's own logout, the old
  session cookie replayed makes it answer `session-ended`.
- `SCENARIO 27`, the workload grant: the probe's client is created with
  `serviceAccountsEnabled: false`, so its `client_credentials` request is answered
  `token-request-refused` with `unauthorized_client`. A successful workload token is not proven
  here.

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
through the shim: it reaches no `/state`, log or table, a token no header can
carry is not sent (and counted as refused), and a failing UserInfo call is logged by
exception type only. The host runs with the shipped default
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
driven and held, 1 skipped, no known finding, exit status 0:

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
        uv run --group dev --group e2e python e2e/oidc/conformance.py --scratch EMPTY_DIR

Stopping works as above (SIGTERM to `timeout` or to the python process; exit
status 1). On every exit path the suite project is taken down with its volumes
and the run lists the containers, volumes and networks still carrying its
compose project label. The `down` always runs (60 s) and the three listings are
independent calls (10 s each), so one failure never hides another kind. The
`down` runs a second time only when the first did not complete cleanly
(interrupted, failed or timed out). Worst case: 15 s worker join + 30 s host
stop + 90 s first teardown + 90 s backstop teardown = 225 s, inside `--kill-after=240`.
Every failure or timeout, with its stderr tail, is reported as a leftover line,
and the result table still follows. After a SIGKILL nothing can clean up: find the project
with `docker ps -a --filter name=d2-suite`, then `docker compose -p NAME -f
e2e/oidc/suite-compose.yaml down -v --remove-orphans` (with `SUITE_HOST` set to
anything), and `rm -rf SCRATCH/runtime`.

## Refreshing the pins

Dependabot ignores the `==` pins of `playwright` and `uvicorn` in the `e2e` dependency group, and does not watch the image digests (it has no docker ecosystem here): `RELAY_IMAGE` in `shim.py`, the two images in `suite-compose.yaml`. Only a probe run vouches for them. `EDGE_SHA` is
a hand-set pin as well. A bump of any of them can break what only a real browser, a real
Keycloak or the OIDF suite shows, and CI does not run those.

By hand: bump the pin, then one D1 run (`prove.py`) and one conformance run
(`conformance.py`), each under `/tmp/probe-stack.lock` as above, and land the bump only
when both exit 0. A new image digest is pulled first, outside
the lock.

## Last run: session cookie after the redirect

| App origin | `cookie_samesite` | First page | Session cookie sent | `Sec-Fetch-Site` |
|---|---|---|---|---|
| `https://demo.hallucinai.de` (same site as Keycloak) | strict | Signed in | yes | same-site |
| `https://demo.example.test` (cross site) | strict | Signed out (`FAILED-as-found`) | no | cross-site |
| `https://demo.hallucinai.de` | lax | Signed in | yes | same-site |
| `https://demo.example.test` | lax | Signed in | yes | cross-site |

The pull request that last changed this directory carries the full result table.

## Last run: back-channel logout

Exit status 0, the stack and the relay containers removed. Scenarios
10 to 13 held at 390x844 and at 1280x800, scenarios 14, 15, 17 and 21 to 23 at 1280x800; scenario 5 is
unchanged (`https://demo.example.test` with `strict` stays `FAILED-as-found`).

| Scenario | What a person did | Held |
|---|---|---|
| 10 | two contexts signed in to app A; one logged out through Keycloak | the other session ended through one accepted callback |
| 11 | one context in A and B, a second in B; a logout in A | both B sessions ended through B's callback |
| 12 | Keycloak's admin logout (204) of a person in A and B | both apps called back once, `/me` 401 in each |
| 13 | the account disabled, then Keycloak's admin logout (204) | the disable alone ended nothing; then each app called back exactly once, `/me` 401, and a fresh sign in was refused |
| 21 | the ID token (15 s lifespan) past its `exp` by 2.1 s, then logout | the end-session request carried the hint; a redirect to the app, no confirmation page, "Signed out", Keycloak's form at the next sign-in |
| 22 | a form on `https://demo.example.test` posted to app A's `/logout` | 403 `Cross-origin request rejected`; the session and the hint cookie stood |
| 23 | A's session ended by Keycloak's admin logout, B signed in, then A's logout with the first session's ID token | Keycloak asked to confirm; after confirming B was called back |
