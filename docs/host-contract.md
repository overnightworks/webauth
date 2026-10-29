# Host contract

For a host developer: what a host sees from webauth and what it must provide.

## Trusted proxies

`WebAuthConfig.trusted_proxies` names the trusted proxy addresses for the host.
It lists the app's direct peer and every proxy whose address the
`X-Forwarded-For` chain carries; listing every proxy between the client and the
app is the simple way to be sure. webauth reads `X-Forwarded-For` and
`X-Forwarded-Proto` and never RFC 7239 `Forwarded`. It reads the chain from the
right and takes the first address it does not trust as the client, so a proxy
whose address the chain carries but which the list lacks becomes the client
address, and every visitor that reaches the app through it shares that address
and its rate-limit budget. With a CDN, a tunnel and a reverse proxy in front of
the app, list whichever of their addresses appear in the chain. The operator's
[edge](https://github.com/overnightworks/edge) project owns that reachability
infrastructure; the changelog's edge references name this project.
`trusted_proxies` decides alone only when the ASGI server does not rewrite the
client address or scheme from those headers, so the host turns the server's own
forwarded-header handling off (uvicorn's `proxy_headers`, on by default:
`proxy_headers=False` or `--no-proxy-headers`).

## What every app gets

Every app that signs people in through Keycloak behaves the same way, unless it
configures `EverySubject` to require no login group or `NoAdmins` to grant no
admin role. The details are in the sections below.

**Who gets in.** Only members of the app's `login_group`, such as
`/apps/notes`, get in. Members of its `admin_group`, such as
`/apps/notes/admin`, are admins. Both are decided again at every login, so a
change in Keycloak takes effect at the person's next sign-in; an app session
that is already open keeps its access until it ends; a changed admin role
reaches every open session at the person's next sign-in. The session's absolute
cap bounds the delay before a login-group removal takes effect. The issuer's
SSO session makes a fresh login a redirect the person does not notice; an
immediate removal requires disabling the user at the issuer together with
[back-channel logout](ARCHITECTURE.md#back-channel-logout). See
[Admitting an identity](ARCHITECTURE.md#admitting-an-identity).

Admission never looks up a username and has no local active-user flag; disabling
people belongs to the issuer ([#279](https://github.com/overnightworks/webauth/issues/279),
operator ruling 19.10.2026). A host store may still reject a new account's name
with `UsernameTakenError`. Store-controlled username uniqueness is proven by
`test_a_store_without_unique_usernames_admits_two_subjects_sharing_one` and
`test_a_username_the_store_refuses_on_create_is_taken_and_nothing_is_written`
in [test_oidc_login_admission.py](../tests/test_oidc_login_admission.py). The absence of a local
active-user policy is visible in `UserRecord` and `SubjectUserStore` in
[ports.py](../src/webauth/ports.py), the admission steps in
[oidc_login.py](../src/webauth/oidc_login.py) and `admit_session` in
[dependencies.py](../src/webauth/dependencies.py).

**When Keycloak is down.** People who are already signed in keep working until
their app session ends, because the app checks a session in its own store and
never asks Keycloak. A new sign-in fails at Keycloak: the app sends the browser
to Keycloak's sign-in page, which does not load, so the person sees the
browser's or the proxy's error page, not the app's. Only when Keycloak fails
during the sign-in, or the browser reaches Keycloak but the app does not, does
the sign-in stop at the app's callback, on the host's refusal page. webauth
offers no local fallback login. See
[The store decides every request](ARCHITECTURE.md#the-store-decides-every-request).

**Machine callers and the person's token.** See [The host's machine routes](#the-hosts-machine-routes)
and [The person's token on the app's API](#the-persons-token-on-the-apps-api).

**Signing out.** Signing out of an app ends its session in that browser at once
and shows a short page that posts to Keycloak, which ends the person's Keycloak session in
that browser without asking anything. Keycloak then tells each app the
person signed in to through that Keycloak session, and each of those apps ends
all of the person's sessions, on every device. An app they used only on another
device is not told and keeps them signed in there. On their other devices, the
next sign-in asks for no password while that device's own Keycloak session
lasts. The logout page is `no-store`, clears the app's cookies and submits itself;
where scripts cannot run, it shows one button. If Keycloak is down, the person
still leaves the app signed out.

The page sends the client ID, `post_logout_redirect_uri` and the stored ID token
as `id_token_hint` by POST to Keycloak's end-session endpoint; no URL carries
the token. Without the session's row
(ended by the host, swept, pruned or ended by back-channel logout), or with a row
that holds no ID token (stored before the host held them or opened with
`keeps_id_token=False`), it sends no hint, and Keycloak asks once to confirm
while its own session lives. If the realm key that signed a supplied token has
been deleted since, Keycloak shows an error page instead. See
[Logging out and the ID token hint](ARCHITECTURE.md#logging-out-and-the-id-token-hint)
for the mechanism and its trust boundaries. The POST page and fallback follow
[#418 R4](https://github.com/overnightworks/webauth/issues/418), operator ruling
22.10.2026; `test_the_logout_page_posts_the_client_and_the_hint_to_the_end_session_endpoint`
and `test_a_same_origin_logout_still_answers_the_page` in
[test_oidc_login_logout.py](../tests/test_oidc_login_logout.py) prove the response shape,
including a missing hint. Browser behavior is driven by `logout` and
`logout_after_the_app_session_ended` in [prove.py](../tests/e2e/oidc/prove.py) and
`logout_through_the_page` in [engines.py](../tests/e2e/oidc/engines.py).
These are hand-run browser proofs, not CI tests; [#420's review journal](https://github.com/overnightworks/webauth/issues/420#issuecomment-6351975830)
records the page implementation's browser evidence.

An old hint cookie is neither read nor cleared and expires by its own `Max-Age`,
at most the absolute session cap after the host's upgrade
([#418 R5](https://github.com/overnightworks/webauth/issues/418), operator ruling
22.10.2026). `test_an_old_cookie_changes_no_decision_and_is_neither_read_nor_cleared`
in [test_oidc_login_logout.py](../tests/test_oidc_login_logout.py) proves it leaves the
response and session outcome unchanged.

## CSRF origin

Every app supplies `csrf_origin=CsrfPolicy(...)` when installing the middleware;
there is no frontend CSRF-token obligation. A state-changing request (POST, PUT,
PATCH or DELETE) needs trustworthy provenance regardless of its body or content
type. `Sec-Fetch-Site: same-origin` passes; `same-site` or an absent Fetch
Metadata header falls back to `Origin`; every other Fetch Metadata value is
refused. Without either header the request is refused, and `Referer` is never
read. These are [#429 S-1, S-3, S-5 and S-6](https://github.com/overnightworks/webauth/issues/429),
operator ruling 23.10.2026. The proofs are
`test_a_request_is_judged_by_sec_fetch_site_then_origin`,
`test_a_state_changing_request_without_provenance_is_refused_whatever_its_body`,
`test_the_referer_is_not_read` and
`test_a_session_request_is_decided_by_its_provenance_whatever_token_material_it_carries`
in [test_csrf.py](../tests/middleware/test_csrf.py), plus
`TestRefusedInstallation.test_an_install_without_csrf_origin_is_refused_before_touching_the_app`
in [test_stack.py](../tests/middleware/test_stack.py).

Only verified bearer admission (on a machine path or a person path) and the sessionless server paths the host names
in `CsrfPolicy.exempt` bypass this check; an adjacent path is still checked
([#429 S-2](https://github.com/overnightworks/webauth/issues/429), operator ruling
23.10.2026). Proofs: `test_a_bearer_request_needs_no_csrf_origin_header_or_cookie`
in [test_bearer_gate_admission.py](../tests/middleware/test_bearer_gate_admission.py) and
`test_protect_everything_checks_every_route_but_the_exempt_ones` in
[test_csrf.py](../tests/middleware/test_csrf.py).

The `Origin` fallback matches exact hosts in `WebAuthConfig.allowed_hosts_exact`,
never host patterns; its docstring owns port matching. With `cookie_secure` on,
the origin must use HTTPS; with it off, the scheme is not compared. This also
holds for WebSocket handshakes, which check `Origin` directly
([#429 S-4 and P-3](https://github.com/overnightworks/webauth/issues/429), operator
ruling 23.10.2026). Proofs: `test_an_origin_that_only_resembles_the_exact_host_is_refused`
in [test_csrf.py](../tests/middleware/test_csrf.py), and
`test_the_origin_scheme_is_compared_only_while_cookie_secure_is_on` in both that
module and [test_dependencies_websocket_auth.py](../tests/test_dependencies_websocket_auth.py).

An old CSRF cookie changes no decision and is neither read nor cleared; it
expires by its own `Max-Age` ([#429 P-2](https://github.com/overnightworks/webauth/issues/429),
operator ruling 23.10.2026). Proofs:
`test_an_old_csrf_cookie_changes_no_decision_signed_in_or_out` in
[test_csrf.py](../tests/middleware/test_csrf.py) and
`test_an_old_cookie_changes_no_decision_and_is_neither_read_nor_cleared` in
[test_oidc_login_logout.py](../tests/test_oidc_login_logout.py).

webauth supports the current releases of Chrome, Edge, Firefox and Safari
(macOS and iOS). On every request whose method is not GET or HEAD, each sends
`Origin`, possibly `null`, and, to an HTTPS app, `Sec-Fetch-Site`
([#429 S-3](https://github.com/overnightworks/webauth/issues/429), operator ruling
23.10.2026).

## Signed out and refused

Every app shows signed-out and refused people the same way. This is the rule
every app follows; [the session gate](ARCHITECTURE.md#the-session-gate) enforces it, and a
host without the gate follows it itself. The page/API split, public paths and
host pages follow [#246](https://github.com/overnightworks/webauth/issues/246),
operator ruling 19.10.2026; [#349](https://github.com/overnightworks/webauth/issues/349)
added the enforcing gate. Its page, API and public-path proofs are
`test_a_page_without_a_session_is_redirected_to_the_start_route_with_next`,
`test_an_api_call_without_a_session_gets_401_authentication_required` and
`test_a_public_path_passes_untouched_and_asks_no_store` in
[test_session_gate.py](../tests/middleware/test_session_gate.py).

- **A page without a session** sends the browser straight to the app's start
  route, with `next` naming the page, so the person lands there after signing
  in. The start route reads `next` as the path to return to, and the callback
  sends the browser to it when it is a same-origin path of the app, otherwise to the
  app root. An API call without a session gets
  401, and the app's UI then navigates to its start route. See
  [The sign-in routes](#the-sign-in-routes)
  and, for the rule the return path must pass,
  [The return path](ARCHITECTURE.md#the-return-path). For a
  server-rendered host, `LoginRedirect` makes the redirect-or-401 split; see
  [Reading the session](ARCHITECTURE.md#reading-the-session).
  Keeping the deep link follows [#281](https://github.com/overnightworks/webauth/issues/281),
  operator ruling 19.10.2026, qualified by
  [#304](https://github.com/overnightworks/webauth/issues/304) on 20.10.2026:
  only request-address construction may prepend `root_path`; the start route
  never prepends it to an explicit `next`. Proofs:
  `test_a_login_returns_only_a_path_of_this_app_and_otherwise_the_app_root`
  in [test_oidc_login_callback.py](../tests/test_oidc_login_callback.py) and
  `test_only_a_path_of_this_app_is_a_return_path` in
  [test_paths.py](../tests/test_paths.py). `deep_link_survives_the_login` in
  [prove.py](../tests/e2e/oidc/prove.py) drives the browser round trip in the hand-run
  harness, not CI.
- **A machine route** (see [The host's machine routes](#the-hosts-machine-routes))
  answers 401 with a `WWW-Authenticate: Bearer realm="admin"` challenge, never a
  redirect, and 403 for a valid token without the admin group:

  | Case | Status | `WWW-Authenticate` | `detail` |
  |---|---|---|---|
  | no credentials | 401 | `Bearer realm="admin"` | `Authentication required` |
  | malformed request (repeated or combined `Authorization`, or `access_token` in the query beside an `Authorization: Bearer`; in the query alone it is no credential) | 401 | `Bearer realm="admin", error="invalid_request"` | `Invalid request` |
  | invalid token (any verification failure, an unavailable key set included) | 401 | `Bearer realm="admin", error="invalid_token"` | `Invalid token` |
  | valid token, not an admin | 403 | `Bearer realm="admin", error="insufficient_scope"` | `Admin access required` |

  A **person path** (see [The person's token on the app's API](#the-persons-token-on-the-apps-api))
  answers a bearer credential as follows; the challenge names `realm="api"` only where
  no credential was sent:

  | Case | Status | `WWW-Authenticate` | `detail` |
  |---|---|---|---|
  | no bearer credential, refused by the library for want of a session (`current_user`, `admin_user`, the session gate, `admitted_admin`) | 401, or the 302 a navigation gets under `login_redirect` | `Bearer realm="api"` on the 401 | the session refusal's own |
  | malformed (as above) | 401 | `Bearer error="invalid_request"` | `Invalid request` |
  | invalid token (any verification failure, a foreign audience and an unavailable key set included) | 401 | `Bearer error="invalid_token"` | `Invalid token` |
  | valid token, not a member of the app | 403 | `Bearer error="insufficient_scope"` | `No access` |
  | valid member token, the store refuses the new username | 403 | none | `Login failed` |
  | token person refused by `admin_user` or `admitted_admin` | 403 | `Bearer error="insufficient_scope"` | `Admin access required` |

  A cookie person refused by an admin reader on a person path keeps the 403 without a
  challenge, and a path outside the person paths keeps its answers. The 401 challenge
  follows RFC 7235 section 3.1 and RFC 6750 section 3; a malformed header answers 401, not
  the 400 RFC 6750 section 3.1 recommends, as the machine paths do. A host's own 401 on a
  person path carries no challenge unless the host adds it.
  `test_a_person_path_refuses_a_malformed_or_invalid_token_with_a_challenge_without_realm`
  and `test_a_person_path_refused_for_want_of_a_session_challenges_with_bearer` in
  [test_bearer_gate_person_paths.py](../tests/middleware/test_bearer_gate_person_paths.py)
  prove the table.

  The machine refusal contract comes from
  [#350](https://github.com/overnightworks/webauth/issues/350), operator ruling
  22.10.2026; [#409](https://github.com/overnightworks/webauth/issues/409)
  supplies the implementation and precise response table.
  `test_a_request_without_a_valid_admin_token_is_refused_with_a_challenge` in
  [test_bearer_gate.py](../tests/middleware/test_bearer_gate.py) proves these responses,
  including 401 when the key set is unavailable.

- **Public paths** are the exception. Each app names its own, and they need
  no session and do not redirect.
- **The page after signing out** is the app's `post_logout_redirect_uri`. It
  never redirects by itself.
- **Which refusal shows which page.** "No access" is for
  `AdmissionRefusal.NOT_A_MEMBER`; "Login failed" is for an `OidcRefusal`
  and for `AdmissionRefusal.FOREIGN_ISSUER` and `USERNAME_TAKEN`, which are
  setup errors, not missing rights. That setup-error page choice is the operator
  ruling of 20.10.2026, recorded in
  [c1318d7](https://github.com/overnightworks/webauth/commit/c1318d768afa16148d680e11b10b4359ebff3012).
  Both types reach the host's `refused` hook inside a `SignInRefusal`, whose `page` is
  this mapping; see
  [The sign-in routes](#the-sign-in-routes).
  `test_a_refusal_shows_no_access_for_a_person_outside_the_app_and_login_failed_otherwise` in
  [test_sign_in_routes.py](../tests/test_sign_in_routes.py) proves it for every cause.
  A refusal carries no identity (`AdmissionRefusal` in
  [oidc_login.py](../src/webauth/oidc_login.py), `OidcRefusal` in
  [oidc.py](../src/webauth/oidc.py)), so the page shows no name. A
  `NOT_A_MEMBER` login stores no session, so signing out from "no access"
  follows the missing-ID-token case in [Signing out](#what-every-app-gets).
  `outsider_is_refused` in [prove.py](../tests/e2e/oidc/prove.py) drives the harness's
  refusal with no account or session; it is a hand-run browser proof, not a
  test of every host's page. Page choice and presentation remain host duties.
- **Look.** The three pages (logged out, no access, login failed), their
  wording and their ways out are the sign-in pattern of
  [ui-style](https://github.com/overnightworks/ui-style) (formerly ui-console); each app takes
  the colours from its own tokens.

## The host's machine routes

hal is the operator's CLI for calling an app's machine routes with a bearer
token. A host declares its machine (admin) paths once, and hal calls them with
the access token Keycloak issued it in `Authorization: Bearer`. `BearerGate` is passed to
`install_web_auth_middleware(bearer_gate=...)`; it holds the paths
(`PathRules`), the app's own `OidcRelyingParty`, the app's `AdmissionConfig` and
`AuthorizedParties`, the `azp` values (hal's client ids) the host admits, read
from configuration. A route reads the admitted caller with
`Depends(bearer_caller)`; `BearerCaller.subject` is the token's `sub`, with no
account and no role. This follows
[#350](https://github.com/overnightworks/webauth/issues/350), operator ruling
22.10.2026, including the accepted defaults for opt-in admission, no session or
cookie, and shared rate limits; [#409](https://github.com/overnightworks/webauth/issues/409)
is its implementation, not a separate ruling.

- **What passes.** Only an RS256 `at+jwt` of the app's issuer whose only
  `aud` is the app's client, whose `azp` is allowed and whose `groups` hold the
  admin group or a group below it. Nothing is created or provisioned, and webauth
  emits no event: the host audits the admitted call itself (subject, route,
  outcome). `test_the_audience_must_be_the_app_alone` and
  `test_an_authorized_party_the_host_did_not_allow_is_refused` in
  [test_oidc_access_token.py](../tests/test_oidc_access_token.py) prove the audience and
  `azp` restrictions; [bearer.py](../tests/e2e/oidc/bearer.py) holds the hand-run
  real-issuer admission proofs.
- **What it replaces.** On a gated path the cookie, the CSRF check and the
  session gate decide nothing, every answer is `no-store`, and webauth sets no
  cookie. `admitted_user` returns `None` and `session_id_from_request` answers
  `None`, whatever cookie the request carries. The same rate
  limit applies where a rate policy covers the path; a flood of invalid tokens
  is bounded only by it. A session dependency (`current_user`, `admin_user`,
  `admitted_admin`) on a machine path raises, so the library answers 500. `test_the_cookie_counts_for_nothing_beside_a_token` in
  [test_bearer_gate_admission.py](../tests/middleware/test_bearer_gate_admission.py) proves admission
  uses the token's subject without opening a session transaction.
- **Token lifetime.** A block at Keycloak reaches the gate only when the token
  expires, plus the leeway; signing out of a browser leaves the token valid
  (#350 sentences 4/5, operator ruling 22.10.2026).
  `test_an_expired_token_is_admitted_until_expiry_plus_leeway` in
  [test_oidc_access_token.py](../tests/test_oidc_access_token.py) proves the expiry boundary.
  `disabled_person_keeps_the_token`, `sign_out_leaves_the_token` and
  `short_token_fails_after_exp_and_leeway` in [bearer.py](../tests/e2e/oidc/bearer.py)
  drive the real-issuer cases in the hand-run harness, not CI.
- **The paths** are written as every other policy's are; the `PathRules`
  docstring says how.
  They must cover every machine route, a prefix being the safe form. Every method
  is gated, `OPTIONS` included; a CORS preflight is the host's own layer outside
  the stack. A path that machine paths and person paths both select is a machine path.
- **Mounts and sockets.** Install the gate on the app that serves the machine
  routes. A sub-app mounted below a gated path keeps its own CSRF and session
  gate, and its `bearer_caller` raises. WebSocket scopes are not gated.

## The person's token on the app's API

A token created through hal can call an app's ordinary API with exactly the rights of the
person behind it, deletion included, and no layer sits on top of the person's rights.
A host names its API paths in `PersonPaths(paths, transaction)` and passes it as
`BearerGate(person_paths=...)`; the gate's `paths` may then be `PathRules()`
(machine paths are optional, and a `NoAdmins` app may name person paths alone). On such a
path `Authorization: Bearer` is the account behind the token: `current_user`, `admin_user`,
`admitted_user` and `admitted_admin` return it as they return the browser's person, and no
host route changes. This follows the operator's rulings of 23.10.2026 (a token carries the
rights of the identity behind it and the app checks it as it checks the browser; ordinary
routes admit tokens issued to the hal registration, the same way in every app) and 29.10.2026
(whoever holds the operator's token may do what the operator may, with no extra security
layer), with the applied lines of
[#405](https://github.com/overnightworks/webauth/issues/405).

- **Which paths.** Only the paths the host names. A path neither rule selects is untouched,
  so a route that takes a foreign secret in `Authorization: Bearer` (a webhook) keeps
  working, and an API route outside `PersonPaths` is not reachable by token. A request with
  no bearer credential (no header, another scheme such as `Basic` or `DPoP`, or
  `access_token` only in the query) is decided by the cookie as on any other path; a bearer
  credential is judged by the token and never falls back to the cookie.
- **The account.** The verified `sub` is admitted by the same `app_role` and the same
  account step as a browser sign-in, in one `SignInTransaction` entry. A person outside the
  app's login group is refused before any store is touched. An unknown subject gets an
  account with the token's `preferred_username` (the subject when it carries none) and
  `USER_CREATED`. A known subject keeps its account, and its role follows the token's
  groups, written and recorded as `ROLE_CHANGED` when it differs, exactly as at sign-in. No
  session is created. Nothing is committed here: durability is the exit of the host's
  transaction, a store, audit or exit failure is the library 500, and no issuer call happens
  inside the block.
- **Clients.** The same `AuthorizedParties` admits tokens on machine and person paths, so a
  token that opens the API also opens the machine routes when its person is an admin.
- **No origin, no cookie.** A verified token request bypasses the CSRF origin check, so a
  CLI needs no `Origin`. A cookie-only request is checked as before.
- **The cookie beside a token.** The token decides and the cookie names no session for that
  request: `session_id_from_request` answers `None` and the session is not renewed. A host
  route that binds work to the session answers its own refusal when it gets `None`. Host
  dependencies such as `current_user`'s `session_store` still resolve before the reader runs.
- **Refusals.** See the person-path table under
  [Signed out and refused](#signed-out-and-refused).
- **Residues.** Signing out in a browser, a back-channel logout, or disabling the person at
  Keycloak does not end a token: it works until its `exp` plus leeway. Group changes reach a
  token request with the next token, at most one token lifetime later, and an older token can
  write the old role back within its lifetime. There is no sender constraint: webauth checks
  no DPoP proof, so a bound token is plain bearer here, and a copied token is the person until
  it expires. The per-address rate limit is shared with the browser's. Every token request
  enters the host's serialized transaction once. A WebSocket handshake is not gated.

Proofs: [test_bearer_gate_person_paths.py](../tests/middleware/test_bearer_gate_person_paths.py)
in CI, and scenarios 55 to 60 of [bearer.py](../tests/e2e/oidc/bearer.py) against real
Keycloak in the hand-run harness.

## The sign-in routes

`install_sign_in_routes` registers the start, callback, logout and back-channel logout routes on the host's
`FastAPI` app over its one `OidcRelyingParty` (read per request), and `SignInPaths`
derives the policies for exactly those paths: `public_rules` for the session gate (`GET` of
start and callback, `POST` of logout and of the back-channel), `browser_paths` for the sign-in
rate budget, `backchannel` for `CsrfPolicy.exempt` and `RateLimitPolicy.exempt`,
`backchannel_body_size_rule` (32 KiB for `POST`), `cache_control_rule` (`no-store`) and `login_redirect`, so the host lists the paths once. It is browser-absolute, so
`login_redirect` is right for an app at its origin's root; a host below a `root_path`
builds its own `LoginRedirect`. The library serves the logout route at `SignInPaths.logout` for `POST` only, with the
button text from the host's `logout_button_label`, read per request; a single-page app logs
out by a top-level form POST to that route, and the host never lists the path in
`CsrfPolicy.exempt`. `paths.logout` and `logout_button_label` come together, or both
are `None` for a host without logout. `webauth.cookies` carries the pending login in a signed cookie of its own, one
per login, so the library keeps no server-side store and `WebAuthConfig` knows nothing
of OpenID Connect. The `webauth.sign_in_routes` module and `install_sign_in_routes` docstrings hold the routes' contract, the
`webauth.oidc_login` and `webauth.cookies` module docstrings hold the login and its
cookies, and `build_app` in [`tests/e2e/oidc/host_app.py`](../tests/e2e/oidc/host_app.py)
is the worked host, type-checked and run against a real issuer.

The host supplies a `SignInTransaction` (`webauth.ports`) and a `refused` hook. The
callback enters the transaction once, only after the issuer's code exchange and the pure
admission decision, so no issuer call runs inside it and a refusal before admission
enters none. It writes the account and the session through `SignInStores` and issues
the session cookie only after the transaction's exit returned. The library never
commits: a successful exit makes the writes durable. An exception in the block escapes
through the exit, and what is rolled back is the host's choice: a host whose stores apply
each call keeps the account created, the sessions ended by replacement or pruning and the
events recorded before the failure, and the next sign-in opens a new session and
restores nothing; a rolling-back host keeps none of them.

The hook receives a `SignInRefusal` (the cause and its `page`) for every refusal and
returns any `Response`. Every callback answer sent after the pending cookie was selected
carries its deletion, also when the hook raises or the answer fails before it starts: the
route then sends a plain 500 with the deletion and raises the failure. Other tabs'
pending cookies stay. A pending login is single-use because its cookie is cleared and the
issuer accepts a code once; webauth keeps no replay store.

The logout route enters the transaction once, only when the request's cookie names a
session, and never commits. An exception in the route, the transaction or the host's
callables answers a plain 500 with no page and no cookie cleared. A rolling-back host
keeps the session, and a retry ends it with its hint; under per-call persistence or an
uncertain commit the row and its ID token may already be gone, and a retry still reaches
the issuer's end-session page, without the hint.

`SignInPaths.backchannel_logout` serves the issuer's back-channel logout for `POST` only, and
must differ from every other path, `logout` included. Only that exact path is exempt from the
origin check and the rate limit, and logout is never exempt. The host's `backchannel_dependencies`
run before the body is read, and are given only with that path or install raises `ValueError`
before any route is registered. A host answers an empty 404 by raising its own exception class
and mapping it with `app.add_exception_handler(ThatError, lambda request, error:
Response(status_code=404))`: an `HTTPException(404)` answers JSON, and a `Response` returned
from a dependency does not stop the route. The answers are, in order: 413 for a declared
`Content-Length` over the bound, before any dependency; the dependencies' own; 413 for a
streamed body over the bound; an empty 400 for a request that is not one URL-encoded form with exactly one
non-empty `logout_token`, or whose token does not verify, before any transaction is entered; an
empty 200 after the clean exit of one `SignInTransaction` entry; and an empty 400, then the
failure re-raised, for any exception in `relying_party`, the verification, a store, the audit
sink or the exit. A subject without an account is accepted and provisions nothing; a known
subject loses every session in every browser, and one `BACKCHANNEL_LOGOUT` event with
`actor_id=None` is recorded when at least one session ended. The route clears no cookie and
calls no issuer endpoint beyond the key fetch of verification. `relying_party` receives the
request with the Host the issuer posted to, often an internal alias.

The host's transaction must roll back when the back-channel block raises, also when the audit
sink fails after the deletion, and commit only for an accepted token. A per-call host keeps the
sessions ended before the failure, and no event is emitted again.

The back-channel route is open to anyone who can reach it, and the token is its only control.
The host lets the issuer reach it over an internal network alone, never the public route
(tunnel, CDN, access proxy); its URL may name the public hostname through an internal alias.

`install_sign_in_routes` requires the host's explicit `keeps_id_token` choice, with no
default, and validates `max_sessions` before it registers a route. A host that serves no logout
route passes `False`: its session row keeps no
ID token, while refresh-token storage is unchanged. With `True`, the row keeps
the login's ID token for logout. Renewal and refresh-token rotation preserve
that choice and the original token. This is [#418 R1/R2](https://github.com/overnightworks/webauth/issues/418)
(operator ruling 22.10.2026), qualified by [#428 R1](https://github.com/overnightworks/webauth/issues/428)
(operator ruling 23.10.2026). [test_oidc_login_open_session_id_token.py](../tests/test_oidc_login_open_session_id_token.py)
proves the explicit choice, refresh-token retention, hint-free logout and
renewal/rotation with no ID token;
`test_a_new_session_holds_the_refresh_token_and_id_token_of_the_admitted_login`
in [test_oidc_login_open_session.py](../tests/test_oidc_login_open_session.py) and
`test_rotation_and_renewal_keep_the_logins_id_token_for_the_logout` in
[test_oidc_login_logout.py](../tests/test_oidc_login_logout.py) prove the retained-token case.
