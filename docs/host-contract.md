# Host contract

For a host developer: what a host sees from webauth and what it must provide.

A rule webauth promises opens with its ID, such as **CSRF-01**, and a test that
proves it names the ID at the start of its docstring. A test under `tests/e2e/`
runs by hand against a real Keycloak, not in CI. A paragraph or bullet that opens
with **Host duty:** says what the host must do and prove itself. A sentence with
neither an ID nor a label explains. A section without IDs still names its proofs in its own lines.

## Trusted proxies

`WebAuthConfig.trusted_proxies` names the trusted proxy addresses for the host.

- **PROXY-01** A request from a peer that `trusted_proxies` does not list keeps the
  peer's address and the connection's own scheme, whatever forwarded headers it carries.
- **PROXY-02** webauth reads `X-Forwarded-For` and `X-Forwarded-Proto` from a trusted peer.
- **PROXY-03** webauth never reads RFC 7239 `Forwarded`.
- **PROXY-04** It reads the `X-Forwarded-For` chain from the right and takes the first
  address it does not trust as the client.
- **PROXY-05** A proxy whose address the chain carries but which the list lacks becomes
  the client address.
- **PROXY-06** Every visitor that reaches the app through that proxy shares its address
  and its rate-limit budget.
- **Host duty:** list the app's direct peer and every proxy whose address the
  `X-Forwarded-For` chain carries; listing every proxy between the client and the app is
  the simple way to be sure. With a CDN, a tunnel and a reverse proxy in front of the
  app, list whichever of their addresses appear in the chain. The operator's
  [hal](https://github.com/overnightworks/hal) project owns that reachability
  infrastructure.
- **Host duty:** turn the ASGI server's own forwarded-header handling off (uvicorn's
  `proxy_headers`, on by default: `proxy_headers=False` or `--no-proxy-headers`);
  `trusted_proxies` decides alone only when the server does not rewrite the client
  address or scheme from those headers.

## What every app gets

The operator ruled APP-20, APP-21, APP-22, APP-34, APP-35, APP-36 and APP-37; no other sentence of this section is ruled.

Every app that signs people in through Keycloak behaves the same way, except for the
two values below. The details are in the sections that follow.

- **APP-01** An app that configures `EverySubject` requires no login group.
- **APP-02** An app that configures `NoAdmins` grants no admin role.
- **APP-03** Only members of the app's `login_group`, such as `/apps/notes`, get in.
- **APP-04** Members of its `admin_group`, a path below it such as
  `/apps/notes/admin`, are admins.
- **APP-05** An `AdmissionConfig` binds the issuer whose groups count, and only that
  issuer's groups decide the role.
- **APP-06** Membership and role are decided again at every login, so a change in
  Keycloak takes effect at the person's next sign-in.
- **APP-07** An app session that is already open keeps its access until it ends.
- **APP-08** A changed admin role, which lives on the account, reaches every open
  session at the person's next sign-in.
- **APP-09** The session's absolute cap bounds the delay before a login-group removal
  takes effect.

The issuer's SSO session makes a fresh login a redirect the person does not notice;
an immediate removal requires disabling the user at the issuer together with
[back-channel logout](ARCHITECTURE.md#back-channel-logout). See
[Admitting an identity](ARCHITECTURE.md#admitting-an-identity).

- **APP-10** The stored role is a plain string: webauth writes `"admin"` for an admin
  and `"user"` for every other member.
- **APP-11** The admin checks admit exactly `"admin"`.
- **APP-12** `NoAdmins` demotes a stored admin to `"user"` at its next sign-in or
  person-token admission.
- **APP-13** Resource admission rewrites no role.

The host's store keeps the stored roles. Only a Breaking release that names the
migration of stored accounts changes these values.

- **APP-14** A person is a member when one of their groups is the group's path or a
  subgroup of it, compared character for character and by path segment, so
  `/apps/notes/admin` counts for `/apps/notes` and `/apps/notes2` does not.
- **Host duty:** switch Keycloak's group mapper to `full.path` on, because the groups
  claim must carry full paths.
- **APP-15** A missing or empty groups claim means no membership.
- **APP-16** The membership check runs before any account is looked up or created.
- **APP-17** A person removed from the group is refused at their next login while their
  account and data stay.
- **APP-18** A person put back into the group returns to the same account.
- **APP-19** `app_role` in `webauth.admission` is the membership rule's public form, for
  a second service that verifies the issuer's token itself.

- **APP-20** Admission never looks up a username.
- **APP-21** Admission has no local active-user flag; disabling people belongs to the
  issuer.
- **APP-22** A host store may still reject a new account's name with `UsernameTakenError`.

- **APP-23** People who are already signed in keep working until their app session
  ends, because the app checks a session in its own store and never asks Keycloak.
- **APP-24** Only when Keycloak fails during the sign-in, or the browser reaches
  Keycloak but the app does not, does the sign-in stop at the app's callback, on the
  host's refusal page.

When Keycloak is down, a new sign-in fails at Keycloak, not at the app.

- **APP-25** The sign-in route answers with a redirect to the issuer's sign-in page and
  reaches no issuer endpoint first.

That page does not load, so the person sees the browser's or the proxy's error page, not
the app's. webauth offers no local fallback login. See
[The store decides every request](ARCHITECTURE.md#the-store-decides-every-request).

For the machine callers and the person's token, see
[The host's machine routes](#the-hosts-machine-routes)
and [The person's token on the app's API](#the-persons-token-on-the-apps-api).

- **APP-26** Signing out of an app ends its session in that browser at once.
- **APP-27** Signing out shows a short page that posts to Keycloak.
- **APP-28** Posting that page to Keycloak ends the person's Keycloak session in that
  browser without asking anything.
- **APP-29** Each app that Keycloak tells ends all of the person's sessions, on every
  device.
- **APP-30** The logout page is `no-store`.
- **APP-31** The logout page clears the app's cookies.
- **APP-32** The logout page submits itself; where scripts cannot run, it shows one
  button.
- **APP-33** If Keycloak is down, the person still leaves the app signed out.

Keycloak tells each app the person signed in to through that Keycloak session. An app
they used only on another device is not told and keeps them signed in there. On their
other devices, the next sign-in asks for no password while that device's own Keycloak
session lasts.

- **APP-34** The page sends the client ID, `post_logout_redirect_uri` and the stored ID
  token as `id_token_hint` by POST to Keycloak's end-session endpoint.
- **APP-35** No URL carries the token.
- **APP-36** Without the session's row (ended by the host, swept, pruned or ended by
  back-channel logout), or with a row that holds no ID token (stored before the host
  held them or opened with `keeps_id_token=False`), the page sends no hint.
- **APP-37** Without a hint, Keycloak asks once to confirm while its own session lives.

If the realm key that signed a supplied token has been deleted since, Keycloak shows
an error page instead. See
[Logging out and the ID token hint](ARCHITECTURE.md#logging-out-and-the-id-token-hint)
for the mechanism and its trust boundaries.

## Where the host's own middleware goes

- **STACK-01** Added before `install_web_auth_middleware`, a host middleware sits inside
  the library stack, so a request the library refuses early (413 by `Content-Length`,
  429, 503, the CSRF 403s, the session gate's 302 and 401) never reaches it.
- **Host duty:** put a middleware that must see only admitted requests (session lookups,
  audit) before the call.
- **STACK-02** Added after the call, a host middleware sits outside the library stack and
  sees every library refusal with its headers already set; it is the place for access
  logs and metrics.
- **STACK-03** A response or exception that such a host middleware produces itself does
  not carry the library headers.
- **STACK-04** The library middleware run the app in the caller's task, so a `ContextVar`
  that the app or an inner middleware sets is visible to an outer host middleware after
  the call returns.
- **Host duty:** write a middleware that must see admitted requests as pure ASGI. A host
  `BaseHTTPMiddleware` or `@app.middleware("http")` makes a response that fails
  mid-stream look complete wherever it sits, and added before the call it also turns the
  413 for a streamed body the route reads into the library 500.
- **Host duty:** a host that relied on `BaseHTTPMiddleware`'s task isolation restores its
  own context, for example by resetting the token it set.

## CSRF origin

The operator ruled CSRF-01, CSRF-03, CSRF-04, CSRF-05, CSRF-06, CSRF-07, CSRF-08, CSRF-09, CSRF-10, CSRF-11, CSRF-12, CSRF-13, CSRF-14, CSRF-15, CSRF-16 and CSRF-17; no other sentence of this section is ruled.

- **CSRF-01** Every app supplies `csrf_origin=CsrfPolicy(...)` when installing the
  middleware.
- **CSRF-02** An install without it is refused.
- **CSRF-03** There is no frontend CSRF-token obligation.
- **CSRF-04** A state-changing request (POST, PUT, PATCH or DELETE) needs trustworthy
  provenance regardless of its body or content type.
- **CSRF-05** `Sec-Fetch-Site: same-origin` passes.
- **CSRF-06** `same-site` or an absent Fetch Metadata header falls back to `Origin`.
- **CSRF-07** Every other Fetch Metadata value is refused.
- **CSRF-08** Without either header the request is refused.
- **CSRF-09** `Referer` is never read.

- **CSRF-10** Only verified bearer admission (on a machine path or a person path) and the
  sessionless server paths the host names in `CsrfPolicy.exempt` bypass this check.
- **CSRF-11** An adjacent path is still checked.

- **CSRF-12** The `Origin` fallback matches exact hosts in
  `WebAuthConfig.allowed_hosts_exact`, never host patterns; its docstring owns port
  matching.
- **CSRF-13** With `cookie_secure` on, the origin must use HTTPS; with it off, the scheme
  is not compared.
- **CSRF-14** A repeated `Origin` header counts as foreign.
- **CSRF-15** These three also hold for WebSocket handshakes, which check `Origin`
  directly.

- **CSRF-16** webauth supports the current releases of Chrome, Edge, Firefox and Safari
  (macOS and iOS).
- **CSRF-17** On every request whose method is not GET or HEAD, each sends `Origin`,
  possibly `null`, and, to an HTTPS app, `Sec-Fetch-Site`.

## Signed out and refused

The operator ruled the opening paragraph and the host duty after it, REFUSE-01, REFUSE-02, REFUSE-03, REFUSE-04 and the host duty after it, REFUSE-05, REFUSE-06, REFUSE-07, REFUSE-08, the lead-in of the machine table, REFUSE-09, REFUSE-10, REFUSE-11, REFUSE-12, REFUSE-22 and the host duty after it, REFUSE-23 and the host duty after it, REFUSE-24, REFUSE-25, REFUSE-26, REFUSE-27, REFUSE-28, the host duty after it that names page choice and presentation, and the paragraph that closes the section; no other sentence of this section is ruled.

Every app shows signed-out and refused people the same way. This is the rule
every app follows; [the session gate](ARCHITECTURE.md#the-session-gate) enforces it.

- **Host duty:** a host without the gate follows this rule itself.
- **REFUSE-01** A page without a session sends the browser straight to the app's start
  route, with `next` naming the page.
- **REFUSE-02** The person then lands there after signing in.
- **REFUSE-03** The start route reads `next` as the path to return to, and the callback
  sends the browser to it when it is a same-origin path of the app, otherwise to the
  app root. See [The sign-in routes](#the-sign-in-routes) and, for the rule the return
  path must pass, [The return path](ARCHITECTURE.md#the-return-path).
- **REFUSE-04** An API call without a session gets 401.
- **Host duty:** the app's UI navigates to its start route when an API call gets 401.
- **REFUSE-05** For a server-rendered host, `LoginRedirect` makes the redirect-or-401
  split; see [Reading the session](ARCHITECTURE.md#reading-the-session).
- **REFUSE-06** To keep the deep link, only request-address construction may prepend
  `root_path`.
- **REFUSE-07** The start route never prepends it to an explicit `next`.
- **REFUSE-08** A machine route (see [The host's machine routes](#the-hosts-machine-routes))
  never answers with a redirect.

  A machine route answers 401 with a `WWW-Authenticate: Bearer realm="admin"` challenge,
  and 403 for a valid token without the admin group:

  | ID | Case | Status | `WWW-Authenticate` | `detail` |
  |---|---|---|---|---|
  | **REFUSE-09** | no credentials | 401 | `Bearer realm="admin"` | `Authentication required` |
  | **REFUSE-10** | malformed request (repeated or combined `Authorization`, or `access_token` in the query beside an `Authorization: Bearer`; in the query alone it is no credential) | 401 | `Bearer realm="admin", error="invalid_request"` | `Invalid request` |
  | **REFUSE-11** | invalid token (any verification failure, an unavailable key set included) | 401 | `Bearer realm="admin", error="invalid_token"` | `Invalid token` |
  | **REFUSE-12** | valid token, not an admin | 403 | `Bearer realm="admin", error="insufficient_scope"` | `Admin access required` |

  A **person path** (see [The person's token on the app's API](#the-persons-token-on-the-apps-api))
  answers a bearer credential as follows; the challenge names `realm="api"` only where
  no credential was sent:

  | ID | Case | Status | `WWW-Authenticate` | `detail` |
  |---|---|---|---|---|
  | **REFUSE-13** | no bearer credential, refused by the library for want of a session (`current_user`, `admin_user`, the session gate, `admitted_admin`) | 401, or the 302 a navigation gets under `login_redirect` | `Bearer realm="api"` on the 401 | the session refusal's own |
  | **REFUSE-14** | malformed (as above) | 401 | `Bearer error="invalid_request"` | `Invalid request` |
  | **REFUSE-15** | invalid token (any verification failure, a foreign audience and an unavailable key set included) | 401 | `Bearer error="invalid_token"` | `Invalid token` |
  | **REFUSE-16** | valid token, not a member of the app | 403 | `Bearer error="insufficient_scope"` | `No access` |
  | **REFUSE-17** | valid member token, the store refuses the new username | 403 | none | `Login failed` |
  | **REFUSE-18** | token person refused by `admin_user` or `admitted_admin` | 403 | `Bearer error="insufficient_scope"` | `Admin access required` |

- **REFUSE-19** A cookie person refused by an admin reader on a person path keeps the
  403 without a challenge,
- **REFUSE-20** and a path outside the person paths keeps its answers.

  The 401 challenge follows RFC 7235 section 3.1 and RFC 6750 section 3; a malformed
  header answers 401, not the 400 RFC 6750 section 3.1 recommends, as the machine paths do.

- **REFUSE-21** A host's own 401 on a person path carries no challenge unless the host
  adds it.
- **REFUSE-22** Public paths are the exception: they need no session and do not redirect.
- **Host duty:** each app names its own public paths.
- **REFUSE-23** The page after signing out is the app's `post_logout_redirect_uri`.
- **Host duty:** the page after signing out never redirects by itself.
- **REFUSE-24** "No access" is for `AdmissionRefusal.NOT_A_MEMBER`;
- **REFUSE-25** "Login failed" is for an `OidcRefusal` and for
  `AdmissionRefusal.FOREIGN_ISSUER` and `USERNAME_TAKEN`, which are setup errors, not
  missing rights.
- **REFUSE-26** Both types reach the host's `refused` hook inside a `SignInRefusal`, whose
  `page` is this mapping; see [The sign-in routes](#the-sign-in-routes).
- **REFUSE-27** A refusal carries no identity.
- **REFUSE-28** A `NOT_A_MEMBER` login stores no session.
- **Host duty:** page choice and presentation.
- **Host duty:** give the three pages (logged out, no access, login failed), their
  wording and their ways out, the sign-in pattern of
  [ui-style](https://github.com/overnightworks/ui-style); take the colours from the
  app's own tokens.

A refusal carries no identity, so the page has no name to show. A refused login stores no
session, so signing out from "no access" follows the missing-ID-token case in
[Signing out](#what-every-app-gets).

## The host's machine routes

The operator ruled the passages that open "A route reads the admitted caller" and "Token lifetime"; no other sentence of this section is ruled, and proof lines are not rulings.

hal is the operator's CLI for calling an app's machine routes with a bearer
token. A host declares its machine (admin) paths once, and hal calls them with
the access token Keycloak issued it in `Authorization: Bearer`. `BearerGate` is passed to
`install_web_auth_middleware(bearer_gate=...)`; it holds the app's own
`OidcRelyingParty`, the app's `AdmissionConfig` and `MachinePaths(paths, authorized_parties)`:
the paths (`PathRules`) and `AuthorizedParties`, the `azp` values (hal's client ids) the host
admits on them, read from configuration. A route reads the admitted caller with
`Depends(bearer_caller)`; `BearerCaller.subject` is the token's `sub`, with no
account and no role. Admission is
opt-in, opens no session and sets no cookie, and bearer requests share the
per-address rate limits of browser requests.

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
  expires, plus the leeway; signing out of a browser leaves the token valid.
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

The operator ruled the passages that open "A token created through hal" and "On such a path"; no other sentence of this section is ruled, and proof lines are not rulings.

A token created through hal can call an app's ordinary API with exactly the rights of the
person behind it, deletion included, and no layer sits on top of the person's rights.
A host names its API paths in `PersonPaths(paths, authorized_parties, transaction)` and passes it
as `BearerGate(person_paths=...)`; `machine_paths` may then be left out (a gate needs one kind
of path, and a `NoAdmins` app may name person paths alone). On such a
path `Authorization: Bearer` is the account behind the token: `current_user`, `admin_user`,
`admitted_user` and `admitted_admin` return it as they return the browser's person, and no
host route changes. A token carries the
rights of the identity behind it and the app checks it as it checks the browser; ordinary
routes admit tokens issued to the hal registration, the same way in every app. Whoever
holds the operator's token may do what the operator may, with no extra security layer.

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
- **Clients.** Each kind of path names its own `AuthorizedParties`, so a client admitted on the
  person paths is refused on the machine routes unless `MachinePaths` lists it too, and the
  other way round. No empty set admits anybody.
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
and [test_bearer_gate_person_paths_challenges_and_neighbours.py](../tests/middleware/test_bearer_gate_person_paths_challenges_and_neighbours.py)
in CI, and scenarios 55 to 60 of [bearer.py](../tests/e2e/oidc/bearer.py) against real
Keycloak in the hand-run harness.

## A person's current groups

`current_groups(relying_party, session_id, *, session_transaction, config)` answers the
group paths the issuer holds for the person a session signs in, from the ID token of a
refresh grant made in that call: a check at the moment of use, such as whether a person may
start a turn that spends the app's budget, is judged against groups that are fresh and
verified, not those of the login. It stores nothing but the rotated refresh token, and no token
leaves webauth. The caller is the app, which maps each outcome once:

| Outcome | Meaning | Turn? |
|---|---|---|
| a tuple of paths | the current groups; `()` is no membership, so a realm without the groups scope admits nobody | only if the check below holds |
| `SESSION_ENDED` | the session is gone, expired or deleted during the grant | no |
| `SIGN_IN_AGAIN` | no refresh token, or the issuer refused it as `invalid_grant` (its session ended, or overlapping calls where the issuer refuses reuse) | no |
| `ISSUER_UNAVAILABLE` | the issuer failed or its new ID token was refused; `issuer_refusal` says why | no |

The call reads no stored ID token, so a session with or without one answers alike, and a host
with `keeps_id_token=False` works. A store failure or a failed transaction exit raises, and no
groups are handed out then.

A subgroup-aware check passes the tuple to `app_role` with `AdmissionConfig(bound_issuer=...,
login_group=..., admin_group=NoAdmins.IN_THIS_APP)`: a member of the group or of a subgroup of it is admitted.

- **The source.** Only the new ID token counts: `iss` is the configured issuer, `sub` the
  session account's id, `aud` the client, `azp` as at login, `exp` has not passed, and it holds no `nonce` key.
  OpenID Connect Core 1.0 section 12.2 says the refreshed ID token SHOULD NOT have one and
  section 2 requires a present one to be verified; webauth keeps nothing to verify it against, so
  a present nonce, whatever its value, is refused as `nonce-mismatch`. The precondition is that
  the issuer's refreshed ID token holds no nonce; an issuer that echoes the original's is refused.
  Freshness is judged against the grant's start, with the configured leeway. A reply without an
  ID token, or a `groups` claim that is not a list of strings, is `ISSUER_UNAVAILABLE`, never `()`.
- **The rotation survives.** A replacement refresh token is stored whatever the ID token said,
  unless the session is gone, which is `SESSION_ENDED` and never recreated.
- **Overlap.** Each call is one grant. Where the issuer lets a refresh token be used again, two
  overlapping calls, with each other or with `fresh_access_token`, each succeed and the last
  replacement written wins; an echoed token never overwrites a replacement. Where it refuses
  reuse, the second call answers a false `SIGN_IN_AGAIN` on a standing session. An app that
  calls this on every turn must expect that.
- **Residue.** The second transaction cannot rule out a session deleted after its load: with a
  store that commits each statement, a deletion before the transaction's exit also escapes when
  the rotation is omitted or echoed, as [Risks and Technical Debt](ARCHITECTURE.md#8-risks-and-technical-debt) says.

Proofs: [test_oidc_login_current_groups.py](../tests/test_oidc_login_current_groups.py) in CI,
and `CHECK refreshed-id-token-facts` in
[bearer_groups.py](../tests/e2e/oidc/bearer_groups.py) against real Keycloak in the hand-run
harness.

## The protected resource

A host that serves an MCP-style resource names it in `ProtectedResource(url, scope, required_group, authorized_parties, transaction, marked_routes)` and passes
it as `BearerGate(resource=...)`; a gate needs one kind of path, and the resource counts as one.
`url` is the resource's identifier, an endpoint URL with a plain host, an optional port and a path of
one or more segments of RFC 3986 unreserved characters (letters, digits, `-`, `.`, `_`, `~`), none
being `.` or `..`, with no trailing slash; its path is the entry point; `scope` is the one scope token the challenge asks for and a token must hold; `authorized_parties` (an `AuthorizedParties`, else `TypeError`) are the clients whose token the resource takes, apart from the parties of the machine and person paths; `required_group` (a group path, else `ValueError`) is the group a person must hold in the token, or one below it, besides the admission's login group; `transaction` is the host's `SignInTransaction`, the same port the person paths use. Everything else
derives from `url`: the metadata path is `/.well-known/oauth-protected-resource` plus the entry
point (RFC 9728 section 3.1), and the challenge names the metadata URL.

**The resource admits an agent's token, capped and read-only.** A token for the resource is refused on the machine paths, and on the person paths except on a route the resource marks; an app token is refused at the entry point; a party listed on one kind is not thereby listed on another. At the entry point, on every method and the exact path only,
the gate decides before CSRF and the session gate, and a refusal runs no route:

- no credential: 401 `WWW-Authenticate: Bearer resource_metadata="<metadata url>", scope="<scope>"`;
- a token the resource's check refuses: 401 with `error="invalid_token"` and the same two
  parameters. The check is `OidcRelyingParty.resource_token_verifier`: an RS256 `at+jwt` of the
  relying party's issuer whose only audience is the resource's `url` (not the app's client ID,
  not a list of two) and whose `azp` is one of the resource's parties;
- a token that passes that but whose `scope` claim, read as space-separated tokens, lacks the
  resource's scope (absent, not a string, another scope, or the scope only as a substring of
  another): 403 with `error="insufficient_scope"` and the same two parameters;
- a token that holds, whose person the resource does not admit (the groups lack `required_group` or the admission's login group, or no account has the token's subject): a plain 403 without `WWW-Authenticate`, because a client answers `insufficient_scope` with a new sign-in, which cannot help. No route runs, the store is not touched for a missing group, and nothing is created, changed or audited;
- a token that holds, whose person is admitted: the request passes with no cookie and no `Origin`, CSRF and the session gate reading the admission as they read a person path's. The lookup is one `accounts.get` in one entry of `transaction`, so a person must have signed in once. The person is `AuthenticatedUser(id, username, role)` with the role `"user"` whatever role is stored: a stored admin is admitted as a plain user, and `admin_user` answers 403 without `WWW-Authenticate` (a person path's 403 keeps its `insufficient_scope` challenge). A store or exit failure is the library's 500 and records no admission;
- a credential the gate refuses (a repeated header, a malformed one): that refusal, with the same
  two parameters.

A cookie decides nothing there: no session transaction runs. The entry
point's answers carry `no-store`. A trailing slash or a longer path is not the entry point, and a
machine path that overlaps it stays a machine path (paths are selected machine, resource, person).

`install_resource_metadata(app, resource, issuer=...)` registers `GET` of the metadata path,
answering JSON with `resource`, `authorization_servers` (`[issuer]`) and `scopes_supported`
(`[scope]`). Install it ahead of any catch-all route, and list `resource.public_rule` in
`SessionGate.public` so a client without a session reads it. The entry point is matched on the
route path, as every policy is, so a host below a `root_path` cannot name a resource yet: the `url` is the public identifier and the route path differs from it.

**Marked routes.** `marked_routes` is a `frozenset` of `MarkedRoute(method, template)` (else `TypeError`), the host's operations besides the entry point that take the same token; empty by default, so a resource has only its entry point. `method` is one upper-case HTTP method token. `template` is one or more `/`-separated segments, each a literal of unreserved characters (never a literal `.` or `..` segment) or one `{name}` filling the whole segment: no converter, no partial parameter, no empty segment, no trailing slash, else `ValueError`. The match is exact, on the route path: the method equals, the segment count equals, each literal equals, each parameter is one non-empty segment other than `.` and `..`. A trailing slash, `HEAD` on a marked `GET`, a longer path below a template and a decoded `/` in a parameter do not match. The gate selects machine path, entry point, marked route, person path; a marked template overlapping a machine path stays a machine path. On a marked route:

- no bearer credential, another scheme included: session and CSRF as without the marking;
- a token whose audience is not the resource (the resource's check refuses it as `INVALID_AUDIENCE`): the request goes on exactly as unmarked, so a person path runs its complete check and any other path ignores the bearer. It is never a resource admission;
- any other refusal answers there as at the entry point with the challenge, a valid cookie beside it deciding nothing: a refused credential, an invalid or expired token, a token naming the resource among two audiences, and `insufficient_scope`;
- a token that holds runs the entry point's admission: the plain 403, or the capped person recorded for the request's method, so CSRF and the session gate step aside and `current_user`, `admitted_user` and `resource_person` return the capped person.

The host's duties: the gate runs before routing, so the host proves that every request a marked route permits resolves to a marked operation (no earlier unmarked route shadows the template); the host marks no operation in a deletion area and no admin operation, because the role cap keeps neither out (an ordinary user may delete, and an admin operation only answers 403); the token reaches a marked route directly, not only through the entry point. Responses on a marked route are the host's own and carry no `no-store`, as on a person path.

`webauth.middleware.resource_person(connection)` returns the person for this very request and raises `RuntimeError` on a session, person or machine request, in a sub-app, and after the `Authorization` header or the method changed. `current_user` returns the same capped person on the entry point and a marked route and refuses after a method change.

Proofs: [test_bearer_gate_resource_admission.py](../tests/middleware/test_bearer_gate_resource_admission.py)
[test_bearer_gate_resource.py](../tests/middleware/test_bearer_gate_resource.py)
and [test_bearer_gate_marked_routes.py](../tests/middleware/test_bearer_gate_marked_routes.py)
in CI, and [bearer_resource.py](../tests/e2e/oidc/bearer_resource.py) against real
Keycloak in the hand-run harness.

## A service's callers

A service that is not a browser app (no sessions, no sign-in) admits an app acting for a person, with
`ServiceCallerCheck` of `webauth.service_callers`. The service builds one per process from a
`ServiceIdentity` (issuer, key-set URL, its own audience, the realm role that marks a workload, the group
claim, the clock leeway) and its registered apps (`RegisteredApp`, keyed by the workload client id). Nothing
has a default and nothing is read from the environment. `person_caller(workload_token, person_token)` is
synchronous, so an async service runs it in a thread.

It returns a `PersonCaller` (the app, the client id, the person's `Principal` and groups, and the person's
`AppRole`) or a `CallerRefusal`. It never says which token a refusal concerns. Both tokens are verified and
read before any check that compares them, so every `UNAUTHENTICATED` and `UNAVAILABLE` refusal comes before
any `FORBIDDEN` one. The checks run in this order: the workload token is checked for a missing token and then
by the verifier, then the person token the same way; then the workload token's subject and groups, then the
person token's; then the rows from `NOT_A_WORKLOAD` down, in table order. The table lists each reason where it
is first checked, and the first fault is the refusal. `CallerRefusal.refusal_class` names its
`CallerRefusalClass`, and the host owns the wire codes, here the recommended ones:

| Reason | Fault | Class |
|---|---|---|
| `MISSING_TOKEN` | the workload token, then the person token, is absent or empty | `UNAUTHENTICATED` (401) |
| `KEY_SET_UNAVAILABLE` | the verifier cannot fetch the key set, see below | `UNAVAILABLE` (503) |
| `TOKEN_REJECTED` | the verifier refuses either token, see below | `UNAUTHENTICATED` (401) |
| `INVALID_SUBJECT` | `sub` absent or not valid text, in the workload token, then in the person token | `UNAUTHENTICATED` (401) |
| `MALFORMED_GROUPS` | the group claim is present and not a list of strings, in the workload token, then in the person token | `UNAUTHENTICATED` (401) |
| `NOT_A_WORKLOAD` | the workload token's `realm_access.roles` lacks the workload role | `FORBIDDEN` (403) |
| `UNBOUND_CLIENT` | the workload token's `azp` is absent or empty, or its `client_id` differs from it | `FORBIDDEN` (403) |
| `UNREGISTERED_CLIENT` | the workload token's `azp` is no registered app | `FORBIDDEN` (403) |
| `CLIENT_MISMATCH` | the person's `azp` is not the workload's `azp` | `FORBIDDEN` (403) |
| `SAME_SUBJECT` | the person's subject is the workload's | `FORBIDDEN` (403) |
| `NOT_A_MEMBER` | the person's groups make no member of the app, by `app_role` and the registered admission | `FORBIDDEN` (403) |

Neither token's lifetime is bounded beyond its `exp` against the clock; the issuer owns it. The person token
gets no role check; its `azp` is the client binding and is never evidence of an exchange.

The verifier stage keeps the verifier's own order: a malformed header or unsupported algorithm is
`TOKEN_REJECTED` before any key lookup, so no key set is fetched. `KEY_SET_UNAVAILABLE` (503) is
the verifier's refusal when the key set cannot be fetched and the token's key is not among the
cached ones, also when other keys are cached; with a usable cached key, a failed refresh still
verifies. Every other verifier refusal is `TOKEN_REJECTED` (401) with its `token_rejection`.

By class: `UNAVAILABLE` (503) is `KEY_SET_UNAVAILABLE`; `UNAUTHENTICATED` (401) is `MISSING_TOKEN`, `TOKEN_REJECTED`,
`INVALID_SUBJECT` and `MALFORMED_GROUPS`; `FORBIDDEN` (403) is `NOT_A_WORKLOAD`, `UNBOUND_CLIENT`,
`UNREGISTERED_CLIENT`, `CLIENT_MISMATCH`, `SAME_SUBJECT` and `NOT_A_MEMBER`.

A group claim that is a JSON `null` is `MALFORMED_GROUPS`; only an absent claim means no groups.

The token's `aud` must name the service; it may name others. The check has no policy: which
groups reach which route is the service's. Nothing taken from a token (subject, client id,
groups) appears in a repr, an error message or a log record of the module, and `jwks_url` is left
out of the repr of `ServiceIdentity`.

Proofs: [test_service_callers.py](../tests/test_service_callers.py) in CI.

## The sign-in routes

The operator ruled the passage that opens "`install_sign_in_routes` requires the host's explicit `keeps_id_token` choice"; no other sentence of this section is ruled, and proof lines are not rulings.

`install_sign_in_routes` registers the start, callback, logout and back-channel logout routes on the host's
`FastAPI` app over its one `OidcRelyingParty` (read per request), and `SignInPaths`
derives the policies for exactly those paths: `public_rules` for the session gate (`GET` of
start and callback, `POST` of logout and of the back-channel), `browser_paths` for the sign-in
rate budget, `backchannel` for `CsrfPolicy.exempt` and `RateLimitPolicy.exempt`,
`backchannel_body_size_rule` (32 KiB for `POST`), `cache_control_rule` (`no-store`) and `login_redirect`, so the host lists the paths once. It is browser-absolute, so
`login_redirect` is right for an app at its origin's root; a host below a `root_path`
builds its own `LoginRedirect`. The library serves the logout route at `SignInPaths.logout` for `POST` only, with the
page's text from the host's `logout_page_text`, read per request: a `LogoutPageText` whose
`button_label` is the title and the button, and whose `language` (a BCP 47 tag, validated in shape
when the record is built) is the page's `<html lang>`; a single-page app logs
out by a top-level form POST to that route, and the host never lists the path in
`CsrfPolicy.exempt`. `paths.logout` and `logout_page_text` come together, or both
are `None` for a host without logout. `webauth.cookies` carries the pending login in a signed cookie of its own, one
per login, so the library keeps no server-side store and `WebAuthConfig` knows nothing
of OpenID Connect. The `webauth.sign_in_routes` module and `install_sign_in_routes` docstrings hold the routes' contract, the
`webauth.oidc_login` and `webauth.cookies` module docstrings hold the login and its
cookies, and `build_app` in [`tests/e2e/oidc/host_app.py`](../tests/e2e/oidc/host_app.py)
is the worked host, type-checked and run against a real issuer.

Proofs: `test_the_derived_policies_open_the_sign_in_paths_and_send_a_signed_out_page_to_start`,
`test_the_derived_cache_rule_marks_the_sign_in_answers_no_store` and
`test_the_derived_browser_paths_spend_one_sign_in_budget`, among others, in
[test_sign_in_routes_derived_policies.py](../tests/test_sign_in_routes_derived_policies.py).

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
that choice and the original token. [test_oidc_login_open_session_id_token.py](../tests/test_oidc_login_open_session_id_token.py)
proves the explicit choice, refresh-token retention, hint-free logout and
renewal/rotation with no ID token;
`test_a_new_session_holds_the_refresh_token_and_id_token_of_the_admitted_login`
in [test_oidc_login_open_session.py](../tests/test_oidc_login_open_session.py) and
`test_rotation_and_renewal_keep_the_logins_id_token_for_the_logout` in
[test_oidc_login_logout.py](../tests/test_oidc_login_logout.py) prove the retained-token case.

## Testing a host

A test that needs a signed-in person needs no issuer. It creates the account and
a session inside the configured lifetime in the host's own store, calls
`issue_session_cookies(response, session_id, config)` from `webauth.cookies` on
a `Response` and copies the one cookie it sets into its client. A state-changing
request also sends `Sec-Fetch-Site: same-origin` ([CSRF origin](#csrf-origin)).
When the client keeps the cookie's attributes and `cookie_secure` is on, use an
`https` base URL.

A test of a host that installs the sign-in routes gives
`OidcRelyingParty` its own `post_token_request` (a `TokenRequestPost`, from
`webauth.oidc`) and `fetch_key_set` (a `KeySetFetch`, from
`webauth.jwt_verification`) instead of the HTTPS ones. The host owns that stub.

The sign-in flow itself is proven against a real issuer: webauth's own proof
drives Keycloak in a real browser ([run the browser
proof](runbooks/run-the-browser-proof.md)). A host proves its own sign-in
against an issuer of its choosing. webauth ships no fake issuer, because one
that mints tokens does not belong in every production install.
