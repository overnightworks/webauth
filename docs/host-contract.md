# Host contract

For a host developer: what a host sees from webauth and what it must provide.

A rule webauth promises opens with its ID, such as **CSRF-01**, and a test that
proves it names the ID at the start of its docstring. A test under `tests/e2e/`
runs by hand against a real Keycloak, not in CI. A paragraph or bullet that opens
with **Host duty:** says what the host must do and prove itself. A sentence with
neither an ID nor a label explains.

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
  [platform](https://github.com/overnightworks/platform) project owns that reachability
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
  the library stack, so a request the library refuses early (400 for a malformed path,
  413 by `Content-Length`, 429, 503, the CSRF 403s, the session gate's 302 and 401) never
  reaches it.
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

What the installer refuses before any rule or route:

- **STACK-08** A request whose route path, the path below `root_path`, carries a control character (U+0000 to U+001F or U+007F) gets 400 with the JSON body `{"detail": "Malformed request path"}` and the security headers. Starlette's route patterns end in `$`, which also matches before a final line feed, so without the refusal a path with a trailing newline reaches a route that the path rules, which compare exactly, do not know.
- **STACK-09** The refusal sits directly inside the security headers and ahead of every other library middleware: a refused request spends no rate budget, opens no session lookup, and reaches neither a host middleware added before the call nor a route.
- **STACK-10** The refusal reads the path below `root_path`; a control character in `root_path` itself refuses nothing.
- **STACK-11** The installer always installs it. It has no policy and no option. `webauth.middleware` exports the class so a host can name it in a stack-order check; `install_web_auth_middleware` stays the only supported way to add it, and an app that already carries it is refused like any library middleware.
- **STACK-12** WebSocket and lifespan scopes pass: no library rule reads a handshake's path, and `authenticate_websocket` decides a handshake.
- **STACK-13** A path with a space, a `;`, a trailing slash or a non-ASCII character keeps the answer it has without the refusal.
- **Host duty:** a route takes no control character in its path; free text goes in the query or the body.

What the installer applies when the host passes none:

- **STACK-05** The policy's default budget is 600 requests per 60 seconds per address unless the host names one, and the installer applies that policy when the host passes none; that budget is named "default", so a host rule takes another name unless the host names its own default.
- **Host duty:** a host behind a shared proxy address, where many people share one budget (PROXY-06), passes its own policy.
- **STACK-06** Without a `body_size`, and in a `BodySizePolicy` that names no default, the body limit is 4 KiB unless the host names another; a larger body gets 413.
- **STACK-07** Without a `permissions_policy` the header turns off `camera`, `microphone`, `geolocation` and `display-capture`.

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
- **REFUSE-07** The start route never prepends `root_path` to an explicit `next`.
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

A refusal carries no identity, so the page has no name to show. A `NOT_A_MEMBER` login
stores no session, so signing out from "no access" follows the missing-ID-token case in
[Signing out](#what-every-app-gets).

## The host's machine routes

The operator ruled MACHINE-01 to MACHINE-06, MACHINE-24 and MACHINE-25; no other sentence of this section is ruled.

hal is the operator's CLI for calling an app's machine routes with a bearer
token. It calls them with the access token Keycloak issued it in `Authorization: Bearer`.

**Host duty:** A host declares its machine (admin) paths once. `BearerGate` is passed to
`install_web_auth_middleware(bearer_gate=...)`; it holds the app's own
`OidcRelyingParty`, the app's `AdmissionConfig` and `MachinePaths(paths, authorized_parties)`:
the paths (`PathRules`) and `AuthorizedParties`, the `azp` values (hal's client ids) the host
admits on them, read from configuration.

- **MACHINE-01** A route reads the admitted caller with `Depends(bearer_caller)`;
  `BearerCaller.subject` is the token's `sub`.
- **MACHINE-02** The caller carries no account and no role.
- **MACHINE-03** Admission is opt-in.
- **MACHINE-04** Admission opens no session.
- **MACHINE-05** Admission sets no cookie.
- **MACHINE-06** Bearer requests share the per-address rate limits of browser requests.

- **What passes.**
  - **MACHINE-07** A token passes only as an RS256 `at+jwt`.
  - **MACHINE-08** A token passes only from the app's issuer.
  - **MACHINE-09** A token passes only if its only `aud` is the app's client.
  - **MACHINE-10** A token passes only if its `azp` is allowed.
  - **MACHINE-11** A token passes only if its `groups` hold the admin group or a group below it.
  - **MACHINE-12** Nothing is created or provisioned.
  - **MACHINE-13** webauth emits no event.
  - **Host duty:** The host audits the admitted call itself (subject, route, outcome).
- **What it replaces.** On a gated path:
  - **MACHINE-14** The cookie decides nothing.
  - **MACHINE-15** The CSRF check decides nothing.
  - **MACHINE-16** The session gate decides nothing.
  - **MACHINE-17** Every answer is `no-store`.
  - **MACHINE-18** webauth sets no cookie.
  - **MACHINE-19** `admitted_user` returns `None`, whatever cookie the request carries.
  - **MACHINE-20** `session_id_from_request` answers `None`, whatever cookie the request carries.
  - **MACHINE-21** The same rate limit applies: the installer always installs one.
  - **MACHINE-22** A flood of invalid tokens is bounded only by that rate limit.
  - **MACHINE-23** A session dependency (`current_user`, `admin_user`, `admitted_admin`) on a
    machine path raises, so the library answers 500.
- **Token lifetime.**
  - **MACHINE-24** A block at Keycloak reaches the gate only when the token expires, plus the leeway.
  - **MACHINE-25** Signing out of a browser leaves the token valid.
- **The paths** are written as every other policy's are; the `PathRules` docstring says how.
  - **Host duty:** The paths must cover every machine route, a prefix being the safe form.
  - **MACHINE-26** Every method is gated, `OPTIONS` included.
  - **Host duty:** A CORS preflight is the host's own layer outside the stack.
  - **MACHINE-27** A path that machine paths and person paths both select is a machine path.
- **Mounts and sockets.**
  - **Host duty:** Install the gate on the app that serves the machine routes.
  - **MACHINE-28** A sub-app mounted below a gated path keeps its own CSRF check.
  - **MACHINE-29** A sub-app mounted below a gated path keeps its own session gate.
  - **MACHINE-30** The `bearer_caller` of a route in such a sub-app raises.
  - **MACHINE-31** WebSocket scopes are not gated.

## The person's token on the app's API

The operator ruled TOKEN-01, TOKEN-02, TOKEN-06, TOKEN-07, TOKEN-08, TOKEN-09 and TOKEN-10; no other sentence of this section is ruled.

**TOKEN-01** A token created through hal can call an app's ordinary API with exactly the rights of
the person behind it, deletion included.

**TOKEN-02** No layer sits on top of the person's rights.

**Host duty:** Name the API paths in `PersonPaths(paths, authorized_parties, transaction)` and pass
it as `BearerGate(person_paths=...)`.

**TOKEN-03** `machine_paths` may then be left out.

**TOKEN-04** A gate needs one kind of path.

**TOKEN-05** A `NoAdmins` app may name person paths alone.

**TOKEN-06** On such a path `Authorization: Bearer` is the account behind the token: `current_user`,
`admin_user`, `admitted_user` and `admitted_admin` return it as they return the browser's person,
and no host route changes.

**TOKEN-07** A token carries the rights of the identity behind it and the app checks it as it
checks the browser.

**TOKEN-08** Ordinary routes admit tokens issued to the hal registration, the same way in every app.

**TOKEN-09** Whoever holds the operator's token may do what the operator may.

**TOKEN-10** That holds with no extra security layer.

- **Which paths.**
  - **TOKEN-11** Only the paths the host names take a token: an API route outside `PersonPaths` is
    not reachable by token.
  - **TOKEN-12** A path neither rule selects is untouched.
  - **TOKEN-13** A route that takes a foreign secret in `Authorization: Bearer` (a webhook) keeps
    working.
  - **TOKEN-14** A request with no bearer credential (no header, another scheme such as `Basic` or
    `DPoP`, or `access_token` only in the query) is decided by the cookie as on any other path.
  - **TOKEN-15** A bearer credential is judged by the token and never falls back to the cookie.
- **The account.**
  - **TOKEN-16** The verified `sub` is admitted by the same `app_role` and the same account step as
    a browser sign-in.
  - **TOKEN-17** Every token request enters the host's serialized `SignInTransaction` once.
  - **TOKEN-18** A person outside the app's login group is refused before any store is touched.
  - **TOKEN-19** An unknown subject gets an account of the kind `PERSON` with the token's `preferred_username` (the
    subject when it carries none) and `USER_CREATED`.
  - **TOKEN-20** A known subject keeps its account.
  - **TOKEN-21** Its role follows the token's groups, written and recorded as `ROLE_CHANGED` when
    it differs, exactly as at sign-in.
  - **TOKEN-22** No session is created.
  - **TOKEN-23** Nothing is committed here: durability is the exit of the host's transaction.
  - **TOKEN-24** A store, audit or exit failure is the library 500.
  - **TOKEN-25** No issuer call happens inside the block.
- **Clients.**
  - **TOKEN-26** Each kind of path names its own `AuthorizedParties`, so a client admitted on the
    person paths is refused on the machine routes unless `MachinePaths` lists it too, and the
    other way round.
  - **TOKEN-27** No empty set admits anybody.
- **No origin, no cookie.**
  - **TOKEN-28** A verified token request bypasses the CSRF origin check, so a CLI needs no
    `Origin`.
  - **TOKEN-29** A cookie-only request is checked as before.
- **The cookie beside a token.**
  - **TOKEN-30** The token decides and the cookie names no session for that request:
    `session_id_from_request` answers `None`.
  - **TOKEN-31** The session is not renewed.
  - **Host duty:** A host route that binds work to the session answers its own refusal when it
    gets `None`.
  - **TOKEN-32** Host dependencies such as `current_user`'s `session_store` still resolve before
    the reader runs.
- **Refusals.** See the person-path table under
  [Signed out and refused](#signed-out-and-refused).
- **Residues.**
  - **TOKEN-33** Disabling the person at Keycloak does not end a token: it works until its `exp`
    plus leeway.
  - **TOKEN-34** Signing out in a browser does not end a token before its `exp` plus leeway.
  - **TOKEN-35** A back-channel logout does not end a token before its `exp` plus leeway.
  - Group changes reach a token request with the next token, at most one token lifetime later.
  - **TOKEN-36** An older token can write the old role back within its lifetime.
  - **TOKEN-37** There is no sender constraint: webauth checks no DPoP proof, so a bound token is
    plain bearer here, and a copied token is the person until it expires.
  - **TOKEN-38** The per-address rate limit is shared with the browser's.
  - **TOKEN-39** A WebSocket handshake is not gated.

## A person's current groups

**GROUPS-01** `current_groups(relying_party, session_id, *, session_transaction, config)` answers the
group paths the issuer holds for the person a session signs in, from the ID token of a
refresh grant made in that call.

A check at the moment of use, such as whether a person may start a turn that spends the app's
budget, is judged against groups that are fresh and verified, not those of the login.

**GROUPS-02** `current_groups` stores nothing but the rotated refresh token.

**GROUPS-03** No token leaves webauth.

**Host duty:** The caller is the app, which maps each outcome once:

| ID | Outcome | Meaning | Turn? |
|---|---|---|---|
| **GROUPS-04** | a tuple of paths | the current groups | only if the check below holds |
| **GROUPS-05** | `()` | no membership, so a realm without the groups scope admits nobody | only if the check below holds |
| **GROUPS-06** | `SESSION_ENDED` | the session is gone, expired or deleted during the grant | no |
| **GROUPS-07** | `SIGN_IN_AGAIN` | no refresh token, or the issuer refused it as `invalid_grant` (its session ended, or overlapping calls where the issuer refuses reuse) | no |
| **GROUPS-08** | `ISSUER_UNAVAILABLE` | the issuer failed or its new ID token was refused; `issuer_refusal` says why | no |

- **GROUPS-09** The call reads no stored ID token, so a session with or without one answers alike,
  and a host with `keeps_id_token=False` works.
- **GROUPS-10** A store failure raises, and no groups are handed out then.
- **GROUPS-11** A failed transaction exit raises, and no groups are handed out then.

**GROUPS-12** A subgroup-aware check passes the tuple, or the `frozenset` the async reader answers, to `app_role` as it is, with `AdmissionConfig(bound_issuer=...,
login_group=..., admin_group=NoAdmins.IN_THIS_APP)`: a member of the group or of a subgroup of it is admitted.

- **The source.** Only the new ID token counts:
  - **GROUPS-13** `iss` is the configured issuer.
  - **GROUPS-14** `sub` is the session account's id.
  - **GROUPS-15** `aud` is the client.
  - **GROUPS-16** `azp` is as at login.
  - **GROUPS-17** `exp` has not passed.
  - **GROUPS-18** It holds no `nonce` key: a present nonce, whatever its value, is refused as
    `nonce-mismatch`.
  - OpenID Connect Core 1.0 section 12.2 says the refreshed ID token SHOULD NOT have a nonce and
    section 2 requires a present one to be verified; webauth keeps nothing to verify it against.
    The precondition is that the issuer's refreshed ID token holds no nonce.
  - **GROUPS-19** An issuer that echoes the original's nonce is refused.
  - **GROUPS-20** Freshness is judged against the grant's start, with the configured leeway.
  - **GROUPS-21** A reply without an ID token is `ISSUER_UNAVAILABLE`, never `()`.
  - **GROUPS-22** A `groups` claim that is not a list of strings is `ISSUER_UNAVAILABLE`, never `()`.
- **The rotation survives.**
  - **GROUPS-23** While the session stands, a replacement refresh token is stored whatever the ID token said.
  - **GROUPS-24** A session that is gone is `SESSION_ENDED` and never recreated.
- **Overlap.**
  - **GROUPS-25** Each call is one grant.
  - **GROUPS-26** Where the issuer lets a refresh token be used again, two overlapping calls, with
    each other or with `fresh_access_token`, each succeed and the last replacement written wins.
  - **GROUPS-27** An echoed token never overwrites a replacement.
  - Where the issuer refuses reuse, the second call answers a false `SIGN_IN_AGAIN` on a standing session.
  - **Host duty:** An app that calls this on every turn must expect that.
- **Residue.** The second transaction cannot rule out a session deleted after its load: with a
  store that commits each statement, a deletion before the transaction's exit also escapes when
  the rotation is omitted or echoed, as [Risks and Technical Debt](ARCHITECTURE.md#8-risks-and-technical-debt) says.
- **The async reader.** `SessionGroups(relying_party, session_transaction, config)` from
  `webauth.session_groups` takes the host's `SessionTransaction`, as `current_groups` does:
  - **GROUPS-28** `await of_session(session_id)` and `await of_connection(connection)` answer the
    groups of a session, or of the session the connection's cookie names, as a `frozenset` or the
    refusal `current_groups` answers, by one `current_groups` call on a worker thread. The `frozenset`
    passes to `app_role` as it is (GROUPS-12).
  - **GROUPS-29** A connection without a session answers `SIGN_IN_AGAIN` and makes no grant.
  - **GROUPS-30** A cancelled caller gets no answer, but its grant still stores its rotated refresh token.
    The cancellation reaches the caller only after the grant ends, so a timeout around the call fires
    then, not at its deadline; the host's `SessionTransaction` is entered and left on the worker thread.
  - It takes no lock, so overlapping calls are GROUPS-26. **Host duty:** The app maps each refusal to
    its own answer and names the group it checks.

## A person's language

`resolve_language(languages, *, account_tag, accept_language)` from `webauth.languages` answers
one of the app's own languages for a request. `languages` is an `AppLanguages(offered, default)`
the app builds once. `account_tag` is the account's tag as the issuer gave it, and
`accept_language` is the request's `Accept-Language` header as one string: a host with several
header lines joins them with commas. `account_language_of_session(connection, *, sessions, config)`
from `webauth.dependencies` answers the account's tag for the request, from the session row.
`install_sign_in_routes(..., ui_language=...)` names the resolved language to the issuer.

**LANGUAGE-01** `AppLanguages` raises `ValueError` when built if an offered tag or the default is not a
language tag in shape, the shape `SIGNIN-14` gives.

**LANGUAGE-02** `AppLanguages` raises `ValueError` when built if `default` is not one of `offered` exactly
as spelled, which includes an empty `offered`.

**LANGUAGE-03** `AppLanguages` raises `ValueError` when built if two offered tags are equal ignoring case,
the same tag included.

**LANGUAGE-04** The answer is the first of these that finds an offered tag: the account's tag, then each
language range of the header by descending weight, then `default`.

**LANGUAGE-05** A range is matched by RFC 4647 Lookup (section 3.4): first as given, equal to an offered
tag ignoring case; if none is, the range loses its last subtag and any single-character subtag left at
its end, and is tried again, until nothing is left. `de-DE-u-co-phonebk` is tried as `de-DE-u-co`,
`de-DE` and `de`.

**LANGUAGE-06** A range never matches an offered tag more specific than itself: `de` does not find an
offered `de-CH`.

**LANGUAGE-07** The answer is the offered tag as the app spelled it: `de-de` answers an offered `de-DE`.

**LANGUAGE-08** The header is a list of language ranges separated by commas, each with an optional `;q=`
weight from 0 to 1 with at most three decimals, which is 1 when absent (RFC 9110 section 12.5.4). The
ranges answer by descending weight, and equal weights keep the header's order.

**LANGUAGE-09** A range of weight 0 is skipped and excludes no other element: `de;q=0, de` answers `de`
when `de` is offered.

**LANGUAGE-10** `*` is skipped, whatever its weight.

**LANGUAGE-11** An element whose range is not a language tag in shape (`de-*`, `pt_BR`) or whose weight is
malformed (`q=2`, `q=x`) is dropped alone, and the rest of the header still counts.

**LANGUAGE-12** An account tag that is `None`, not a language tag in shape (`pt_BR`, `x-private`,
`i-klingon`, the empty string), or that matches no offered tag counts as absent, and the header decides.
Nothing is normalised: `" de"` is not `de`.

**LANGUAGE-13** The callback reads the verified ID token's `locale` claim into the session row it creates,
as `SessionRecord.account_language`: kept when it is a non-empty string of at most
`MAX_ACCOUNT_LANGUAGE_CHARS` characters (35, the length RFC 5646 section 4.4.1 asks every implementation
to support) and every character of it is printable (`str.isprintable`), else `None`: a missing claim, a
claim that is not a string, the empty string, a longer one, one carrying a control character such as NUL or a
line break. The printable rule is storage hygiene, not a judgement of the tag.

**LANGUAGE-14** The tag is kept as the issuer gave it: webauth neither checks its shape nor normalises it.
`resolve_language` is the one place that judges a tag.

**LANGUAGE-15** A `locale` claim never refuses a sign-in.

**LANGUAGE-16** The tag is written once, when the callback creates the session. Renewal, refresh-token
rotation and `touch` leave it, so a change of the account's language shows after the next sign-in.

**LANGUAGE-17** `account_language_of_session(connection, *, sessions, config)` answers the
`account_language` of the session the connection's cookie names.

**LANGUAGE-18** It answers `None` when `session_id_from_request` does (no cookie, a forged or doubled one,
a request the bearer gate admitted), when the store holds no such row, when the row is outside its
lifetime by the rule `admit_session` applies, and when the row holds none.

**LANGUAGE-19** It only calls `load`: it never renews a session, refuses a request or sets a cookie, so a
public page calls it without sliding a session's expiry.

**LANGUAGE-20** A failing store raises.

**LANGUAGE-21** `install_sign_in_routes` requires `ui_language: Callable[[Request], str | None]`, with no
default: an install without it raises `TypeError` and registers no route.

**LANGUAGE-22** The start route calls it once per request, with that request.

**LANGUAGE-23** A tag sends `ui_locales=<tag>` in the authorization request (OpenID Connect Core 1.0
section 3.1.2.1), exactly once and spelled as the host gave it. The rest of the request is the one
sent without a language.

**LANGUAGE-24** `None` sends no `ui_locales`.

**LANGUAGE-25** A string that is not a language tag in shape (`pt_BR`, the empty string, two tags with a
space) raises `ValueError` from the start route: a host's error, never sent to the issuer. The route
sends no redirect and sets no pending cookie.

**LANGUAGE-26** `OidcRelyingParty.begin_login(*, ui_locales)` requires the keyword and follows
LANGUAGE-23 to LANGUAGE-25 on its own, for a host that begins a login itself. `is_language_tag` is the
one judge of the shape.

**LANGUAGE-27** The value is stored in neither the pending cookie nor the session, and webauth writes it
to no log line.

**Host duty:** The session table has a nullable column of at least `MAX_ACCOUNT_LANGUAGE_CHARS`
characters, written at `create` and returned by the record as `account_language`; a row stored before
the column reads `None`.

**Host duty:** The app passes the function's answer to `resolve_language` as `account_tag` and writes only
the resolver's answer into `<html lang>`, never an account's tag as received.

**Host duty:** The `ui_language` callable answers `resolve_language`'s answer for the request, or `None` for
a host that names no language (`lambda request: None`).

## The protected resource

A host that serves an MCP-style resource names it in `ProtectedResource(url, scope, required_group, agent_group, authorized_parties, transaction, marked_routes, admits_client_audience)` and passes
it as `BearerGate(resource=...)`.

- **RESOURCE-01** A gate needs one kind of path, and the resource counts as one.
- **RESOURCE-02** `url` is the resource's identifier, an endpoint URL with a plain host, an optional port and a path of
  one or more segments of RFC 3986 unreserved characters (letters, digits, `-`, `.`, `_`, `~`), none
  being `.` or `..`, with no trailing slash; its path is the entry point. Any other `url` is a `ValueError`.
- **RESOURCE-03** `scope` is one scope token, else `ValueError`.
- **RESOURCE-04** `authorized_parties` is an `AuthorizedParties`, else `TypeError`.
- **RESOURCE-05** `required_group` and `agent_group` are group paths, else `ValueError`.
- `scope` is the scope the challenge asks for and a token must hold. `authorized_parties` are the clients whose token
  the resource takes, apart from the parties of the machine and person paths. `required_group` is the group a person
  must hold in the token, or one below it, besides the admission's login group. `agent_group` is the group an autonomous
  agent's own client holds in its token, as an exact element: the realm alone decides which clients can mint a token for
  `url`, and the group lets them through the party check at this resource only.
- `transaction` is the host's `SignInTransaction`, the same port the person paths use.
- Everything else derives from `url`:
  - **RESOURCE-06** the metadata path is `/.well-known/oauth-protected-resource` plus the entry
    point (RFC 9728 section 3.1);
  - **RESOURCE-07** the challenge names the metadata URL.

**The resource admits a token for an agent.** An interactive agent's token is capped and read-only; the token of an agent with its own client, which holds `agent_group`, registers its account.

- **RESOURCE-08** A token for the resource is refused on the machine paths.
- **RESOURCE-09** A token for the resource is refused on the person paths except on a route the resource marks.
- **RESOURCE-10** An app token is refused at the entry point.
- **RESOURCE-11** A party the resource lists is not thereby listed on the machine and person paths.
- **RESOURCE-12** A party the machine or person paths list is not thereby listed on the resource.

At the entry point, on every method and the exact path only:

- **RESOURCE-13** The gate decides before CSRF and the session gate.
- **RESOURCE-14** No credential: 401 `WWW-Authenticate: Bearer resource_metadata="<metadata url>", scope="<scope>"`. No route runs.
- **RESOURCE-15** A token the resource's check refuses: 401 with `error="invalid_token"` and the same two
  parameters, and no route runs. The check is `OidcRelyingParty.resource_token_verifier`:
  - **RESOURCE-16** an RS256 `at+jwt`,
  - **RESOURCE-17** of the relying party's issuer,
  - **RESOURCE-18** whose only audience is the resource's `url` (not the app's client ID,
    not a list of two); a resource declared with `admits_client_audience=True` also admits a token
    whose audiences are exactly its `url` and the relying party's client ID, in either order, and
    nothing else,
  - **RESOURCE-19** and whose `azp` is one of the resource's parties, unless the next rule applies.
- **RESOURCE-70** A token whose validated `groups` list holds `agent_group` as one element passes the party check
  (RESOURCE-19) whatever its `azp`, and other groups beside it change nothing. Every other check of
  RESOURCE-15 to RESOURCE-22 stays.
- **RESOURCE-71** These do not count as the agent group: a path below it (`/agents/x`), a path that only starts with it
  (`/agentsX`) and a malformed `groups` claim, which stays a 401 `invalid_token`.
- **RESOURCE-72** The group widens no other path's parties: the person paths and the machine paths keep their own.
- **RESOURCE-73** With the agent group, `agent_owner` must be a non-empty string and `agent_name` a printable string
  (`str.isprintable`) of 1 to 64 characters, else 401 `invalid_token` as RESOURCE-15. The claims are checked inside the
  token check, so this refusal comes before the scope (RESOURCE-20), before the group refusals (RESOURCE-21,
  RESOURCE-22) and before any `transaction` entry, also when the `azp` is among the resource's parties.
- **RESOURCE-74** Without the agent group both claims are ignored and the token is a person's, with `agent` `None`.
- **RESOURCE-84** `admits_client_audience` is `False` by default, and anything but a `bool` is a `TypeError`.
- **RESOURCE-85** It exists for an app that exchanges the admitted token at the issuer, which exchanges only a token that
  names the exchanging client; an app that does not exchange leaves it off.
- **RESOURCE-86** A token naming the `url` and the client ID is refused on the machine paths and on the person paths
  whatever the flag says (MACHINE-09 and the person paths' one-audience rule stay), and on a resource without the flag.
- **RESOURCE-87** With the flag on, the one-audience check of the machine and person paths is the layer between a token
  minted for the resource and the rights of a person path.
- **RESOURCE-20** A token that passes that but whose `scope` claim, read as space-separated tokens, lacks the
  resource's scope (absent, not a string, another scope, or the scope only as a substring of
  another): 403 with `error="insufficient_scope"` and the same two parameters, and no route runs.
- A token that holds, whose person the resource does not admit, gets a plain 403 without `WWW-Authenticate`, because a client answers `insufficient_scope` with a new sign-in, which cannot help. No route runs, and nothing is created, changed or audited:
  - **RESOURCE-21** the groups lack `required_group`, and the store is not touched;
  - **RESOURCE-22** the groups lack the admission's login group, and the store is not touched;
  - **RESOURCE-23** no account has the token's subject, for a token without the agent group.

  RESOURCE-21 and RESOURCE-22 hold for a token with the agent group as for any other.
- A token with the agent group that holds and passes RESOURCE-21 and RESOURCE-22, at the entry point and on a marked route alike, registers its account in the one `transaction` entry:
  - **RESOURCE-75** no account has its subject: `create_for_subject(subject, username, "user", AccountKind.AGENT)` with
    the username TOKEN-19 gives (the token's `preferred_username`, else the subject), and `USER_CREATED`;
  - **RESOURCE-76** its account's kind is `PERSON`: `set_kind(id, AccountKind.AGENT)` and one `KIND_CHANGED` event
    carrying `account_kind` and `previous_account_kind`; its kind is `AGENT`: the account is only read.
- A token that holds, whose person is admitted:
  - **RESOURCE-24** the request passes with no cookie and no `Origin`, the session gate reading the admission as it reads a person path's;
  - **RESOURCE-25** CSRF reads the admission as it reads a person path's;
  - **RESOURCE-26** for a token without the agent group, the lookup is one `accounts.get` in one entry of `transaction`, so a person must have signed in once;
  - **RESOURCE-27** the person is `AuthenticatedUser(id, username, role, agent)` with the role `"user"` whatever role is stored: a stored admin is admitted as a plain user, and `agent` is `None` without the agent group;
  - **RESOURCE-77** with the agent group the admitted agent is `AuthenticatedUser(id, username, "user", agent=AgentFacts(owner, name))` whatever role is stored and whatever kind the account stores, its `kind` derived from `agent`; CSRF and the session gate step aside as RESOURCE-24 and RESOURCE-25 say, `current_user`, `admitted_user` and `resource_person` return it with its `AgentFacts` (RESOURCE-62, RESOURCE-63, RESOURCE-65), and a changed method or `Authorization` header still ends the admission (RESOURCE-67 to RESOURCE-69);
  - **RESOURCE-28** `admin_user` answers that person 403 without `WWW-Authenticate` (a person path's 403 keeps its `insufficient_scope` challenge);
  - **RESOURCE-29** a store or exit failure is the library's 500 and records no admission;
  - **RESOURCE-78** the same for a failed `create_for_subject`, `set_kind`, `USER_CREATED` or `KIND_CHANGED` audit of an agent: the library promises no rollback, so what the failed entry leaves is the host's, as the `SignInTransaction` docstring says: a host whose stores apply each call can keep the `AGENT` account or kind, and a later request then admits it as known with no second event;
  - **RESOURCE-79** a username already taken at an agent's creation is a plain 403 without `WWW-Authenticate`, after the transaction's cleanup; a failing cleanup stays the 500, as on the person paths;
  - **RESOURCE-80** a token without the agent group keeps RESOURCE-23, RESOURCE-26, RESOURCE-27 and RESOURCE-60 unchanged, and a stored `AGENT` account met so is only read: its stored kind stays, `agent` is `None`, and the derived `kind` is `PERSON`.
- **Host duty:** The store keeps each account's kind, an existing store backfills `person`, and its `SubjectUserStore` implements `set_kind`.
- **Host duty:** An agent account's username is no display name: show an agent by `AgentFacts.name`.
- **Host duty:** The library only records the kind; "an agent's service account is no person" is the host's to apply with `AuthenticatedUser.kind`.
- **RESOURCE-30** A credential the gate refuses (a repeated header, a malformed one): that refusal, with the same
  two parameters, and no route runs.
- **RESOURCE-31** A cookie decides nothing there: no session transaction runs.
- **RESOURCE-32** The entry point's answers carry `no-store`.
- **RESOURCE-33** A trailing slash or a longer path is not the entry point.
- **RESOURCE-34** A machine path that overlaps the entry point stays a machine path.
- **RESOURCE-35** An entry point below a person path is decided as the entry point.

`install_resource_metadata(app, resource, issuer=...)`:

- **RESOURCE-36** registers `GET` of the metadata path,
- **RESOURCE-37** answering JSON with `resource`, `authorization_servers` (`[issuer]`) and `scopes_supported`
  (`[scope]`).
- **Host duty:** Install it ahead of any catch-all route.
- **Host duty:** List `resource.public_rule` in `SessionGate.public`.
- **RESOURCE-38** So listed, a client without a session reads the metadata document.
- **Host duty:** A host below a `root_path` names no resource: the entry point is matched on the route path,
  as every policy is, and the `url` is the public identifier, so the route path differs from it.

**Marked routes.** `marked_routes` are the host's operations besides the entry point that take the same token.

- **RESOURCE-39** `marked_routes` is a `frozenset` of `MarkedRoute(method, template)`, else `TypeError`.
- **RESOURCE-40** It is empty by default, so a resource has only its entry point.
- **RESOURCE-41** `method` is one upper-case HTTP method token, else `ValueError`.
- **RESOURCE-42** `template` is one or more `/`-separated segments, each a literal of unreserved characters
  or one `{name}` filling the whole segment.
- **RESOURCE-43** Any other `template` is a `ValueError`: a converter, a partial parameter, an empty segment, a
  trailing slash, a missing leading `/`, a literal `.` or `..` segment or a literal of other characters.
- **RESOURCE-44** The match is exact, on the route path: the method equals, the segment count equals, each literal equals, each parameter is one non-empty segment other than `.` and `..`.
- **RESOURCE-45** A trailing slash, `HEAD` on a marked `GET`, a longer path below a template and a decoded `/` in a parameter do not match.
- The gate selects machine path, entry point, marked route, person path:
  - **RESOURCE-46** a marked template overlapping a machine path stays a machine path;
  - **RESOURCE-47** a marked route at the entry point is decided as the entry point;
  - **RESOURCE-48** a marked route below a person path is decided as the marked route.

On a marked route:

- **RESOURCE-49** With no bearer credential the session decides as without the marking.
- **RESOURCE-50** With no bearer credential CSRF decides as without the marking.
- **RESOURCE-51** Another scheme is no bearer credential.
- A token whose audience is not the resource (the resource's check refuses it as `INVALID_AUDIENCE`) goes on exactly as unmarked:
  - **RESOURCE-52** a person path runs its complete check;
  - **RESOURCE-53** any other path ignores the bearer;
  - **RESOURCE-54** it is never a resource admission.
- Any other refusal answers there as at the entry point with the challenge, a valid cookie beside it deciding nothing:
  - **RESOURCE-55** a refused credential;
  - **RESOURCE-56** an invalid or expired token, and a token naming the resource among audiences its check does not admit;
  - **RESOURCE-57** `insufficient_scope`.
- A token that holds runs the entry point's admission:
  - **RESOURCE-58** the groups lack `required_group`: the plain 403;
  - **RESOURCE-59** the groups lack the admission's login group: the plain 403;
  - **RESOURCE-60** no account has the subject, for a token without the agent group: the plain 403;
  - **RESOURCE-61** a stored admin on an `admin_user` route: the plain 403;
  - **RESOURCE-62** the capped person is recorded for the request's method, so CSRF and the session gate step aside;
  - **RESOURCE-63** `current_user`, `admitted_user` and `resource_person` return the capped person.
- **Host duty:** The gate runs before routing, so prove that every request a marked route permits resolves to a marked operation (no earlier unmarked route shadows the template).
- **Host duty:** Mark no operation in a deletion area and no admin operation, because the role cap keeps neither out (an ordinary user may delete, and an admin operation only answers 403).
- **Host duty:** Let the token reach a marked route directly, not only through the entry point.
- **RESOURCE-64** Responses on a marked route are the host's own and carry no `no-store`, as on a person path.

`webauth.middleware.resource_person(connection)`:

- **RESOURCE-65** at the entry point `resource_person` and `current_user` return the capped person for this very request;
- **RESOURCE-66** `resource_person` raises `RuntimeError` on a session, person or machine request;
- **RESOURCE-67** at the entry point `resource_person` raises `RuntimeError` in a sub-app, and after the `Authorization` header or the method changed;
- **RESOURCE-68** the same on a marked route;
- **RESOURCE-69** `current_user` refuses after a method change, at the entry point and on a marked route.

`webauth.middleware.is_resource_admission(connection)`:

- **RESOURCE-81** it is true for this very request at the resource's entry point and on a marked route, with agent facts or without;
- **RESOURCE-82** it is false on a session, on a person-path token (on a marked route below a person path too, and for a token of another audience on a marked route), on a machine request, on a request without a credential, on a WebSocket, and in an app without a bearer gate;
- **RESOURCE-83** it raises `RuntimeError` where a bearer admission is recorded but no longer holds for this request: in a sub-app, and after the `Authorization` header or the method changed. Otherwise it never raises.

## The exchange of an admitted token

An app whose protected resource admitted a caller's token acts for that caller at another service by exchanging the token at the issuer (RFC 8693).
`await webauth.middleware.exchanged_access_token(connection, scopes=...)` answers an `ExchangedAccess` (`access_token`, a `SecretStr`, and `expires_at`, whole wall-clock seconds) or an `OidcRefusal`.

- **EXCHANGE-01** It raises `RuntimeError` exactly where `resource_person` raises (RESOURCE-66 to RESOURCE-68): on a session, person or machine request, in a sub-app, after the `Authorization` header or the method changed, and on a WebSocket. Nothing is posted.
- **EXCHANGE-02** It then reads the credential again with the gate's one grammar, and any refusal of that reading is the same `RuntimeError`, which can only happen when `access_token` was added to the query after admission.
- **EXCHANGE-03** `scopes` is judged after the admission, by the rule and with the message of `workload_access_token`: a non-empty tuple of RFC 6749 scope tokens, else `ValueError`, and nothing is posted.
- **EXCHANGE-04** The token is posted only to the token endpoint of the relying party whose gate admitted it, as that gate's client, `client_secret_basic`; the admission record carries that relying party's grant, so no registry and no relying-party argument exists.
- **EXCHANGE-05** The form is `grant_type=urn:ietf:params:oauth:grant-type:token-exchange`, `subject_token` byte for byte, `subject_token_type` and `requested_token_type` both `urn:ietf:params:oauth:token-type:access_token`, and `scope` the `scopes` joined by one space; it names no `audience` and no `resource`. Nothing is cached or locked, so each call is one post.
- **EXCHANGE-06** The post runs on a worker thread, not on the event loop.
- **EXCHANGE-07** A cancelled caller gets no answer, and its cancellation arrives after the post ends (GROUPS-30).
- **EXCHANGE-08** An accepted answer holds the workload grant's bearer token (`token_type` compared in ASCII case-insensitively, an `access_token` of RFC 6750's `b64token` shape), an `issued_token_type` equal to `urn:ietf:params:oauth:token-type:access_token` and an `expires_in` that is a whole number of at least 1 (`bool` and `float` are not); `expires_at` is the wall clock read before the post, in whole seconds, plus `expires_in`. `refresh_token` and `scope` are not read.
- **EXCHANGE-09** Any other answer, a transport error, an answer that is not JSON and an answer without an `error` code on a refused status is `TOKEN_ENDPOINT_FAILED`; requiring `expires_in` is stricter than RFC 8693 section 2.2.1, which recommends it.
- **EXCHANGE-10** Unlike every other grant, a 403 with an `error` code is `TOKEN_REQUEST_REFUSED` with that code (as 400 and 401 are); the issuer's free text is never carried.
- **EXCHANGE-11** It never returns, stores or logs the admitted token; the host sees only the exchanged one.
- **EXCHANGE-12** The exchanged expiry is never compared with the admitted token's; it can lie after it.
- **EXCHANGE-13** The admission is no freshness proof: the issuer judges the subject token, so a call late in a long request can be refused.
- **EXCHANGE-14** The exchanged token's audiences are what the realm gives the requested scopes; the call names none.
- **Host duty:** `scopes` come from the host's configuration, never from the request. Admission at the resource proves access to the resource, not agreement to a downstream scope; what the app may obtain for a principal is the issuer's policy (the realm offers the scope to the app's client) and the service's group check.
- **Host duty:** A held exchanged token is keyed by `resource_person(connection).id` of the same request.
- **Host duty:** At most one exchange is in flight per principal, and a refusal is not retried on every request; the post runs on the worker threads the gate's verifier uses.
- **Host duty:** A resource whose token must be exchangeable declares `admits_client_audience=True` (RESOURCE-18).
- **Host duty:** A host's test passes its own `post_token_request` to the gate's relying party and answers this grant type there (beside HOSTTEST-04).

The operator ruled the sentence that says the call exists for every app and names the delegation policy: the issuer grants an exchanged scope only when the realm offers it to the app's client, and the service alone checks that the principal is in its group. No other sentence here is ruled.

## A service's callers

A service that is not a browser app (no sessions, no sign-in) admits an app acting for a person, with
`ServiceCallerCheck` of `webauth.service_callers`. The service builds one per process from a
`ServiceIdentity` (issuer, key-set URL, its own audience, the realm role that marks a workload, the group
claim, the clock leeway) and its registered apps (`RegisteredApp`, keyed by the workload client id).

- **CALLER-01** nothing has a default;
- **CALLER-02** nothing is read from the environment;
- **CALLER-03** `person_caller(workload_token, person_token)` is synchronous;
- **Host duty:** an async service runs `person_caller` in a thread.

- **CALLER-04** it returns a `PersonCaller` (the app, the client id, the person's `Principal` and groups, and the
  person's `AppRole`) or a `CallerRefusal`;
- **CALLER-05** it never says which token a refusal concerns;
- **CALLER-06** both tokens are verified and read before any check that compares them, so every `UNAUTHENTICATED` and
  `UNAVAILABLE` refusal comes before any `FORBIDDEN` one;
- **CALLER-07** the checks run in this order: the workload token is checked for a missing token and then by the
  verifier, then the person token the same way; then the workload token's subject and groups, then the person
  token's; then the rows from `NOT_A_WORKLOAD` down, in table order. The first fault is the refusal;
- **CALLER-08** `CallerRefusal.refusal_class` names its `CallerRefusalClass`;
- **Host duty:** the host owns the wire codes, here the recommended ones.

The table lists each reason where it is first checked:

| ID | Reason | Fault | Class |
|---|---|---|---|
| **CALLER-09** | `MISSING_TOKEN` | the workload token, then the person token, is absent or empty | `UNAUTHENTICATED` (401) |
| **CALLER-10** | `KEY_SET_UNAVAILABLE` | the verifier cannot fetch the key set, see below | `UNAVAILABLE` (503) |
| **CALLER-11** | `TOKEN_REJECTED` | the verifier refuses either token, see below | `UNAUTHENTICATED` (401) |
| **CALLER-12** | `INVALID_SUBJECT` | `sub` absent or not valid text, in the workload token, then in the person token | `UNAUTHENTICATED` (401) |
| **CALLER-13** | `MALFORMED_GROUPS` | the group claim is present and not a list of strings, in the workload token, then in the person token | `UNAUTHENTICATED` (401) |
| **CALLER-14** | `NOT_A_WORKLOAD` | the workload token's `realm_access.roles` lacks the workload role | `FORBIDDEN` (403) |
| **CALLER-15** | `UNBOUND_CLIENT` | the workload token's `azp` is absent or empty, or its `client_id` differs from it | `FORBIDDEN` (403) |
| **CALLER-16** | `UNREGISTERED_CLIENT` | the workload token's `azp` is no registered app | `FORBIDDEN` (403) |
| **CALLER-17** | `CLIENT_MISMATCH` | the person's `azp` is not the workload's `azp` | `FORBIDDEN` (403) |
| **CALLER-18** | `SAME_SUBJECT` | the person's subject is the workload's | `FORBIDDEN` (403) |
| **CALLER-19** | `NOT_A_MEMBER` | the person's groups make no member of the app, by `app_role` and the registered admission | `FORBIDDEN` (403) |

**CALLER-20** Neither token's lifetime is bounded beyond its `exp` against the clock; the issuer owns it.

**CALLER-21** The person token gets no role check.

**CALLER-22** The person token's `azp` is the client binding and is never evidence of an exchange.

The verifier stage keeps the verifier's own order:

- **CALLER-23** a malformed header or unsupported algorithm is `TOKEN_REJECTED` before any key lookup, so no key set
  is fetched;
- **CALLER-24** `KEY_SET_UNAVAILABLE` (503) is the verifier's refusal when the key set cannot be fetched and the
  token's key is not among the cached ones, also when other keys are cached;
- **CALLER-25** with a usable cached key, a failed refresh still verifies;
- **CALLER-34** any token verification, not only a service caller's, that finds no current key set while another
  request refreshes waits for that refresh, at most `KEY_SET_REFRESH_WAIT_SECONDS`, unless the last refresh attempt
  failed; it then uses the key set the refresh left or is refused `KEY_SET_UNAVAILABLE`;
- **CALLER-26** every other verifier refusal is `TOKEN_REJECTED` (401) with its `token_rejection`.

By class: `UNAVAILABLE` (503) is `KEY_SET_UNAVAILABLE`; `UNAUTHENTICATED` (401) is `MISSING_TOKEN`, `TOKEN_REJECTED`,
`INVALID_SUBJECT` and `MALFORMED_GROUPS`; `FORBIDDEN` (403) is `NOT_A_WORKLOAD`, `UNBOUND_CLIENT`,
`UNREGISTERED_CLIENT`, `CLIENT_MISMATCH`, `SAME_SUBJECT` and `NOT_A_MEMBER`.

- **CALLER-27** a group claim that is a JSON `null` is `MALFORMED_GROUPS`;
- **CALLER-28** only an absent group claim means no groups;
- **CALLER-29** the token's `aud` must name the service;
- **CALLER-30** the token's `aud` may name others;
- **CALLER-31** the check has no policy;
- **Host duty:** which groups reach which route is the service's;
- **CALLER-32** nothing taken from a token (subject, client id, groups) appears in a repr, an error message or a log
  record of the module;
- **CALLER-33** `jwks_url` is left out of the repr of `ServiceIdentity`.

## The sign-in routes

The operator ruled the host duty that a single-page app logs out by a top-level form POST; SIGNIN-58; the host duty that a host serving no logout route passes `False`; SIGNIN-60; SIGNIN-61; no other sentence of this section is ruled.

- **SIGNIN-01** `install_sign_in_routes` registers the start, callback, logout and back-channel logout routes on the host's
  `FastAPI` app.
- **SIGNIN-02** Every route reads the host's one `OidcRelyingParty` through `relying_party` per request.

`install_web_auth_middleware` takes the host's `SignInPaths` and applies the policies for exactly those paths:

- **SIGNIN-03** the session gate's public rules, when a session gate is installed (`GET` of start and callback, `POST` of logout and of the back-channel);
- **SIGNIN-04** the sign-in rate budget on start, callback and logout;
- **SIGNIN-05** the back-channel path is exempt from the origin check;
- **SIGNIN-06** the back-channel path is exempt from the rate limit;
- **SIGNIN-07** a body rule of 32 KiB for `POST` of the back-channel path;
- **SIGNIN-08** `no-store` on every sign-in path;
- **SIGNIN-09** `SignInPaths.login_redirect` is the one derived value the host passes itself, to its session gate.

So the host lists the paths once. `login_redirect` is browser-absolute, so it is right for an app at its origin's root.

- **Host duty:** a host below a `root_path` builds its own `LoginRedirect`.
- **SIGNIN-64** `sign_in_paths` is a required argument of `install_web_auth_middleware`; without it the call raises `TypeError`.
- **SIGNIN-65** The derived rules come ahead of the host's own in every policy, so the first match is the derived one (a host exemption wins: SIGNIN-69).
- **SIGNIN-66** The sign-in budget is `RateLimitPolicy.sign_in`, 40 requests per 600 seconds per address unless the host's policy sets another, and it is the first rate rule.
- **SIGNIN-67** The name of the `sign_in` budget (`"sign-in"` unless the host renames it) is reserved: a `RateLimitPolicy` whose default or rule carries it raises `ValueError` naming it when it is built.
- **SIGNIN-68** A `SignInPaths` without `logout` or `backchannel_logout` derives no rule for the route it leaves out.
- **SIGNIN-69** A path in the host's `RateLimitPolicy.exempt` spends no budget, a sign-in path included.
- **SIGNIN-70** The rate limit counts every method on a path, so `HEAD` and `OPTIONS` on a sign-in path spend the sign-in budget; a host's CORS middleware installed outside the stack answers preflights first.
- **SIGNIN-10** The library serves the logout route at `SignInPaths.logout` for `POST` only,
- **SIGNIN-11** with the page's text from the host's `logout_page_text`, read per request:
- **SIGNIN-12** a `LogoutPageText` whose `button_label` is the title and the button,
- **SIGNIN-13** and whose `language` is the page's `<html lang>`;
- **SIGNIN-14** `language` is a BCP 47 tag, validated in shape when the record is built.
- **Host duty:** a single-page app logs out by a top-level form POST to that route.
- **Host duty:** the host never lists the logout path in `CsrfPolicy.exempt`.
- **SIGNIN-15** `paths.logout` and `logout_page_text` come together,
- **SIGNIN-16** or both are `None` for a host without logout.

- **SIGNIN-17** `webauth.cookies` carries the pending login in a signed cookie of its own, one per login.

So the library keeps no server-side store and `WebAuthConfig` knows nothing
of OpenID Connect. The `webauth.sign_in_routes` module and `install_sign_in_routes` docstrings hold the routes' contract, the
`webauth.oidc_login` and `webauth.cookies` module docstrings hold the login and its
cookies, and `build_app` in [`tests/e2e/oidc/host_app.py`](../tests/e2e/oidc/host_app.py)
is the worked host, type-checked and run against a real issuer.

- **Host duty:** the host supplies a `SignInTransaction` (`webauth.ports`) and a `refused` hook.
- **SIGNIN-18** The callback enters the transaction once,
- **SIGNIN-19** only after the issuer's code exchange and the pure admission decision, so no issuer call runs inside it,
- **SIGNIN-20** and a refusal before admission enters none.
- **SIGNIN-21** It writes the account and the session through `SignInStores`
- **SIGNIN-22** and issues the session cookie only after the transaction's exit returned.

**SIGNIN-23** The library never commits: a successful exit makes the writes durable.

What is rolled back is the host's choice:

- **SIGNIN-24** an exception in the block escapes through the exit, and a rolling-back host keeps none of the account created, the sessions ended and the events recorded;
- **SIGNIN-25** a host whose stores apply each call keeps the account created and the events recorded before the failure;
- **SIGNIN-26** a host whose stores apply each call keeps the sessions ended by replacement or pruning;
- **SIGNIN-27** a host whose stores apply each call opens a new session at its next sign-in after a failure and restores nothing.

The hook:

- **SIGNIN-28** receives a `SignInRefusal` (the cause and its `page`) for every refusal
- **SIGNIN-29** and returns any `Response`.
- **SIGNIN-30** Every callback answer sent after the pending cookie was selected carries its deletion,
- **SIGNIN-31** also when the hook raises or the answer fails before it starts: the
  route then sends a plain 500 with the deletion and raises the failure.
- **SIGNIN-32** Other tabs' pending cookies stay.

A pending login is single-use because its cookie is cleared and the
issuer accepts a code once; webauth keeps no replay store.

**SIGNIN-33** The logout route never commits:

- **SIGNIN-34** it enters the transaction once,
- **SIGNIN-35** only when the request's cookie names a session.
- **SIGNIN-36** An exception in the route answers a plain 500 with no page and no cookie cleared.
- **SIGNIN-37** An exception in the transaction, on entering it or at its exit, answers the same.
- **SIGNIN-38** An exception in the host's callables answers the same.
- **SIGNIN-39** A rolling-back host keeps the session, and a retry ends it with its hint.
- **SIGNIN-40** Under per-call persistence or an uncertain commit the row and its ID token may already be gone, and a retry still reaches the
  issuer's end-session page, without the hint.

The back-channel logout route:

- **SIGNIN-41** `SignInPaths.backchannel_logout` serves the issuer's back-channel logout for `POST` only,
- **SIGNIN-42** and must differ from every other path, `logout` included.
- **SIGNIN-43** Only that exact path is exempt from the origin check, and logout is never exempt;
- **SIGNIN-44** only that exact path is exempt from the rate limit, and logout is never exempt.

The answers are, in order:

- **SIGNIN-45** 413 for a declared `Content-Length` over the bound, before the body is read;
- **SIGNIN-46** 413 for a streamed body over the bound;
- **SIGNIN-47** an empty 400 for a request that is not one URL-encoded form with exactly one
  non-empty `logout_token`, before any transaction is entered;
- **SIGNIN-48** an empty 400 for a token that does not verify, before any transaction is entered;
- **SIGNIN-49** an empty 200 after the clean exit of one `SignInTransaction` entry;
- **SIGNIN-50** an empty 400, then the failure re-raised, for any exception in `relying_party`, the verification, a store, the audit
  sink or the exit.

- **SIGNIN-51** A subject without an account is accepted and provisions nothing;
- **SIGNIN-52** a known subject loses every session in every browser,
- **SIGNIN-53** and one `BACKCHANNEL_LOGOUT` event with `actor_id=None` is recorded when at least one session ended.
- **SIGNIN-54** The route clears no cookie
- **SIGNIN-55** and calls no issuer endpoint beyond the key fetch of verification.
- **SIGNIN-56** `relying_party` receives the request with the Host the issuer posted to, often an internal alias.

- **Host duty:** the host's transaction rolls back when the back-channel block raises, also when the audit
  sink fails after the deletion.
- **Host duty:** the host's transaction commits only for an accepted token.
- **SIGNIN-57** A per-call host keeps the sessions ended before the failure, and no event is emitted again.

The back-channel route is open to anyone who can reach it, and the token is its only control.

- **Host duty:** the host lets the issuer reach it over an internal network alone, never the public route
  (tunnel, CDN, access proxy); its URL may name the public hostname through an internal alias.

- **SIGNIN-58** `install_sign_in_routes` requires the host's explicit `keeps_id_token` choice, with no
  default,
- **SIGNIN-59** and validates `max_sessions` before it registers a route.
- **Host duty:** a host that serves no logout route passes `False`.
- **SIGNIN-60** With `False`, its session row keeps no ID token, while refresh-token storage is unchanged.
- **SIGNIN-61** With `True`, the row keeps the login's ID token for logout.
- **SIGNIN-62** Renewal and refresh-token rotation preserve the original token of a row that keeps it,
- **SIGNIN-63** and the choice of a row that keeps none.

## The single-process stores

`webauth.single_process_stores` implements the account, session and sign-in transaction ports in the memory of one process, for a host that runs one worker.

- **Host duty:** one worker only, because a restart forgets every account and session and a second worker sees none of the first's. A host with several workers, or one that keeps sessions across a restart, implements the ports over its database.
- **MEMSTORE-01** `SingleProcessStores(audit=...)` bundles `accounts` (a `SubjectUserStore`), `sessions` (a `SessionRecordStore`) and `transaction` (a `SignInTransaction`) over one set of tables; the host passes its own `AuditSink`, and webauth ships no logging sink.
- **MEMSTORE-02** A session id is distinct, URL-safe, 43 to 135 characters, and drawn from a CSPRNG.
- **MEMSTORE-03** `get` compares the subject character for character: no case, trailing-space or Unicode-normalization folding.
- **MEMSTORE-04** `set_role`, `set_kind` and a session `create` for a missing account raise.
- **MEMSTORE-05** `touch` and `replace_refresh_token` on a missing session answer `False` and create no row.
- **MEMSTORE-06** `touch` writes the `expires_at` it is given and keeps both tokens; `replace_refresh_token` keeps the ID token.
- **MEMSTORE-07** `delete` of an unknown id is a no-op.
- **MEMSTORE-08** `prune_overflow` keeps the newest sessions by `created_at`; `0` keeps none.
- **MEMSTORE-09** `delete_for_user` ends every session of the account, returns how many ended, and removes the account too: an account that outlives its sign-out serves nothing in memory, and the next sign-in creates it again, so its `USER_CREATED` event is true.
- **MEMSTORE-10** `create_for_subject` never raises `UsernameTakenError` and has no flag: the username is for display and the issuer decides who a subject is, so a raise would lock a re-created person out until a restart.
- **MEMSTORE-11** `load` returns an expired row, as the port says; the gate decides expiry.
- **MEMSTORE-12** `delete_expired(now)` removes the expired sessions and returns how many; `create` prunes the sessions expired at its `now`.
- **MEMSTORE-13** An entry of the transaction holds one re-entrant guard from enter to exit, so a second entry, and every store call from another thread, waits until the first exits; an entry whose enter fails gives the guard back.
- **MEMSTORE-14** Store calls from several threads leave the stores consistent.
- **MEMSTORE-15** A raise inside an entry restores both stores from a snapshot taken at entry and drops the entry's audit events; a clean entry hands them to the sink as its last step.
- **MEMSTORE-16** A sink that fails at the exit rolls the entry back and its exception reaches the route.
- **MEMSTORE-17** Entering an entry again raises; the transaction hands out a new entry per call.
- **MEMSTORE-18** `sessions.records_of(subject)` returns the account and, for each session oldest first, its start, its expiry and whether it holds a refresh token and an ID token; it returns no session id and no token.
- **MEMSTORE-19** `StoredAccount` and `StoredSession` implement `UserRecord` and `SessionRecord`.
- **MEMSTORE-20** The sign-in routes and the session gate hold over the adapter: callback, gate, logout and back-channel logout.
- **MEMSTORE-21** `create` keeps the account's language it is given on the session, and `load` returns it.
- **Host duty:** an entry copies both tables, so its cost grows with the stored accounts and sessions; keep the store small by calling `delete_expired` on a timer.

The adapter has no public guard, no write-lock class and no `SessionTransaction` class: the port's own docstring names `lambda: nullcontext(sessions)`.

## Testing a host

A test that needs a signed-in person needs no issuer:

- **Host duty:** it creates the account and a session inside the configured lifetime in the host's own store, or in `SingleProcessStores` ([the single-process stores](#the-single-process-stores)).
- **HOSTTEST-01** `issue_session_cookies(response, session_id, config)` from `webauth.cookies`, called on a `Response`, sets one cookie.
- **Host duty:** it copies that cookie into its client.
- **HOSTTEST-02** A request with that cookie and that session in the store is admitted as that person on a session path.
- **HOSTTEST-03** A state-changing request is admitted the same way when it also sends `Sec-Fetch-Site: same-origin` ([CSRF origin](#csrf-origin)).
- **Host duty:** when the client keeps the cookie's attributes and `cookie_secure` is on, it uses an `https` base URL.

A test of a host that installs the sign-in routes:

- **HOSTTEST-04** `OidcRelyingParty` takes its own `post_token_request` (a `TokenRequestPost`, from
  `webauth.oidc`) and `fetch_key_set` (a `KeySetFetch`, from `webauth.jwt_verification`) instead of the HTTPS ones,
  and the callback route then makes no HTTPS call.
- **Host duty:** the host owns that stub.

The sign-in flow itself is proven against a real issuer: webauth's own proof
drives Keycloak in a real browser ([run the browser
proof](runbooks/run-the-browser-proof.md)).

- **Host duty:** a host proves its own sign-in against an issuer of its choosing.

webauth ships no fake issuer, because one that mints tokens does not belong in every production install.
