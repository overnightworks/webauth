# Changelog

All notable changes to `overnightworks-webauth` are recorded here, after
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/). While the version is
0.x, a minor release may break a public contract and says so under **Breaking**.
Versions before 0.3.0 and releases without an entry here are described in the
[GitHub release notes](https://github.com/overnightworks/webauth/releases).

## 0.18.0 - Unreleased

**Breaking**

- `WebAuthConfig` refuses a `session_cookie_name` or `csrf_cookie_name` that is
  one of webauth's own cookies, in either variant: the ID token hint cookie
  (`__Secure-oidc_id_token_hint`, `oidc_id_token_hint`) or a name starting with
  the pending-login prefix (`__Host-oidc_pending_`, `oidc_pending_`). Such a
  name made the browser send two same-name cookies at logout, and the logout
  ended no stored session. Migration: choose another name; no known host sets
  one.
- `SessionIdentityChanged.session_ref`, `AccountEvent.session_ref` and
  `SessionSummary.session_ref` are typed `webauth.ports.SessionReference`, no
  longer `str`: host code that constructs these dataclasses with a plain `str`,
  including an already-hashed reference, fails type checking. Migration:
  construct them with `webauth.cookies.session_reference(raw_session_id)`.
  Hosts that only read the fields are unaffected.
- `WebAuthConfig` refuses an empty `allowed_hosts_exact` together with an empty
  `allowed_hosts_patterns`; the silent fallback to `localhost` and `127.0.0.1`
  is gone. Migration: `allowed_hosts_exact={"localhost", "127.0.0.1"}` admits
  exactly what the fallback admitted.
- `webauth.middleware.security_headers.STRICT_TRANSPORT_SECURITY` is removed;
  `SecurityHeadersPolicy.strict_transport_security` renders the header. Its
  default value is unchanged.

- `post_token_request_over_https` moved from `webauth.oidc_login` to the new
  `webauth.oidc_transport`, and `webauth.jwt_verification` no longer
  re-exports `ExchangeFailure`, which `webauth.https_client` owns. Migration:
  `from webauth.oidc_transport import post_token_request_over_https` and
  `from webauth.https_client import ExchangeFailure`. The old imports fail with
  `ImportError` when they execute.

**Added**

- `webauth.ports.SessionReference`, a `NewType` over `str`, is the type of
  `SessionIdentityChanged.session_ref`, `AccountEvent.session_ref` and
  `SessionSummary.session_ref`, and `webauth.cookies.session_reference` returns
  it. A type checker now refuses a raw session id when an audit event is
  constructed or assigned with one. Hosts that read these fields as `str` are
  unaffected, at run time and in their own types.
- `SecurityHeadersPolicy.hsts_max_age_seconds` (default
  `DEFAULT_HSTS_MAX_AGE_SECONDS`, 31536000, a whole number
  from 0 up; 0 sends `max-age=0`, which rolls a pin back) and
  `hsts_include_subdomains` (default `True`). The defaults send today's header;
  `cookie_secure` still decides whether HSTS is sent at all.

**Fixed**

- A keyword source added to a Content-Security-Policy (`'SELF'`) is lowercased,
  so it no longer repeats the default `'self'`. Host sources, paths, nonces and
  hashes keep their case.

**Changed**

- `max_user_agent_chars` is validated like the other positive quantities: its
  refusal reads `max_user_agent_chars must be a positive whole number of
  characters, not ...`.

## 0.17.0

**Added**

- `webauth.oidc_login.open_session(request, config, account, *, sessions, lock,
  expires_at, max_sessions)` opens an admitted account's session in one call
  under the host's lock: it ends the session the request's verified cookie
  names, creates the new one, and with a cap ends the account's oldest sessions
  last. `max_sessions` is required (`None` states no cap) and must otherwise be
  a positive whole number. It raises `RuntimeError`, so the host rolls back, when
  the store returns the replaced session's id or `prune_overflow` would end the
  new session. When the store returns the replaced session's id, it ends that
  session before it raises, so no session stays under the id the incoming
  cookie named even without a rollback. It never commits and sets no cookie:
  the host commits, then issues the cookies.

## 0.16.0

**Breaking**

- Admission and logout through the OIDC relying party.
  - `finish_login` and `admit_identity` take `admission: AdmissionConfig`
    instead of `bound_issuer: str`. `AdmissionConfig(bound_issuer=...,
    login_group=...)` requires the app's group path (or
    `EverySubject.OF_THE_BOUND_ISSUER`, to admit every subject of the issuer on
    purpose); a missing `login_group` is a `TypeError` and a malformed one a
    `ValueError`. A person who is in neither `login_group` nor a subgroup of it
    is refused with the new `AdmissionRefusal.NOT_A_MEMBER` before any account
    is looked up or created. The README now recommends a 12-hour session
    instead of 30 days, since an open session is not re-checked.
  - `AdmissionConfig` also requires `admin_group`: a group path (such as
    `/apps/songmaker/admin`), or `NoAdmins.IN_THIS_APP` when the app has no
    admins. When `login_group` is a group path, `admin_group` must lie
    strictly below it; under `EverySubject.OF_THE_BOUND_ISSUER` any valid
    group path is allowed. A missing `admin_group` is a `TypeError`; an
    `admin_group` that is malformed, or not below a `login_group` that is a
    group path, is a `ValueError`. Admission now sets the account's role at every login:
    `admin_role` for a member of `admin_group`, otherwise `user_role`, so a
    stored role is overwritten (a stored role other than `admin_role` and
    `user_role` becomes `admin_role` when the identity belongs to
    `admin_group`, otherwise `user_role`), and each change on a returning account is
    audited as `AccountEventKind.ROLE_CHANGED` with `previous_role` (a new
    field on `AccountEvent`). `SubjectUserStore` gains `set_role(user_id, role)
    -> UserRecord`, which changes the role in the caller's transaction and
    never commits.
  - Migration, before upgrading, or everyone is locked out or demoted: when
    `login_group` is a group path, put every person who signs in into it (or a
    subgroup), or they are refused as `NOT_A_MEMBER`, and turn on `full.path`
    in the client's group membership mapper, or the claim carries bare names
    and everyone is refused (under `EverySubject.OF_THE_BOUND_ISSUER`
    identities without groups are admitted); put the admins into `admin_group`,
    created per app at its cutover (edge#50, edge#20 row 10), or a stored admin
    is demoted at their next login.
  - `OidcClientConfig` requires the keyword fields `end_session_endpoint` and
    `post_logout_redirect_uri`; both are https URLs under the same rules as the
    other endpoints, and a missing one is a `TypeError`. A host that does not
    want the issuer's logout does not call `log_out`.
    `OidcRelyingParty.logout_url()` answers the end-session URL, and the new
    `webauth.oidc_login.log_out(relying_party, request, response, config, *,
    sessions, lock)` ends the session the request's cookie names, clears the
    session cookies and returns that URL, so an app's logout also ends the
    browser's Keycloak session; with the ID token hint (next entry) Keycloak
    asks nothing, and without one it asks the person to confirm once. It
    ends only this browser's app session; ending the person's other sessions
    is the back-channel logout (under Added). Migration: register each app's
    post-logout redirect URI (`post.logout.redirect.uris`) on its Keycloak
    client, in edge's `realm.yaml`, before upgrading; a host whose logout is a
    form adds the end-session endpoint's origin to `form-action`, and protects
    `/logout` with the origin check and a `token_exempt` rule (README,
    "Logging out").
- Signing out asks nothing at Keycloak: the login's ID token travels as the
  `id_token_hint`.
  - `OidcClientConfig` requires the keyword field `logout_path`, the
    browser-visible path of the host's logout route or a parent of all its
    logout routes (such as `/logout`). It starts with `/` and holds only RFC
    3986 path characters other than `;`; a malformed value is a `ValueError`
    and a missing one a `TypeError`. `OidcRelyingParty.logout_path` exposes it.
  - `OidcIdentity` gains the required field `id_token`, the verified ID token
    as received (`repr=False`). A host or test that constructs an
    `OidcIdentity` itself passes it.
  - `finish_login` sets the cookie `__Secure-oidc_id_token_hint`
    (`oidc_id_token_hint` with `cookie_secure=False`) on an admitted login,
    `Path=logout_path`, `HttpOnly`, `SameSite=Strict`, with the session
    cookie's `Max-Age`; an ID token longer than the new
    `webauth.cookies.MAX_ID_TOKEN_HINT_CHARS` (3072) is not kept, and an older
    hint is cleared instead. `log_out` sends it as `id_token_hint` through
    `OidcRelyingParty.logout_url(*, id_token_hint=None)` and clears it. The
    hint is never decoded, verified or accepted as a credential; an unusable one
    is left out and Keycloak asks once. Because the logout is a GET, the hint
    reaches the browser's history and the TLS-terminating edge (README, "The
    ID token hint").
  - Migration: add `logout_path` to the `OidcClientConfig`; `finish_login` and
    `log_out` take a relying party built from that one `OidcClientConfig` and
    the same `WebAuthConfig`, or the logout finds no hint and Keycloak asks.
    A person signed in
    before the upgrade has no hint cookie and is asked once at their next
    logout.
- `RateLimitClass` is gone, and `RateLimitPolicy` takes `default` and `rules`
  instead of `budgets`, `media` and `stream`. `RateLimitBudget` gains a
  leading `name` (lowercase letters, digits, `-` and `_`, starting with a
  letter); an invalid name string or a repeated name is a `ValueError`.
  `RateLimitRule(paths, budget)` is new, and the first matching rule decides.
  `classify` and `budget` become `budget_for(path)`. The limiter keys are now
  `<name>:<address>`, so budgets start fresh and the old `API:`, `MEDIA:` and
  `STREAM:` keys expire within one window. Migrating the former three classes:
  `default=RateLimitBudget("api", ip_limit, w)`,
  `rules=(RateLimitRule(media_paths, RateLimitBudget("media", media_limit, w)),
  RateLimitRule(stream_paths, RateLimitBudget("stream", stream_limit, w)))`,
  media first as before; `policy.classify(p) is RateLimitClass.API` becomes
  `policy.budget_for(p) is policy.default`, and
  `policy.budget(RateLimitClass.API)` becomes `policy.default`.
- `RateLimitBudget` refuses, with a `ValueError` naming the budget and the
  field, a `max_requests` or `window_seconds` that is not a positive `int` (`0`,
  a negative number, a `bool`, a `float`, a `str` or `None`). Before, a window
  of `0` or less made both backends admit every request. A host that passed
  such a value must now pass a positive whole number.
- `IpRateLimitMiddleware` calls `RateLimitBackend.is_allowed` from a worker
  thread, so a slow limiter no longer stalls the event loop; a host's own
  backend must be thread-safe (both library backends are). A check holds its
  worker thread until the backend answers, so give a Redis client short
  timeouts and few retries (README, "Rate limiting").
- `RedisRateLimitBackend` needs Redis 5.0 or later, or Valkey; v0.15.0 stated
  no floor. See Fixed.
- `WebAuthConfig.session_cookie_name` and `csrf_cookie_name` are annotated
  `str`, with the library's default as their default, and are refused unless
  they are an RFC 6265 token and distinct from each other; a name that is empty,
  or contains a space, a control character, a non-ASCII character or any of
  `( ) < > @ , ; : \ " / [ ] ? = { }`, is not a token and is refused. An
  explicit `None` (or any other non-`str`) raises `ValueError`,
  so `dataclasses.replace(config,
  session_cookie_name=None)` no longer resets the field to the default: leave
  the field out of `replace` instead. Starlette's `set_cookie` raised
  `http.cookies.CookieError` for every invalid name except one containing `:`,
  which RFC 6265 forbids as well, so the host failed at its first sign-in;
  equal names would make one cookie overwrite the other. A host that set
  either now fails at start instead.
- `default_content_security_policy()` writes `base-uri 'self'` after
  `default-src 'none'` and ends with `form-action 'self'`, so a `<base>` may
  point only at this origin and a form may submit only to it. Neither directive
  falls back to `default-src`, so both were unrestricted before. A host whose
  form posts to, or is redirected to, another origin (such as an issuer's
  authorization endpoint behind a sign-in form, or its end-session endpoint
  behind a logout form) adds that origin to `CspDirective.FORM_ACTION`.
- `UserManagementEvent`, `UserManagementEventKind` and
  `AuditSink.user_management_event` are renamed `AccountEvent`,
  `AccountEventKind` and `AuditSink.account_event`. Update the imports and
  implement the sink as `account_event`; payloads and the serialized values of
  the existing kinds are unchanged. `AccountEventKind` gains `ROLE_CHANGED`
  (with `AccountEvent.previous_role`) and `BACKCHANNEL_LOGOUT`. A sink that
  refuses an unknown kind must map both, because whatever it raises propagates
  and the host rolls back.
- `UserManagementError` is removed. Use `WebAuthError` for the wider catch, or
  catch `(UsernameTakenError, NotAnAdminError, UnknownSessionError)` to keep
  the previous catch set.
- `SessionAdministrationStore` no longer declares `count_active`. A host may
  keep its own; a caller that needs a total uses its concrete store or a
  host-owned interface.
- `SessionRecordStore.delete` must treat an id the store does not hold as a
  no-op, never an error: `log_out` deletes whatever session the browser's
  cookie names.
- The first parameter of `webauth.config.web_auth_config`,
  `webauth.proxies.resolve_client_ip` and `client_user_agent`, and
  `webauth.dependencies.session_id_from_request` is renamed `request` ->
  `connection` and accepts any Starlette `HTTPConnection` (a `Request` or a
  `WebSocket`). A host that passes it by keyword renames the keyword;
  positional calls are unchanged.

**Added**

- `webauth.dependencies.authenticate_websocket(connection, *, sessions, audit)`
  decides a WebSocket handshake: the `Origin` first (exactly one, naming an
  allowed host; no `Referer` fallback, `Sec-Fetch-Site` ignored), then the
  session by the code `current_user_dependency` runs, renewal and identity
  audit included. It answers an `AuthenticatedUser` or a `WebSocketRefusal`
  (`no-session`, `invalid-session`, `session-ended-or-expired`,
  `account-disabled`, `missing-origin`, `foreign-origin`). `session_id_from_request`,
  `web_auth_config`, `resolve_client_ip` and `client_user_agent` accept any
  `HTTPConnection` (see Breaking). A socket outlives its session unless the host
  re-checks in a fresh transaction (README, "WebSocket handshakes").
- `webauth.WebAuthError` is the common base of the public operational
  exceptions: `UsernameTakenError`, `NotAnAdminError`, `UnknownSessionError`,
  `KeySetFetchError` and `TokenEndpointError`.
- Back-channel logout. `OidcRelyingParty.verify_logout_token(logout_token)`
  answers a `VerifiedLogout(subject)` or an `OidcRefusal` for a Logout Token
  that is RS256, of the configured issuer, for exactly this client, issued
  within `LOGOUT_TOKEN_MAX_AGE_SECONDS` (120) plus the leeway, with an `exp`
  after its `iat`, the back-channel logout event, a `sub`, no `nonce` and the
  `logout+jwt` type; its `sid` is never read. `OidcRefusalReason` gains
  `LOGOUT_TOKEN_REJECTED` and `INVALID_LOGOUT_CLAIM`. The new
  `webauth.oidc_login.receive_backchannel_logout(relying_party, logout_token,
  *, accounts, sessions, lock, audit)` answers `BackchannelLogoutResult.ACCEPTED`
  or `REFUSED`. On `ACCEPTED` it has ended every session of the subject, an
  inactive account's included, and emitted one
  `AccountEventKind.BACKCHANNEL_LOGOUT` event when a session ended. It keeps no
  replay store and never commits: the host commits before it answers 200 and
  answers 400 otherwise (README, "Back-channel logout"). `JwtVerifier.verify`
  takes `expected_type`, and a missing or unequal header `typ` is
  `RejectionReason.INVALID_TOKEN_TYPE`; callers that do not pass it are
  unchanged. To use it: register `backchannel.logout.url` on each app's
  Keycloak client, in edge's `realm.yaml`, by an internal name, never through
  Cloudflare Access, and set up the route as README "Back-channel logout"
  does: the exact path in `exempt` of both `csrf_origin` and `csrf_token`, and
  in `RateLimitPolicy.exempt`; a 32 KiB `BodySizeRule`; a `no-store`
  `CacheControlRule`.
- `CspDirective.FORM_ACTION`. A host's addition extends `'self'`. It accepts
  `'self'`, scheme sources and host sources, as `frame-ancestors` does, and
  refuses nonces, hashes and other keywords with a `ValueError`. `base-uri` is
  fixed and not extendable.

**Fixed**

- Hosts sharing one Redis neither overspend nor deny each other's rate-limit
  budget when their clocks differ, because `RedisRateLimitBackend` measures the
  window on the Redis server's clock. A server older than 5.0 refuses the
  script, and the middleware then answers every rate-limited request with 503.

- `SingleProcessRateLimitBackend.is_allowed` reads its clock inside its lock.
  Before, two concurrent checks of one key could file an older timestamp after a
  newer one, and the periodic sweep, which reads the last timestamp as the
  newest, could drop a key whose newest event was still inside its window and so
  admit extra requests.

## 0.15.0

**Breaking**

- `COOKIE_PATH`, `issue_session_cookies` and `clear_session_cookies` moved from
  `webauth.login` to `webauth.cookies`. `webauth.login` no longer exports them
  and keeps no alias: import them from `webauth.cookies`.
- The 0.14 line receives no further fixes; see [SECURITY.md](SECURITY.md). A host
  on 0.14.x moves to the OpenID Connect login to receive fixes.
- The session cookie's signature is an HMAC-SHA256 over `session:` and the session
  identifier, so a signature made for another purpose is no session cookie. Cookies
  issued by 0.14.x and earlier no longer verify: everyone signs in once after the
  upgrade. CSRF tokens are unchanged (#28 finding 36).
- `UserManagement.list_sessions` and `revoke_session` became
  `webauth.session_administration.SessionAdministration`, which needs only a
  session store, an audit sink, a lock and the config.
- `SessionSummary`, `UnknownSessionError` and `NotAnAdminError` moved to
  `webauth.session_administration`.
- The module `webauth.users` is gone with `UserManagement`, `complete_first_run_setup`,
  `UnknownRoleError`, `LastAdminError`, `SelfDeactivationError`, `WeakPasswordError`,
  `WrongPasswordError`, `PasswordlessAccountError`, `SetupAlreadyDoneError` and
  `SetupRacedError`, and with them `change_role`, `deactivate_user`,
  `ensure_not_last_admin`, `revoke_user_sessions`, `create_user`, `list_users`,
  `set_password` and `change_own_password`. `ports.UserStore`,
  `ports.UserAdministrationStore` and `ports.UnknownUserError` are gone, and so are the
  event kinds `ROLE_CHANGED`, `USER_DEACTIVATED`, `SESSIONS_REVOKED`,
  `FIRST_ADMIN_CREATED`, `PASSWORD_SET_BY_ADMIN` and `PASSWORD_CHANGED` and
  `UserManagementEvent.session_count`. People, roles and blocking move to the issuer.
- The password login is gone. The module `webauth.login` is removed with `LoginOutcome`,
  `LoginRefusal`, `login_attempt_budget`, `judge_credentials`, `http_refusal`,
  `ACCOUNT_LOCKED_DETAIL`, `TOO_MANY_LOGIN_ATTEMPTS_DETAIL`, `INVALID_CREDENTIALS_DETAIL`
  and `RETRY_AFTER_HEADER`, and `ports.LoginAttemptStore` with it. A host signs in through
  OpenID Connect instead: `webauth.oidc_login.start_login` and `finish_login` (README,
  "OpenID Connect login"). `WebAuthConfig` loses `login_rate_limit`,
  `login_lockout_threshold`, `login_lockout_window_seconds` and
  `login_rate_window_seconds`, and `DEFAULT_LOGIN_RATE_WINDOW_SECONDS` is gone: a host that
  passes any of the four gets `TypeError`.
- `UserRecord.password_hash` and `AdmissionRefusal.SUBJECT_HELD_BY_PASSWORD_ACCOUNT` are
  removed. An account whose id equals the subject character for character is
  admitted whatever other fields the host's model has, unless it is inactive:
  `admit_identity` still refuses that as `account-deactivated`. `SubjectUserStore.get`
  must compare ids exactly (no case, accent or trailing-space folding); a host that
  migrates legacy accounts makes sure that no legacy id can equal a subject of
  the bound issuer.
- The module `webauth.passwords` is gone with `Argon2idPasswordHasher`, `OWASP_ARGON2ID`,
  `MIN_PASSWORD_LENGTH`, `MIN_UNIQUE_CHARS`, `check_password_strength` and
  `UnknownHashFormatError`, and `ports.PasswordHasher` and `WebAuthConfig.password_hasher`
  with it: a host that passes `password_hasher` gets `TypeError`. `argon2-cffi` is no
  longer installed with webauth; a host that still hashes passwords declares it itself.
- `WebAuthConfig.session_max_age_seconds` is removed, and `cookie_max_age_seconds` is
  required: the library never reads a session lifetime, which belongs to the host's
  store, and a host states the cookie's `Max-Age` once. A config without
  `cookie_max_age_seconds` is a `TypeError`, and one that passes
  `session_max_age_seconds` is refused as an unknown keyword. `WebAuthConfig` takes
  keyword arguments only, so a positional call is a `TypeError`.
- The default Content-Security-Policy holds no host fact: `style-src` is `'self'` without
  `'unsafe-inline'`, and `font-src` is `'self'` without Google Fonts. The signature is
  now `default_content_security_policy(script_hashes=(), *, added_sources=None)`. A host
  adds its own sources per directive with
  `added_sources={CspDirective.STYLE_SRC: [...]}`, where `CspDirective` names the
  directives it may extend, and each source is validated against a declared CSP3 subset.
  A non-empty `CspDirective.FRAME_ANCESTORS` addition replaces the default `'none'`.
  `script_hashes` is validated too (it closed an injection through the unchecked text):
  each element must be a bare `sha256-`, `sha384-` or `sha512-` hash. A malformed hash or
  source is a `ValueError` naming the directive; a bare string, a non-sequence, a
  non-mapping `added_sources` or a non-string element is a `TypeError`.
- `webauth.proxies`, `webauth.rate_limit`, `webauth.policies` and the `webauth.middleware`
  submodules declare `__all__`. Not public: `proxies.get_client_ip` (call
  `resolve_client_ip(request)`), `budget_address` (it pools IPv6 addresses into a network,
  which `resolve_client_ip`, returning the client's own address, does not do: the helper
  loses public support, and a host that needs per-address rate limits uses
  `IpRateLimitMiddleware`), `MAX_ADDRESS_CHARS`, `MAX_FORWARDED_FOR_HOPS`, `IpAddress`
  (write `ipaddress.IPv4Address | IPv6Address`), `IpNetwork` (write `ipaddress.IPv4Network
  | IPv6Network`), `FORWARDED_FOR_HEADER`, `FORWARDED_PROTO_HEADER`, `HTTPS_SCHEME`,
  `UNKNOWN_CLIENT_IP`, `ZONE_SEPARATOR` and `log`; `rate_limit.PRUNE_INTERVAL_SECONDS`;
  `middleware.rate_limit.log` and `LIMITER_UNAVAILABLE_RETRY_AFTER_SECONDS`;
  `middleware.refusal.RefusalMiddleware` (the module is now the private
  `middleware._refusal`). Every policy name stays public, and so do both
  spellings of the middleware classes (`webauth.middleware` and its submodules).
- A module's public names are the names its `__all__` lists; any other name may
  change or disappear in any release (README, Versioning). A name a module imports is
  public there only when its `__all__` lists it as a deliberate re-export, as
  `webauth.middleware` does for its middleware names and `webauth.jwt_verification`
  for `ExchangeFailure`; import any other imported name from the module that defines
  it, for example `webauth.config.WebAuthConfig` (not
  `webauth.dependencies.WebAuthConfig`) and `webauth.proxies.TrustedProxies` (not
  `webauth.config.TrustedProxies`). `webauth.config`, `webauth.cookies`,
  `webauth.dependencies`, `webauth.liveness`, `webauth.ports`,
  `webauth.session_administration` and `webauth.session_ending` declare it. A host
  that imports a name that left the public surface switches to what follows:
  - `config`: `MIN_SESSION_SECRET_CHARS` and `IPV6_BUDGET_PREFIX_RANGE` (no public
    equivalent; `WebAuthConfig` refuses a short secret or an out-of-range prefix with a
    `ValueError`), `DEFAULT_MAX_USER_AGENT_CHARS`, `DEFAULT_IPV6_BUDGET_PREFIX`,
    `DEFAULT_ADMIN_ROLE` and `DEFAULT_USER_ROLE` (read `config.max_user_agent_chars`,
    `ipv6_budget_prefix`, `admin_role`, `user_role`), `WEB_AUTH_STATE_ATTRIBUTE` (use
    `installed_web_auth_config(app)` or `web_auth_config(request)`).
  - `cookies`: `default_cookie_name`, `is_host_only_cookie_name`,
    `is_secure_prefixed_cookie_name`, `HOST_ONLY_COOKIE_PREFIX` and
    `SECURE_COOKIE_PREFIX` (read `config.session_cookie_name` or
    `config.csrf_cookie_name`, resolved when the config is built, or use
    `DEFAULT_SESSION_COOKIE_NAME` and `DEFAULT_CSRF_COOKIE_NAME`);
    `verify_session_cookie` (read the session with
    `dependencies.session_id_from_request`); `generate_csrf_token` (`issue_session_cookies`
    issues the token with the session); `verify_csrf_token` (`CsrfTokenMiddleware`
    verifies it); `cookie_pairs` and `cookie_values` (no public equivalent);
    `DEFAULT_CSRF_HEADER_NAME` (read `config.csrf_header_name`);
    `DEFAULT_COOKIE_SAMESITE` (read `config.cookie_samesite`);
    `pending_login_cookie_prefix`, `pending_login_cookie_name`,
    `is_pending_login_cookie_name`, `sign_pending_login`, `verify_pending_login`,
    `PLAIN_PENDING_LOGIN_COOKIE_NAME`, `MAX_PENDING_LOGIN_COOKIE_CHARS` and
    `PENDING_SECRET_BYTES` (`webauth.oidc_login.start_login` and `finish_login` own the
    pending login; `PendingLogin` stays public).
  - `dependencies`: `ACCOUNT_DISABLED_DETAIL`, `ADMIN_REQUIRED_DETAIL`,
    `AUTHENTICATION_REQUIRED_DETAIL`, `INVALID_SESSION_DETAIL` and
    `SESSION_EXPIRED_DETAIL` (no public equivalent).
  - `liveness`: `_require_positive_seconds` is now the package-internal
    `require_positive_seconds` (no public equivalent).
  - `session_administration`: `require_admin` (no public equivalent; `revoke_session`
    checks the role).
  - `ports` and `session_ending`: every name of their own stays public.
- `webauth.jwt_verification` no longer re-exports `KEY_SET_FETCH_TIMEOUT_SECONDS`,
  `MAX_KEY_SET_BYTES`, `KeySetFetchError`, `fetch_key_set_over_https` and `is_https_url`:
  import the four public ones (`MAX_KEY_SET_BYTES`, `KeySetFetchError`,
  `fetch_key_set_over_https`, `is_https_url`) from `webauth.https_client`.
  `KEY_SET_FETCH_TIMEOUT_SECONDS` is internal and has no new public home: omit
  `timeout_seconds` in `fetch_key_set_over_https` to get the library default. Importing
  `fetch_key_set_over_https` or `KEY_SET_FETCH_TIMEOUT_SECONDS` from the old place raises
  `ImportError`, and a host's pyright reports the others as not exported.
  `ExchangeFailure` stays importable from both modules.
  `webauth.https_client`, `webauth.jwt_verification`, `webauth.oidc`, `webauth.oidc_login`
  and `webauth` declare `__all__`. Not public: `https_client.post_form_over_https`,
  `HttpsAnswer`, `HttpsExchangeError` and `KEY_SET_FETCH_TIMEOUT_SECONDS`;
  `jwt_verification.strict_json_object`, `VerificationRefusal`, `MAX_JSON_NESTING_DEPTH`,
  `MAX_KEY_ID_CHARACTERS`, `KEY_SET_TTL_SECONDS`, `MIN_RSA_KEY_BITS` and `log`;
  `oidc.callback_state`; `oidc_login.MAX_PENDING_LOGINS` and
  `TOKEN_REQUEST_TIMEOUT_SECONDS`; `jwt_verification._is_rs256_verification_key` is now
  the package-internal `is_rs256_verification_key` (no public equivalent). A name a
  module imports is public only where it is defined, unless its `__all__` lists it as
  a deliberate re-export, for example `OidcRefusal` from `webauth.oidc` (not
  `oidc_login`) and `PendingLogin` from `webauth.cookies` (not `oidc`).

**Changed**

- The wheel declares its license as the SPDX expression `MIT`, and releases build
  with a hash-pinned setuptools.

**Fixed**

- A key set that publishes more than ten keys, most of them for other algorithms or for
  encryption, is no longer refused as `key-count-out-of-range`: `MAX_KEY_SET_KEYS` counts
  the RS256 signing keys only. The size of the document stays bounded by 64 KiB.
- A token without a `kid` header member verifies when the key set holds exactly one
  RS256 verification key, and that key may lack `kid` (OIDC Core 10.1). Against several
  eligible keys, named or not, it is refused as `invalid-key-id`. A key without `kid`
  beside other eligible keys is admitted but unreachable; an explicit `"kid": null`
  stays malformed and a duplicate named `kid` is still refused. `MAX_KEY_SET_KEYS`
  counts every eligible key. A rotation of the sole key, or a change between one and
  several keys, can stay unseen until the key set's one-hour TTL expires, unless a
  token naming an unfamiliar `kid` triggers an earlier refresh.

## 0.14.0

This is the last release with password parts.

**Breaking**

- `IpRateLimitMiddleware`, `CsrfOriginMiddleware`, `CsrfTokenMiddleware` and
  `SecurityHeadersMiddleware` are pure ASGI middleware and no longer subclass
  Starlette's `BaseHTTPMiddleware`:
  an `isinstance` or `issubclass` check against `BaseHTTPMiddleware` fails, and a
  variable or parameter typed `BaseHTTPMiddleware` no longer accepts them. Their
  `.dispatch`, `.dispatch_func` and public `.app` attribute are gone, and so is
  any subclass override of `dispatch`. The constructor is `(app, policy)`: the
  `dispatch=` argument that `BaseHTTPMiddleware` accepted now raises `TypeError`;
  any other unknown keyword argument raised `TypeError` already. They also run
  the app in the caller's task: a `ContextVar` that the app or an inner
  middleware sets is now visible to an outer host middleware after the call
  returns, where `BaseHTTPMiddleware` isolated it in a task of its own; a host
  that relied on that isolation restores its own context, for example by
  resetting the token it set.
- The declared dependency floors are raised to the versions the suite is proven
  on: fastapi 0.123.7, starlette 0.46, pydantic 2.6 and anyio 4.12; starlette and
  anyio are now declared directly, capped below 2 and below 5, and
  `cryptography` is capped below 51. A host on older versions must upgrade.
- `LoginRedirect` refuses, when it is built, a `path` in backslash, tab, CR or
  LF form (`/\x`, `/<tab>/x`) with `ValueError`; v0.13.0 constructed them.
- `SecurityHeadersMiddleware` (also pure ASGI, see the first item): the 500
  of an unhandled exception now carries the security headers, and the exception
  still reaches the server. A host's 500 handler still runs, but the response it
  returns is no longer sent. With `debug=True` Starlette's traceback page is no
  longer sent either: the client gets the library 500 with the headers, and the
  traceback still reaches the server log.
- `SessionRecordStore.touch` returns a `bool`: `True` when a stored row was
  renewed, `False` when the row is gone, which refuses the request like an
  expired session. Any other answer raises `TypeError`; answer `rowcount == 1`,
  not `rowcount`.
- The Redis session cache is gone: the store decides every request.
  `SessionCache`, `CachedSessionData`, `SessionLivenessPolicy.admits_cached_session`,
  the module `webauth.session_store` with `RedisSessionCache`, and
  `WebAuthConfig.session_cache` are removed.
- `end_session`, `end_user_sessions` and `prune_sessions` no longer take a cache;
  `end_session(sessions, *, session_id)` also drops `user_id`.
- `webauth.ports.StoredSessionT` is dropped; `SessionLivenessPolicy` is generic in
  its stored-session type by its own parameter.
- `WebAuthConfig` refuses, at construction, an `admin_role` equal to `user_role`
  (and a role that is not a non-blank string), a `max_user_agent_chars` that is
  not a positive `int`, and a `__Secure-` cookie name with `cookie_secure=False`.
- `sign_session_id` raises `ValueError` for an empty session id or one whose
  signed value exceeds `MAX_SESSION_COOKIE_CHARS`, which moved from
  `webauth.dependencies` to `webauth.cookies`.
- The CSRF origin check compares the parsed host and port, matches
  `allowed_hosts_patterns` against the whole `host[:port]`, and refuses an
  origin without a host or with userinfo. Bracketed IPv6 origins match.

**Added and changed**

- Under the library stack a streamed body over the limit (no Content-Length)
  that the route reads through `request.body()` or `request.stream()` answers the
  413 with the security headers, where v0.13.0 answered Starlette's 500 without
  the security headers, and spends one
  request of the rate budget; a body FastAPI parses still answers FastAPI's 400
  through the host's `HTTPException` handler. A response that fails after it
  started streaming now ends incomplete, and its exception reaches the server; it
  used to end as a complete response.
- `install_web_auth_middleware` (see [Middleware order](README.md#middleware-order))
  installs the whole stack in the order that makes every library refusal carry
  the headers. It refuses, before touching the app, a token policy without an
  origin policy, a token policy that exempts paths the origin policy does not
  check (decided by `CsrfPolicy.token_exemptions_outside_origin_check`), and an
  app that already carries library middleware.
- A redirect target that a browser reads as another host (`/\x`, `/<tab>/x`)
  collapses to `/`, as `//x` did.
- Comparing a session cookie or CSRF token that holds a non-ASCII value now
  works on bytes: it is refused like a forged one where v0.13.0 raised `TypeError`
  and answered 500.
- The OIDC token answer is read by the verifier's strict parser: bad UTF-8,
  non-finite numbers and nesting that is too deep are refused.
  `webauth.jwt_verification` exposes `VerificationRefusal` and
  `strict_json_object`.
- A key-set fetch that timed out says so in its `KeySetFetchError` message.
- A `timeout_seconds` of zero or less in `fetch_key_set_over_https`,
  `post_form_over_https` and `post_token_request_over_https` now raises the
  library's own `ValueError` naming `timeout_seconds`, before urllib3 sees it;
  v0.13.0 raised urllib3's.
- `IdleWindowLiveness` raises `TypeError` for a stored row whose `last_seen` is
  naive, naming the cause; v0.13.0 failed on the comparison with a bare
  `TypeError`.
- `BodySizeLimitMiddleware` never sends a second response start. Once the app has
  handed over a response's start, a streamed body over the limit cuts that response
  off (a response that already finished stays complete) and the error reaches the server,
  where a 413 used to follow the start. The start is sent whole: a cancellation
  inside the stack waits until it is sent. Every start the app hands over is bounded
  by the new `BodySizePolicy.start_send_seconds` (default 10.0, positive and finite);
  one still pending after it is cut off with an error that reaches the server; no
  413 and no second start follow. Any `Content-Length` header over the limit
  now refuses the request with 413, whatever its position among the headers.
- `SECURITY.md` names the supported release and how to report a vulnerability;
  a release is built only from a commit of `main` whose CI run finished green.

## 0.13.0

**Breaking**

v0.13.0 adds the OpenID Connect relying party (`webauth.oidc` and
`webauth.oidc_login`) with PKCE and the signed pending-login cookie, and the one
HTTPS client `webauth.https_client` that every outbound request goes through,
with a total deadline of ten seconds on top of the per-step timeout. The
verifier rejects a token naming an unknown `kid` as `KEY_SET_UNAVAILABLE` when
the key-set refresh failed, not as `UNKNOWN_KEY_ID`. It also changes
three public contracts: a `deadline_seconds` or `timeout_seconds` of zero or
less raises `ValueError` in `fetch_key_set_over_https`, `post_form_over_https`
and `post_token_request_over_https`;
`TokenEndpointError.failure` is the `ExchangeFailure` that ended the token
request, so a caller can tell `TIMED_OUT` from other transport failures; and
`post_token_request_over_https` takes `deadline_seconds`, raising `ValueError`
when `timeout_seconds` exceeds it instead of capping it silently.

## 0.12.0

**Breaking**

v0.12.0 adds the RS256 verifier `webauth.jwt_verification` (install the
`jwt` extra), a cookie lifetime separate from the idle window
(`cookie_max_age_seconds`), and an absolute cap for `IdleWindowLiveness`
(`absolute_max_age_seconds`) — see [Session lifetime](README.md#session-lifetime). It
also refuses at construction what used to fail later: every lifetime —
`session_max_age_seconds`, `cookie_max_age_seconds`, and the windows and caps
of both liveness policies — must be a positive whole number of seconds, so a
`0`, a negative value, a `float`, a string or a `bool` stops the host from
starting instead of ending in a silent login loop. A capped
`IdleWindowLiveness` names a naive `created_at` instead of failing with a bare
`TypeError`.

## 0.10.0

**Breaking**

v0.10.0 renames the default cookies to `__Host-session_id` and
`__Host-csrf_token`. Browsers still send the old `session_id` cookie, which
no longer authenticates, so every user of a host on the defaults is signed
out once and signs in again; the old cookies and their sessions run out at
their own expiry. A host that names both cookies itself is unaffected (it
may switch to `__Host-` names when it serves over https); a host naming only
one gets the new default for the other. A development setup with
`cookie_secure=False` keeps the plain names. `DEFAULT_SESSION_COOKIE_NAME` and
`DEFAULT_CSRF_COOKIE_NAME` in `webauth.cookies` now hold the `__Host-` names;
the plain ones are `PLAIN_SESSION_COOKIE_NAME` and `PLAIN_CSRF_COOKIE_NAME`. A
client that reads the CSRF cookie by name reads `config.csrf_cookie_name`
instead.

## 0.9.0

**Breaking**

v0.9.0 counts rate-limit budgets per IPv6 network: every IPv6 client in one
`/64` shares one budget by default, and `ipv6_budget_prefix` (32 to 128)
chooses the network size; `ipv6_budget_prefix=128` keeps the old per-address
budgets. The IPv6 budget keys change, so existing Redis
counters for IPv6 clients start from zero once after the upgrade.

## 0.8.0

**Breaking**

v0.8.0 refuses a request that carries the session cookie more than once:
`current_user_dependency` answers 401 and `CsrfTokenMiddleware` 403 where
v0.7 picked one of the values. It adds
`webauth.dependencies.session_id_from_request(request, config)`; a host that
reads the session cookie from `request.cookies` itself switches to it.

## 0.7.0

**Breaking**

v0.7.0 changes three public behaviours a host upgrading from v0.6 must act
on: `issue_session_cookies(response, session_id, config)` no longer takes the
`request`; a host reached over plain http now gets `Secure` cookies and HSTS
unless its configuration sets `cookie_secure=False`; and
`SecurityHeadersMiddleware` reads the installed configuration, so an
application without `install_web_auth_config` gets a `RuntimeError` before
its route runs.

## 0.6.0

**Breaking**

v0.6.0 renames `SessionIdentityChanged.session_id` to `session_ref`, which
carries the reference rather than the raw identifier, and moves
`session_reference` from `webauth.users` to `webauth.cookies`; v0.5.1 hosts
update both the import and the field name.

## 0.3.0

v0.3.0 clears the session cookies with the configured SameSite (`"strict"` by
default), where v0.2.0 cleared them with `lax`. A cookie is deleted by name,
domain and path, so the attribute does not affect the clearing.
