# Changelog

All notable changes to `overnightworks-webauth` are recorded here, after
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/). While the version is
0.x, a minor release may break a public contract and says so under **Breaking**.
Releases before 0.20 are in the [changelog at tag v0.23.0](https://github.com/overnightworks/webauth/blob/v0.23.0/CHANGELOG.md);
releases without an entry are described in the
[GitHub release notes](https://github.com/overnightworks/webauth/releases).

## 0.24.0 - Unreleased

**Breaking**

- `webauth.dependencies.unauthenticated_response` is removed. A host whose own middleware is the session authority answers a missing session itself, or guards its routes with `current_user_dependency`, which, given a `LoginRedirect`, answers the login redirect for a browser navigation and 401 `Authentication required` for every other request; a host-owned authority builds its own answer from its `LoginRedirect`.
- `webauth.proxies.TrustedProxies` no longer defines a truth value, so `if proxies:` is always true; a host that tested it tests `if proxies.networks:`.

## 0.23.0 - 2026-10-23

**Breaking**

- The CSRF origin check refuses a POST, PUT, PATCH or DELETE that sends neither `Sec-Fetch-Site` nor `Origin`, whatever its content type or body, with 403 `Missing Origin header`. Before, only a form submission was refused, and `Referer` stood in for a missing `Origin`; it is no longer read. A sessionless server call (a worker, a webhook, the back-channel logout) goes into `CsrfPolicy.exempt`, and a bearer-admitted request is not checked. A host's test client sends `Sec-Fetch-Site: same-origin` on state-changing requests. The supported browsers are named under [CSRF origin](ARCHITECTURE.md#csrf-origin).
- `WebAuthConfig.allowed_hosts_patterns` is removed. The origin check and the WebSocket handshake admit only the hosts `allowed_hosts_exact` names, and a single string there is refused. List each host by name; a `*.suffix` entry has no replacement.
- `open_session` requires the keyword `keeps_id_token: bool`, with no default, so every host states its choice. A host
  that never calls `log_out` passes `False`, and its session rows then hold no ID token. `SessionRecordStore.create`
  takes `id_token: SecretStr | None`, so every typed store widens its own signature.
- The CSRF token check is removed; the origin check is the only CSRF guard. `CsrfTokenMiddleware`, the `csrf_token` argument of `install_web_auth_middleware`, and `CsrfPolicy.token_exempt`, `requires_token` and `token_exemptions_outside_origin_check` are gone. Drop the argument and every front-end line that reads the CSRF cookie or sends `X-CSRF-Token`. A logout route stays POST only and needs no entry of its own.
- `install_web_auth_middleware` requires `csrf_origin`. `CsrfPolicy.protected` is removed: every state-changing request outside `exempt` is checked.
- webauth no longer issues the CSRF cookie. `issue_session_cookies` sets only the session cookie and `clear_session_cookies` clears only it. `WebAuthConfig.csrf_cookie_name` and `csrf_header_name`, and `webauth.cookies.DEFAULT_CSRF_COOKIE_NAME` and `PLAIN_CSRF_COOKIE_NAME`, are removed. A `__Host-csrf_token` (`csrf_token`) cookie set by an earlier version stays in a browser until the `Max-Age` it was given runs out, which was the absolute session cap in force when it was set. webauth neither reads nor clears it, and a host need not clear it. Until that cap has passed since the upgrade, a privacy page names it as a cookie that earlier versions set and that expires by itself.
- `PathRules.exact`, `PublicRule.methods` and `BodySizeRule.methods` refuse a single string with `ValueError`; pass a `frozenset`.
- With `cookie_secure` on, the CSRF origin check's allowlist and the WebSocket handshake admit an `Origin` only over https: `Origin: http://<listed host>` is refused. A plain-http front end that calls an https backend serves itself over https, or runs that environment with `cookie_secure` off.

## 0.22.0 - 2026-10-23

**Breaking**

- `log_out(relying_party, request, config, *, sessions, lock, button_label)` returns the answer itself: a page
  that posts `id_token_hint` to the end-session endpoint and submits itself, `no-store`, under its own
  Content-Security-Policy, which the security-headers middleware leaves in place. It no longer takes `response` or
  returns a URL, and there is no JSON shape: the host commits and returns the answer as it is. A single-page app logs
  out by a top-level form POST, which cannot carry the CSRF token: the host's logout route stays POST only, its exact
  path goes into `CsrfPolicy.token_exempt`, never `exempt`, and the origin check still protects it. `button_label` is
  the text of the button shown when the script does not run. No host CSP needs a new source, and the end-session
  origin may leave `CspDirective.FORM_ACTION`.
- `OidcRelyingParty.logout_url` is removed; `log_out` builds the end-session form itself.
- The browser no longer holds the login's ID token. `finish_login` sets no `__Secure-oidc_id_token_hint`
  (`oidc_id_token_hint`) cookie; `open_session` stores the token in the session row. `log_out` reads the token from the
  row, deletes the row, and answers the page that posts the token.
  - `SessionRecordStore.create` takes a required keyword `id_token: SecretStr`, and `SessionRecord` gains the property
    `id_token -> SecretStr | None`. Migrate as follows: add one nullable text column of at least 8192 characters
    (`webauth.jwt_verification.MAX_TOKEN_CHARACTERS`) to the session table; write the token with `get_secret_value()`
    and return it from the record wrapped in `SecretStr`; keep `touch` and `replace_refresh_token` from changing it.
    Rows stored before the upgrade answer `None`, so their logout makes Keycloak ask once.
  - `AdmittedLogin` gains a required `id_token: SecretStr`.
  - `webauth.cookies.MAX_ID_TOKEN_HINT_CHARS` is removed; no ID token is cut off.
  - `OidcClientConfig.logout_path` and `OidcRelyingParty.logout_path` are removed: drop the argument.
  - A cookie set by an earlier version expires by the `Max-Age` it was given when it was set, which was the absolute
    session cap in force then; the upgrade does not change it. It is neither read nor cleared, and a host need not
    clear it.
  - A logout after the row is gone (swept, deleted by the host, ended by back-channel logout or pruned) sends no hint,
    and Keycloak asks once while its own session lives.
  - Treat the ID token as a secret of the session, like the refresh token: the host's data export lists it under
    `withheld` with the reason `secret` and never shows its value, and erasing a person ends their sessions and with
    them the stored tokens.
- `OidcClientConfig` refuses an `end_session_endpoint` or `post_logout_redirect_uri` whose host is not a plain host and
  optional port, because the logout page's policy names those origins.

**Changed**

- `WebAuthConfig.session_cookie_name` and `csrf_cookie_name` no longer reserve `oidc_id_token_hint` or
  `__Secure-oidc_id_token_hint`; the other cookie-name checks still apply.

## 0.21.0 - 2026-10-22

**Breaking**

- Path rules in every policy are written as the path the application's router routes, below its
  `root_path`: the CSRF token and origin, rate-limit, body-size and cache-control rules now match like
  the session gate's. A host whose policy sees a non-empty `root_path` drops that prefix from those
  rules, behind a server-supplied `root_path`, behind a proxy that keeps an application's own
  `root_path` in the path, or with the library installed on a mounted sub-application; a rule still
  written with that prefix no longer selects the intended route. The session gate is unchanged.

**Added**

- `BearerGate`, `BearerGateMiddleware` and `bearer_caller`, and the parameter
  `install_web_auth_middleware(bearer_gate=...)`: a host declares its machine paths once, and
  there webauth admits only the realm's RS256 `at+jwt` access token whose only audience is the
  app's client, whose `azp` the host allows and whose `groups` hold the admin group or one below
  it. The cookie counts for nothing, CSRF and the session gate step aside, no account is created,
  every answer is `no-store`, and a route reads the caller with `Depends(bearer_caller)`
  (`BearerCaller`). A session dependency on such a request raises.
- `webauth.middleware.admitted_admin`. Behind the session gate, a route refuses with webauth's own
  answers and needs no session store dependency: 403 `Admin access required` for a signed-in
  non-admin, 401 `Authentication required` where the gate admitted no account. On a bearer-admitted
  request it raises, like the session dependencies.
- `AuthorizedParties`, the allowlist of `azp` values a host admits, `OidcRelyingParty.verify_access_token`
  and `.issuer`, `VerifiedAccessToken`, `OidcRefusalReason.ACCESS_TOKEN_REJECTED` and
  `INVALID_ACCESS_CLAIM`, and `JwtVerifier.verify(expected_media_types=...)`, which compares the
  header `typ` as a media type.

**Fixed**

- CSRF and rate-limit rules now match the path the router routes. A `%3F` or `%23` inside a path
  parameter used to cut the path the rules saw short, so a `protected` shape or pattern could miss a
  state-changing route and an `exempt` rule could cover a path it does not name, a rate-limit
  exemption could apply to a path it does not name, and a rate-limit rule could fall back to the
  default budget.

## 0.20.1 - 2026-10-21

**Added**

- `OidcClientConfig` accepts `http` (in any case) for `redirect_uri` and
  `post_logout_redirect_uri` when the host is exactly `localhost`, `127.0.0.1` or `[::1]`, so an
  app's local or CI test stack can boot without a TLS proxy. Every issuer URL stays https and
  every other http host stays refused.

## 0.20.0 - 2026-10-21

**Breaking**

- `SecurityHeadersPolicy.hsts_max_age_seconds`, `hsts_include_subdomains` and
  `strict_transport_security`, and `webauth.policies.DEFAULT_HSTS_MAX_AGE_SECONDS`, are gone.
  The header is always `max-age=31536000; includeSubDomains` (now
  `webauth.middleware.security_headers.STRICT_TRANSPORT_SECURITY`), sent exactly when
  `cookie_secure` is on. Migrate by dropping the two arguments; a host that set neither is
  unchanged.
- `SessionRecordStore.create` takes a required keyword `refresh_token: SecretStr | None`, and
  `SessionRecord` gains the property `refresh_token -> SecretStr | None`. Migrate by adding one
  nullable text column to the session table, writing the token with `get_secret_value()` and
  returning it from the record wrapped in `SecretStr`; nothing is deleted, and existing rows
  answer `None`.
- `open_session(request, config, admitted, *, sessions, lock, max_sessions)` takes the
  `AdmittedLogin` instead of its account, and stores its refresh token in the new session.
- `OidcIdentity` and `AdmittedLogin` gain a required `refresh_token: SecretStr | None`, which
  breaks every caller that constructs one. The code exchange's access token is still never read
  or kept.
- `SessionRecordStore.replace_refresh_token(session_id, *, refresh_token: SecretStr) -> bool` is a
  new required method. It only updates a row that exists and never creates one: `True` means the
  stored row now holds the token, `False` means the session is gone and nothing was written, and
  any other answer raises `TypeError` (answer `rowcount == 1`). Migrate by adding one `UPDATE`
  of the refresh-token column `WHERE id = ?`.
- A code-exchange answer carrying a `refresh_token` outside RFC 6749 Appendix A.17's `1*VSCHAR`
  (printable ASCII) is `TOKEN_ENDPOINT_FAILED`; that login used to be admitted.
- `SessionRecordStore.load` no longer promises to hold the session against concurrent
  writers until the caller commits. The library relies on `touch`'s update-only answer
  instead, which a store that applies each call at once meets too. A host's store needs no
  change; a host that relied on the hold itself keeps it only from its own transactional
  store.

**Added**

- `webauth.oidc_login.app_role(groups, admission)` and `AppRole` name the app role a list of
  groups carries (`ADMIN`, `USER`, or `None` for no member) by the rule `admit_identity` applies,
  so a second service that verifies the issuer's token itself calls it with the same
  `AdmissionConfig` instead of copying the rule. It reads nothing but its arguments and does
  not check the issuer.
- `OidcRelyingParty.renew_access(refresh_token: SecretStr)` posts a refresh grant and answers a
  `RenewedAccess` (the new access token and the rotated refresh token, or `None`) or an
  `OidcRefusal`.
- `webauth.oidc_login.fresh_access_token(relying_party, session_id, *, session_transaction,
  config)` answers a new access token (`SecretStr`) for a live session, or an
  `AccessTokenRefusal` with `AccessTokenRefusalReason` `SESSION_ENDED`, `SIGN_IN_AGAIN` or
  `ISSUER_UNAVAILABLE`. It reads the session in one `SessionTransaction`, sends the refresh token
  with no transaction open, and decides again in a second one; it stores a rotated refresh token
  and never renews the session. Call it from a worker thread (a sync route, or
  `run_in_threadpool`), outside any open session transaction and outside its `WriteLock`, and
  keep the token only for the one call it serves.
- `OidcRelyingParty.workload_access_token()` posts a `client_credentials` grant and answers the
  client's own access token or an `OidcRefusal`. Both calls need a Bearer token in the answer and
  hold nothing between calls.
- `install_web_auth_middleware` takes `session_gate=SessionGate(...)` and then installs the new
  `webauth.middleware.SessionGateMiddleware` innermost. Every HTTP request then needs a live
  session, except those named by `public` (`PublicRule`, by path and optionally by method) and
  `optional`. A request without one gets what `current_user_dependency` answers for it, with the
  gate's own `login_redirect`: the login redirect for a navigation, otherwise 401 with the
  dependency's detail (`Authentication required`, `Invalid session` or `Session expired`). A
  WebSocket handshake passes the gate untouched; `authenticate_websocket` still decides it. The
  gate opens the host's transaction through the new `webauth.ports.SessionTransaction`, and
  commits the session renewal before the route runs; a route that fails afterwards does not undo
  it.
- Behind the gate, `current_user`, `admin_user` and `verified_session_id` return the gate's
  admission for the request's own session cookie, so a request still costs one `load` and one
  `touch`. `webauth.middleware.admitted_user` reads the account where no dependency is used,
  and on optional paths.
