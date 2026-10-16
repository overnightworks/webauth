# Changelog

All notable changes to `overnightworks-webauth` are recorded here, after
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/). While the version is
0.x, a minor release may break a public contract and says so under **Breaking**.
Versions before 0.3.0 and releases without an entry here are described in the
[GitHub release notes](https://github.com/overnightworks/webauth/releases).

## 0.14.0 - Unreleased

This is the last release with password parts.

**Breaking**

- `SecurityHeadersMiddleware` is a pure ASGI middleware: its `.dispatch`, the
  `dispatch=` argument and any subclass override of `dispatch` are gone. The 500
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

- `install_web_auth_middleware` (see [Middleware order](README.md#middleware-order))
  installs the whole stack in the order that makes every library refusal carry
  the headers. It refuses, before touching the app, a token policy without an
  origin policy, a token policy that exempts paths the origin policy does not
  check (decided by `CsrfPolicy.token_exemptions_outside_origin_check`), and an
  app that already carries library middleware.
- A redirect target that a browser reads as another host (`/\x`, `/<tab>/x`)
  collapses to `/`, as `//x` did. `LoginRedirect` refuses a backslash or tab
  form of its `path` when it is built.
- Comparing a session cookie or CSRF token that holds a non-ASCII value now
  works on bytes: it is refused (401 or 403) where v0.13.0 raised `TypeError`
  and answered 500.
- The OIDC token answer is read by the verifier's strict parser: bad UTF-8,
  non-finite numbers and nesting that is too deep are refused.
  `webauth.jwt_verification` exposes `VerificationRefusal` and
  `strict_json_object`.
- A key-set fetch that timed out says so in its `KeySetFetchError` message.
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
