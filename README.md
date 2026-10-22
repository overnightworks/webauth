# webauth

OpenID Connect login and session authentication for FastAPI applications. It is
built for [Keycloak](https://www.keycloak.org/); any OpenID Connect issuer that
signs ID tokens with RS256 and publishes static endpoints works. The host serves
a start and a callback route. webauth runs the flow, then keeps the session:
sessions the store decides on every request, HMAC-signed cookies, CSRF
double-submit, admin checks, per-address rate limits, and the audit events they
raise. The client is a confidential client: it authenticates at the token
endpoint with HTTP Basic and sends PKCE with the `S256` method.

Distribution `overnightworks-webauth`, import package `webauth`. [Install](#install) names
where the wheel comes from.

## Quick start

```python
import os

from fastapi import Depends, FastAPI
from pydantic import SecretStr

from webauth.config import SessionLifetime, WebAuthConfig, install_web_auth_config
from webauth.dependencies import current_user_dependency
from webauth.middleware import install_web_auth_middleware
from webauth.policies import CsrfPolicy, SecurityHeadersPolicy, default_content_security_policy
from webauth.ports import AuthenticatedUser
from webauth.proxies import TrustedProxies
from webauth.rate_limit import SingleProcessRateLimitBackend

app = FastAPI()
config = WebAuthConfig(
    session_secret=SecretStr(os.environ["SESSION_SECRET"]),
    trusted_proxies=TrustedProxies.parse("10.0.0.0/8"),
    rate_limits=SingleProcessRateLimitBackend(),
    allowed_hosts_exact=frozenset({"app.example.com"}),
    allowed_hosts_patterns=(),
    session_lifetime=SessionLifetime(idle_seconds=43200, absolute_max_age_seconds=43200),
)
install_web_auth_config(app, config)
install_web_auth_middleware(
    app,
    security_headers=SecurityHeadersPolicy(
        content_security_policy=default_content_security_policy(),
    ),
    csrf_origin=CsrfPolicy(),
    csrf_token=CsrfPolicy(),
)
auth = current_user_dependency(
    session_store=the_hosts_session_store,
    on_authenticated=bind_the_hosts_log_context,
)


@app.get("/me")
def me(user: AuthenticatedUser = Depends(auth.current_user)) -> AuthenticatedUser:
    return user
```

`current_user_dependency` returns an `AuthDependencies` (`current_user`,
`admin_user`, `verified_session_id`) and its docstring says what `session_store`
and `on_authenticated` are. The sign-in routes are under [OpenID Connect login](#openid-connect-login); [`tests/typing/oidc_host.py`](tests/typing/oidc_host.py)
is a complete host, checked in CI against the built wheel.

`trusted_proxies` lists the app's direct peer and every proxy whose address the
`X-Forwarded-For` chain carries; listing every proxy between the client and the
app is the simple way to be sure. webauth reads `X-Forwarded-For` and
`X-Forwarded-Proto` and never RFC 7239 `Forwarded`. It reads the chain from the
right and takes the first address it does not trust as the client, so a proxy
whose address the chain carries but which the list lacks becomes the client
address, and every visitor that reaches the app through it shares that address
and its rate-limit budget. With a CDN, a tunnel and a reverse proxy in front of
the app, list whichever of their addresses appear in the chain.
`trusted_proxies` decides alone only when the ASGI server does not rewrite the
client address or scheme from those headers, so the host turns the server's own
forwarded-header handling off (uvicorn's `proxy_headers`, on by default:
`proxy_headers=False` or `--no-proxy-headers`).

## Documentation

[`docs/ARCHITECTURE.md`](docs/ARCHITECTURE.md) holds the architecture and the trust model: the building blocks and what
the host owns, how a request and a sign-in run, the concepts behind each module, and [Trust](docs/ARCHITECTURE.md#trust),
who the library defends against and what it trusts.

## Testing a host

A test that needs a signed-in person needs no issuer. It creates the account and
a session inside the configured lifetime in the host's own store, calls
`issue_session_cookies(response, session_id, config)` from `webauth.cookies` on
a `Response` and copies both cookies it sets into its client. A state-changing
request also sends the CSRF cookie's value in the header named
`config.csrf_header_name` and passes the origin check ([CSRF origin](docs/ARCHITECTURE.md#csrf-origin)).
When the client keeps the cookies' attributes and `cookie_secure` is on, use an
`https` base URL.

A test of the host's own start, callback and logout routes gives
`OidcRelyingParty` its own `post_token_request` (a `TokenRequestPost`, from
`webauth.oidc`) and `fetch_key_set` (a `KeySetFetch`, from
`webauth.jwt_verification`) instead of the HTTPS ones. The host owns that stub.

The sign-in flow itself is proven against a real issuer: `e2e/oidc/` drives
Keycloak in a real browser and is webauth's own proof. A host proves its own
sign-in against an issuer of its choosing. webauth ships no fake issuer, because
one that mints tokens does not belong in every production install.

## OpenID Connect login

### What every app gets

Every app that signs people in through Keycloak behaves the same way, unless it
names `EverySubject` or `NoAdmins` under
[Admitting an identity](docs/ARCHITECTURE.md#admitting-an-identity). The details are in the
sections linked below.

**Who gets in.** Only members of the app's `login_group`, such as
`/apps/notes`, get in. Members of its `admin_group`, such as
`/apps/notes/admin`, are admins. Both are decided again at every login, so a
change in Keycloak takes effect at the person's next sign-in; an app session
that is already open keeps its access until it ends; a changed admin role
reaches every open session at the person's next sign-in. See
[Admitting an identity](docs/ARCHITECTURE.md#admitting-an-identity).

**When Keycloak is down.** People who are already signed in keep working until
their app session ends, because the app checks a session in its own store and
never asks Keycloak. A new sign-in fails at Keycloak: the app sends the browser
to Keycloak's sign-in page, which does not load, so the person sees the
browser's or the proxy's error page, not the app's. Only when Keycloak fails
during the sign-in, or the browser reaches Keycloak but the app does not, does
the sign-in stop at the app's callback, on the host's refusal page. webauth
offers no local fallback login. See
[The store decides every request](docs/ARCHITECTURE.md#the-store-decides-every-request).

**hal on the admin routes.** The host's machine (admin) routes take hal's
Keycloak access token alone, in `Authorization: Bearer`; the cookie counts for
nothing there. A block in Keycloak reaches hal when the token expires, plus
the leeway, and signing out of a browser leaves the token valid. See
[The host's machine routes](#the-hosts-machine-routes).

**Signing out.** Signing out of an app ends its session in that browser at once
and shows a short page that posts to Keycloak, which ends the person's Keycloak session in
that browser without asking anything. Keycloak then tells each app the
person signed in to through that Keycloak session, and each of those apps ends
all of the person's sessions, on every device. An app they used only on another
device is not told and keeps them signed in there. On their other devices, the
next sign-in asks for no password while that device's own Keycloak session
lasts. Without the session's row (ended, swept, pruned or ended by
back-channel logout), the app has no ID token to send, and Keycloak asks once
to confirm while its own session lives; if the realm key that signed that
token has been deleted since, Keycloak shows an error page instead. See
[The ID token hint](docs/ARCHITECTURE.md#logging-out-and-the-id-token-hint), [Logging out](docs/ARCHITECTURE.md#logging-out-and-the-id-token-hint) and
[Back-channel logout](docs/ARCHITECTURE.md#back-channel-logout).

#### Signed out and refused

Every app shows signed-out and refused people the same way. This is the rule
every app follows; [the session gate](docs/ARCHITECTURE.md#the-session-gate) enforces it, and a
host without the gate follows it itself.

- **A page without a session** sends the browser straight to the app's start
  route, with `next` naming the page, so the person lands there after signing
  in. The host passes `next` to `start_login` as `return_to`, and
  `finish_login` hands back the same-origin path or `None`. An API call without a session gets
  401, and the app's UI then navigates to its start route. See
  [The host's start, callback and logout routes](#the-hosts-start-callback-and-logout-routes)
  and, for the rule `return_to` must pass,
  [The return path](docs/ARCHITECTURE.md#the-return-path). For a
  server-rendered host, `LoginRedirect` makes the redirect-or-401 split; see
  [Reading the session](docs/ARCHITECTURE.md#reading-the-session).
- **A machine route** (see [The host's machine routes](#the-hosts-machine-routes))
  answers 401 with a `WWW-Authenticate: Bearer realm="admin"` challenge, never a
  redirect, and 403 for a valid token without the admin group:

  | Case | Status | `WWW-Authenticate` | `detail` |
  |---|---|---|---|
  | no credentials | 401 | `Bearer realm="admin"` | `Authentication required` |
  | malformed request (repeated or combined `Authorization`, or `access_token` in the query beside an `Authorization: Bearer`; in the query alone it is no credential) | 401 | `Bearer realm="admin", error="invalid_request"` | `Invalid request` |
  | invalid token (any verification failure, an unavailable key set included) | 401 | `Bearer realm="admin", error="invalid_token"` | `Invalid token` |
  | valid token, not an admin | 403 | `Bearer realm="admin", error="insufficient_scope"` | `Admin access required` |

- **Public paths** are the exception. Each app names its own, and they need
  no session and do not redirect.
- **The page after signing out** is the app's `post_logout_redirect_uri`. It
  never redirects by itself. See [Logging out](docs/ARCHITECTURE.md#logging-out-and-the-id-token-hint).
- **Which refusal shows which page.** "No access" is for
  `AdmissionRefusal.NOT_A_MEMBER`; "Login failed" is for an `OidcRefusal`
  and for `AdmissionRefusal.FOREIGN_ISSUER` and `USERNAME_TAKEN`, which are
  setup errors, not missing rights.
  Both types are returned by `finish_login`, see
  [The host's start, callback and logout routes](#the-hosts-start-callback-and-logout-routes).
  A refusal carries no identity, so the page shows no name. A
  `NOT_A_MEMBER` login stores no session, so signing out from "no access"
  makes Keycloak ask once while its own session lives (see
  [The ID token hint](docs/ARCHITECTURE.md#logging-out-and-the-id-token-hint)).
- **Look.** The three pages (logged out, no access, login failed), their
  wording and their ways out are the sign-in pattern of
  [ui-console](https://github.com/overnightworks/ui-console); each app takes
  the colours from its own tokens.

### The host's machine routes

A host declares its machine (admin) paths once, and hal calls them with the
access token Keycloak issued it. `BearerGate` is passed to
`install_web_auth_middleware(bearer_gate=...)`; it holds the paths
(`PathRules`), the app's own `OidcRelyingParty`, the app's `AdmissionConfig` and
`AuthorizedParties`, the `azp` values (hal's client ids) the host admits, read
from configuration. A route reads the admitted caller with
`Depends(bearer_caller)`; `BearerCaller.subject` is the token's `sub`, with no
account and no role.

- **What passes.** Only an RS256 `at+jwt` of the app's issuer whose only
  `aud` is the app's client, whose `azp` is allowed and whose `groups` hold the
  admin group or a group below it. Nothing is created or provisioned, and webauth
  emits no event: the host audits the admitted call itself (subject, route,
  outcome).
- **What it replaces.** On a gated path the cookie, the CSRF checks and the
  session gate decide nothing, and every answer is `no-store`. The same rate
  limit applies where a rate policy covers the path; a flood of invalid tokens
  is bounded only by it. A session dependency (`current_user`, `admin_user`,
  `admitted_admin`, `verified_session_id`) on a gated path raises, so the library answers 500,
  and `session_id_from_request` reads the cookie, which is the host's duty not to
  trust there.
- **The paths** are written as every other policy's are; the `PathRules`
  docstring says how.
  They must cover every machine route, a prefix being the safe form. Every method
  is gated, `OPTIONS` included; a CORS preflight is the host's own layer outside
  the stack.
- **Mounts and sockets.** Install the gate on the app that serves the machine
  routes. A sub-app mounted below a gated path keeps its own CSRF and session
  gate, and its `bearer_caller` raises. WebSocket scopes are not gated.

### The host's start, callback and logout routes

The host serves three routes over its one `OidcRelyingParty`: start
(`start_login`), callback (`finish_login`, then `open_session`) and logout
(`log_out`), whose answer, a page that posts to Keycloak, the route returns as it is; a
single-page app logs out by a top-level form POST to that route. `webauth.oidc_login` carries the pending login in a signed cookie of
its own, one per login, so the host keeps no server-side store and
`WebAuthConfig` knows nothing of OpenID Connect. Each function's docstring holds
its contract, the `webauth.oidc_login` and `webauth.cookies` module docstrings
hold the login and its cookies, and `build_app` in
[`e2e/oidc/host_app.py`](e2e/oidc/host_app.py) is the worked set of routes,
type-checked and run against a real issuer.

The library never commits: the host commits an admitted login before it issues
the cookies. A pending login is single-use because its cookie is cleared and the
issuer accepts a code once; webauth keeps no replay store. The `finish_login`
docstring holds the callback's outcomes and the host's duties.

## Install

`overnightworks-webauth` is not on PyPI: it installs only from the wheel
published as an asset on each tag's release. Take the version from the
[Releases page](https://github.com/overnightworks/webauth/releases) and put it in
place of `X.Y.Z`, in a `pyproject.toml`:

```toml
dependencies = [
    "overnightworks-webauth @ https://github.com/overnightworks/webauth/releases/download/vX.Y.Z/overnightworks_webauth-X.Y.Z-py3-none-any.whl",
]
```

Tags are never moved; a broken release gets the next patch tag.

## Versioning

The version follows [semantic versioning](https://semver.org/). While it is 0.x,
a minor release may break a public contract and says so under **Breaking** in the
[CHANGELOG](CHANGELOG.md); a patch release never does. Only the latest minor
release receives security fixes, as [SECURITY.md](SECURITY.md) says.

A module's public names are the names its `__all__` lists. Every other name it
defines starts with an underscore, and a module whose name starts with one (such
as `webauth._validation`) is private as a whole, as the Python typing
specification defines it. A name a module only imports is public there only when
its `__all__` re-exports it. Anything private may change or disappear in any
release.

## Development

[AGENTS.md](AGENTS.md) holds the repository's rules, the checks a change must
pass and how a release is made. The commands live under `scripts/`:

- `scripts/check.sh` runs every static check CI's `checks` job runs;
- `scripts/regenerate-build-constraints.sh` regenerates the hash-pinned build
  constraints from the setuptools floor in `pyproject.toml`;
- `scripts/verify-release.sh` downloads a release and checks the checksums and
  build-provenance attestations of its wheel and sdist.

The proof runs against a real issuer are described in
[`e2e/oidc/README.md`](e2e/oidc/README.md).

## Licence

MIT — see [LICENSE](LICENSE).
