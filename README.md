# webauth

OpenID Connect login and session authentication for FastAPI applications. It is
built for [Keycloak](https://www.keycloak.org/); any OpenID Connect issuer that
signs ID tokens with RS256 works; it is configured from its OpenID Connect Discovery document by
default, or by hand when it publishes none. webauth serves the start, callback, logout and
back-channel logout routes, runs the flow, then keeps the session: sessions the store decides on every request, HMAC-signed cookies, CSRF
origin checks, admin checks, per-address rate limits, and the audit events they
raise. The client is a confidential client: it authenticates at the token
endpoint with HTTP Basic and sends PKCE with the `S256` method.

Distribution `overnightworks-webauth`, import package `webauth`. [Install](#install) says how a host
pins it.

## Quick start

```python
from pathlib import Path

from fastapi import Depends, FastAPI
from pydantic import SecretStr

from webauth.admission import AdmissionConfig, GroupPath
from webauth.config import SessionLifetime, WebAuthConfig
from webauth.dependencies import current_user
from webauth.https_client import fetch_provider_metadata_over_https
from webauth.oidc import discover_oidc_client_config
from webauth.policies import CsrfPolicy, SecurityHeadersPolicy, default_content_security_policy
from webauth.ports import AuthenticatedUser
from webauth.proxies import TrustedProxies
from webauth.rate_limit import SingleProcessRateLimitBackend
from webauth.sign_in_routes import LogoutPageText, SignInPaths
from webauth.web_auth import SignInPages, WebAuth, WebAuthSettings, WebAuthStores

client = discover_oidc_client_config(
    "https://keycloak.example/realms/notes",
    fetch_provider_metadata=fetch_provider_metadata_over_https,
    client_id="notes",
    client_secret=SecretStr(Path("/run/secrets/client_secret").read_text().strip()),
    redirect_uri="https://app.example.com/auth/callback",
    post_logout_redirect_uri="https://app.example.com/",
    scopes=("openid", "profile"),
    leeway_seconds=30,
)
auth = WebAuth.build(
    WebAuthSettings(
        config=WebAuthConfig(
            session_secret=SecretStr(Path("/run/secrets/session_secret").read_text().strip()),
            rate_limits=SingleProcessRateLimitBackend(),
            allowed_hosts_exact=frozenset({"app.example.com"}),
            session_lifetime=SessionLifetime(idle_seconds=43200, absolute_max_age_seconds=43200),
        ),
        client=client,
        sign_in_paths=SignInPaths(
            start="/login/oidc", callback="/auth/callback", logout="/logout",
            backchannel_logout="/auth/backchannel-logout",
        ),
        keeps_id_token=True,
        max_sessions=None,
        security_headers=SecurityHeadersPolicy(
            content_security_policy=default_content_security_policy(),
        ),
        csrf_origin=CsrfPolicy(),
    ),
    stores=WebAuthStores(
        sign_in=the_hosts_sign_in_transaction,
        sessions=the_hosts_session_transaction,
    ),
    groups=AdmissionConfig(
        bound_issuer=client.issuer,
        login_group=GroupPath("/apps/notes"),
        admin_group=GroupPath("/apps/notes/admin"),
    ),
    pages=SignInPages(
        refused=the_hosts_refusal_page,
        logout_page_text=lambda _request: LogoutPageText(language="en", button_label="Log out"),
        ui_language=lambda _request: None,
    ),
    front=TrustedProxies.parse("10.0.0.0/8"),
)

app = FastAPI()


@app.get("/me")
def me(user: AuthenticatedUser = Depends(current_user)) -> AuthenticatedUser:
    return user


auth.install(app, bearer=None)
```

`WebAuth.build` runs before the host's routes, which take `auth.relying_party`, `auth.config` and `auth.admission`; `auth.install(app, bearer=...)` runs after the last route, with the host's `BearerGate` or `None`. The host passes each transaction once, in `stores`: the call binds `stores.sessions` to the session gate and `current_user`, and `stores.sign_in` to the sign-in routes, the person paths and the protected resource, so no gate carries a transaction of its own ([the composition call](docs/host-contract.md#the-composition-call)). Neither reads the environment or calls the issuer. `discover_oidc_client_config` reads the issuer's discovery document once, at startup, and the host does not start when it raises ([the client configuration](docs/host-contract.md#the-client-configuration)). `ui_language` names the person's language to the issuer as `ui_locales`: a host passes `resolve_language`'s answer for the request, or `lambda request: None` to name none ([a person's language](docs/host-contract.md#a-persons-language)). `front` names the proxies whose forwarding headers are believed: `TrustedProxies` makes `install` place logline's request line and webauth's client-address writer, and a host with several apps behind one router builds each with `ServedBehind.SHARED_FRONT` and serves `web_auth_front(Router(...), trusted_proxies=...)`, so the host adds neither by hand ([trusted proxies](docs/host-contract.md#trusted-proxies)). The host's own middleware goes in the `outside` and `inside` slots of `build` ([the composition call](docs/host-contract.md#the-composition-call)).

A host with one worker and no database keeps its accounts and sessions in memory with `SingleProcessStores(audit=the_hosts_audit_sink)` from `webauth.single_process_stores`: pass its `transaction` as `stores.sign_in` and `lambda: nullcontext(stores.sessions)` as `stores.sessions`. A restart forgets every account and session ([the single-process stores](docs/host-contract.md#the-single-process-stores)).

`install` derives the policies of the four sign-in routes from `sign_in_paths` and applies them ahead of the host's own, so the host lists them once; it also applies a rate limit and a body limit when the host passes none. The sign-in routes are in the [host contract](docs/host-contract.md#the-sign-in-routes); [`tests/fixtures/typing_hosts/oidc_host.py`](tests/fixtures/typing_hosts/oidc_host.py)
is a complete host, checked in CI against the built wheel.

## Documentation

- A host developer: the [host contract](docs/host-contract.md), which holds the trusted-proxy rule, what every app gets, the machine routes, the person paths a token can call, the sign-in and logout routes and how to test a host.
- An engineer changing the library: [`docs/ARCHITECTURE.md`](docs/ARCHITECTURE.md) holds the architecture: the context, the building blocks and what the host owns, how a request and a sign-in run, the deployment, the concepts behind each module, the constraints with their reasons, the alternatives not chosen and the risks.
- Security: [Trust](docs/ARCHITECTURE.md#trust) says who the library defends against and what it trusts; [SECURITY.md](.github/SECURITY.md) says how to report.
- The proof harness, by task: [run the browser proof](docs/runbooks/run-the-browser-proof.md), [run the conformance suite](docs/runbooks/run-the-conformance-suite.md), [stop a run](docs/runbooks/stop-a-run.md), [clean up after a killed run](docs/runbooks/clean-up-after-a-killed-run.md) and [refresh the e2e pins](docs/runbooks/refresh-the-e2e-pins.md).

## Install

`overnightworks-webauth` is not on PyPI. A host pins a tag by git. Put the tag in place of `vX.Y.Z`, in a `pyproject.toml`:

```toml
dependencies = [
    "overnightworks-webauth @ git+https://github.com/overnightworks/webauth@vX.Y.Z",
]
```

The host's lock records the commit of the tag. A build needs git and builds webauth from source.

webauth depends on `overnightworks-logline` as a version range by name (`>=0.5,<2`), so the host pins logline's git tag in its own `dependencies`, as [logline's README](https://github.com/overnightworks/logline#install) says, and a tag outside the range is refused:

```toml
dependencies = [
    "overnightworks-webauth @ git+https://github.com/overnightworks/webauth@vX.Y.Z",
    "overnightworks-logline @ git+https://github.com/overnightworks/logline@vA.B.C",
]
```

A host's Dependabot entry for uv ignores `overnightworks-*`, because Dependabot looks the name up on PyPI. Real uv Dependabot runs in hosts end green with this pin, both with webauth alone and with other overnightworks libraries pinned by git beside it.

Two extras are optional: `redis` shares rate-limit windows across processes, and `postgres` stores the sessions in the host's Postgres over its SQLAlchemy 2 connection ([the host contract](docs/host-contract.md#the-postgres-session-store)); the host brings its own driver. Name one the same way, with `overnightworks-webauth[postgres] @ git+https://github.com/overnightworks/webauth@vX.Y.Z`.

Tags are never moved; a broken release gets the next patch tag.

## Versioning

The version follows [semantic versioning](https://semver.org/). While it is 0.x,
a minor release may break a public contract and says so under **Breaking** in the
[release pages](https://github.com/overnightworks/webauth/releases); a patch
release never does. Only the latest minor release receives security fixes, as
[SECURITY.md](.github/SECURITY.md) says.

A module's public names are the names its `__all__` lists. Every other name it
defines starts with an underscore, and a module whose name starts with one (such
as `webauth._validation`) is private as a whole, as the Python typing
specification defines it. A name a module only imports is public there only when
its `__all__` re-exports it. Anything private may change or disappear in any
release.

## Development

[AGENTS.md](AGENTS.md) holds the repository's rules, the checks a change must
pass and how a release is made. The commands live under `scripts/`:

- `scripts/run_static_checks.sh` runs every static check CI's `checks` job runs;
- `scripts/regenerate_build_constraints.sh` regenerates the hash-pinned build
  constraints from the setuptools floor in `pyproject.toml`.

A release is dispatched with the version alone:
`gh workflow run release.yml -R overnightworks/webauth -f version=X.Y.Z`. `main` must carry
X.Y.Z in `webauth.__version__` and a green CI run.

## Licence

MIT — see [LICENSE](LICENSE).
