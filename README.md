# webauth

OpenID Connect login and session authentication for FastAPI applications. It is
built for [Keycloak](https://www.keycloak.org/); any OpenID Connect issuer that
signs ID tokens with RS256 and publishes static endpoints works. The host serves
a start and a callback route. webauth runs the flow, then keeps the session:
sessions the store decides on every request, HMAC-signed cookies, CSRF
origin checks, admin checks, per-address rate limits, and the audit events they
raise. The client is a confidential client: it authenticates at the token
endpoint with HTTP Basic and sends PKCE with the `S256` method.

Distribution `overnightworks-webauth`, import package `webauth`. [Install](#install) names
where the wheel comes from.

## Quick start

```python
from pathlib import Path

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
    session_secret=SecretStr(Path("/run/secrets/session_secret").read_text().strip()),
    trusted_proxies=TrustedProxies.parse("10.0.0.0/8"),
    rate_limits=SingleProcessRateLimitBackend(),
    allowed_hosts_exact=frozenset({"app.example.com"}),
    session_lifetime=SessionLifetime(idle_seconds=43200, absolute_max_age_seconds=43200),
)
install_web_auth_config(app, config)
install_web_auth_middleware(
    app,
    security_headers=SecurityHeadersPolicy(
        content_security_policy=default_content_security_policy(),
    ),
    csrf_origin=CsrfPolicy(),
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
and `on_authenticated` are. The sign-in routes are in the [host contract](docs/host-contract.md#openid-connect-login); [`tests/typing/oidc_host.py`](tests/typing/oidc_host.py)
is a complete host, checked in CI against the built wheel.

The `trusted_proxies` rule is in the [host contract](docs/host-contract.md#trusted-proxies).

## Documentation

- A host developer: [How to test a host](docs/testing-a-host.md) and the [host contract](docs/host-contract.md), which holds the trusted-proxy rule, what every app gets, the machine routes and the start, callback and logout routes.
- An engineer changing the library: [`docs/ARCHITECTURE.md`](docs/ARCHITECTURE.md) holds the architecture: the building blocks and what the host owns, how a request and a sign-in run, and the concepts behind each module.
- Security: [Trust](docs/ARCHITECTURE.md#trust) says who the library defends against and what it trusts; [SECURITY.md](.github/SECURITY.md) says how to report.
- The proof harness: [`e2e/oidc/README.md`](e2e/oidc/README.md).

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
[CHANGELOG](docs/CHANGELOG.md); a patch release never does. Only the latest minor
release receives security fixes, as [SECURITY.md](.github/SECURITY.md) says.

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
