# webauth

OpenID Connect login and session authentication for FastAPI applications. It is
built for [Keycloak](https://www.keycloak.org/); any OpenID Connect issuer that
signs ID tokens with RS256 and publishes static endpoints works. webauth serves
the start, callback, logout and back-channel logout routes, runs the flow, then keeps the session:
sessions the store decides on every request, HMAC-signed cookies, CSRF
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

from webauth.admission import AdmissionConfig
from webauth.config import SessionLifetime, WebAuthConfig, install_web_auth_config
from webauth.dependencies import current_user_dependency
from webauth.middleware import install_web_auth_middleware
from webauth.policies import (
    BodySizePolicy,
    CsrfPolicy,
    SecurityHeadersPolicy,
    default_content_security_policy,
)
from webauth.ports import AuthenticatedUser
from webauth.proxies import TrustedProxies
from webauth.rate_limit import SingleProcessRateLimitBackend
from webauth.sign_in_routes import LogoutPageText, SignInPaths, install_sign_in_routes

app = FastAPI()
config = WebAuthConfig(
    session_secret=SecretStr(Path("/run/secrets/session_secret").read_text().strip()),
    trusted_proxies=TrustedProxies.parse("10.0.0.0/8"),
    rate_limits=SingleProcessRateLimitBackend(),
    allowed_hosts_exact=frozenset({"app.example.com"}),
    session_lifetime=SessionLifetime(idle_seconds=43200, absolute_max_age_seconds=43200),
)
install_web_auth_config(app, config)
paths = SignInPaths(
    start="/login/oidc", callback="/auth/callback", logout="/logout",
    backchannel_logout="/auth/backchannel-logout",
)
install_web_auth_middleware(
    app,
    security_headers=SecurityHeadersPolicy(
        content_security_policy=default_content_security_policy(),
        cache_control_rules=(paths.cache_control_rule,),
    ),
    body_size=BodySizePolicy(
        default_max_bytes=64 * 1024, rules=(paths.backchannel_body_size_rule,),
    ),
    csrf_origin=CsrfPolicy(exempt=paths.backchannel),
)
install_sign_in_routes(
    app,
    paths=paths,
    relying_party=the_hosts_relying_party,
    admission=AdmissionConfig(
        bound_issuer="https://keycloak.example/realms/notes",
        login_group="/apps/notes",
        admin_group="/apps/notes/admin",
    ),
    transaction=the_hosts_sign_in_transaction,
    refused=the_hosts_refusal_page,
    keeps_id_token=True,
    max_sessions=None,
    logout_page_text=lambda _request: LogoutPageText(language="en", button_label="Log out"),
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
`admin_user`) and its docstring says what `session_store`
and `on_authenticated` are. `paths` also derives the policies of the four routes (`public_rules`, `browser_paths`, `backchannel`, `backchannel_body_size_rule`, `cache_control_rule`, `login_redirect`), so the host lists them once. The sign-in routes are in the [host contract](docs/host-contract.md#the-sign-in-routes); [`tests/fixtures/typing_hosts/oidc_host.py`](tests/fixtures/typing_hosts/oidc_host.py)
is a complete host, checked in CI against the built wheel.

The `trusted_proxies` rule is in the [host contract](docs/host-contract.md#trusted-proxies).

## Documentation

- A host developer: the [host contract](docs/host-contract.md), which holds the trusted-proxy rule, what every app gets, the machine routes, the person paths a token can call, the sign-in and logout routes and how to test a host.
- An engineer changing the library: [`docs/ARCHITECTURE.md`](docs/ARCHITECTURE.md) holds the architecture: the building blocks and what the host owns, how a request and a sign-in run, and the concepts behind each module.
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

A host's Dependabot entry for uv ignores `overnightworks-*`, because Dependabot looks the name up on PyPI. Real uv Dependabot runs in hosts end green with this pin, both with webauth alone and with other overnightworks libraries pinned by git beside it.

Do not pin the wheel URL: one in a resolved tree fails a uv Dependabot run. The wheel stays on each tag's [release page](https://github.com/overnightworks/webauth/releases), and `scripts/verify_release.sh` checks it.

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
  constraints from the setuptools floor in `pyproject.toml`;
- `scripts/verify_release.sh` downloads a release and checks the checksums and
  build-provenance attestations of its wheel and sdist.

## Licence

MIT — see [LICENSE](LICENSE).
