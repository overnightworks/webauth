"""The client configuration `OidcRelyingParty` is built from.

A refused value names the field it breaks, never the value; the form targets and
the loopback `http` exception are the URLs a configuration accepts.
"""

from __future__ import annotations

import dataclasses

import pytest
from pydantic import SecretStr

from tests.support.oidc_arrangement import (
    REALM_ISSUER,
)
from tests.support.oidc_relying_party import (
    AUTHORIZATION_ENDPOINT,
    END_SESSION_ENDPOINT,
    JWKS_URL,
    POST_LOGOUT_REDIRECT_URI,
    TOKEN_ENDPOINT,
    a_realm_client_config,
)
from webauth.oidc import (
    OidcClientConfig,
)


def _text_of(value: object) -> str:
    return value.get_secret_value() if isinstance(value, SecretStr) else str(value)


@pytest.mark.parametrize(
    ("field_name", "value"),
    [
        pytest.param("issuer", "http://login.example.org/realms/workshop", id="issuer-http"),
        pytest.param(
            "authorization_endpoint",
            f"{AUTHORIZATION_ENDPOINT}?prompt=login",
            id="authorization-endpoint-with-query",
        ),
        pytest.param(
            "token_endpoint", f"{TOKEN_ENDPOINT}#fragment", id="token-endpoint-with-fragment"
        ),
        pytest.param("jwks_url", "ftp://login.example.org/certs", id="jwks-url-not-https"),
        pytest.param(
            "redirect_uri", "http://example.test/auth/callback", id="redirect-uri-http-remote"
        ),
        pytest.param(
            "redirect_uri",
            "https://user:pass@notes.example.org/auth/callback",
            id="redirect-uri-with-credentials",
        ),
        pytest.param(
            "redirect_uri",
            "https://notes.example.org:99999/auth/callback",
            id="redirect-uri-with-invalid-port",
        ),
        pytest.param(
            "authorization_endpoint",
            "https://login.exa\nmple.org/auth",
            id="authorization-endpoint-with-a-newline-in-its-host",
        ),
        pytest.param(
            "redirect_uri",
            "https://notes.example.org/auth/call\rback",
            id="redirect-uri-with-a-carriage-return-in-its-path",
        ),
        pytest.param(
            "redirect_uri",
            "https://notes.example.org/auth/call\x85back",
            id="redirect-uri-with-a-c1-control-character",
        ),
        pytest.param("issuer", f"\n{REALM_ISSUER}", id="issuer-led-by-a-newline"),
        pytest.param(
            "end_session_endpoint", f"{END_SESSION_ENDPOINT}?client_id=x",
            id="end-session-endpoint-with-a-query",
        ),
        pytest.param(
            "post_logout_redirect_uri", "http://notes.example.org/",
            id="post-logout-redirect-uri-over-http",
        ),
        pytest.param(
            "post_logout_redirect_uri", f"{POST_LOGOUT_REDIRECT_URI}#signed-out",
            id="post-logout-redirect-uri-with-a-fragment",
        ),
        pytest.param("end_session_endpoint", "https://id.example;x/logout", id="host-semicolon"),
        pytest.param("post_logout_redirect_uri", "https://id.example,x/", id="host-comma"),
        pytest.param("end_session_endpoint", "https://*.example/logout", id="wildcard-host"),
        pytest.param("jwks_url", f"{JWKS_URL}\x00", id="jwks-url-with-a-nul"),
        pytest.param("token_endpoint", f"{TOKEN_ENDPOINT} ", id="token-endpoint-with-a-space"),
        pytest.param("client_id", "", id="client-id-empty"),
        pytest.param("client_secret", SecretStr(""), id="client-secret-empty"),
        pytest.param("client_secret", "a-plain-string-secret", id="client-secret-not-secret-str"),
        pytest.param("scopes", ("profile", "email"), id="scopes-without-openid"),
        pytest.param("scopes", "openid profile", id="scopes-as-one-string"),
        pytest.param("scopes", ("openid", "two words"), id="scope-with-a-space"),
    ],
)
def test_a_client_configuration_is_refused_by_the_field_it_breaks_never_its_value(
    field_name: str, value: object
) -> None:
    with pytest.raises(ValueError, match=f"^{field_name} must ") as refusal:
        a_realm_client_config(**{field_name: value})

    text = _text_of(value)
    assert not text or text not in str(refusal.value)


@pytest.mark.parametrize("field_name", ["end_session_endpoint", "post_logout_redirect_uri"])
@pytest.mark.parametrize("port", ["", ":8443"])
def test_a_plain_host_with_or_without_a_port_is_a_form_target(field_name: str, port: str) -> None:
    url = f"https://keycloak.example.org{port}/realms/r/protocol/openid-connect/logout"

    assert getattr(a_realm_client_config(**{field_name: url}), field_name) == url


_LOOPBACK_HTTP_URLS = [
    "http://localhost",
    "http://LOCALHOST:8080/cb",
    "http://127.0.0.1:8080/cb",
    "http://[::1]:8080/cb",
    "HTTP://localhost/cb",
    "Http://127.0.0.1:8080/cb",
]


@pytest.mark.parametrize("field_name", ["redirect_uri", "post_logout_redirect_uri"])
@pytest.mark.parametrize("url", _LOOPBACK_HTTP_URLS)
def test_the_apps_own_two_urls_may_be_http_on_a_loopback_host(
    field_name: str, url: str
) -> None:
    config = a_realm_client_config(**{field_name: url})

    assert getattr(config, field_name) == url


@pytest.mark.parametrize(
    "field_name",
    ["issuer", "authorization_endpoint", "token_endpoint", "jwks_url", "end_session_endpoint"],
)
@pytest.mark.parametrize("url", _LOOPBACK_HTTP_URLS)
def test_an_issuer_url_stays_https_even_on_a_loopback_host(field_name: str, url: str) -> None:
    with pytest.raises(ValueError, match=f"^{field_name} must "):
        a_realm_client_config(**{field_name: url})


@pytest.mark.parametrize("field_name", ["redirect_uri", "post_logout_redirect_uri"])
@pytest.mark.parametrize(
    "url",
    [
        "http://127.0.0.2/cb",
        "http://localhost.example/cb",
        "http://0.0.0.0/cb",
        "http://example.test/cb",
        "http://user:pass@localhost:8080/cb",
        "http://localhost:8080/cb?next=/",
        "http://localhost:8080/cb#top",
        "ftp://localhost/cb",
        "ws://localhost/cb",
        "http://127.0.0.1.nip.io/cb",
        "http://localhost./cb",
        "http://local\thost/cb",
        "http://local\nhost/cb",
        "http://localhost /cb",
        "http://localhost:99999/cb",
        "http://localhost@evil.test/cb",
    ],
)
def test_the_apps_own_two_urls_refuse_http_unless_the_host_is_loopback_and_the_rest_is_plain(
    field_name: str, url: str
) -> None:
    with pytest.raises(ValueError, match=f"^{field_name} must "):
        a_realm_client_config(**{field_name: url})


def test_a_client_configuration_given_a_logout_path_is_refused() -> None:
    with pytest.raises(TypeError, match="logout_path"):
        a_realm_client_config(logout_path="/logout")


@pytest.mark.parametrize(
    "missing", ["end_session_endpoint", "post_logout_redirect_uri"],
)
def test_a_client_configuration_missing_a_logout_field_fails_at_construction(
    missing: str,
) -> None:
    complete = a_realm_client_config()
    arguments = {each.name: getattr(complete, each.name) for each in dataclasses.fields(complete)}
    del arguments[missing]

    with pytest.raises(TypeError, match=missing):
        OidcClientConfig(**arguments)
