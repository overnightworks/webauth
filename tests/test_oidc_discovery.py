"""The client configuration a relying party builds from its issuer's discovery document.

`discover_oidc_client_config` runs once at host startup. Its fetch is injected, so
the document's content is served by `FakeKeySetEndpoint`; one scenario runs it on
the production fetch against a loopback TLS server. Every refusal is loud and names
the field it concerns, never the document's value.
"""

from __future__ import annotations

import json
from collections.abc import Callable
from typing import Any

import pytest
from pydantic import SecretStr

from tests.support.oidc_arrangement import (
    ABSENT,
    ACCESS_TOKEN_LEEWAY_SECONDS,
    APP_CLIENT_ID,
    CLIENT_SECRET,
    POST_LOGOUT_REDIRECT_URI,
    REALM_ISSUER,
    REDIRECT_URI,
    FakeKeySetEndpoint,
    LoopbackHttpsServer,
    a_provider_metadata,
    a_realm_client_config,
)
from webauth import WebAuthError
from webauth.https_client import (
    ExchangeFailure,
    ProviderMetadataFetchError,
    fetch_provider_metadata_over_https,
)
from webauth.oidc import OidcClientConfig, OidcDiscoveryError, discover_oidc_client_config

_WELL_KNOWN_URL = f"{REALM_ISSUER}/.well-known/openid-configuration"
_SCOPES = ("openid", "profile")


def _discover(
    fetch: Callable[[str], bytes], issuer: str = REALM_ISSUER, **changes: Any
) -> OidcClientConfig:
    arguments: dict[str, Any] = {
        "fetch_provider_metadata": fetch,
        "client_id": APP_CLIENT_ID,
        "client_secret": SecretStr(CLIENT_SECRET),
        "redirect_uri": REDIRECT_URI,
        "post_logout_redirect_uri": POST_LOGOUT_REDIRECT_URI,
        "scopes": _SCOPES,
        "leeway_seconds": ACCESS_TOKEN_LEEWAY_SECONDS,
    }
    return discover_oidc_client_config(issuer, **{**arguments, **changes})


def test_the_issuers_four_endpoints_and_the_hosts_own_values_make_the_client_configuration() -> (
    None
):
    metadata = FakeKeySetEndpoint(a_provider_metadata())

    assert _discover(metadata) == a_realm_client_config()
    assert metadata.fetched_urls == [_WELL_KNOWN_URL]


def test_a_host_that_names_no_scopes_gets_the_one_scope_a_configuration_defaults_to() -> None:
    config = discover_oidc_client_config(
        REALM_ISSUER,
        fetch_provider_metadata=FakeKeySetEndpoint(a_provider_metadata()),
        client_id=APP_CLIENT_ID,
        client_secret=SecretStr(CLIENT_SECRET),
        redirect_uri=REDIRECT_URI,
        post_logout_redirect_uri=POST_LOGOUT_REDIRECT_URI,
        leeway_seconds=ACCESS_TOKEN_LEEWAY_SECONDS,
    )

    assert config.scopes == ("openid",)


def test_one_trailing_slash_of_the_issuer_is_dropped_from_the_document_url_only() -> None:
    issuer = f"{REALM_ISSUER}/"
    metadata = FakeKeySetEndpoint(a_provider_metadata(issuer))

    config = _discover(metadata, issuer)

    assert metadata.fetched_urls == [_WELL_KNOWN_URL]
    assert config.issuer == issuer


@pytest.mark.parametrize(
    ("issuer", "claimed"),
    [
        pytest.param(f"{REALM_ISSUER}/", REALM_ISSUER, id="trailing-slash-only-configured"),
        pytest.param(REALM_ISSUER, f"{REALM_ISSUER}/", id="trailing-slash-only-claimed"),
        pytest.param(REALM_ISSUER, "https://login.example.org/realms/other", id="another-realm"),
        pytest.param(REALM_ISSUER, REALM_ISSUER.upper(), id="another-case"),
        pytest.param(REALM_ISSUER, None, id="not-a-string"),
        pytest.param(REALM_ISSUER, ABSENT, id="missing"),
    ],
)
def test_a_document_whose_issuer_is_not_exactly_the_configured_one_is_refused(
    issuer: str, claimed: object
) -> None:
    metadata = FakeKeySetEndpoint(a_provider_metadata(issuer, issuer=claimed))

    with pytest.raises(OidcDiscoveryError, match="issuer"):
        _discover(metadata, issuer)


def test_a_refused_issuer_does_not_repeat_what_the_document_claims() -> None:
    claimed = "https://evil.example.net/realms/workshop"
    metadata = FakeKeySetEndpoint(a_provider_metadata(issuer=claimed))

    with pytest.raises(OidcDiscoveryError) as refused:
        _discover(metadata)

    assert claimed not in str(refused.value)


@pytest.mark.parametrize(
    "body",
    [
        pytest.param(b"", id="empty"),
        pytest.param(b"<html>not the issuer</html>", id="not-json"),
        pytest.param(b"\xff\xfe\x00", id="not-utf8"),
        pytest.param(b"[" * 50_000, id="nested-past-the-parsers-depth"),
        pytest.param(b'["issuer"]', id="a-list"),
        pytest.param(b'"issuer"', id="a-string"),
        pytest.param(b"null", id="null"),
    ],
)
def test_a_body_that_is_not_a_json_object_is_refused(body: bytes) -> None:
    with pytest.raises(OidcDiscoveryError, match="JSON object"):
        _discover(FakeKeySetEndpoint(body))


@pytest.mark.parametrize(
    "field_name",
    ["authorization_endpoint", "token_endpoint", "jwks_uri", "end_session_endpoint"],
)
@pytest.mark.parametrize(
    "value",
    [
        pytest.param(ABSENT, id="missing"),
        pytest.param(None, id="null"),
        pytest.param(7, id="number"),
        pytest.param(["https://login.example.org/x"], id="list"),
    ],
)
def test_an_endpoint_missing_or_not_a_string_is_refused_naming_the_field(
    field_name: str, value: object
) -> None:
    metadata = FakeKeySetEndpoint(a_provider_metadata(**{field_name: value}))

    with pytest.raises(OidcDiscoveryError, match=field_name):
        _discover(metadata)


@pytest.mark.parametrize(
    ("field_name", "refused_field", "url"),
    [
        pytest.param(
            "authorization_endpoint",
            "authorization_endpoint",
            "http://login.example.org/auth",
            id="authorization-endpoint-over-http",
        ),
        pytest.param(
            "token_endpoint",
            "token_endpoint",
            f"{REALM_ISSUER}/token?client_secret=leak",
            id="token-endpoint-with-query",
        ),
        pytest.param(
            "jwks_uri", "jwks_url", "https://user:pass@login.example.org/certs", id="jwks-uri"
        ),
        pytest.param(
            "end_session_endpoint",
            "end_session_endpoint",
            "https://login.example.org:99999/logout",
            id="end-session-endpoint-with-a-bad-port",
        ),
    ],
)
def test_an_endpoint_the_configuration_refuses_is_refused_with_the_configurations_error(
    field_name: str, refused_field: str, url: str
) -> None:
    metadata = FakeKeySetEndpoint(a_provider_metadata(**{field_name: url}))

    with pytest.raises(ValueError, match=f"^{refused_field} must be an https URL") as refused:
        _discover(metadata)

    assert url not in str(refused.value)


@pytest.mark.parametrize(
    "methods",
    [
        pytest.param([], id="empty"),
        pytest.param(["plain"], id="plain-only"),
        pytest.param(["s256"], id="another-case"),
        pytest.param("S256", id="a-string"),
        pytest.param(None, id="null"),
    ],
)
def test_a_document_advertising_code_challenge_methods_without_s256_is_refused(
    methods: object,
) -> None:
    metadata = FakeKeySetEndpoint(a_provider_metadata(code_challenge_methods_supported=methods))

    with pytest.raises(OidcDiscoveryError, match="code_challenge_methods_supported"):
        _discover(metadata)


def test_a_document_advertising_no_code_challenge_methods_is_accepted() -> None:
    metadata = FakeKeySetEndpoint(a_provider_metadata(code_challenge_methods_supported=ABSENT))

    assert _discover(metadata) == a_realm_client_config()


def test_a_fetch_that_fails_fails_the_discovery_with_the_fetchs_own_error() -> None:
    failure = ProviderMetadataFetchError("fetching failed", ExchangeFailure.TIMED_OUT)

    with pytest.raises(ProviderMetadataFetchError) as refused:
        _discover(FakeKeySetEndpoint(failure))

    assert refused.value is failure


def test_a_discovery_refusal_is_a_web_auth_error() -> None:
    with pytest.raises(WebAuthError):
        _discover(FakeKeySetEndpoint(json.dumps([]).encode()))


def test_the_production_fetch_reads_the_servers_document_at_its_well_known_path(
    token_server: LoopbackHttpsServer,
) -> None:
    config = _discover(fetch_provider_metadata_over_https, token_server.base_url)

    assert token_server.requested_paths == ["/.well-known/openid-configuration"]
    assert config.token_endpoint == f"{token_server.base_url}/protocol/openid-connect/token"
