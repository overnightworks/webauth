"""The client configuration a relying party builds from its issuer's discovery document.

`discover_oidc_client_config` runs once at host startup. Its fetch is injected, so
the document's content is served by `FakeKeySetEndpoint`; one scenario runs it on
the production fetch against a loopback TLS server. Every refusal is loud and names
the field it concerns, never the document's value. The production fetch,
`fetch_provider_metadata_over_https`, has the transport scenarios of its own at the end,
beside the shared ones of `test_https_client`.
"""

from __future__ import annotations

import json
import traceback
from collections.abc import Callable
from typing import Any

import pytest
from pydantic import SecretStr

from tests.support.oidc_arrangement import (
    ACCESS_TOKEN_LEEWAY_SECONDS,
    APP_CLIENT_ID,
    CLIENT_SECRET,
    POST_LOGOUT_REDIRECT_URI,
    REALM_ISSUER,
    REDIRECT_URI,
    FakeKeySetEndpoint,
    LoopbackHttpsServer,
    a_realm_client_config,
)
from tests.support.provider_metadata import (
    ABSENT,
    METADATA_LIMIT_BYTES,
    a_provider_metadata,
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


def test_the_documents_four_endpoints_and_the_hosts_own_values_make_the_configuration() -> None:
    """DISCOVERY-01, DISCOVERY-09: the document is read once."""
    metadata = FakeKeySetEndpoint(a_provider_metadata(REALM_ISSUER))

    assert _discover(metadata) == a_realm_client_config(
        authorization_response_iss_parameter_supported=True
    )
    assert metadata.fetched_urls == [_WELL_KNOWN_URL]


def test_a_host_that_names_no_scopes_gets_the_one_scope_a_configuration_defaults_to() -> None:
    """DISCOVERY-01: scopes default to openid."""
    config = discover_oidc_client_config(
        REALM_ISSUER,
        fetch_provider_metadata=FakeKeySetEndpoint(a_provider_metadata(REALM_ISSUER)),
        client_id=APP_CLIENT_ID,
        client_secret=SecretStr(CLIENT_SECRET),
        redirect_uri=REDIRECT_URI,
        post_logout_redirect_uri=POST_LOGOUT_REDIRECT_URI,
        leeway_seconds=ACCESS_TOKEN_LEEWAY_SECONDS,
    )

    assert config.scopes == ("openid",)


def test_one_trailing_slash_of_the_issuer_is_dropped_from_the_document_url_only() -> None:
    """DISCOVERY-01: one trailing slash leaves the document URL, not the issuer."""
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
    """DISCOVERY-02, DISCOVERY-06."""
    metadata = FakeKeySetEndpoint(a_provider_metadata(issuer, issuer=claimed))

    with pytest.raises(OidcDiscoveryError, match="issuer"):
        _discover(metadata, issuer)


def test_a_refused_issuer_does_not_repeat_what_the_document_claims() -> None:
    """DISCOVERY-06: the message never repeats the document's value."""
    claimed = "https://evil.example.net/realms/workshop"
    metadata = FakeKeySetEndpoint(a_provider_metadata(REALM_ISSUER, issuer=claimed))

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
    """DISCOVERY-06."""
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
    """DISCOVERY-04."""
    metadata = FakeKeySetEndpoint(a_provider_metadata(REALM_ISSUER, **{field_name: value}))

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
    """DISCOVERY-05."""
    metadata = FakeKeySetEndpoint(a_provider_metadata(REALM_ISSUER, **{field_name: url}))

    with pytest.raises(ValueError, match=f"^{refused_field} must be an https URL") as refused:
        _discover(metadata)

    assert url not in str(refused.value)


@pytest.mark.parametrize(
    "issuer",
    [
        pytest.param(f"{REALM_ISSUER}?q=1", id="query"),
        pytest.param(f"{REALM_ISSUER}#fragment", id="fragment"),
        pytest.param(REALM_ISSUER.replace("https:", "http:"), id="not-https"),
    ],
)
def test_a_malformed_issuer_is_refused_with_the_configurations_error_before_any_fetch(
    issuer: str,
) -> None:
    """DISCOVERY-11."""
    metadata = FakeKeySetEndpoint(a_provider_metadata(issuer))

    with pytest.raises(ValueError, match="^issuer must be an https URL") as refused:
        _discover(metadata, issuer)

    assert issuer not in str(refused.value)
    assert metadata.fetched_urls == []


@pytest.mark.parametrize(
    ("field_name", "value"),
    [
        pytest.param("code_challenge_methods_supported", [], id="methods-empty"),
        pytest.param("code_challenge_methods_supported", ["plain"], id="methods-plain-only"),
        pytest.param("code_challenge_methods_supported", ["s256"], id="methods-another-case"),
        pytest.param("code_challenge_methods_supported", "S256", id="methods-a-string"),
        pytest.param("code_challenge_methods_supported", None, id="methods-null"),
        pytest.param("authorization_response_iss_parameter_supported", "true", id="iss-text"),
        pytest.param("authorization_response_iss_parameter_supported", 1, id="iss-number"),
        pytest.param("authorization_response_iss_parameter_supported", None, id="iss-null"),
        pytest.param("authorization_response_iss_parameter_supported", ["true"], id="iss-list"),
    ],
)
def test_a_document_member_of_the_wrong_shape_is_refused_naming_it(
    field_name: str, value: object
) -> None:
    """DISCOVERY-03, DISCOVERY-12, DISCOVERY-06: code challenge methods without S256 and an iss
    support member that is no boolean."""
    metadata = FakeKeySetEndpoint(a_provider_metadata(REALM_ISSUER, **{field_name: value}))

    with pytest.raises(OidcDiscoveryError, match=field_name):
        _discover(metadata)


@pytest.mark.parametrize(
    ("member", "supported"),
    [
        pytest.param(True, True, id="announced"),
        pytest.param(False, False, id="denied"),
        pytest.param(ABSENT, False, id="absent-defaults-to-false"),
    ],
)
def test_the_document_says_whether_the_issuer_sends_iss_and_silence_means_it_does_not(
    member: object, supported: bool
) -> None:
    """DISCOVERY-12."""
    metadata = FakeKeySetEndpoint(
        a_provider_metadata(REALM_ISSUER, authorization_response_iss_parameter_supported=member)
    )

    config = _discover(metadata)

    assert config.authorization_response_iss_parameter_supported is supported


def test_a_document_advertising_no_code_challenge_methods_is_accepted() -> None:
    """DISCOVERY-03."""
    metadata = FakeKeySetEndpoint(
        a_provider_metadata(REALM_ISSUER, code_challenge_methods_supported=ABSENT)
    )

    assert _discover(metadata) == a_realm_client_config(
        authorization_response_iss_parameter_supported=True
    )


def test_a_fetch_that_fails_fails_the_discovery_with_the_fetchs_own_error() -> None:
    """DISCOVERY-08."""
    failure = ProviderMetadataFetchError("fetching failed", ExchangeFailure.TIMED_OUT)

    with pytest.raises(ProviderMetadataFetchError) as refused:
        _discover(FakeKeySetEndpoint(failure))

    assert refused.value is failure


def test_a_discovery_refusal_is_a_web_auth_error() -> None:
    """DISCOVERY-06."""
    endpoint = FakeKeySetEndpoint(json.dumps([]).encode())

    with pytest.raises(WebAuthError):
        _discover(endpoint)


def test_the_production_fetch_reads_the_servers_document_at_its_well_known_path(
    token_server: LoopbackHttpsServer,
) -> None:
    """DISCOVERY-01, DISCOVERY-07: through the production fetch."""
    config = _discover(fetch_provider_metadata_over_https, token_server.base_url)

    assert token_server.requested_paths == ["/.well-known/openid-configuration"]
    assert config.token_endpoint == f"{token_server.base_url}/protocol/openid-connect/token"


def test_a_provider_metadata_document_of_exactly_the_size_limit_comes_back_whole(
    token_server: LoopbackHttpsServer,
) -> None:
    """DISCOVERY-07."""
    document = fetch_provider_metadata_over_https(f"{token_server.base_url}/metadata-at-limit")

    assert len(document) == METADATA_LIMIT_BYTES


@pytest.mark.parametrize("path", ["/metadata-past-limit", "/oversized"], ids=["valid-json", "far"])
def test_a_provider_metadata_document_past_the_size_limit_is_refused_as_too_large(
    token_server: LoopbackHttpsServer, path: str
) -> None:
    """DISCOVERY-07."""
    with pytest.raises(ProviderMetadataFetchError) as refused:
        fetch_provider_metadata_over_https(f"{token_server.base_url}{path}")

    assert refused.value.failure is ExchangeFailure.TOO_LARGE


@pytest.mark.parametrize("path", ["/missing", "/moved"], ids=["not-found", "redirect"])
def test_a_provider_metadata_origin_answering_another_status_is_refused_naming_it(
    token_server: LoopbackHttpsServer, path: str
) -> None:
    """DISCOVERY-07."""
    with pytest.raises(ProviderMetadataFetchError) as refused:
        fetch_provider_metadata_over_https(f"{token_server.base_url}{path}")

    assert str(refused.value).startswith("the provider metadata origin answered ")
    assert refused.value.failure is None
    assert token_server.requested_paths == [path]


@pytest.mark.parametrize(
    "url", ["http://{authority}/doc", "https://["], ids=["http", "unparseable"]
)
def test_a_provider_metadata_fetch_refuses_any_url_but_a_well_formed_https_one_before_a_request(
    token_server: LoopbackHttpsServer, url: str
) -> None:
    """DISCOVERY-07."""
    authority = token_server.base_url.removeprefix("https://")
    refused_url = url.format(authority=authority)

    with pytest.raises(ProviderMetadataFetchError) as refused:
        fetch_provider_metadata_over_https(refused_url)

    assert refused.value.failure is ExchangeFailure.NOT_AN_HTTPS_URL
    assert token_server.requested_paths == []


def test_a_provider_metadata_origin_the_system_does_not_trust_is_refused_without_the_url(
    token_server: LoopbackHttpsServer, monkeypatch: pytest.MonkeyPatch
) -> None:
    """DISCOVERY-07."""
    monkeypatch.delenv("SSL_CERT_FILE")
    secret = "s3cr3t-in-the-query"  # noqa: S105

    with pytest.raises(ProviderMetadataFetchError) as refused:
        fetch_provider_metadata_over_https(f"{token_server.base_url}/doc?signature={secret}")

    assert refused.value.failure is ExchangeFailure.TLS_FAILED
    assert secret not in "".join(traceback.format_exception(refused.value))
    assert refused.value.__cause__ is None
    assert refused.value.__context__ is None
