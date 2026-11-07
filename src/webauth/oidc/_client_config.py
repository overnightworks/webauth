"""The registration of one OpenID Connect client: its URLs, credentials and scopes."""

from __future__ import annotations

import re
import urllib.parse
from dataclasses import dataclass

from pydantic import SecretStr

from webauth._validation import is_scope_token_tuple
from webauth.https_client import is_https_url

__all__ = ["OidcClientConfig"]

_OPENID_SCOPE = "openid"
_ENDPOINT_URL_FIELDS = (
    "issuer",
    "authorization_endpoint",
    "token_endpoint",
    "jwks_url",
    "end_session_endpoint",
)
_APP_URL_FIELDS = ("redirect_uri", "post_logout_redirect_uri")
# The logout page posts to `end_session_endpoint`; the issuer then redirects to
# `post_logout_redirect_uri`; both are `form-action` sources: a plain host and optional port.
_FORM_TARGET_FIELDS = ("end_session_endpoint", "post_logout_redirect_uri")
_PLAIN_AUTHORITY = re.compile(r"(?:[A-Za-z0-9.-]+|\[[0-9A-Fa-f:.]+\])(?::\d+)?", re.ASCII)
# RFC 8252 sections 7.3 and 8.3: the loopback literals and localhost.
# `urlsplit` lowercases the hostname and drops the brackets of an IPv6 literal.
_LOOPBACK_HOSTS = frozenset({"localhost", "127.0.0.1", "::1"})
_URL_RULE = (
    "a host, a valid port if any, and no control character, space, credentials, query or fragment"
)


@dataclass(frozen=True, kw_only=True)
class OidcClientConfig:
    """One client registered at one issuer.

    `end_session_endpoint` is the issuer's logout page and
    `post_logout_redirect_uri` the app page it sends the browser back to; the
    issuer checks the latter against the client's registered post-logout URIs.
    Every URL names a host and carries no control character, space,
    credentials, query or fragment. The host of `end_session_endpoint` and
    `post_logout_redirect_uri` is letters, digits, `.` and `-`, or a bracketed IPv6 literal,
    so it can stand as a source in the logout page's policy. The issuer, the three endpoints and
    `jwks_url` are https, because the library connects to them or trusts what
    they sign. `redirect_uri` and `post_logout_redirect_uri` are only values
    the browser is sent to, so they may also be http when the host is exactly
    `localhost`, `127.0.0.1` or `[::1]`, for local and CI test stacks. Browsers
    differ in whether they keep a `Secure` cookie over http on a loopback host,
    so a stack that must work in each sets `cookie_secure=False` on its
    `WebAuthConfig`. `scopes` includes `openid`. `leeway_seconds`
    is checked by the `_JwtVerifier` the relying party builds from it."""

    issuer: str
    authorization_endpoint: str
    token_endpoint: str
    jwks_url: str
    end_session_endpoint: str
    client_id: str
    client_secret: SecretStr
    redirect_uri: str
    post_logout_redirect_uri: str
    scopes: tuple[str, ...] = (_OPENID_SCOPE,)
    leeway_seconds: int

    def __post_init__(self) -> None:
        self._check_urls()
        if not isinstance(self.client_id, str) or not self.client_id:
            raise ValueError("client_id must be a non-empty string")
        if (
            not isinstance(self.client_secret, SecretStr)
            or not self.client_secret.get_secret_value()
        ):
            raise ValueError("client_secret must be a non-empty SecretStr")
        if not _is_scope_list_with_openid(self.scopes):
            raise ValueError("scopes must be a tuple of scope tokens that includes openid")

    def _check_urls(self) -> None:
        for name in _ENDPOINT_URL_FIELDS:
            if not _is_endpoint_url(getattr(self, name)):
                raise ValueError(f"{name} must be an https URL naming {_URL_RULE}")
        for name in _APP_URL_FIELDS:
            if not _is_app_url(getattr(self, name)):
                raise ValueError(
                    f"{name} must be an https URL, or an http URL whose host is"
                    f" localhost, 127.0.0.1 or [::1], naming {_URL_RULE}"
                )
        for name in _FORM_TARGET_FIELDS:
            if not _PLAIN_AUTHORITY.fullmatch(urllib.parse.urlsplit(getattr(self, name)).netloc):
                raise ValueError(f"{name} must name a plain host and optional port")


def _is_endpoint_url(url: object) -> bool:
    return is_https_url(url) and "?" not in url and "#" not in url


def _is_app_url(url: object) -> bool:
    """An endpoint URL, or the same shape over http on a loopback host.

    The http form is judged by `is_https_url` with its scheme swapped, so the
    control character, space, credential and port guards stay in one place."""
    if _is_endpoint_url(url):
        return True
    if not isinstance(url, str) or url[:5].lower() != "http:":
        return False
    try:
        host = urllib.parse.urlsplit(url).hostname
    except ValueError:
        return False
    return host in _LOOPBACK_HOSTS and _is_endpoint_url(f"https:{url[5:]}")


def _is_scope_list_with_openid(scopes: object) -> bool:
    return is_scope_token_tuple(scopes) and _OPENID_SCOPE in scopes
