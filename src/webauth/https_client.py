"""Outbound HTTPS to an issuer: the key-set fetch and the token-endpoint form POST.

This module is the one owner of urllib3, and every request it sends holds the
same bounded posture: HTTPS only, under the system's trusted certificates
(`SSL_CERT_FILE` included); a connect and a read timeout per operation; no
retry; no redirect followed; no content decoding; and at most one byte past
the operation's size limit read from the answer.

No error this module raises carries any part of the URL, the request or
urllib3's error, and none chains urllib3's error, since its message may quote
the whole URL: a URL may hold a secret in its credentials, path or query, and
a token request carries the client secret, the code and the PKCE verifier.

`fetch_key_set_over_https` is the production `KeySetFetch` of
`webauth.jwt_verification`; `post_form_over_https` is the transport under the
production `TokenRequestPost`, which `webauth.oidc_login` fits to that port.

Install the `jwt` extra to use this module.
"""

from __future__ import annotations

import re
import urllib.parse
from collections.abc import Callable, Mapping
from dataclasses import dataclass, field
from enum import StrEnum
from http import HTTPStatus
from typing import TypeGuard

import urllib3
from pydantic import SecretStr

KEY_SET_FETCH_TIMEOUT_SECONDS = 5
MAX_KEY_SET_BYTES = 64 * 1024

_URL_CONTROL_OR_SPACE = re.compile(r"[\x00-\x20\x7f-\x9f]")


class KeySetFetchError(Exception):
    """The key set could not be fetched: refused, timed out, redirected, or broken off."""


class ExchangeFailure(StrEnum):
    """Why an HTTPS exchange brought back no usable answer, in words this
    module owns."""

    NOT_AN_HTTPS_URL = (
        "refusing the request: not an https URL naming a host, a valid port if any,"
        " and no control character, space or credentials"
    )
    UNREACHABLE = "the origin could not be reached"
    TLS_FAILED = "the TLS handshake with the origin failed or its certificate is not trusted"
    TIMED_OUT = "the origin did not answer within the timeout"
    BROKEN_OFF = "the HTTP exchange with the origin broke off"
    REDIRECTED = "the origin answered with a redirect, which is never followed"
    TOO_LARGE = "the origin's answer exceeds its size limit"


class HttpsExchangeError(Exception):
    """An HTTPS exchange that brought back no usable answer; its message is
    the `failure`'s."""

    def __init__(self, failure: ExchangeFailure) -> None:
        super().__init__(failure.value)
        self.failure = failure


@dataclass(frozen=True)
class HttpsAnswer:
    status: int
    body: bytes = field(repr=False)


def fetch_key_set_over_https(
    url: str, *, timeout_seconds: float = KEY_SET_FETCH_TIMEOUT_SECONDS
) -> bytes:
    """The production `KeySetFetch`. At most one byte past `MAX_KEY_SET_BYTES`
    is read, so the verifier refuses an oversized answer without buffering it.
    A compressed answer reaches the verifier still compressed and fails as
    invalid JSON.

    `timeout_seconds` bounds connecting and each read on its own, not the
    fetch in total: a stalled DNS lookup, or an origin that trickles bytes
    within each read timeout, holds this refresh for as long as it lasts.
    Every failure fails closed, and every other request is refused at once
    rather than waiting for this refresh."""
    if not is_https_url(url):
        raise KeySetFetchError(
            "refusing to fetch the key set: not an https URL naming a host,"
            " a valid port if any, and no control character, space or credentials"
        )
    try:
        answer = _exchange(
            "GET",
            url,
            reads_body=lambda status: status == HTTPStatus.OK,
            timeout_seconds=timeout_seconds,
            max_body_bytes=MAX_KEY_SET_BYTES,
        )
    except HttpsExchangeError:
        failed = KeySetFetchError(
            "fetching the key set failed: the origin could not be reached,"
            " or the TLS handshake or HTTP exchange failed"
        )
    else:
        if answer.status != HTTPStatus.OK:
            raise KeySetFetchError(f"the key set origin answered {answer.status}, not 200")
        return answer.body
    # Raised outside the handler so not even the exchange error is its context.
    raise failed


def post_form_over_https(
    url: str,
    form: Mapping[str, str],
    *,
    authorization: SecretStr,
    max_body_bytes: int,
    timeout_seconds: float,
) -> HttpsAnswer:
    """POSTs `form` URL-encoded, sending `authorization` as the whole
    `Authorization` header and asking for JSON, and answers the status and
    body of any answer that is not a redirect.

    Raises `HttpsExchangeError` for a URL that is not well-formed https, an
    origin that cannot be reached, a failed TLS handshake, a timeout, a
    broken exchange, a redirect, and a body past `max_body_bytes`."""
    if not is_https_url(url):
        raise HttpsExchangeError(ExchangeFailure.NOT_AN_HTTPS_URL)
    answer = _exchange(
        "POST",
        url,
        reads_body=lambda status: not _is_redirect(status),
        timeout_seconds=timeout_seconds,
        max_body_bytes=max_body_bytes,
        headers={
            "Authorization": authorization.get_secret_value(),
            "Accept": "application/json",
            "Content-Type": "application/x-www-form-urlencoded",
        },
        body=urllib.parse.urlencode(form),
    )
    if _is_redirect(answer.status):
        raise HttpsExchangeError(ExchangeFailure.REDIRECTED)
    if len(answer.body) > max_body_bytes:
        raise HttpsExchangeError(ExchangeFailure.TOO_LARGE)
    return answer


def is_https_url(url: object) -> TypeGuard[str]:
    """A string that is an https URL naming a host, a valid port if any, and
    no control character, space or credentials.

    A control character or space is refused outright: the URL parser strips
    some of them before judging, so the parse would pass a URL that is not
    the one stored and later sent."""
    if not isinstance(url, str) or _URL_CONTROL_OR_SPACE.search(url):
        return False
    try:
        origin = urllib.parse.urlsplit(url)
        _ = origin.port
    except ValueError:
        return False
    return origin.scheme == "https" and bool(origin.hostname) and "@" not in origin.netloc


def _is_redirect(status: int) -> bool:
    return HTTPStatus.MULTIPLE_CHOICES <= status < HTTPStatus.BAD_REQUEST


def _exchange(
    method: str,
    url: str,
    *,
    reads_body: Callable[[int], bool],
    timeout_seconds: float,
    max_body_bytes: int,
    headers: Mapping[str, str] | None = None,
    body: str | None = None,
) -> HttpsAnswer:
    """One request under the bounded posture. The answer's body is read, at
    most one byte past `max_body_bytes` of it, only for a status the caller
    `reads_body` for; any other status comes back with an empty body, so an
    answer the caller refuses by its status alone never waits for its body."""
    timeout = urllib3.Timeout(connect=timeout_seconds, read=timeout_seconds)
    try:
        with urllib3.PoolManager(timeout=timeout, retries=False) as pool:
            response = pool.request(
                method,
                url,
                headers=headers,
                body=body,
                redirect=False,
                preload_content=False,
                decode_content=False,
            )
            try:
                answered = response.read(max_body_bytes + 1) if reads_body(response.status) else b""
                return HttpsAnswer(response.status, answered)
            finally:
                response.close()
    except urllib3.exceptions.SSLError:
        failure = ExchangeFailure.TLS_FAILED
    # Before TimeoutError, which urllib3 makes its base class.
    except urllib3.exceptions.NewConnectionError:
        failure = ExchangeFailure.UNREACHABLE
    except urllib3.exceptions.TimeoutError:
        failure = ExchangeFailure.TIMED_OUT
    except (urllib3.exceptions.HTTPError, OSError):
        failure = ExchangeFailure.BROKEN_OFF
    # Raised outside the handler so urllib3's error is not even its context.
    raise HttpsExchangeError(failure)
