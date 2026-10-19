"""Outbound HTTPS to an issuer: the key-set fetch and the token-endpoint form POST.

This module is the one owner of urllib3, and every request it sends holds the
same bounded posture: HTTPS only, under the system's trusted certificates
(`SSL_CERT_FILE` included); a connect and a read timeout per operation, and a
total deadline over connecting, the TLS handshake, the status, the headers and
the body together, so an origin that drips its answer cannot hold the caller;
no retry; no redirect followed; no content decoding; and at most one byte past
the operation's size limit read from the answer. Only the host name lookup
runs outside the deadline: the resolver offers no way to bound it.

No error this module raises carries any part of the URL, the request or
urllib3's error, and none chains urllib3's error, since its message may quote
the whole URL: a URL may hold a secret in its credentials, path or query, and
a token request carries the client secret, the code and the PKCE verifier.
For the same reason urllib3 logs nothing during an exchange: its records
quote the URL, and a malformed answer's header text, which the origin can
fill with what it was sent.

`fetch_key_set_over_https` is the production `KeySetFetch` of
`webauth.jwt_verification`; `_post_form_over_https` is the transport under the
production `TokenRequestPost`, which `webauth.oidc_transport` fits to that port.
"""

from __future__ import annotations

import contextlib
import logging
import re
import socket
import ssl
import sys
import time
import urllib.parse
from collections.abc import Buffer, Callable, Iterable, Iterator, Mapping
from contextvars import ContextVar
from dataclasses import dataclass, field
from enum import StrEnum
from http import HTTPStatus
from pathlib import Path
from typing import TypeGuard

import urllib3
from pydantic import SecretStr
from urllib3.connection import HTTPSConnection
from urllib3.exceptions import (
    ConnectTimeoutError,
    LocationParseError,
    NameResolutionError,
    NewConnectionError,
)
from urllib3.util import create_urllib3_context
from urllib3.util.connection import allowed_gai_family

from webauth import WebAuthError

_KEY_SET_FETCH_TIMEOUT_SECONDS = 5
KEY_SET_FETCH_DEADLINE_SECONDS = 10
TOKEN_EXCHANGE_DEADLINE_SECONDS = 10
MAX_KEY_SET_BYTES = 64 * 1024

__all__ = [
    "KEY_SET_FETCH_DEADLINE_SECONDS",
    "MAX_KEY_SET_BYTES",
    "TOKEN_EXCHANGE_DEADLINE_SECONDS",
    "ExchangeFailure",
    "KeySetFetchError",
    "fetch_key_set_over_https",
    "is_https_url",
]

_URL_CONTROL_OR_SPACE = re.compile(r"[\x00-\x20\x7f-\x9f]")
_exchanging: ContextVar[bool] = ContextVar("webauth_https_exchanging", default=False)


class KeySetFetchError(WebAuthError):
    """The key set could not be fetched: refused, timed out, redirected, or broken off.

    `failure` names why when the exchange itself failed; it is `None` when the
    origin answered with a status other than 200."""

    def __init__(self, message: str, failure: ExchangeFailure | None = None) -> None:
        super().__init__(message)
        self.failure = failure


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


class _HttpsExchangeError(Exception):
    """An HTTPS exchange that brought back no usable answer; its message is
    the `failure`'s."""

    def __init__(self, failure: ExchangeFailure) -> None:
        super().__init__(failure.value)
        self.failure = failure


@dataclass(frozen=True)
class _HttpsAnswer:
    status: int
    body: bytes = field(repr=False)


@dataclass(frozen=True)
class _RefusedStatus:
    """An answer refused by its status alone, whose body was never read."""

    status: int


def fetch_key_set_over_https(
    url: str,
    *,
    timeout_seconds: float = _KEY_SET_FETCH_TIMEOUT_SECONDS,
    deadline_seconds: float = KEY_SET_FETCH_DEADLINE_SECONDS,
) -> bytes:
    """The production `KeySetFetch`. At most one byte past `MAX_KEY_SET_BYTES`
    is read, so the verifier refuses an oversized answer without buffering it.
    A compressed answer reaches the verifier still compressed and fails as
    invalid JSON.

    `timeout_seconds` bounds connecting and each read on its own;
    `deadline_seconds` bounds the fetch in total, so an origin that trickles
    bytes within each read timeout is cut off. Only a stalled DNS lookup holds
    this refresh past the deadline. Every failure fails closed, and every other
    request is refused at once rather than waiting for this refresh. A
    `timeout_seconds` or `deadline_seconds` of zero or less raises
    `ValueError`."""
    if not is_https_url(url):
        raise KeySetFetchError(
            "refusing to fetch the key set: not an https URL naming a host,"
            " a valid port if any, and no control character, space or credentials",
            ExchangeFailure.NOT_AN_HTTPS_URL,
        )
    try:
        answer = _exchange(
            "GET",
            url,
            accepts_status=_is_key_set_status,
            timeout_seconds=timeout_seconds,
            deadline_seconds=deadline_seconds,
            max_body_bytes=MAX_KEY_SET_BYTES,
        )
    except _HttpsExchangeError as refusal:
        reason = (
            refusal.failure.value
            if refusal.failure is ExchangeFailure.TIMED_OUT
            else "the origin could not be reached, or the TLS handshake or HTTP exchange failed"
        )
        failed = KeySetFetchError(f"fetching the key set failed: {reason}", refusal.failure)
    else:
        if isinstance(answer, _RefusedStatus):
            raise KeySetFetchError(f"the key set origin answered {answer.status}, not 200")
        return answer.body
    # Raised outside the handler so not even the exchange error is its context.
    raise failed


def _post_form_over_https(
    url: str,
    form: Mapping[str, str],
    *,
    authorization: SecretStr,
    max_body_bytes: int,
    timeout_seconds: float,
    deadline_seconds: float = TOKEN_EXCHANGE_DEADLINE_SECONDS,
) -> _HttpsAnswer:
    """POSTs `form` URL-encoded, sending `authorization` as the whole
    `Authorization` header and asking for JSON, and answers the status and
    body of any answer that is not a redirect.

    Raises `_HttpsExchangeError` for a URL that is not well-formed https, an
    origin that cannot be reached, a failed TLS handshake, a timeout or the
    total `deadline_seconds` passing, a broken exchange, a redirect, and a
    body past `max_body_bytes`. A `timeout_seconds` or `deadline_seconds` of
    zero or less raises `ValueError`."""
    if not is_https_url(url):
        raise _HttpsExchangeError(ExchangeFailure.NOT_AN_HTTPS_URL)
    answer = _exchange(
        "POST",
        url,
        accepts_status=_is_form_answer_status,
        timeout_seconds=timeout_seconds,
        deadline_seconds=deadline_seconds,
        max_body_bytes=max_body_bytes,
        headers={
            "Authorization": authorization.get_secret_value(),
            "Accept": "application/json",
            "Content-Type": "application/x-www-form-urlencoded",
        },
        body=urllib.parse.urlencode(form),
    )
    if isinstance(answer, _RefusedStatus):
        raise _HttpsExchangeError(ExchangeFailure.REDIRECTED)
    if len(answer.body) > max_body_bytes:
        raise _HttpsExchangeError(ExchangeFailure.TOO_LARGE)
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


def _is_key_set_status(status: int) -> bool:
    return status == HTTPStatus.OK


def _is_form_answer_status(status: int) -> bool:
    """Any status but a redirect, which is never followed."""
    return not HTTPStatus.MULTIPLE_CHOICES <= status < HTTPStatus.BAD_REQUEST


def _exchange(
    method: str,
    url: str,
    *,
    accepts_status: Callable[[int], bool],
    timeout_seconds: float,
    deadline_seconds: float,
    max_body_bytes: int,
    headers: Mapping[str, str] | None = None,
    body: str | None = None,
) -> _HttpsAnswer | _RefusedStatus:
    """One request under the bounded posture. The answer's body is read, at
    most one byte past `max_body_bytes` of it, only for a status the caller
    `accepts_status`; any other status comes back as `_RefusedStatus`, so an
    answer the caller refuses by its status alone never waits for its body.

    A `timeout_seconds` or `deadline_seconds` of zero or less raises
    `ValueError`, since every exchange would then time out at once.

    Once `deadline_seconds` have passed, the next connect attempt, read,
    write or handshake step raises a timeout, and the exchange fails as
    `TIMED_OUT` whatever error urllib3 made of it."""
    if timeout_seconds <= 0:
        raise ValueError(f"timeout_seconds must be positive, not {timeout_seconds}")
    if deadline_seconds <= 0:
        raise ValueError(f"deadline_seconds must be positive, not {deadline_seconds}")
    deadline = _Deadline.after(deadline_seconds)
    timeout = urllib3.Timeout(connect=timeout_seconds, read=timeout_seconds)
    try:
        with (
            _urllib3_unlogged(),
            urllib3.PoolManager(
                timeout=timeout, retries=False, ssl_context=_tls_context_under(deadline)
            ) as pool,
        ):
            pool.pool_classes_by_scheme = {"https": _https_pool_class_under(deadline)}
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
                if not accepts_status(response.status):
                    return _RefusedStatus(response.status)
                return _HttpsAnswer(response.status, response.read(max_body_bytes + 1))
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
    if deadline.has_passed():
        failure = ExchangeFailure.TIMED_OUT
    # Raised outside the handler so urllib3's error is not even its context.
    raise _HttpsExchangeError(failure)


@dataclass(frozen=True)
class _Deadline:
    expires_at: float

    @classmethod
    def after(cls, seconds: float) -> _Deadline:
        return cls(time.monotonic() + seconds)

    def has_passed(self) -> bool:
        return time.monotonic() >= self.expires_at

    def bound(self, timeout: float | None) -> float:
        """`timeout` shortened to what is left of the deadline; raises the
        socket timeout once nothing is left, since a timeout of zero would
        make the socket non-blocking instead."""
        remaining = self.expires_at - time.monotonic()
        if remaining <= 0:
            raise TimeoutError("the deadline of the exchange has passed")
        return remaining if timeout is None else min(timeout, remaining)


def _tls_context_under(deadline: _Deadline) -> ssl.SSLContext:
    """urllib3's own default context, whose sockets bound every blocking TLS
    step by `deadline`.

    A socket timeout bounds one blocking step, and an origin that drips one
    byte per step never trips it; shortening the timeout before every step to
    what is left of the deadline bounds them all together. The TLS socket is
    where every step after connecting passes through Python, so that is where
    the deadline sits."""

    class SocketUnderDeadline(ssl.SSLSocket):
        def do_handshake(self, block: bool = False) -> None:
            self.settimeout(deadline.bound(self.gettimeout()))
            super().do_handshake(block)

        def read(self, len: int = 1024, buffer: Buffer | None = None) -> bytes:
            self.settimeout(deadline.bound(self.gettimeout()))
            return super().read(len, buffer)

        def send(self, data: Buffer, flags: int = 0) -> int:
            self.settimeout(deadline.bound(self.gettimeout()))
            return super().send(data, flags)

    # urllib3 loads the system's trusted certificates only into a context it
    # makes itself, so this one loads them as urllib3 would.
    context = create_urllib3_context()
    context.load_default_certs()
    context.sslsocket_class = SocketUnderDeadline
    return context


def _https_pool_class_under(deadline: _Deadline) -> type[urllib3.HTTPSConnectionPool]:
    """urllib3's HTTPS pool, whose connections connect within `deadline`.

    urllib3 gives each address the host name resolves to a connect timeout of
    its own, so a host whose every address drops the connection would hold
    the call for that timeout once per address. Here each attempt gets at
    most what is left of the deadline, and none starts once it has passed;
    urllib3's own error classes keep the failure's category."""

    class ConnectionUnderDeadline(HTTPSConnection):
        def _new_conn(self) -> socket.socket:
            try:
                connection = _connect_within(
                    deadline, self._dns_host, self.port, self.timeout, self.socket_options
                )
            # The resolver's IDNA codec refuses an empty label or one over 63
            # characters, which urllib3 reports as a URL it cannot parse.
            except UnicodeError as error:
                raise LocationParseError("label empty or too long") from error
            except socket.gaierror as error:
                raise NameResolutionError(self.host, self, error) from error
            except TimeoutError as error:
                raise ConnectTimeoutError(self, "connecting timed out") from error
            except OSError as error:
                raise NewConnectionError(self, "connecting failed") from error
            sys.audit("http.client.connect", self, self.host, self.port)
            return connection

    class PoolUnderDeadline(urllib3.HTTPSConnectionPool):
        # Under pyright, urllib3's own HTTPSConnection does not satisfy the
        # BaseHTTPSConnection protocol this attribute is declared as.
        ConnectionCls = ConnectionUnderDeadline  # pyright: ignore[reportAssignmentType]

    return PoolUnderDeadline


def _connect_within(
    deadline: _Deadline,
    host: str,
    port: int,
    timeout: float | None,
    socket_options: Iterable[tuple[int, int, int | bytes]] | None,
) -> socket.socket:
    """A socket connected to the first address of `host` that answers, every
    attempt bounded by `timeout` and by what is left of `deadline`."""
    failure = OSError("the host name resolves to no address")
    for family, kind, protocol, _, address in socket.getaddrinfo(
        host.strip("[]"), port, allowed_gai_family(), socket.SOCK_STREAM
    ):
        attempt_timeout = deadline.bound(timeout)
        connection = socket.socket(family, kind, protocol)
        try:
            for option in socket_options or ():
                connection.setsockopt(*option)
            connection.settimeout(attempt_timeout)
            connection.connect(address)
        except OSError as error:
            connection.close()
            failure = error
        else:
            return connection
    raise failure


@contextlib.contextmanager
def _urllib3_unlogged() -> Iterator[None]:
    exchanging = _exchanging.set(True)
    try:
        yield
    finally:
        _exchanging.reset(exchanging)


def _outside_an_exchange(record: logging.LogRecord) -> bool:
    del record
    return not _exchanging.get()


def _quiet_urllib3_during_exchanges() -> None:
    # A logger's filter sees only the records logged on that logger, not on
    # its children, and urllib3 loads some modules only when first used, so
    # the logger of every urllib3 module, loaded or not, gets it now.
    for module_name in _urllib3_module_names():
        logging.getLogger(module_name).addFilter(_outside_an_exchange)


def _urllib3_module_names() -> Iterator[str]:
    """Read from the installed package's files, so no module is imported;
    each is its logger's name, since urllib3 logs only on `__name__`."""
    package = Path(urllib3.__file__).parent
    for source in package.rglob("*.py"):
        module = source.relative_to(package.parent).with_suffix("")
        yield ".".join(module.parent.parts if module.name == "__init__" else module.parts)


_quiet_urllib3_during_exchanges()
