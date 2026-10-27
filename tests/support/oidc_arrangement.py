"""Builders for tokens, key sets and the issuer endpoints a relying party talks to.

The keys, signed tokens and key-set documents here are what an issuer
publishes; the fakes stand in for the injected clock, key-set fetch and token
POST, so the verifier and the relying party run offline and deterministically.
`loopback_https_server` is the real counterpart of both endpoints, a TLS
server on loopback for the production HTTPS transport.
"""

from __future__ import annotations

import base64
import contextlib
import datetime
import gzip
import hashlib
import ipaddress
import itertools
import json
import secrets
import socket
import ssl
import threading
import time
import urllib.parse
from collections.abc import Callable, Iterator, Mapping
from dataclasses import dataclass, field, fields, is_dataclass
from functools import cache
from html.parser import HTMLParser
from http.server import BaseHTTPRequestHandler, HTTPServer
from pathlib import Path
from typing import Any, Protocol

import pytest
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding, rsa
from cryptography.x509.oid import ExtendedKeyUsageOID, NameOID
from fastapi import FastAPI, Request
from jwt.algorithms import RSAAlgorithm
from pydantic import SecretStr

from tests.support.webauth_arrangement import an_http_scope, session_cookie_header
from webauth.config import WebAuthConfig, install_web_auth_config
from webauth.https_client import MAX_KEY_SET_BYTES
from webauth.jwt_verification import KeySetFetch, MonotonicClock
from webauth.oidc import (
    MAX_TOKEN_RESPONSE_BYTES,
    OidcClientConfig,
    OidcRelyingParty,
    TokenEndpointAnswer,
    TokenRequest,
    TokenRequestPost,
)
from webauth.oidc_login import AdmittedLogin, open_session
from webauth.ports import SessionRecord, SessionRecordStore, WallClock, WriteLock

ABSENT = object()
"""A claim or header change that removes the member instead of setting it."""


@cache
def rsa_key(name: str) -> rsa.RSAPrivateKey:
    """One generated key per name for the whole session: RSA generation is the
    slow part, and a key is immutable scenario data."""
    del name
    return rsa.generate_private_key(public_exponent=65537, key_size=2048)


def segment(value: dict[str, Any] | str) -> str:
    """A base64url segment of a JSON object, or of raw JSON text when the
    scenario needs bytes `json.dumps` cannot produce (duplicate members)."""
    text = value if isinstance(value, str) else json.dumps(value)
    return base64.urlsafe_b64encode(text.encode()).rstrip(b"=").decode()


def a_fake_id_token(label: str) -> str:
    """A compact-JWS-shaped string that no issuer signed and no verifier would accept."""
    return f"{segment({'typ': 'JWT'})}.{segment({'sub': label})}.{segment(label)}"


def a_token_of_length(length: int, make: Callable[[str, str], str]) -> str:
    """The token ``make(header_padding, claim_padding)`` builds with exactly ``length``
    characters. Base64url cannot spell some payload lengths, so the header's padding is the
    second knob."""
    for header_padding in ("", "h", "hh"):
        shortest = len(make(header_padding, ""))
        estimate = (length - shortest) * 3 // 4
        for claim_padding in range(estimate - 12, estimate + 1):
            token = make(header_padding, "/" + "p" * claim_padding)
            if len(token) == length:
                return token
    raise AssertionError(f"no token of {length} characters")


def rs256(key: rsa.RSAPrivateKey) -> Callable[[bytes], bytes]:
    return lambda signing_input: key.sign(signing_input, padding.PKCS1v15(), hashes.SHA256())


def jws(header: dict[str, Any] | str, claims: dict[str, Any] | str, sign: Callable) -> str:
    signing_input = f"{segment(header)}.{segment(claims)}"
    signature = base64.urlsafe_b64encode(sign(signing_input.encode())).rstrip(b"=").decode()
    return f"{signing_input}.{signature}"


ISSUED_REFRESH_TOKEN = "refresh-token-rt-1"  # noqa: S105
ISSUED_ACCESS_TOKEN_CANARY = "access-token-canary-never-stored"  # noqa: S105


def changed(base: dict[str, Any], changes: dict[str, Any]) -> dict[str, Any]:
    merged = {**base, **changes}
    return {name: value for name, value in merged.items() if value is not ABSENT}


def public_jwk(key: rsa.RSAPrivateKey, key_id: str, **changes: Any) -> dict[str, Any]:
    jwk = RSAAlgorithm.to_jwk(key.public_key(), as_dict=True)
    return changed({**jwk, "kid": key_id, "alg": "RS256", "use": "sig"}, changes)


def weak_public_jwk(key_id: str) -> dict[str, Any]:
    """A 1024-bit RSA public key, static so that no weak key is ever generated."""
    return {
        "kty": "RSA",
        "n": (
            "otF29DKe2dz_RcReQ7qYAQuuKBU5DOolwjQ3rIHi6r6tLI0SXGN1SK4ip_n6LyuyIUHI0tm2Zpi_Gq1WjFJ-7"
            "zFUPaf6HlY8znnZKEkycPyM5fnFZWx6FQmvi8JVHUKaKgtcF3UB4VPm5LRbva8cQPVTlzkf0WQ2UrjK1P9Rb2M"
        ),
        "e": "AQAB",
        "kid": key_id,
        "alg": "RS256",
        "use": "sig",
    }


def key_set_document(*jwks: object) -> bytes:
    return json.dumps({"keys": list(jwks)}).encode()


BACKCHANNEL_LOGOUT_EVENT = "http://schemas.openid.net/event/backchannel-logout"


def a_logout_token(
    *,
    issuer: str,
    audience: str,
    subject: str,
    now: int,
    key_id: str = "current-key",
    key_name: str = "current",
    claims: dict[str, Any] | None = None,
    header: dict[str, Any] | None = None,
) -> str:
    """A back-channel Logout Token as Keycloak signs it, issued ten seconds
    before `now`; `claims` and `header` change or, with `ABSENT`, remove members."""
    token_claims = {
        "iss": issuer,
        "aud": audience,
        "sub": subject,
        "iat": now - 10,
        "exp": now + 50,
        "jti": "logout-token-1",
        "sid": "4c2a9f0e-session",
        "events": {BACKCHANNEL_LOGOUT_EVENT: {}},
    }
    token_header = {"alg": "RS256", "kid": key_id, "typ": "logout+jwt"}
    return jws(
        changed(token_header, header or {}),
        changed(token_claims, claims or {}),
        rs256(rsa_key(key_name)),
    )


@dataclass
class FakeClock:
    now: float
    step: float = 0.0

    def __call__(self) -> float:
        reading = self.now
        self.now += self.step
        return reading


@dataclass
class FakeKeySetEndpoint:
    """Answers each fetch with `response`: a document, or the error to raise."""

    response: bytes | Exception
    fetched_urls: list[str] = field(default_factory=list)
    before_answer: Callable[[], None] = lambda: None

    def __call__(self, url: str) -> bytes:
        self.fetched_urls.append(url)
        self.before_answer()
        if isinstance(self.response, Exception):
            raise self.response
        return self.response


@dataclass
class FakeTokenEndpoint:
    """Answers each token request with `answer`, or raises it when it is an
    error, and keeps every request it received."""

    answer: TokenEndpointAnswer | Exception = field(
        default_factory=lambda: TokenEndpointAnswer(500, b"")
    )
    requests: list[TokenRequest] = field(default_factory=list)

    def __call__(self, request: TokenRequest) -> TokenEndpointAnswer:
        self.requests.append(request)
        if isinstance(self.answer, Exception):
            raise self.answer
        return self.answer


REALM_ISSUER = "https://login.example.org/realms/workshop"
REALM_JWKS_URL = f"{REALM_ISSUER}/protocol/openid-connect/certs"
APP_CLIENT_ID = "notes-app"
OPERATOR_SUBJECT = "operator-account-1"
ACCESS_TOKEN_LEEWAY_SECONDS = 30
ACCESS_TOKEN_NOW = 1_800_000_000
ACCESS_TOKEN_LIFETIME_SECONDS = 300


def an_access_token(
    *,
    issuer: str = REALM_ISSUER,
    client_id: str = APP_CLIENT_ID,
    subject: str = OPERATOR_SUBJECT,
    now: int = ACCESS_TOKEN_NOW,
    key_id: str = "current-key",
    key_name: str = "current",
    claims: dict[str, Any] | None = None,
    header: dict[str, Any] | None = None,
) -> str:
    """An access token as Keycloak signs it for hal acting on `client_id`'s behalf:
    an `at+jwt` living 300 seconds whose `azp` is hal and whose groups hold the
    app's admin group; `claims` and `header` change or, with `ABSENT`, remove members."""
    token_claims = {
        "iss": issuer,
        "aud": client_id,
        "sub": subject,
        "azp": "hal",
        "iat": now,
        "exp": now + ACCESS_TOKEN_LIFETIME_SECONDS,
        "jti": "access-token-1",
        "groups": ["/apps/x/admin"],
    }
    token_header = {"alg": "RS256", "kid": key_id, "typ": "at+jwt"}
    return jws(
        changed(token_header, header or {}),
        changed(token_claims, claims or {}),
        rs256(rsa_key(key_name)),
    )


def a_relying_party(
    *,
    post_token_request: TokenRequestPost | None = None,
    fetch_key_set: KeySetFetch | None = None,
    wall_clock: WallClock | None = None,
    monotonic_clock: MonotonicClock | None = None,
) -> OidcRelyingParty:
    """The relying party of `APP_CLIENT_ID` at `REALM_ISSUER`, publishing the
    "current" key by default, that makes no token request unless the caller passes a poster."""

    def post_no_token_request(request: TokenRequest) -> TokenEndpointAnswer:
        raise AssertionError(f"a token request was posted to {request.url}")

    endpoint = f"{REALM_ISSUER}/protocol/openid-connect"
    config = OidcClientConfig(
        issuer=REALM_ISSUER,
        authorization_endpoint=f"{endpoint}/auth",
        token_endpoint=f"{endpoint}/token",
        jwks_url=REALM_JWKS_URL,
        end_session_endpoint=f"{endpoint}/logout",
        client_id=APP_CLIENT_ID,
        client_secret=SecretStr(secrets.token_urlsafe(16)),
        redirect_uri="https://notes.example.org/auth/callback",
        post_logout_redirect_uri="https://notes.example.org/",
        scopes=("openid", "profile"),
        leeway_seconds=ACCESS_TOKEN_LEEWAY_SECONDS,
    )
    return OidcRelyingParty(
        config,
        post_token_request=post_token_request or post_no_token_request,
        fetch_key_set=fetch_key_set
        or FakeKeySetEndpoint(key_set_document(public_jwk(rsa_key("current"), "current-key"))),
        wall_clock=wall_clock or FakeClock(float(ACCESS_TOKEN_NOW)),
        monotonic_clock=monotonic_clock or FakeClock(5_000.0),
    )


def token_endpoint_answer(status: int, document: dict[str, Any] | bytes) -> TokenEndpointAnswer:
    body = document if isinstance(document, bytes) else json.dumps(document).encode()
    return TokenEndpointAnswer(status, body)


@dataclass(frozen=True)
class _IssuedCode:
    nonce: str
    code_challenge: str


@dataclass
class FakeIssuer:
    """An issuer's authorization and token endpoints that remember what they issued.

    `authorize` plays the person signing in at the issuer: it reads the
    authorization URL and answers the callback query with a fresh code bound
    to the login's nonce and PKCE challenge. Called as the token endpoint, it
    dispatches on `grant_type`; `before_exchange` runs before every grant, so
    a test can hold two together.

    The code exchange answers each code once, and only to the verifier of
    that challenge, with the ID token `mint_id_token` makes for the nonce.
    `code_answer_members` are the members besides `id_token` of its 200
    answer: a refresh token, and an access token with its type as the canary
    no store may hold. `ABSENT` removes a member.

    The refresh grant answers a new access token and a new refresh token each
    time, and keeps accepting every refresh token it issued (reuse allowed, as
    in edge's realm); any other token, and every token after
    `end_sso_session()`, is `invalid_grant`. `refresh_tokens` holds the
    accepted ones, so a test can add a token without a login. The
    `client_credentials` grant answers a new access token per call, or
    `unauthorized_client` while `service_accounts_enabled` is false. The
    refresh grant's answer takes `refresh_answer_members` as the code exchange
    takes `code_answer_members`.
    """

    mint_id_token: Callable[[str], str]
    requests: list[TokenRequest] = field(default_factory=list)
    before_exchange: Callable[[], object] = lambda: None
    code_answer_members: dict[str, Any] = field(
        default_factory=lambda: {
            "refresh_token": ISSUED_REFRESH_TOKEN,
            "access_token": ISSUED_ACCESS_TOKEN_CANARY,
            "token_type": "Bearer",
        }
    )
    refresh_answer_members: dict[str, Any] = field(default_factory=dict)
    service_accounts_enabled: bool = True
    refresh_tokens: set[str] = field(default_factory=lambda: {ISSUED_REFRESH_TOKEN})
    _codes: dict[str, _IssuedCode] = field(default_factory=dict)
    _codes_lock: threading.Lock = field(default_factory=threading.Lock)
    _minted: Iterator[int] = field(default_factory=lambda: itertools.count(2))

    def authorize(self, authorization_url: str) -> str:
        query = urllib.parse.parse_qs(urllib.parse.urlsplit(authorization_url).query)
        code = secrets.token_urlsafe(32)
        self._codes[code] = _IssuedCode(query["nonce"][0], query["code_challenge"][0])
        return urllib.parse.urlencode({"state": query["state"][0], "code": code})

    def end_sso_session(self) -> None:
        self.refresh_tokens.clear()

    def __call__(self, request: TokenRequest) -> TokenEndpointAnswer:
        self.requests.append(request)
        self.before_exchange()
        match request.form["grant_type"]:
            case "authorization_code":
                return self._exchanged_code(request)
            case "refresh_token":
                return self._refreshed(request)
            case "client_credentials":
                return self._workload()
        return token_endpoint_answer(400, {"error": "unsupported_grant_type"})

    def _exchanged_code(self, request: TokenRequest) -> TokenEndpointAnswer:
        with self._codes_lock:
            issued = self._codes.pop(request.form["code"], None)
        verifier = request.form["code_verifier"]
        if issued is None or s256_code_challenge(verifier) != issued.code_challenge:
            return token_endpoint_answer(400, {"error": "invalid_grant"})
        refresh_token = self.code_answer_members.get("refresh_token")
        if isinstance(refresh_token, str):
            self.refresh_tokens.add(refresh_token)
        return token_endpoint_answer(
            200,
            changed({"id_token": self.mint_id_token(issued.nonce)}, self.code_answer_members),
        )

    def _refreshed(self, request: TokenRequest) -> TokenEndpointAnswer:
        if request.form["refresh_token"] not in self.refresh_tokens:
            return token_endpoint_answer(400, {"error": "invalid_grant"})
        number = next(self._minted)
        rotated = f"refresh-token-rt-{number}"
        self.refresh_tokens.add(rotated)
        members = {
            "access_token": f"access-token-at-{number}",
            "token_type": "Bearer",
            "refresh_token": rotated,
        }
        return token_endpoint_answer(200, changed(members, self.refresh_answer_members))

    def _workload(self) -> TokenEndpointAnswer:
        if not self.service_accounts_enabled:
            return token_endpoint_answer(400, {"error": "unauthorized_client"})
        members = {"access_token": f"workload-token-{next(self._minted)}", "token_type": "Bearer"}
        return token_endpoint_answer(200, members)


def s256_code_challenge(code_verifier: str) -> str:
    digest = hashlib.sha256(code_verifier.encode()).digest()
    return base64.urlsafe_b64encode(digest).rstrip(b"=").decode()


# The real HTTPS endpoints, served from loopback under a self-signed certificate.


SILENT_HOLD_SECONDS = 10
"""How long `/silent` keeps a request unanswered unless the test releases it."""
DRIP_INTERVAL_SECONDS = 0.2
"""How long `/dripping-head` and `/dripping-body` wait between two bytes."""
SERVED_TOKEN_ANSWER = json.dumps(
    {"access_token": "served-access-token", "id_token": "served.id.token", "token_type": "Bearer"}
).encode()
REFUSED_TOKEN_ANSWER = json.dumps({"error": "invalid_grant"}).encode()
_OVERSIZED_ANSWER_BYTES = 2 * max(MAX_KEY_SET_BYTES, MAX_TOKEN_RESPONSE_BYTES)


@dataclass(frozen=True)
class ReceivedRequest:
    """One request as the server read it; `headers` are keyed in lower case."""

    method: str
    path: str
    headers: Mapping[str, str]
    body: bytes


@dataclass
class LoopbackHttpsServer:
    """Answers by path, whatever the method or query: `/token` a token answer,
    `/token-refused` a 400 `invalid_grant`, `/token-at-limit` and
    `/token-past-limit` a body of `MAX_TOKEN_RESPONSE_BYTES` and one byte
    more, `/token-reflecting` a token
    answer whose header block carries the request body as a malformed line,
    `/moved` a 302, `/moved-stalling` a 302 whose body never arrives until
    released, `/missing` a 404,
    `/oversized` a body past every size limit, `/compressed` the key set
    gzipped, `/silent` nothing until released, `/dripping-status`,
    `/dripping-head` and `/dripping-body` a 200 whose status line, header
    block or body arrives one byte every `DRIP_INTERVAL_SECONDS` until
    released, hung up on or `SILENT_HOLD_SECONDS` have passed, and any other
    path the key set.
    """

    base_url: str
    received: list[ReceivedRequest]
    silent_request_arrived: threading.Event
    release_silent_request: threading.Event

    @property
    def requested_paths(self) -> list[str]:
        return [request.path for request in self.received]


def served_key_set() -> bytes:
    return key_set_document(public_jwk(rsa_key("current"), "current-key"))


@contextlib.contextmanager
def loopback_https_server(
    directory: Path, monkeypatch: pytest.MonkeyPatch
) -> Iterator[LoopbackHttpsServer]:
    """Serves until the block ends, under a certificate written to `directory`
    that `SSL_CERT_FILE` makes the system trust; a test unsets it to see the
    certificate refused."""
    certificate_path, key_path = _self_signed_loopback_certificate(directory)
    monkeypatch.setenv("SSL_CERT_FILE", str(certificate_path))
    received: list[ReceivedRequest] = []
    silent_request_arrived, release_silent_request = threading.Event(), threading.Event()

    class LoopbackHandler(BaseHTTPRequestHandler):
        def do_GET(self) -> None:
            self._receive(b"")

        def do_POST(self) -> None:
            self._receive(self.rfile.read(int(self.headers.get("Content-Length", "0"))))

        def _receive(self, body: bytes) -> None:
            headers = {name.lower(): value for name, value in self.headers.items()}
            received.append(ReceivedRequest(self.command, self.path, headers, body))
            route = urllib.parse.urlsplit(self.path).path
            if route == "/silent":
                silent_request_arrived.set()
                release_silent_request.wait(timeout=SILENT_HOLD_SECONDS)
            elif route == "/moved":
                self._send_head(302, {"Location": "/certs", "Content-Length": "0"})
            elif route == "/moved-stalling":
                self._send_head(302, {"Location": "/certs", "Content-Length": "1"})
                release_silent_request.wait(timeout=SILENT_HOLD_SECONDS)
            elif route == "/dripping-status":
                self._drip(b"HTTP/1.1 200 ")
            elif route == "/dripping-head":
                self._drip(b"HTTP/1.1 200 OK\r\nX-Dripping: ")
            elif route == "/dripping-body":
                self._drip(b"HTTP/1.1 200 OK\r\nContent-Length: 65536\r\n\r\n")
            elif route == "/missing":
                self._send_head(404, {"Content-Length": "0"})
            elif route == "/oversized":
                self._answer(200, b" " * _OVERSIZED_ANSWER_BYTES)
            elif route == "/compressed":
                self._answer(200, gzip.compress(served_key_set()), content_encoding="gzip")
            elif route == "/token":
                self._answer(200, SERVED_TOKEN_ANSWER)
            elif route == "/token-refused":
                self._answer(400, REFUSED_TOKEN_ANSWER)
            elif route == "/token-at-limit":
                self._answer(200, b" " * MAX_TOKEN_RESPONSE_BYTES)
            elif route == "/token-past-limit":
                self._answer(200, b" " * (MAX_TOKEN_RESPONSE_BYTES + 1))
            elif route == "/token-reflecting":
                self._answer_reflecting_in_a_malformed_header(body)
            else:
                self._answer(200, served_key_set())

        def _answer(self, status: int, body: bytes, content_encoding: str | None = None) -> None:
            headers = {"Content-Length": str(len(body))}
            if content_encoding is not None:
                headers["Content-Encoding"] = content_encoding
            self._send_head(status, headers)
            # The client may hang up once it read its limit.
            with contextlib.suppress(OSError):
                self.wfile.write(body)

        def _drip(self, head: bytes) -> None:
            # Dripping ends with an OSError once the client hangs up, and after
            # SILENT_HOLD_SECONDS at the latest, so a client that never hangs
            # up fails its test instead of holding it for hours.
            dripping_ends = time.monotonic() + SILENT_HOLD_SECONDS
            with contextlib.suppress(OSError):
                self.wfile.write(head)
                while time.monotonic() < dripping_ends and not release_silent_request.wait(
                    DRIP_INTERVAL_SECONDS
                ):
                    self.wfile.write(b"x")

        def _answer_reflecting_in_a_malformed_header(self, reflected: bytes) -> None:
            self.wfile.write(
                b"HTTP/1.0 200 OK\r\n"
                + reflected
                + f"\r\nContent-Length: {len(SERVED_TOKEN_ANSWER)}\r\n\r\n".encode()
                + SERVED_TOKEN_ANSWER
            )

        def _send_head(self, status: int, headers: dict[str, str]) -> None:
            # The client may already have hung up, refusing the certificate or
            # the answer.
            with contextlib.suppress(OSError):
                self.send_response(status)
                for name, value in headers.items():
                    self.send_header(name, value)
                self.end_headers()

        def log_message(self, format: str, *args: Any) -> None:
            del format, args

    tls = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    tls.minimum_version = ssl.TLSVersion.TLSv1_2
    tls.load_cert_chain(certificate_path, key_path)
    server = HTTPServer(("127.0.0.1", 0), LoopbackHandler)
    server.socket = tls.wrap_socket(server.socket, server_side=True)
    serving = threading.Thread(target=server.serve_forever, daemon=True)
    serving.start()
    try:
        yield LoopbackHttpsServer(
            f"https://127.0.0.1:{server.server_port}",
            received,
            silent_request_arrived,
            release_silent_request,
        )
    finally:
        release_silent_request.set()
        server.shutdown()
        server.server_close()
        serving.join(timeout=10)


@contextlib.contextmanager
def closed_loopback_port() -> Iterator[int]:
    """A loopback port bound by nobody listening on it, for as long as the block lasts."""
    with socket.socket() as probe:
        probe.bind(("127.0.0.1", 0))
        yield probe.getsockname()[1]


@contextlib.contextmanager
def unanswering_loopback_port() -> Iterator[int]:
    """A loopback port whose connections the kernel accepts but nobody ever
    answers, so a TLS handshake waits on it, for as long as the block lasts."""
    with socket.socket() as listener:
        listener.bind(("127.0.0.1", 0))
        listener.listen()
        yield listener.getsockname()[1]


@contextlib.contextmanager
def unconnectable_loopback_port() -> Iterator[int]:
    """A loopback port whose accept queue is full, so the kernel drops every
    further connection attempt and connecting waits, for as long as the block
    lasts."""
    with socket.socket() as listener, socket.socket() as queued:
        listener.bind(("127.0.0.1", 0))
        listener.listen(0)
        queued.connect(listener.getsockname())
        yield listener.getsockname()[1]


def _self_signed_loopback_certificate(directory: Path) -> tuple[Path, Path]:
    key = rsa_key("loopback-tls")
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "127.0.0.1")])
    now = datetime.datetime.now(datetime.UTC)
    certificate = (
        x509.CertificateBuilder()
        .subject_name(name)
        .issuer_name(name)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - datetime.timedelta(hours=1))
        .not_valid_after(now + datetime.timedelta(hours=1))
        .add_extension(
            x509.SubjectAlternativeName([x509.IPAddress(ipaddress.ip_address("127.0.0.1"))]),
            critical=False,
        )
        .add_extension(x509.BasicConstraints(ca=True, path_length=None), critical=True)
        .add_extension(x509.SubjectKeyIdentifier.from_public_key(key.public_key()), critical=False)
        .add_extension(
            x509.AuthorityKeyIdentifier.from_issuer_public_key(key.public_key()), critical=False
        )
        .add_extension(x509.ExtendedKeyUsage([ExtendedKeyUsageOID.SERVER_AUTH]), critical=False)
        .sign(key, hashes.SHA256())
    )
    certificate_path, key_path = directory / "cert.pem", directory / "key.pem"
    certificate_path.write_bytes(certificate.public_bytes(serialization.Encoding.PEM))
    key_path.write_bytes(
        key.private_bytes(
            serialization.Encoding.PEM,
            serialization.PrivateFormat.PKCS8,
            serialization.NoEncryption(),
        )
    )
    return certificate_path, key_path


def leaf_texts(
    subject: object,
    path: tuple[str, ...] = (),
) -> Iterator[tuple[tuple[str, ...], str]]:
    """Every leaf a value holds as text with its field path, a secret unwrapped."""
    if isinstance(subject, SecretStr):
        yield path, subject.get_secret_value()
    elif is_dataclass(subject) and not isinstance(subject, type):
        for member in fields(subject):
            yield from leaf_texts(getattr(subject, member.name), (*path, member.name))
    elif isinstance(subject, Mapping):
        for key, member in subject.items():
            yield from leaf_texts(key, path)
            yield from leaf_texts(member, (*path, str(key)))
    elif isinstance(subject, list | tuple | set | frozenset):
        for index, member in enumerate(subject):
            yield from leaf_texts(member, (*path, str(index)))
    else:
        yield path, str(subject)


class HoldsRefreshToken(Protocol):
    @property
    def refresh_token(self) -> SecretStr | None: ...


def assert_holds_only_the_refresh_token(subject: HoldsRefreshToken) -> None:
    """The issued refresh token is in the `refresh_token` field alone, the access token nowhere."""
    leaves = list(leaf_texts(subject))
    assert not [path for path, text in leaves if ISSUED_ACCESS_TOKEN_CANARY in text]
    assert [path for path, text in leaves if ISSUED_REFRESH_TOKEN in text] == [("refresh_token",)]
    assert subject.refresh_token is not None
    assert subject.refresh_token.get_secret_value() == ISSUED_REFRESH_TOKEN


def opened_session(
    config: WebAuthConfig, admitted: AdmittedLogin, *cookie_values: str,
    sessions: SessionRecordStore, lock: WriteLock,
    max_sessions: int | None = None, keeps_id_token: bool = True,
) -> SessionRecord:
    """``open_session`` for a request that carries the given session-cookie values."""
    app = FastAPI()
    install_web_auth_config(app, config)
    headers: list[tuple[bytes, bytes]] = []
    if cookie_values:
        headers.append((b"cookie", session_cookie_header(*cookie_values).encode()))
    return open_session(
        Request(an_http_scope(app, headers=headers)), config, admitted,
        sessions=sessions, lock=lock, max_sessions=max_sessions, keeps_id_token=keeps_id_token,
    )


class LogoutPage(HTMLParser):
    """The logout answer as a browser parses it."""

    def __init__(self, markup: str) -> None:
        super().__init__()
        self.elements: list[tuple[str, dict[str, str | None]]] = []
        self.texts: dict[str, str] = {}
        self.feed(markup)

    def handle_starttag(self, tag: str, attrs: list[tuple[str, str | None]]) -> None:
        self.elements.append((tag, dict(attrs)))

    def handle_data(self, data: str) -> None:
        tag = self.elements[-1][0]
        self.texts[tag] = self.texts.get(tag, "") + data

    def attributes_of(self, tag: str) -> list[dict[str, str | None]]:
        return [attributes for name, attributes in self.elements if name == tag]

    @property
    def hidden_fields(self) -> dict[str | None, str | None]:
        return {field["name"]: field["value"] for field in self.attributes_of("input")}

    @property
    def script_source(self) -> str:
        """The CSP source that admits exactly the page's one inline script."""
        digest = hashlib.sha256(self.texts["script"].encode()).digest()
        return f"'sha256-{base64.b64encode(digest).decode()}'"
