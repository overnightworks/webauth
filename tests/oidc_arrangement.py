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
import json
import secrets
import ssl
import threading
import urllib.parse
from collections.abc import Callable, Iterator, Mapping
from dataclasses import dataclass, field
from functools import cache
from http.server import BaseHTTPRequestHandler, HTTPServer
from pathlib import Path
from typing import Any

import pytest
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding, rsa
from cryptography.x509.oid import ExtendedKeyUsageOID, NameOID
from jwt.algorithms import RSAAlgorithm

from webauth.https_client import MAX_KEY_SET_BYTES
from webauth.oidc import MAX_TOKEN_RESPONSE_BYTES, TokenEndpointAnswer, TokenRequest

ABSENT = object()
"""A claim or header change that removes the member instead of setting it."""


@cache
def rsa_key(name: str, bits: int = 2048) -> rsa.RSAPrivateKey:
    """One generated key per name for the whole session: RSA generation is the
    slow part, and a key is immutable scenario data."""
    del name
    return rsa.generate_private_key(public_exponent=65537, key_size=bits)


def segment(value: dict[str, Any] | str) -> str:
    """A base64url segment of a JSON object, or of raw JSON text when the
    scenario needs bytes `json.dumps` cannot produce (duplicate members)."""
    text = value if isinstance(value, str) else json.dumps(value)
    return base64.urlsafe_b64encode(text.encode()).rstrip(b"=").decode()


def rs256(key: rsa.RSAPrivateKey) -> Callable[[bytes], bytes]:
    return lambda signing_input: key.sign(signing_input, padding.PKCS1v15(), hashes.SHA256())


def jws(header: dict[str, Any] | str, claims: dict[str, Any] | str, sign: Callable) -> str:
    signing_input = f"{segment(header)}.{segment(claims)}"
    signature = base64.urlsafe_b64encode(sign(signing_input.encode())).rstrip(b"=").decode()
    return f"{signing_input}.{signature}"


def changed(base: dict[str, Any], changes: dict[str, Any]) -> dict[str, Any]:
    merged = {**base, **changes}
    return {name: value for name, value in merged.items() if value is not ABSENT}


def public_jwk(key: rsa.RSAPrivateKey, key_id: str, **changes: Any) -> dict[str, Any]:
    jwk = RSAAlgorithm.to_jwk(key.public_key(), as_dict=True)
    return changed({**jwk, "kid": key_id, "alg": "RS256", "use": "sig"}, changes)


def key_set_document(*jwks: object) -> bytes:
    return json.dumps({"keys": list(jwks)}).encode()


@dataclass
class FakeClock:
    now: float

    def __call__(self) -> float:
        return self.now


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
    answers each code once, and only to the verifier of that challenge, with
    the ID token `mint_id_token` makes for the nonce; `before_exchange` runs
    before a code is looked up, so a test can hold two exchanges together.
    """

    mint_id_token: Callable[[str], str]
    requests: list[TokenRequest] = field(default_factory=list)
    before_exchange: Callable[[], None] = lambda: None
    _codes: dict[str, _IssuedCode] = field(default_factory=dict)
    _codes_lock: threading.Lock = field(default_factory=threading.Lock)

    def authorize(self, authorization_url: str) -> str:
        query = urllib.parse.parse_qs(urllib.parse.urlsplit(authorization_url).query)
        code = secrets.token_urlsafe(32)
        self._codes[code] = _IssuedCode(query["nonce"][0], query["code_challenge"][0])
        return urllib.parse.urlencode({"state": query["state"][0], "code": code})

    def __call__(self, request: TokenRequest) -> TokenEndpointAnswer:
        self.requests.append(request)
        self.before_exchange()
        with self._codes_lock:
            issued = self._codes.pop(request.form["code"], None)
        verifier = request.form["code_verifier"]
        if issued is None or s256_code_challenge(verifier) != issued.code_challenge:
            return token_endpoint_answer(400, {"error": "invalid_grant"})
        return token_endpoint_answer(200, {"id_token": self.mint_id_token(issued.nonce)})


def s256_code_challenge(code_verifier: str) -> str:
    digest = hashlib.sha256(code_verifier.encode()).digest()
    return base64.urlsafe_b64encode(digest).rstrip(b"=").decode()


# The real HTTPS endpoints, served from loopback under a self-signed certificate.


SILENT_HOLD_SECONDS = 10
"""How long `/silent` keeps a request unanswered unless the test releases it."""
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
    `/token-refused` a 400 `invalid_grant`, `/token-reflecting` a token
    answer whose header block carries the request body as a malformed line,
    `/moved` a 302, `/moved-stalling` a 302 whose body never arrives until
    released, `/missing` a 404,
    `/oversized` a body past every size limit, `/compressed` the key set
    gzipped, `/silent` nothing until released, and any other path the key set.
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
