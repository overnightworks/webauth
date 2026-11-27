"""The real HTTPS endpoints, served from loopback under a self-signed certificate,
and the loopback ports that accept nothing, answer nothing or are closed."""

from __future__ import annotations

import contextlib
import datetime
import gzip
import ipaddress
import json
import socket
import ssl
import threading
import time
import urllib.parse
from collections.abc import Callable, Iterator, Mapping
from dataclasses import dataclass
from http.server import BaseHTTPRequestHandler, HTTPServer
from pathlib import Path
from typing import Any, cast

import pytest
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.x509.oid import ExtendedKeyUsageOID, NameOID

from tests.support.oidc_arrangement import rsa_key, served_key_set
from tests.support.provider_metadata import (
    METADATA_LIMIT_BYTES,
    a_json_object_of_bytes,
    a_provider_metadata,
)

SILENT_HOLD_SECONDS = 10
"""How long `/silent` keeps a request unanswered unless the test releases it."""
DRIP_INTERVAL_SECONDS = 0.2
"""How long `/dripping-head` and `/dripping-body` wait between two bytes."""
SERVED_TOKEN_ANSWER = json.dumps(
    {"access_token": "served-access-token", "id_token": "served.id.token", "token_type": "Bearer"}
).encode()
REFUSED_TOKEN_ANSWER = json.dumps({"error": "invalid_grant"}).encode()
_OVERSIZED_ANSWER_BYTES = 2 * (64 * 1024)


@dataclass(frozen=True)
class ReceivedRequest:
    """One request as the server read it: `headers` lower-cased, `header_lines` as they arrived."""

    method: str
    path: str
    headers: Mapping[str, str]
    body: bytes
    header_lines: tuple[tuple[str, str], ...] = ()


@dataclass
class LoopbackHttpsServer:
    """Answers by path, whatever the method or query: `/token` a token answer,
    `/token-refused` a 400 `invalid_grant`, `/token-at-limit` and `/token-past-limit` a body
    of `64 * 1024` and one byte more, `/token-reflecting` a token answer whose header block
    carries the request body as a malformed line, `/moved` a 302, `/moved-stalling` a 302
    whose body never arrives until released, `/missing` a 404,
    `/oversized` a body past every size limit, `/.well-known/openid-configuration` the
    discovery document of this server as its own issuer, `/metadata-at-limit` and
    `/metadata-past-limit` a valid JSON object of `METADATA_LIMIT_BYTES` and
    one byte more, `/compressed` the key set
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


class _RecordingServer(HTTPServer):
    """The state the handler shares with the test: what arrived and the hold on `/silent`."""

    def __init__(self, handler: type[BaseHTTPRequestHandler]) -> None:
        super().__init__(("127.0.0.1", 0), handler)
        self.received: list[ReceivedRequest] = []
        self.silent_request_arrived = threading.Event()
        self.release_silent_request = threading.Event()


class _LoopbackHandler(BaseHTTPRequestHandler):
    @property
    def recording(self) -> _RecordingServer:
        return cast("_RecordingServer", self.server)

    def do_GET(self) -> None:
        self._receive(b"")

    def do_POST(self) -> None:
        self._receive(self.rfile.read(int(self.headers.get("Content-Length", "0"))))

    def _receive(self, body: bytes) -> None:
        headers = {name.lower(): value for name, value in self.headers.items()}
        header_lines = tuple((name, value) for name, value in self.headers.items())
        self.recording.received.append(
            ReceivedRequest(self.command, self.path, headers, body, header_lines)
        )
        route = urllib.parse.urlsplit(self.path).path
        _ROUTES.get(route, _serve_the_key_set)(self, body)

    def answer(self, status: int, body: bytes, content_encoding: str | None = None) -> None:
        headers = {"Content-Length": str(len(body))}
        if content_encoding is not None:
            headers["Content-Encoding"] = content_encoding
        self.send_head(status, headers)
        # The client may hang up once it read its limit.
        with contextlib.suppress(OSError):
            self.wfile.write(body)

    def send_head(self, status: int, headers: dict[str, str]) -> None:
        # The client may already have hung up, refusing the certificate or
        # the answer.
        with contextlib.suppress(OSError):
            self.send_response(status)
            for name, value in headers.items():
                self.send_header(name, value)
            self.end_headers()

    def log_message(self, format: str, *args: Any) -> None:
        del format, args


type _Route = Callable[[_LoopbackHandler, bytes], None]


def _answers(status: int, body: bytes) -> _Route:
    return lambda handler, _body: handler.answer(status, body)


def _serve_the_key_set(handler: _LoopbackHandler, _body: bytes) -> None:
    handler.answer(200, served_key_set())


def _serve_compressed(handler: _LoopbackHandler, _body: bytes) -> None:
    handler.answer(200, gzip.compress(served_key_set()), content_encoding="gzip")


def _serve_discovery_document(handler: _LoopbackHandler, _body: bytes) -> None:
    issuer = f"https://127.0.0.1:{handler.recording.server_port}"
    handler.answer(200, a_provider_metadata(issuer))


def _stay_silent(handler: _LoopbackHandler, _body: bytes) -> None:
    handler.recording.silent_request_arrived.set()
    handler.recording.release_silent_request.wait(timeout=SILENT_HOLD_SECONDS)


def _redirect(handler: _LoopbackHandler, _body: bytes) -> None:
    handler.send_head(302, {"Location": "/certs", "Content-Length": "0"})


def _redirect_and_stall(handler: _LoopbackHandler, _body: bytes) -> None:
    handler.send_head(302, {"Location": "/certs", "Content-Length": "1"})
    handler.recording.release_silent_request.wait(timeout=SILENT_HOLD_SECONDS)


def _dripping(head: bytes) -> _Route:
    def drip(handler: _LoopbackHandler, _body: bytes) -> None:
        # Dripping ends with an OSError once the client hangs up, and after
        # SILENT_HOLD_SECONDS at the latest, so a client that never hangs
        # up fails its test instead of holding it for hours.
        release = handler.recording.release_silent_request
        dripping_ends = time.monotonic() + SILENT_HOLD_SECONDS
        with contextlib.suppress(OSError):
            handler.wfile.write(head)
            while time.monotonic() < dripping_ends and not release.wait(DRIP_INTERVAL_SECONDS):
                handler.wfile.write(b"x")

    return drip


def _reflect_in_a_malformed_header(handler: _LoopbackHandler, body: bytes) -> None:
    handler.wfile.write(
        b"HTTP/1.0 200 OK\r\n"
        + body
        + f"\r\nContent-Length: {len(SERVED_TOKEN_ANSWER)}\r\n\r\n".encode()
        + SERVED_TOKEN_ANSWER
    )


_ROUTES: dict[str, _Route] = {
    "/oversized": _answers(200, b" " * _OVERSIZED_ANSWER_BYTES),
    "/metadata-at-limit": _answers(200, a_json_object_of_bytes(METADATA_LIMIT_BYTES)),
    "/metadata-past-limit": _answers(200, a_json_object_of_bytes(METADATA_LIMIT_BYTES + 1)),
    "/token": _answers(200, SERVED_TOKEN_ANSWER),
    "/token-refused": _answers(400, REFUSED_TOKEN_ANSWER),
    "/token-at-limit": _answers(200, b" " * 64 * 1024),
    "/token-past-limit": _answers(200, b" " * (64 * 1024 + 1)),
    "/missing": _answers(404, b""),
    "/silent": _stay_silent,
    "/moved": _redirect,
    "/moved-stalling": _redirect_and_stall,
    "/dripping-status": _dripping(b"HTTP/1.1 200 "),
    "/dripping-head": _dripping(b"HTTP/1.1 200 OK\r\nX-Dripping: "),
    "/dripping-body": _dripping(b"HTTP/1.1 200 OK\r\nContent-Length: 65536\r\n\r\n"),
    "/.well-known/openid-configuration": _serve_discovery_document,
    "/compressed": _serve_compressed,
    "/token-reflecting": _reflect_in_a_malformed_header,
}


@contextlib.contextmanager
def loopback_https_server(
    directory: Path, monkeypatch: pytest.MonkeyPatch
) -> Iterator[LoopbackHttpsServer]:
    """Serves until the block ends, under a certificate written to `directory`
    that `SSL_CERT_FILE` makes the system trust; a test unsets it to see the
    certificate refused."""
    certificate_path, key_path = _self_signed_loopback_certificate(directory)
    monkeypatch.setenv("SSL_CERT_FILE", str(certificate_path))
    tls = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    tls.minimum_version = ssl.TLSVersion.TLSv1_2
    tls.load_cert_chain(certificate_path, key_path)
    server = _RecordingServer(_LoopbackHandler)
    server.socket = tls.wrap_socket(server.socket, server_side=True)
    serving = threading.Thread(target=server.serve_forever, daemon=True)
    serving.start()
    try:
        yield LoopbackHttpsServer(
            f"https://127.0.0.1:{server.server_port}",
            server.received,
            server.silent_request_arrived,
            server.release_silent_request,
        )
    finally:
        server.release_silent_request.set()
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
