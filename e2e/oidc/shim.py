"""A TLS front for the edge's plain-http Traefik, standing in for Cloudflare's tunnel.

It terminates TLS with a throwaway certificate and forwards every request to
the upstream with the public ``Host`` and ``X-Forwarded-Proto: https``. It
keeps no log and writes nothing."""

from __future__ import annotations

import http.client
import socket
import ssl
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from types import TracebackType

from certificates import ThrowawayTls

LOOPBACK = "127.0.0.1"
HOP_BY_HOP = frozenset({
    "connection", "keep-alive", "proxy-authenticate", "proxy-authorization", "te", "trailer",
    "transfer-encoding", "upgrade", "content-length", "host",
})
UPSTREAM_TIMEOUT_SECONDS = 30


class TlsShim:
    """``with TlsShim(tls, upstream_port, public_host) as shim`` serves on ``shim.port``."""

    def __init__(self, tls: ThrowawayTls, upstream_port: int, public_host: str) -> None:
        context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        context.load_cert_chain(tls.leaf_certificate, tls.leaf_key)
        self._server = _ShimServer((LOOPBACK, 0), _forwarding_handler(upstream_port, public_host))
        self._server.tls_context = context
        self._thread = threading.Thread(target=self._server.serve_forever, daemon=True)

    @property
    def port(self) -> int:
        return self._server.server_address[1]

    def __enter__(self) -> TlsShim:
        self._thread.start()
        return self

    def __exit__(
        self, kind: type[BaseException] | None, error: BaseException | None,
        trace: TracebackType | None,
    ) -> None:
        self._server.shutdown()
        self._server.server_close()
        self._thread.join()


class _ShimServer(ThreadingHTTPServer):
    daemon_threads = True
    tls_context: ssl.SSLContext

    def handle_error(self, request: socket.socket, client_address: object) -> None:
        """A client that abandons a handshake is no event worth a trace."""


def _forwarding_handler(upstream_port: int, public_host: str) -> type[BaseHTTPRequestHandler]:
    class Forwarding(BaseHTTPRequestHandler):
        protocol_version = "HTTP/1.1"
        server: _ShimServer

        def setup(self) -> None:
            self.request = self.server.tls_context.wrap_socket(self.request, server_side=True)
            super().setup()

        def log_message(self, format: str, *args: object) -> None:
            """Nothing is logged."""

        def _forward(self) -> None:
            length = int(self.headers.get("Content-Length") or 0)
            body = self.rfile.read(length) if length else None
            headers = {
                name: value for name, value in self.headers.items()
                if name.lower() not in HOP_BY_HOP
            }
            headers["Host"] = public_host
            headers["X-Forwarded-Proto"] = "https"
            upstream = http.client.HTTPConnection(
                LOOPBACK, upstream_port, timeout=UPSTREAM_TIMEOUT_SECONDS
            )
            try:
                upstream.request(self.command, self.path, body=body, headers=headers)
                answer = upstream.getresponse()
                payload = answer.read()
                self.send_response(answer.status, answer.reason)
                for name, value in answer.getheaders():
                    if name.lower() not in HOP_BY_HOP:
                        self.send_header(name, value)
                self.send_header("Content-Length", str(len(payload)))
                self.end_headers()
                if self.command != "HEAD":
                    self.wfile.write(payload)
            finally:
                upstream.close()

        do_GET = do_POST = do_PUT = do_DELETE = do_HEAD = do_OPTIONS = do_PATCH = _forward

    return Forwarding
