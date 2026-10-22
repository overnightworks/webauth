"""A TLS front for the edge's plain-http Traefik, standing in for Cloudflare's tunnel.

It terminates TLS with a throwaway certificate and forwards every request to
the upstream with the public ``Host`` and ``X-Forwarded-Proto: https``, as
Cloudflare's tunnel does. It keeps no log and writes nothing.

How the browser reaches this shim, and which certificate it trusts, is
``harness.py``'s (``launch_pinned_chromium``); ``edge_url`` is the READY line's
address of the probe's Traefik, which the shim forwards to.

How Keycloak reaches the apps: Keycloak's back-channel logout is a request from
its container to the app, and the apps bind loopback, which the browser's host
mapping reaches but a container does not. The machine's firewall also drops a
container's TCP to the host, including the ``keycloak`` network's gateway on
every port (measured with a listener bound to the gateway and a container on a
network of the same shape), so a listener on the host would never be called.
``CallbackBridge`` therefore puts a relay container on the stack's ``keycloak``
network (``stack.py`` finds it by the compose labels and fails on an absent or
ambiguous one): it listens on the container network and passes the bytes to a
unix socket in a private directory, where the host side accepts exactly ``POST
/auth/backchannel-logout``, at most 32 KiB, and forwards it to the app's
loopback HTTPS endpoint, verifying the throwaway CA. Anything else (``/state``,
``/reset``, another path) is answered 404 (an unknown method 501) and reaches
nothing. Every answer carries ``Connection: close``: Keycloak's HTTP client
keeps connections in a pool and does not retry a POST on one the bridge already
closed. Every read waits at most 10 s, no body or header is logged, and the
relay holds no secret (read-only, no capabilities, the caller's user id). The
bridge is shut down, its container removed, before the held stack is released,
and ``edge-kc-probe`` leftovers are listed at the end. The container's name
stands in for production's internal DNS name of the app: it shows that the
route works behind an internal name, not that production's name resolves."""

from __future__ import annotations

import contextlib
import http.client
import os
import secrets
import socket
import socketserver
import ssl
import tempfile
import threading
import time
from http import HTTPStatus
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from types import TracebackType

from certificates import ThrowawayTls
from host_app import BACKCHANNEL_LOGOUT_MAX_BODY_BYTES, BACKCHANNEL_LOGOUT_PATH, FORM_CONTENT_TYPE
from stack import StackError, docker

LOOPBACK = "127.0.0.1"
HOP_BY_HOP = frozenset({
    "connection", "keep-alive", "proxy-authenticate", "proxy-authorization", "te", "trailer",
    "transfer-encoding", "upgrade", "content-length", "host",
})
UPSTREAM_TIMEOUT_SECONDS = 30
BRIDGE_TIMEOUT_SECONDS = 10
RELAY_IMAGE = (
    "python:3.12-slim@sha256:78387bc3881b8273120a12ebe6c1ab22b018ccc2c9adf565ae1ac9b536e184ea"
)
RELAY_NAME_PREFIX = "edge-kc-probe-d1-callback-"
RELAY_PORT = 8080
RELAY_SOCKET = "/bridge/bridge.sock"
RELAY_READY = "READY"
RELAY_STARTS_SECONDS = 30
RELAY_SOURCE = f"""
import asyncio

async def pipe(reader, writer):
    try:
        while data := await reader.read(65536):
            writer.write(data)
            await writer.drain()
    except OSError:
        pass

async def relay(client_reader, client_writer):
    host_reader, host_writer = await asyncio.open_unix_connection("{RELAY_SOCKET}")
    forwards = [
        asyncio.ensure_future(pipe(client_reader, host_writer)),
        asyncio.ensure_future(pipe(host_reader, client_writer)),
    ]
    await asyncio.wait(forwards, return_when=asyncio.FIRST_COMPLETED)
    for forward in forwards:
        forward.cancel()
    client_writer.close()
    host_writer.close()

async def main():
    server = await asyncio.start_server(relay, "0.0.0.0", {RELAY_PORT})
    print("{RELAY_READY}", flush=True)
    await server.serve_forever()

asyncio.run(main())
"""


class TlsShim:
    """``with TlsShim(tls, upstream_port, public_host) as shim`` serves on ``shim.port``."""

    def __init__(self, tls: ThrowawayTls, upstream_port: int, public_host: str) -> None:
        context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        context.load_cert_chain(tls.leaf_certificate, tls.leaf_key)
        self._server = _ShimServer(
            (LOOPBACK, 0), _forwarding_handler(upstream_port, public_host, context)
        )
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

    def handle_error(
        self, request: socket.socket | tuple[bytes, socket.socket], client_address: object
    ) -> None:
        """A client that abandons a handshake is no event worth a trace."""


def _forwarding_handler(
    upstream_port: int, public_host: str, tls_context: ssl.SSLContext
) -> type[BaseHTTPRequestHandler]:
    class Forwarding(BaseHTTPRequestHandler):
        protocol_version = "HTTP/1.1"

        def setup(self) -> None:
            self.request = tls_context.wrap_socket(self.request, server_side=True)
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


class _UnixServer(socketserver.ThreadingUnixStreamServer):
    daemon_threads = True

    def handle_error(
        self, request: socket.socket | tuple[bytes, socket.socket], client_address: object
    ) -> None:
        """A relay that abandons a connection is no event worth a trace."""


class CallbackBridge:
    """``with CallbackBridge(network, host_port, ca_certificate) as bridge`` makes
    ``bridge.url`` reachable from containers of ``network`` and nowhere else. The relay
    container holds no secret and logs nothing but its ready line; the unix socket lives
    in a private directory that is removed with the bridge."""

    def __init__(self, network: str, host_port: int, ca_certificate: Path) -> None:
        self._network = network
        self._name = f"{RELAY_NAME_PREFIX}{secrets.token_hex(4)}"
        self._host_port = host_port
        self._host_trust = ssl.create_default_context(cafile=str(ca_certificate))
        self._exit = contextlib.ExitStack()

    @property
    def url(self) -> str:
        return f"http://{self._name}:{RELAY_PORT}{BACKCHANNEL_LOGOUT_PATH}"

    def __enter__(self) -> CallbackBridge:
        with contextlib.ExitStack() as starting:
            directory = Path(
                starting.enter_context(tempfile.TemporaryDirectory(prefix="d1-relay-"))
            )
            server = _UnixServer(
                str(directory / "bridge.sock"),
                _callback_handler(self._host_port, self._host_trust),
            )
            starting.callback(server.server_close)
            thread = threading.Thread(target=server.serve_forever, daemon=True)
            thread.start()
            starting.callback(thread.join)
            starting.callback(server.shutdown)
            self._run_relay(directory)
            starting.callback(self._remove_relay)
            self._wait_for_relay()
            self._exit = starting.pop_all()
        return self

    def __exit__(
        self, kind: type[BaseException] | None, error: BaseException | None,
        trace: TracebackType | None,
    ) -> None:
        self._exit.close()

    def _run_relay(self, directory: Path) -> None:
        docker(
            "run", "--detach", "--rm", "--name", self._name, "--network", self._network,
            "--user", f"{os.getuid()}:{os.getgid()}", "--read-only", "--cap-drop", "ALL",
            "--security-opt", "no-new-privileges", "--volume", f"{directory}:/bridge:ro",
            RELAY_IMAGE, "python", "-I", "-c", RELAY_SOURCE,
        )

    def _wait_for_relay(self) -> None:
        deadline = time.monotonic() + RELAY_STARTS_SECONDS
        while RELAY_READY not in docker("logs", self._name):
            if time.monotonic() > deadline:
                raise StackError(f"the relay {self._name} did not start")
            time.sleep(0.5)

    def _remove_relay(self) -> None:
        docker("rm", "--force", self._name)


def _callback_handler(
    host_port: int, host_trust: ssl.SSLContext
) -> type[BaseHTTPRequestHandler]:
    class Callback(BaseHTTPRequestHandler):
        protocol_version = "HTTP/1.1"
        timeout = BRIDGE_TIMEOUT_SECONDS

        def log_message(self, format: str, *args: object) -> None:
            """Nothing is logged, a Logout Token least of all."""

        def do_POST(self) -> None:
            if self.path != BACKCHANNEL_LOGOUT_PATH:
                self._answer(HTTPStatus.NOT_FOUND)
                return
            length = self.headers.get("Content-Length", "")
            if not length.isascii() or not length.isdigit():
                self._answer(HTTPStatus.LENGTH_REQUIRED)
                return
            if int(length) > BACKCHANNEL_LOGOUT_MAX_BODY_BYTES:
                self._answer(HTTPStatus.REQUEST_ENTITY_TOO_LARGE)
                return
            self._answer(self._status_from_host(self.rfile.read(int(length))))

        def _status_from_host(self, body: bytes) -> int:
            host = http.client.HTTPSConnection(
                "localhost", host_port, timeout=BRIDGE_TIMEOUT_SECONDS, context=host_trust
            )
            try:
                host.request(
                    "POST", BACKCHANNEL_LOGOUT_PATH, body=body,
                    headers={"Content-Type": self.headers.get("Content-Type", FORM_CONTENT_TYPE)},
                )
                return host.getresponse().status
            except (OSError, http.client.HTTPException):
                return HTTPStatus.BAD_GATEWAY
            finally:
                host.close()

        def _answer(self, status: int) -> None:
            self.close_connection = True
            self.send_response(status)
            self.send_header("Connection", "close")
            self.send_header("Content-Length", "0")
            self.end_headers()

        def _refuse(self) -> None:
            self._answer(HTTPStatus.NOT_FOUND)

        do_GET = do_PUT = do_DELETE = do_HEAD = do_OPTIONS = do_PATCH = _refuse

    return Callback
