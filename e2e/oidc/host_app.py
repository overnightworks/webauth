"""The host application of the proof: the README's start and callback routes
over the library's own in-memory stores, served over TLS.

One process serves one cookie configuration on every origin it is told. Beside
it a plain-http listener on loopback, which no browser is ever pointed at, answers
``GET /state`` with counts only, clears everything on ``POST /reset`` and
deactivates every known account on ``POST /deactivate``."""

from __future__ import annotations

import argparse
import ctypes
import functools
import html
import importlib.util
import json
import os
import signal
import sys
import threading
import time
from dataclasses import asdict, dataclass
from datetime import datetime, timedelta, timezone
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from string import Template
from typing import Any, Literal

import uvicorn
from fastapi import Depends, FastAPI, HTTPException, Request, Response
from fastapi.responses import HTMLResponse
from pydantic import SecretStr

from webauth.config import WebAuthConfig, install_web_auth_config
from webauth.cookies import clear_session_cookies, issue_session_cookies
from webauth.dependencies import AuthenticatedUser, current_user_dependency
from webauth.https_client import fetch_key_set_over_https
from webauth.middleware.csrf import CsrfOriginMiddleware, CsrfTokenMiddleware
from webauth.oidc import OidcClientConfig, OidcRefusal, OidcRelyingParty
from webauth.oidc_login import (
    AdmissionRefusal,
    finish_login,
    post_token_request_over_https,
    start_login,
)
from webauth.policies import CsrfPolicy
from webauth.session_ending import end_session

LOOPBACK = "127.0.0.1"
CALLBACK_PATH = "/auth/callback"
REPOSITORY = Path(__file__).resolve().parents[2]
SCOPES = ("openid", "profile", "groups")
LEEWAY_SECONDS = 30

PAGE = Template("""<!doctype html>
<html><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>webauth demo host</title></head>
<body>
<h1>$headline</h1>
$body
</body></html>""")
LOGOUT_BUTTON = Template("""<button id="logout" type="button">Log out</button>
<script>
document.getElementById("logout").addEventListener("click", async () => {
  const prefix = $csrf_cookie + "=";
  const token = document.cookie.split("; ").find((c) => c.startsWith(prefix)).slice(prefix.length);
  await fetch("/logout", {method: "POST", headers: {[$csrf_header]: token}});
  location.assign("/");
});
</script>""")


@functools.cache
def _arrangement() -> Any:
    """The library suite's in-memory stores, loaded by path from ``tests/``."""
    path = REPOSITORY / "tests" / "webauth_arrangement.py"
    spec = importlib.util.spec_from_file_location("webauth_arrangement", path)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


@dataclass(frozen=True)
class HostSettings:
    """Everything a host process is told; the file that carries it is deleted with the run."""

    app_origins: tuple[str, ...]
    port: int
    observe_port: int
    tls_certificate: str
    tls_key: str
    issuer: str
    authorization_endpoint: str
    token_endpoint: str
    jwks_url: str
    client_id: str
    client_secret: str
    session_secret: str
    cookie_samesite: Literal["strict", "lax"] = "strict"

    @staticmethod
    def read(path: Path) -> HostSettings:
        fields = json.loads(path.read_text())
        return HostSettings(**{**fields, "app_origins": tuple(fields["app_origins"])})

    def write(self, path: Path) -> None:
        path.touch(mode=0o600)
        path.write_text(json.dumps(asdict(self)))


class World:
    """The host's stores and counters; ``reset`` starts them again."""

    def __init__(self) -> None:
        arrangement = _arrangement()
        self.lock = arrangement.WriteLockInMemory()
        self.accounts = arrangement.UsersInMemory(lock=self.lock)
        self.sessions = arrangement.SessionRecordsInMemory(users=self.accounts, lock=self.lock)
        self.audit = arrangement.RecordingAuditSink()
        self.callbacks_received = 0
        self.last_refusal: str | None = None

    def deactivate_accounts(self) -> None:
        with self.lock.hold():
            for account in self.accounts.list():
                account.is_active = False

    def counts(self) -> dict[str, object]:
        return {
            "accounts": len(self.accounts.list()),
            "sessions": self.sessions.count_active(),
            "callbacks_received": self.callbacks_received,
            "last_refusal": self.last_refusal,
        }


class _Observation:
    """The counts-only listener the scenarios read, reset and deactivate accounts through."""

    def __init__(self, port: int, world: dict[str, World]) -> None:
        holder = world

        class Handler(BaseHTTPRequestHandler):
            def log_message(self, format: str, *args: object) -> None:
                """Nothing is logged."""

            def do_GET(self) -> None:
                payload = json.dumps(holder["world"].counts()).encode()
                self.send_response(200 if self.path == "/state" else 404)
                self.send_header("Content-Length", str(len(payload)))
                self.end_headers()
                self.wfile.write(payload)

            def do_POST(self) -> None:
                if self.path == "/reset":
                    holder["world"] = World()
                elif self.path == "/deactivate":
                    holder["world"].deactivate_accounts()
                self.send_response(204 if self.path in ("/reset", "/deactivate") else 404)
                self.send_header("Content-Length", "0")
                self.end_headers()

        self._server = ThreadingHTTPServer((LOOPBACK, port), Handler)
        threading.Thread(target=self._server.serve_forever, daemon=True).start()


def _relying_party(settings: HostSettings, redirect_uri: str) -> OidcRelyingParty:
    return OidcRelyingParty(
        OidcClientConfig(
            issuer=settings.issuer,
            authorization_endpoint=settings.authorization_endpoint,
            token_endpoint=settings.token_endpoint,
            jwks_url=settings.jwks_url,
            client_id=settings.client_id,
            client_secret=SecretStr(settings.client_secret),
            redirect_uri=redirect_uri,
            scopes=SCOPES,
            leeway_seconds=LEEWAY_SECONDS,
        ),
        post_token_request=post_token_request_over_https,
        fetch_key_set=fetch_key_set_over_https,
        wall_clock=time.time,
        monotonic_clock=time.monotonic,
    )


def build_app(settings: HostSettings, world: dict[str, World]) -> FastAPI:
    arrangement = _arrangement()
    config: WebAuthConfig = arrangement.a_web_auth_config(
        session_secret=SecretStr(settings.session_secret),
        cookie_samesite=settings.cookie_samesite,
        allowed_hosts_exact=frozenset(
            origin.removeprefix("https://") for origin in settings.app_origins
        ),
        allowed_hosts_patterns=(),
    )
    relying_parties = {
        origin: _relying_party(settings, f"{origin}{CALLBACK_PATH}")
        for origin in settings.app_origins
    }

    def relying_party_of(request: Request) -> OidcRelyingParty:
        return relying_parties[f"https://{request.headers['host']}"]

    dependencies = current_user_dependency(
        session_store=lambda: world["world"].sessions,
        audit_sink=lambda: world["world"].audit,
        on_authenticated=lambda user: None,
    )
    app = FastAPI(docs_url=None, redoc_url=None, openapi_url=None)
    install_web_auth_config(app, config)
    app.add_middleware(CsrfTokenMiddleware, policy=CsrfPolicy())
    app.add_middleware(CsrfOriginMiddleware, policy=CsrfPolicy())

    @app.middleware("http")
    async def count_callbacks(request: Request, call_next: Any) -> Response:
        if request.url.path == CALLBACK_PATH:
            world["world"].callbacks_received += 1
        return await call_next(request)

    def signed_in_user(request: Request) -> AuthenticatedUser | None:
        try:
            return dependencies.current_user(
                request, world["world"].sessions, world["world"].audit
            )
        except HTTPException:
            return None

    @app.get("/", response_class=HTMLResponse)
    def home(user: AuthenticatedUser | None = Depends(signed_in_user)) -> str:
        if user is None:
            return PAGE.substitute(
                headline="Signed out", body='<a id="sign-in" href="/login/oidc">Sign in</a>'
            )
        button = LOGOUT_BUTTON.substitute(
            csrf_cookie=json.dumps(config.csrf_cookie_name),
            csrf_header=json.dumps(config.csrf_header_name),
        )
        return PAGE.substitute(
            headline=f"Signed in as {html.escape(user.username)}", body=button
        )

    @app.get("/login/oidc")
    def start(request: Request) -> Response:
        response = Response(status_code=303)
        response.headers["location"] = start_login(
            relying_party_of(request), request, response, config
        )
        return response

    @app.get(CALLBACK_PATH, response_class=HTMLResponse)
    def callback(request: Request, response: Response) -> str:
        current = world["world"]
        outcome = finish_login(
            relying_party_of(request), request, response, config,
            bound_issuer=settings.issuer, accounts=current.accounts, lock=current.lock,
            audit=current.audit,
        )
        if isinstance(outcome, (OidcRefusal, AdmissionRefusal)):
            reason = outcome.reason.value if isinstance(outcome, OidcRefusal) else outcome.value
            current.last_refusal = reason
            response.status_code = 403
            return PAGE.substitute(headline="Sign-in refused", body=html.escape(reason))
        with current.lock.hold():
            record = current.sessions.create(
                outcome.id,
                datetime.now(timezone.utc) + timedelta(seconds=config.session_max_age_seconds),
                ip_address=request.client.host if request.client else "",
                user_agent=request.headers.get("user-agent", "")[: config.max_user_agent_chars],
            )
        issue_session_cookies(response, record.id, config)
        response.status_code = 303
        response.headers["location"] = "/"
        return ""

    @app.get("/me")
    def me(user: AuthenticatedUser = Depends(dependencies.current_user)) -> dict[str, str]:
        return {"username": user.username}

    @app.post("/logout", dependencies=[Depends(dependencies.current_user)])
    def logout(
        response: Response,
        session_id: str = Depends(dependencies.verified_session_id),
    ) -> dict[str, bool]:
        with world["world"].lock.hold():
            end_session(world["world"].sessions, session_id=session_id)
        clear_session_cookies(response, config)
        return {"signed_out": True}

    return app


def die_with_parent(parent_pid: int) -> None:
    """Linux ``PR_SET_PDEATHSIG``: a host nobody can stop must not outlive its run."""
    pr_set_pdeathsig = 1
    if ctypes.CDLL(None, use_errno=True).prctl(pr_set_pdeathsig, signal.SIGKILL) != 0:
        raise OSError(ctypes.get_errno(), "prctl(PR_SET_PDEATHSIG) failed")
    if os.getppid() != parent_pid:
        raise SystemExit("the parent ended before the host could watch it")


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--settings", type=Path, required=True)
    parser.add_argument("--parent-pid", type=int, required=True)
    arguments = parser.parse_args()
    die_with_parent(arguments.parent_pid)
    settings = HostSettings.read(arguments.settings)
    world = {"world": World()}
    _Observation(settings.observe_port, world)
    uvicorn.run(
        build_app(settings, world),
        host=LOOPBACK,
        port=settings.port,
        ssl_certfile=settings.tls_certificate,
        ssl_keyfile=settings.tls_key,
        log_level="warning",
        access_log=False,
    )


if __name__ == "__main__":
    main()
