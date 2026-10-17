"""The edge's Keycloak stack, held for the run, and the admin calls the proof needs.

Edge keeps the one copy of the realm and the compose project; this module only
runs its ``hold`` mode as a subprocess and talks to the admin API it names."""

from __future__ import annotations

import json
import subprocess
import sys
import threading
from dataclasses import dataclass, field
from pathlib import Path
from types import TracebackType
from typing import Any

import httpx

EDGE_SHA_FILE = Path(__file__).with_name("EDGE_SHA")
PROBE_FILES = "compose.yaml keycloak probe/keycloak traefik.yml dynamic".split()
REALM = "hallucinai"
READY_MARK = "READY "
HOLD_ENDED = "HOLD ENDED"
STOP_WAIT_SECONDS = 180  # README: --kill-after must exceed the worst-case cleanup, 225 s
ADMIN_TIMEOUT_SECONDS = 30


class StackError(Exception):
    pass


def require_pinned_clean_edge(edge: Path) -> None:
    pinned = EDGE_SHA_FILE.read_text().strip()
    head = _git(edge, "rev-parse", "HEAD").strip()
    if head != pinned:
        raise StackError(f"edge is at {head}, the harness is pinned to {pinned}")
    dirty = _git(edge, "status", "--porcelain", "--", *PROBE_FILES)
    if dirty.strip():
        raise StackError("edge has changes in files the probe consumes")


def _git(edge: Path, *arguments: str) -> str:
    return subprocess.run(  # noqa: S603 fixed command list
        ["git", "-C", str(edge), *arguments], check=True, capture_output=True, text=True  # noqa: S607 the operator's own PATH by design
    ).stdout


@dataclass(frozen=True)
class Admin:
    """The realm's admin API, reached with the config-cli client the stack names."""

    admin_url: str
    token: str

    def create(self, path: str, representation: dict[str, Any]) -> str:
        answer = self._call("POST", path, json=representation)
        if answer.status_code != 201:
            raise StackError(f"POST {path} answered {answer.status_code}")
        return answer.headers["Location"].rsplit("/", 1)[-1]

    def get(self, path: str) -> Any:
        answer = self._call("GET", path)
        if answer.status_code != 200:
            raise StackError(f"GET {path} answered {answer.status_code}")
        return answer.json()

    def put(self, path: str, representation: dict[str, Any] | None = None) -> None:
        answer = self._call("PUT", path, json=representation)
        if answer.status_code not in (200, 204):
            raise StackError(f"PUT {path} answered {answer.status_code}")

    def _call(self, method: str, path: str, **options: Any) -> httpx.Response:
        return httpx.request(
            method, f"{self.admin_url}/admin/realms{path}", timeout=ADMIN_TIMEOUT_SECONDS,
            headers={"Authorization": f"Bearer {self.token}"}, **options,
        )


@dataclass
class HeldStack:
    """``with HeldStack(edge, scratch) as stack`` brings the stack up and removes it on exit."""

    edge: Path
    scratch: Path
    output: list[str] = field(default_factory=list)
    ready: dict[str, Any] = field(default_factory=dict)
    _process: subprocess.Popen[str] | None = None
    _drainer: threading.Thread | None = None

    def __enter__(self) -> HeldStack:
        self._process = subprocess.Popen(  # noqa: S603 fixed command list
            [sys.executable, str(self.edge / "probe/keycloak/probe.py"), "hold",
             "--scratch", str(self.scratch)],
            stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True,
        )
        try:
            self._wait_for_ready()
        except BaseException:
            self._stop()
            raise
        return self

    def _wait_for_ready(self) -> None:
        assert self._process is not None and self._process.stdout is not None
        for line in self._process.stdout:
            self.output.append(line.rstrip())
            if line.startswith(READY_MARK):
                self.ready = json.loads(line[len(READY_MARK):])
                self._drainer = threading.Thread(target=self._drain, daemon=True)
                self._drainer.start()
                return
        self._process.wait()
        raise StackError(f"the stack did not come up: {self.output[-3:]}")

    def __exit__(
        self, kind: type[BaseException] | None, error: BaseException | None,
        trace: TracebackType | None,
    ) -> None:
        self._stop()

    def _stop(self) -> None:
        assert self._process is not None and self._process.stdin is not None
        self._process.stdin.close()
        try:
            status = self._process.wait(timeout=STOP_WAIT_SECONDS)
        except subprocess.TimeoutExpired:
            self._process.kill()
            raise StackError("the stack did not stop") from None
        if self._drainer is not None:
            self._drainer.join()
        if status != 0 or HOLD_ENDED not in self.output:
            raise StackError(f"the stack ended with status {status}: {self.output[-3:]}")

    @property
    def secrets_dir(self) -> Path:
        return self.scratch / "secrets"

    @property
    def edge_url(self) -> str:
        return self.ready["edge_url"]

    def admin(self) -> Admin:
        secret = Path(self.ready["admin_client_secret_file"]).read_text().strip()
        answer = httpx.post(
            f"{self.ready['admin_url']}/realms/master/protocol/openid-connect/token",
            data={
                "grant_type": "client_credentials",
                "client_id": self.ready["admin_client_id"],
                "client_secret": secret,
            },
            timeout=ADMIN_TIMEOUT_SECONDS,
        )
        answer.raise_for_status()
        return Admin(self.ready["admin_url"], answer.json()["access_token"])

    def _drain(self) -> None:
        assert self._process is not None and self._process.stdout is not None
        for line in self._process.stdout:
            self.output.append(line.rstrip())
