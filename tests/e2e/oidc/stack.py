"""The platform's Keycloak, held for the run, and the admin calls the proof needs.

The platform keeps the one copy of the realm and names the compose project; this
module only runs its ``scripts/keycloak_hold.sh`` as a subprocess and talks to the
admin API the hold names."""

from __future__ import annotations

import json
import subprocess
import threading
from dataclasses import dataclass, field
from pathlib import Path
from types import TracebackType
from typing import Any

import httpx

PLATFORM_SHA_FILE = Path(__file__).with_name("platform_sha.txt")
HOLD_SCRIPT = "scripts/keycloak_hold.sh"
# The hold's scratch directory in the run's runtime directory; run_oidc_proof.sh cleanup reads
# the project file the hold writes there.
HOLD_SCRATCH_NAME = "stack"
READY_MARK = "READY "
HOLD_ENDED = "HOLD ENDED"
STOP_WAIT_SECONDS = 180  # run_oidc_proof.sh: --kill-after must exceed the worst-case cleanup
ADMIN_TIMEOUT_SECONDS = 30
DOCKER_TIMEOUT_SECONDS = 30


class StackError(Exception):
    pass


def require_pinned_clean_platform(platform: Path) -> None:
    pinned = PLATFORM_SHA_FILE.read_text().strip()
    head = _git(platform, "rev-parse", "HEAD").strip()
    if head != pinned:
        raise StackError(f"the platform is at {head}, the harness is pinned to {pinned}")
    if _git(platform, "status", "--porcelain").strip():
        raise StackError("the platform checkout has changes")


def docker(*arguments: str) -> str:
    # Fixed command list
    return subprocess.run(  # noqa: S603
        # The operator's own PATH by design
        ["docker", *arguments],  # noqa: S607
        check=True,
        capture_output=True,
        text=True,
        timeout=DOCKER_TIMEOUT_SECONDS,
    ).stdout


def _git(checkout: Path, *arguments: str) -> str:
    # Fixed command list
    return subprocess.run(  # noqa: S603
        # The operator's own PATH by design
        ["git", "-C", str(checkout), *arguments],  # noqa: S607
        check=True,
        capture_output=True,
        text=True,
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

    def delete(self, path: str) -> None:
        answer = self._call("DELETE", path)
        if answer.status_code != 204:
            raise StackError(f"DELETE {path} answered {answer.status_code}")

    def post(self, path: str) -> None:
        answer = self._call("POST", path)
        if answer.status_code != 204:
            raise StackError(f"POST {path} answered {answer.status_code}")

    def _call(self, method: str, path: str, **options: Any) -> httpx.Response:
        return httpx.request(
            method,
            f"{self.admin_url}/admin/realms{path}",
            timeout=ADMIN_TIMEOUT_SECONDS,
            headers={"Authorization": f"Bearer {self.token}"},
            **options,
        )


@dataclass
class HeldStack:
    """``with HeldStack(platform, scratch) as stack`` brings the stack up and removes it on exit.

    ``scratch`` is a directory that does not exist yet or is empty."""

    platform: Path
    scratch: Path
    output: list[str] = field(default_factory=list)
    ready: dict[str, Any] = field(default_factory=dict)
    _process: subprocess.Popen[str] | None = None
    _drainer: threading.Thread | None = None

    def __enter__(self) -> HeldStack:
        # Fixed command list
        self._process = subprocess.Popen(  # noqa: S603
            # The operator's own PATH by design
            [  # noqa: S607
                "mise",
                "exec",
                "-C",
                str(self.platform),
                "--",
                HOLD_SCRIPT,
                "--scratch",
                str(self.scratch),
            ],
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            text=True,
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
                self.ready = json.loads(line[len(READY_MARK) :])
                self._drainer = threading.Thread(target=self._drain, daemon=True)
                self._drainer.start()
                return
        self._process.wait()
        raise StackError(f"the stack did not come up: {self.output[-3:]}")

    def __exit__(
        self,
        kind: type[BaseException] | None,
        error: BaseException | None,
        trace: TracebackType | None,
    ) -> None:
        self._stop()

    def _stop(self) -> None:
        assert self._process is not None and self._process.stdin is not None
        if not self.ready:
            # The hold reads its stdin only after READY; before it, a signal ends the bring-up.
            self._process.terminate()
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
    def edge_url(self) -> str:
        return self.ready["edge_url"]

    @property
    def project(self) -> str:
        return self.ready["project"]

    @property
    def keycloak_network(self) -> str:
        """The network Keycloak's container sits on."""
        return self.ready["keycloak_network"]

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
