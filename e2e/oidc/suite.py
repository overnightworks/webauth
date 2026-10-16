"""The OpenID Foundation conformance suite, held for the run, and the REST calls a driver needs.

``suite-compose.yaml`` keeps the one copy of the pinned images; this module
runs it under a project name of its own, removes everything the project made on
every way out, and talks to the suite's unauthenticated dev-mode API."""

from __future__ import annotations

import json
import os
import secrets
import subprocess
import time
from collections.abc import Callable
from dataclasses import dataclass, field
from pathlib import Path
from types import TracebackType
from typing import Any

import httpx
from stack import StackError

COMPOSE_FILE = Path(__file__).with_name("suite-compose.yaml")
SERVER_PORT_IN_CONTAINER = 8080
PROJECT_LABEL = "com.docker.compose.project"
READY_SECONDS = 240
READY_POLL_SECONDS = 2
COMPOSE_TIMEOUT_SECONDS = 120
DOWN_TIMEOUT_SECONDS = 120
API_TIMEOUT_SECONDS = 30
WAIT_STATE_SLICE_SECONDS = 5
LOG_LINES_IN_ERRORS = 5
STDERR_CHARS_IN_ERRORS = 600
BEHIND_TLS_FRONT = {"X-Forwarded-Proto": "https"}
DOCKER_OBJECTS = ("container", "volume", "network")


def project_leftovers(project: str) -> list[str]:
    """Containers, volumes and networks still carrying the project's label."""
    left = []
    for kind in DOCKER_OBJECTS:
        listing = ["ps", "-a"] if kind == "container" else [kind, "ls"]
        found = subprocess.run(
            ["docker", *listing, "--filter", f"label={PROJECT_LABEL}={project}", "-q"],
            check=True, capture_output=True, text=True,
        ).stdout.split()
        left.extend(f"{kind} {identifier}" for identifier in found)
    return left


@dataclass
class HeldSuite:
    """``with HeldSuite(host, stop_check) as suite`` brings the suite up and removes it on exit.

    ``stop_check`` is called while waiting and raises when the run was told to stop."""

    host: str
    stop_check: Callable[[], None]
    project: str = field(default_factory=lambda: f"d2-suite-{secrets.token_hex(4)}")
    port: int = 0

    def __enter__(self) -> HeldSuite:
        try:
            self._compose("up", "-d", timeout=COMPOSE_TIMEOUT_SECONDS)
            self.port = self._published_port()
            self._wait_until_ready()
        except BaseException:
            self.remove_everything()
            raise
        return self

    def __exit__(
        self, kind: type[BaseException] | None, error: BaseException | None,
        trace: TracebackType | None,
    ) -> None:
        if left := self.remove_everything():
            raise StackError(f"the suite project {self.project} left behind: {left}")

    @property
    def api(self) -> SuiteApi:
        return SuiteApi(f"http://127.0.0.1:{self.port}")

    def remove_everything(self) -> list[str]:
        """Takes the project down, with its volumes, and returns what still carries its label."""
        self._compose("down", "-v", "--remove-orphans", timeout=DOWN_TIMEOUT_SECONDS, check=False)
        return project_leftovers(self.project)

    def _compose(
        self, *arguments: str, timeout: int, check: bool = True
    ) -> subprocess.CompletedProcess[str]:
        finished = subprocess.run(
            ["docker", "compose", "-p", self.project, "-f", str(COMPOSE_FILE), *arguments],
            env={**os.environ, "SUITE_HOST": self.host},
            capture_output=True, text=True, timeout=timeout,
        )
        if check and finished.returncode:
            raise StackError(
                f"docker compose {arguments[0]} exited {finished.returncode}: "
                f"{finished.stderr[-STDERR_CHARS_IN_ERRORS:]}"
            )
        return finished

    def _published_port(self) -> int:
        answer = self._compose(
            "port", "server", str(SERVER_PORT_IN_CONTAINER), timeout=COMPOSE_TIMEOUT_SECONDS
        )
        return int(answer.stdout.strip().rsplit(":", 1)[-1])

    def _wait_until_ready(self) -> None:
        deadline = time.monotonic() + READY_SECONDS
        while time.monotonic() < deadline:
            self.stop_check()
            if self._answers():
                return
            time.sleep(READY_POLL_SECONDS)
        logs = self._compose("logs", "--tail", str(LOG_LINES_IN_ERRORS), "server", timeout=60)
        raise StackError(f"the suite did not answer in {READY_SECONDS} s: {logs.stdout[-600:]}")

    def _answers(self) -> bool:
        try:
            return self.api.answers_plan_listing()
        except httpx.HTTPError:
            return False


@dataclass(frozen=True)
class SuiteApi:
    """The six endpoints a driver needs, plus the readiness probe. The suite refuses
    plain http, so every call says what a TLS front in front of it would say."""

    base_url: str

    def answers_plan_listing(self) -> bool:
        return self._call("GET", "/api/plan", params={"length": 1}).status_code == 200

    def create_plan(
        self, name: str, variant: dict[str, str], configuration: dict[str, Any]
    ) -> dict[str, Any]:
        answer = self._call(
            "POST", "/api/plan", params={"planName": name, "variant": json.dumps(variant)},
            json=configuration, expected=201,
        )
        return answer.json()

    def create_module(self, plan_id: str, module: str) -> str:
        answer = self._call(
            "POST", "/api/runner", params={"test": module, "plan": plan_id}, expected=201
        )
        return answer.json()["id"]

    def start_module(self, module_id: str) -> None:
        self._call("POST", f"/api/runner/{module_id}", expected=200)

    def wait_for_state(self, module_id: str, states: list[str], seconds: float) -> str:
        """The first of ``states`` (or INTERRUPTED) the module reaches within ``seconds``."""
        wanted = ",".join([*states, "INTERRUPTED"])
        deadline = time.monotonic() + seconds
        while time.monotonic() < deadline:
            answer = self._call(
                "GET", f"/api/runner/{module_id}/wait-state",
                params={"states": wanted, "timeoutMs": WAIT_STATE_SLICE_SECONDS * 1000},
                expected=200,
                timeout=WAIT_STATE_SLICE_SECONDS + API_TIMEOUT_SECONDS,
            ).json()
            if state := answer.get("state"):
                return state
        raise StackError(f"module {module_id} did not reach {states} in {seconds} s")

    def module_status(self, module_id: str) -> dict[str, Any]:
        """The running module's state and the values it exposes, among them its issuer."""
        return self._call("GET", f"/api/runner/{module_id}", expected=200).json()

    def cancel_module(self, module_id: str) -> None:
        self._call("DELETE", f"/api/runner/{module_id}", expected=200)

    def export_plan(self, plan_id: str) -> bytes:
        return self._call("GET", f"/api/plan/export/{plan_id}", expected=200).content

    def _call(
        self, method: str, path: str, expected: int | None = None,
        timeout: float = API_TIMEOUT_SECONDS, **options: Any,
    ) -> httpx.Response:
        answer = httpx.request(
            method, f"{self.base_url}{path}", timeout=timeout, headers=BEHIND_TLS_FRONT, **options
        )
        if expected is not None and answer.status_code != expected:
            raise StackError(f"{method} {path} answered {answer.status_code}: {answer.text[:300]}")
        return answer
