"""The run plumbing every proof driver here shares: the private runtime
directory, the host app process, the first-signal handling, the browser
worker thread and the evidence scan. Nothing here knows a scenario.

It owns the pinned Chromium (``launch_pinned_chromium``: each host name mapped to
a loopback port, one certificate trusted by its public-key hash) and the recording
context (``recording_context``: every request logged field by field, every URL
credential and cookie value registered)."""

from __future__ import annotations

import contextlib
import os
import shutil
import signal
import socket
import subprocess
import sys
import threading
import time
import urllib.parse
from collections.abc import Callable, Iterator
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

import httpx
from evidence import (
    NetworkLog,
    SecretRegistry,
    delete_contaminated,
    recorded_cookie_name,
    scan_evidence,
    without_query_values,
)
from host_app import HostSettings
from playwright.sync_api import Browser, BrowserContext, Playwright
from shim import LOOPBACK
from stack import StackError

from webauth.cookies import CookieSameSite

APP_START_SECONDS = 30
STOP_SIGNALS = (signal.SIGTERM, signal.SIGINT)
WORKER_ENDS_SECONDS = 15
HOST_STOPS_SECONDS = 15
PAGE_TIMEOUT_MILLISECONDS = 30_000
URL_PARAMETERS_THAT_ARE_CREDENTIALS = ("code", "nonce", "session_state", "state")


class Interrupted(BaseException):
    """The first stop signal, raised wherever the main thread stands."""


@dataclass
class RunRecord:
    """What every run keeps: its masked lines, its failures and its stop state."""

    evidence_dir: Path
    registry: SecretRegistry
    log: NetworkLog
    lines: list[str] = field(default_factory=list)
    failures: int = 0
    stop_requested: threading.Event = field(default_factory=threading.Event)
    winding_down: bool = False
    browser_outlived_run: bool = False

    @property
    def all_held(self) -> bool:
        return bool(self.lines) and not self.failures

    def fail(self, message: str) -> None:
        self.failures += 1
        self.record(f"FAILED: {without_query_values(message)}")

    def record(self, line: str) -> None:
        masked_line = self.registry.masked(line)
        self.lines.append(masked_line)
        print(masked_line, flush=True)
        leaked = self.registry.labels_in(line.encode())
        if leaked:
            self.fail(f"a recorded line held {', '.join(leaked)}")


@dataclass(frozen=True)
class Host:
    """One running host process: its cookie configuration and the ports it serves on."""

    process: subprocess.Popen[bytes]
    cookie_samesite: CookieSameSite
    app_port: int
    observe_port: int


@contextlib.contextmanager
def runtime_directory(scratch: Path) -> Iterator[Path]:
    """The run's private scratch, deleted on every way out."""
    runtime = scratch / "runtime"
    runtime.mkdir(mode=0o700)
    try:
        yield runtime
    finally:
        shutil.rmtree(runtime)


def free_port() -> int:
    with socket.socket() as probe:
        probe.bind((LOOPBACK, 0))
        return probe.getsockname()[1]


def start_host(run: RunRecord, runtime: Path, settings: HostSettings, ca_certificate: Path) -> Host:
    cookie_samesite = settings.cookie_samesite
    settings_file = runtime / f"host-settings-{cookie_samesite}.json"
    settings.write(settings_file)
    log_file = (runtime / f"host-{cookie_samesite}.log").open("wb")
    process = subprocess.Popen(
        [sys.executable, str(Path(__file__).with_name("host_app.py")),
         "--settings", str(settings_file), "--parent-pid", str(os.getpid())],
        env={"PATH": os.environ["PATH"], "SSL_CERT_FILE": str(ca_certificate)},
        stdout=log_file, stderr=subprocess.STDOUT, start_new_session=True,
    )
    try:
        wait_until_serving(run, process, settings.observe_port, settings.port)
    except BaseException:
        stop_host(process)
        raise
    return Host(process, cookie_samesite, settings.port, settings.observe_port)


def host_state(host: Host) -> dict[str, Any]:
    return httpx.get(f"http://{LOOPBACK}:{host.observe_port}/state").json()


def tell_host(host: Host, order: str) -> None:
    httpx.post(f"http://{LOOPBACK}:{host.observe_port}/{order}").raise_for_status()


def reset_host(host: Host) -> None:
    tell_host(host, "reset")


def launch_pinned_chromium(
    playwright: Playwright, runtime: Path, mapped_hosts: dict[str, int], spki_sha256_base64: str
) -> Browser:
    """Chromium that resolves each host name to its loopback port and trusts one certificate."""
    browser_tmp = runtime / "tmp"
    browser_tmp.mkdir(exist_ok=True)
    os.environ["TMPDIR"] = str(browser_tmp)
    rules = ", ".join(f"MAP {name} {LOOPBACK}:{port}" for name, port in mapped_hosts.items())
    return playwright.chromium.launch(args=[
        f"--host-resolver-rules={rules}",
        f"--ignore-certificate-errors-spki-list={spki_sha256_base64}",
    ])


@contextlib.contextmanager
def recording_context(run: RunRecord, browser: Browser, **options: Any) -> Iterator[BrowserContext]:
    """A browser context whose URL credentials, requests and cookies the run registers and logs."""
    context = browser.new_context(**options)
    context.set_default_timeout(PAGE_TIMEOUT_MILLISECONDS)
    context.on("request", lambda request: remember_url_credentials(run, request.url))
    context.on("request", run.log.watch)
    try:
        yield context
    finally:
        with contextlib.ExitStack() as cleanup:
            cleanup.callback(context.close)
            cleanup.callback(run.log.collect)
            cleanup.callback(remember_cookies, run, context)


def remember_url_credentials(run: RunRecord, url: str) -> None:
    query = urllib.parse.parse_qs(urllib.parse.urlsplit(url).query)
    for name in URL_PARAMETERS_THAT_ARE_CREDENTIALS:
        for value in query.get(name, []):
            run.registry.add(f"url parameter {name}", value)


def remember_cookies(run: RunRecord, context: BrowserContext) -> None:
    for cookie in context.cookies():
        run.registry.add(f"cookie {recorded_cookie_name(cookie['name'])}", cookie["value"])


def wait_until_serving(run: RunRecord, process: subprocess.Popen[bytes], *ports: int) -> None:
    deadline = time.monotonic() + APP_START_SECONDS
    pending = list(ports)
    while pending and time.monotonic() < deadline:
        raise_if_stop_pending(run)
        if process.poll() is not None:
            raise StackError("the host app ended before it served")
        with contextlib.suppress(OSError), socket.create_connection((LOOPBACK, pending[0]), 1):
            pending.pop(0)
    if pending:
        raise StackError("the host app did not serve in time")


def stop_host(process: subprocess.Popen[bytes]) -> None:
    """Ends the host's whole process group, whatever it has spawned."""
    for stop_signal in (signal.SIGTERM, signal.SIGKILL):
        with contextlib.suppress(ProcessLookupError):
            os.killpg(process.pid, stop_signal)
        try:
            process.wait(timeout=HOST_STOPS_SECONDS)
            return
        except subprocess.TimeoutExpired:
            continue
    process.wait()


def containers_left(name_filter: str) -> list[str]:
    return subprocess.run(
        ["docker", "ps", "-a", "--filter", f"name={name_filter}", "--format", "{{.Names}}"],
        check=True, capture_output=True, text=True,
    ).stdout.split()


def own_child_pids() -> set[int]:
    pids: set[int] = set()
    for children in Path("/proc/self/task").glob("*/children"):
        with contextlib.suppress(FileNotFoundError):  # the thread ended while we looked
            pids.update(int(pid) for pid in children.read_text().split())
    return pids


def drive_browser_off_the_main_thread(run: RunRecord, drive: Callable[[], None]) -> None:
    """Playwright's sync API cannot be torn down from a signal handler, so the
    main thread keeps the signals and kills the browser's driver on a stop."""
    raise_if_stop_pending(run)
    before = own_child_pids()
    crashes: list[BaseException] = []
    worker_entered = threading.Event()
    worker_ended = threading.Event()

    def work() -> None:
        worker_entered.set()
        try:
            drive()
        except BaseException as error:
            crashes.append(error)
        finally:
            worker_ended.set()

    worker = threading.Thread(target=work, name="browser", daemon=True)
    try:
        worker.start()
        while not worker_ended.wait(0.5):
            pass
    except Interrupted:
        for pid in own_child_pids() - before:
            with contextlib.suppress(ProcessLookupError):
                os.kill(pid, signal.SIGKILL)
        raise
    finally:
        run.winding_down = True
        if worker_entered.is_set() and not worker_ended.wait(WORKER_ENDS_SECONDS):
            run.browser_outlived_run = True
            run.fail("the browser worker did not stop; evidence is not trustworthy")
    if crashes:
        crash = crashes[0]
        raise RuntimeError(
            f"the browser worker crashed: {type(crash).__name__}: {crash}"
        ) from crash


def raise_if_stop_pending(run: RunRecord) -> None:
    """A signal the handler could not raise (it landed in error handling)
    still ends the run at the next place that calls this."""
    if run.stop_requested.is_set() and not run.winding_down:
        raise Interrupted


def stop_on_first_signal(run: RunRecord) -> None:
    """The first SIGTERM or SIGINT ends the run through ``Interrupted``; the
    cleanup that follows is not interruptible, so later signals are ignored."""

    def handler(signum: int, frame: object) -> None:
        for stop_signal in STOP_SIGNALS:
            signal.signal(stop_signal, signal.SIG_IGN)
        run.stop_requested.set()
        if not run.winding_down and sys.exception() is None:
            raise Interrupted

    for stop_signal in STOP_SIGNALS:
        signal.signal(stop_signal, handler)


def runtime_leftovers(scratch: Path) -> list[str]:
    left = []
    runtime = scratch / "runtime"
    if runtime.exists():
        left.append("runtime/ survived the run")
        try:
            shutil.rmtree(runtime)
        except OSError as error:
            left.append(f"runtime/ could not be removed: {error}")
    return left


def leftovers(scratch: Path, container_filter: str) -> list[str]:
    left = runtime_leftovers(scratch)
    try:
        if containers := containers_left(container_filter):
            left.append(f"containers left behind: {containers}")
    except (subprocess.SubprocessError, OSError) as error:
        left.append(f"could not look for left-over containers: {error}")
    return left


def keep_clean_evidence(run: RunRecord) -> int:
    if run.browser_outlived_run:
        for screenshot in run.evidence_dir.glob("*.png"):
            screenshot.unlink()
        print("FAILED: the browser outlived the run; screenshots deleted, evidence not scanned")
        return 1
    (run.evidence_dir / "result-table.txt").write_text("\n".join(run.lines) + "\n")
    run.log.write(run.evidence_dir / "network.har")
    findings = scan_evidence(run.evidence_dir, run.registry)
    if findings:
        delete_contaminated(run.evidence_dir, findings)
        for finding in findings:
            print(f"FAILED: evidence {finding.file} held {finding.label}; file deleted")
        return 1
    print(f"evidence scan clean: {run.evidence_dir}", flush=True)
    return 0
