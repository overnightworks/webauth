"""Proves login and logout of a webauth host in a real browser against a real Keycloak.

    flock /tmp/probe-stack.lock timeout --kill-after=240 900 \\
        uv run --extra dev --group e2e python e2e/oidc/prove.py --edge PATH --scratch EMPTY_DIR

Read ``README.md`` beside this file first. Nothing of the OIDC path is faked:
the browser fills Keycloak's own form, the host's library talks to the real
token and key-set endpoints, and the only seams are the connection routing and
the one throwaway certificate key the browser is told to accept."""

from __future__ import annotations

import argparse
import contextlib
import json
import os
import re
import secrets
import shutil
import signal
import socket
import ssl
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
from certificates import ThrowawayTls, issue_throwaway_tls
from evidence import (
    NetworkLog,
    SecretRegistry,
    delete_contaminated,
    scan_evidence,
    without_query_values,
)
from host_app import HostSettings
from playwright.sync_api import Browser, BrowserContext, Page, sync_playwright
from shim import LOOPBACK, TlsShim
from stack import Admin, HeldStack, StackError, require_pinned_clean_edge

from webauth.cookies import (
    DEFAULT_SESSION_COOKIE_NAME,
    is_pending_login_cookie_name,
    verify_pending_login,
)

IDP_HOST = "auth.hallucinai.de"
APP_HOST = "demo.hallucinai.de"
SECOND_APP_HOST = "demo.example.test"
UNTRUSTED_HOST = "untrusted.hallucinai.de"
REALM = "hallucinai"
ISSUER = f"https://{IDP_HOST}/realms/{REALM}"
OIDC_PATH = f"{ISSUER}/protocol/openid-connect"
APP_ORIGIN = f"https://{APP_HOST}"
CLIENT_ID = "d1-host"
USER_NAME = "d1-user"
USER_GROUP = "/apps/songmaker"
DESKTOP_VIEWPORT = {"width": 1280, "height": 800}
WIDTH_LABEL = "1280x800"
PAGE_TIMEOUT_MILLISECONDS = 30_000
APP_START_SECONDS = 30
URL_PARAMETERS_THAT_ARE_CREDENTIALS = ("code", "session_state", "state")
STOP_SIGNALS = (signal.SIGTERM, signal.SIGINT)
WORKER_ENDS_SECONDS = 15
HOST_STOPS_SECONDS = 15


class Interrupted(BaseException):
    """The first stop signal, raised wherever the main thread stands."""


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


@dataclass
class Proof:
    """One run: what it created, what it saw, and what it concluded."""

    evidence_dir: Path
    registry: SecretRegistry
    log: NetworkLog
    lines: list[str] = field(default_factory=list)
    browser: Browser | None = None
    app_port: int = 0
    observe_port: int = 0
    ca_certificate: Path | None = None
    session_secret: str = ""
    user_password: str = ""
    client_secret: str = ""
    browser_tmp: Path | None = None
    failures: int = 0
    stop_requested: threading.Event = field(default_factory=threading.Event)
    winding_down: bool = False

    @property
    def all_held(self) -> bool:
        return bool(self.lines) and not self.failures

    def fail(self, message: str) -> None:
        self.failures += 1
        self.record(f"FAILED: {without_query_values(message)}")

    def record(self, line: str) -> None:
        self.lines.append(line)
        print(line, flush=True)

    def held_or_failed(self, label: str, check: Callable[[], str]) -> bool:
        if self.stop_requested.is_set():
            return False
        try:
            observed = check()
        except Exception as error:
            failure = without_query_values(f"{type(error).__name__}: {error}")
            self.failures += 1
            self.record(f"{label} FAILED: {failure}")
            return False
        self.record(f"{label} held: {observed}")
        return True

    @contextlib.contextmanager
    def browsing(self) -> Iterator[Page]:
        assert self.browser is not None
        context = self.browser.new_context(viewport=DESKTOP_VIEWPORT)
        context.set_default_timeout(PAGE_TIMEOUT_MILLISECONDS)
        context.on("request", self._remember_url_credentials)
        context.on("request", self.log.watch)
        page = context.new_page()
        try:
            yield page
        finally:
            self.capture_cookies(context)
            self.log.collect()
            context.close()

    def _remember_url_credentials(self, request: Any) -> None:
        query = urllib.parse.parse_qs(urllib.parse.urlsplit(request.url).query)
        for name in URL_PARAMETERS_THAT_ARE_CREDENTIALS:
            for value in query.get(name, []):
                self.registry.add(f"url parameter {name}", value)

    def capture_cookies(self, context: BrowserContext) -> None:
        for cookie in context.cookies():
            self.registry.add(f"cookie {cookie['name']}", cookie["value"])
            if is_pending_login_cookie_name(cookie["name"], secure=True):
                self._register_pending_login(cookie["value"])

    def _register_pending_login(self, cookie_value: str) -> None:
        pending = verify_pending_login(cookie_value, self.session_secret.encode())
        if pending is None:
            raise AssertionError("a pending-login cookie did not verify; secrets unregistered")
        self.registry.add("pending login state", pending.state)
        self.registry.add("pending login nonce", pending.nonce)
        self.registry.add("pending login code_verifier", pending.code_verifier)

    def shot(self, page: Page, scenario: str, moment: str) -> None:
        page.screenshot(path=self.evidence_dir / f"{scenario}-{moment}.png")

    def host_state(self) -> dict[str, Any]:
        return httpx.get(f"http://{LOOPBACK}:{self.observe_port}/state").json()

    def reset_host(self) -> None:
        httpx.post(f"http://{LOOPBACK}:{self.observe_port}/reset").raise_for_status()

    def start_sign_in(self, page: Page, scenario: str) -> None:
        page.goto(f"{APP_ORIGIN}/")
        self.shot(page, scenario, "start")
        page.click("#sign-in")
        page.wait_for_selector("#username")
        self.capture_cookies(page.context)

    def fill_keycloak_form(self, page: Page, scenario: str, password: str) -> None:
        page.fill("#username", USER_NAME)
        page.fill("#password", password)
        self.shot(page, scenario, "idp-form")
        page.click("#kc-login")

    def sign_in(self, page: Page, scenario: str) -> None:
        self.start_sign_in(page, scenario)
        self.fill_keycloak_form(page, scenario, self.user_password)
        page.wait_for_url(re.compile(f"^{re.escape(APP_ORIGIN)}/"))

    def status_of(self, page: Page, path: str) -> int:
        return page.evaluate("path => fetch(path).then((answer) => answer.status)", path)

    def headline(self, page: Page) -> str:
        return page.inner_text("h1")


def issuer_document_is_canonical(proof: Proof) -> str:
    with proof.browsing() as page:
        page.goto(f"{ISSUER}/.well-known/openid-configuration")
        issuer = json.loads(page.inner_text("body"))["issuer"]
        assert page.url == f"{ISSUER}/.well-known/openid-configuration", "the URL moved"
        assert issuer == ISSUER, "the document names another issuer"
    return f"{ISSUER} answered under its canonical URL and names itself as the issuer"


def untrusted_certificate_is_refused(proof: Proof) -> str:
    with proof.browsing() as page:
        try:
            page.goto(f"https://{UNTRUSTED_HOST}/")
        except Exception as error:
            reason = re.search(r"net::ERR_\w+", str(error))
            assert reason and "CERT" in reason.group(), f"refused for another reason: {error}"
            return f"a throwaway key signed by a CA nobody trusts is refused: {reason.group()}"
    raise AssertionError("the browser accepted a certificate it was not told to trust")


def login(proof: Proof) -> str:
    proof.reset_host()
    with proof.browsing() as page:
        proof.sign_in(page, "1")
        page.goto(f"{APP_ORIGIN}/")
        headline = proof.headline(page)
        assert headline == f"Signed in as {USER_NAME}", f"the page says {headline!r}"
        me_status = proof.status_of(page, "/me")
        assert me_status == 200, f"/me answered {me_status}"
        proof.shot(page, "1", "result")
    held = proof.host_state()
    assert held["accounts"] == 1 and held["sessions"] == 1, f"the host holds {held}"
    signed_in = (
        f"{USER_NAME} signed in at Keycloak's form; '/' says 'Signed in as {USER_NAME}' "
        "and GET /me answered 200"
    )
    return f"{signed_in}; {a_wrong_password_stays_at_keycloak(proof)}"


def a_wrong_password_stays_at_keycloak(proof: Proof) -> str:
    proof.reset_host()
    with proof.browsing() as page:
        wrong_password = secrets.token_urlsafe(12)
        proof.registry.add("wrong password", wrong_password)
        proof.start_sign_in(page, "1b")
        proof.fill_keycloak_form(page, "1b", wrong_password)
        page.get_by_text("Invalid username or password").wait_for()
        assert urllib.parse.urlsplit(page.url).hostname == IDP_HOST, "left Keycloak's form"
        proof.shot(page, "1b", "refused-result")
    held = proof.host_state()
    assert (held["callbacks_received"], held["accounts"], held["sessions"]) == (0, 0, 0), held
    return "a wrong password stays on Keycloak's form: callbacks 0, accounts 0, sessions 0"


def logout(proof: Proof) -> str:
    proof.reset_host()
    with proof.browsing() as page:
        proof.sign_in(page, "2")
        page.goto(f"{APP_ORIGIN}/")
        assert proof.headline(page) == f"Signed in as {USER_NAME}"
        cookies = [c for c in page.context.cookies(APP_ORIGIN)]
        held_names = {c["name"] for c in cookies}
        session = next(c for c in cookies if c["name"] == DEFAULT_SESSION_COOKIE_NAME)
        proof.registry.add("session cookie", session["value"])
        page.click("#logout")
        page.get_by_role("heading", name="Signed out").wait_for()
        page.reload()
        assert proof.headline(page) == "Signed out", "a reload of '/' did not show Sign in"
        proof.shot(page, "2", "result")
        left = held_names & {c["name"] for c in page.context.cookies(APP_ORIGIN)}
        assert not left, f"cookies survived: {sorted(left)}"
        me_status = proof.status_of(page, "/me")
        assert me_status == 401, f"/me answered {me_status}"
        back_shows = back_button_shows(proof, page)
        replay = replayed_session_status(proof, session)
        assert replay == 401, f"the old session cookie was answered {replay}"
        assert proof.host_state()["sessions"] == 0, "the host still holds a session"
        silent = second_sign_in(proof, page)
    return (
        f"after the button the cookies are gone, a reload shows Sign in and /me answers 401; "
        f"the back button shows {back_shows!r} but the old session cookie replayed over HTTPS "
        f"to /me is refused ({replay}); a second Sign in {silent} (Keycloak's SSO session "
        f"is not ended by this logout)"
    )


def back_button_shows(proof: Proof, page: Page) -> str:
    page.go_back()
    page_text = page.inner_text("h1") if page.query_selector("h1") else "no page"
    return f"{page_text} (the host's last sign-in refusal: {proof.host_state()['last_refusal']})"


def replayed_session_status(proof: Proof, session: dict[str, Any]) -> int:
    assert proof.ca_certificate is not None
    return httpx.get(
        f"https://localhost:{proof.app_port}/me",
        headers={"Cookie": f"{session['name']}={session['value']}"},
        verify=ssl.create_default_context(cafile=str(proof.ca_certificate)),
    ).status_code


def second_sign_in(proof: Proof, page: Page) -> str:
    page.goto(f"{APP_ORIGIN}/")
    page.click("#sign-in")
    keycloak_form = page.locator("#username")
    signed_in = page.get_by_role("heading", name=f"Signed in as {USER_NAME}")
    keycloak_form.or_(signed_in).wait_for()
    proof.shot(page, "2", "second-sign-in")
    if keycloak_form.is_visible():
        return "shows Keycloak's form again"
    held = proof.host_state()
    assert held["sessions"] == 1, f"the host holds {held}"
    return "signs in again without a form, through the live SSO session"


def prepare_keycloak(admin: Admin, proof: Proof, client_secret: str) -> None:
    admin.create(f"/{REALM}/clients", {
        "clientId": CLIENT_ID,
        "enabled": True,
        "publicClient": False,
        "clientAuthenticatorType": "client-secret",
        "secret": client_secret,
        "standardFlowEnabled": True,
        "directAccessGrantsEnabled": False,
        "serviceAccountsEnabled": False,
        "frontchannelLogout": False,
        "redirectUris": [
            f"{APP_ORIGIN}/auth/callback", f"https://{SECOND_APP_HOST}/auth/callback",
        ],
        "defaultClientScopes": ["basic", "profile", "groups"],
    })
    user_id = admin.create(f"/{REALM}/users", {
        "username": USER_NAME,
        "enabled": True,
        "email": f"{USER_NAME}@d1.invalid",
        "emailVerified": True,
        "firstName": "D1",
        "lastName": "User",
        "credentials": [{"type": "password", "value": proof.user_password, "temporary": False}],
    })
    group = admin.get(f"/{REALM}/group-by-path{USER_GROUP}")
    admin.put(f"/{REALM}/users/{user_id}/groups/{group['id']}")


def register_stack_secrets(stack: HeldStack, admin: Admin, registry: SecretRegistry) -> None:
    for path in stack.secrets_dir.rglob("*"):
        if path.is_file():
            for line in path.read_text().splitlines():
                registry.add(f"stack secret {path.name}", line.strip())
                registry.add(f"stack secret {path.name}", line.partition("=")[2].strip())
    registry.add("admin token", admin.token)


def start_host(
    proof: Proof, runtime: Path, tls: ThrowawayTls, shim_port: int,
) -> subprocess.Popen[bytes]:
    proof.app_port, proof.observe_port = free_port(), free_port()
    proof.ca_certificate = tls.ca_certificate
    settings = HostSettings(
        app_origin=APP_ORIGIN,
        port=proof.app_port,
        observe_port=proof.observe_port,
        tls_certificate=str(tls.leaf_certificate),
        tls_key=str(tls.leaf_key),
        issuer=ISSUER,
        authorization_endpoint=f"{OIDC_PATH}/auth",
        token_endpoint=f"https://localhost:{shim_port}/realms/{REALM}/protocol/openid-connect/token",
        jwks_url=f"https://localhost:{shim_port}/realms/{REALM}/protocol/openid-connect/certs",
        client_id=CLIENT_ID,
        client_secret=proof.client_secret,
        session_secret=proof.session_secret,
    )
    settings_file = runtime / "host-settings.json"
    settings.write(settings_file)
    log_file = (runtime / "host.log").open("wb")
    process = subprocess.Popen(
        [sys.executable, str(Path(__file__).with_name("host_app.py")),
         "--settings", str(settings_file)],
        env={"PATH": os.environ["PATH"], "SSL_CERT_FILE": str(tls.ca_certificate)},
        stdout=log_file, stderr=subprocess.STDOUT, start_new_session=True,
    )
    wait_until_serving(process, proof.observe_port, proof.app_port)
    return process


def wait_until_serving(process: subprocess.Popen[bytes], *ports: int) -> None:
    deadline = time.monotonic() + APP_START_SECONDS
    pending = list(ports)
    while pending and time.monotonic() < deadline:
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


def containers_left() -> list[str]:
    return subprocess.run(
        ["docker", "ps", "-a", "--filter", "name=edge-kc-probe", "--format", "{{.Names}}"],
        check=True, capture_output=True, text=True,
    ).stdout.split()


def run_proof(proof: Proof, edge: Path, runtime: Path) -> None:
    proof.browser_tmp = runtime / "tmp"
    proof.browser_tmp.mkdir()
    proof.session_secret = secrets.token_urlsafe(48)
    proof.user_password = secrets.token_urlsafe(18)
    proof.client_secret = secrets.token_urlsafe(24)
    for label, value in (
        ("session secret", proof.session_secret), ("user password", proof.user_password),
        ("client secret", proof.client_secret),
    ):
        proof.registry.add(label, value)
    tls = issue_throwaway_tls(runtime, "good", [IDP_HOST, APP_HOST, SECOND_APP_HOST, "localhost"])
    untrusted = issue_throwaway_tls(runtime, "untrusted", [UNTRUSTED_HOST])
    with HeldStack(edge, runtime / "stack") as stack:
        admin = stack.admin()
        register_stack_secrets(stack, admin, proof.registry)
        prepare_keycloak(admin, proof, proof.client_secret)
        edge_port = urllib.parse.urlsplit(stack.edge_url).port
        assert edge_port is not None
        with TlsShim(tls, edge_port, IDP_HOST) as shim, \
                TlsShim(untrusted, edge_port, IDP_HOST) as untrusted_shim:
            host = start_host(proof, runtime, tls, shim.port)
            try:
                drive_browser_off_the_main_thread(proof, tls, shim.port, untrusted_shim.port)
            finally:
                proof.winding_down = True
                stop_host(host)
    print("\n".join(line for line in stack.output if line.startswith("teardown")), flush=True)


def own_child_pids() -> set[int]:
    return {
        int(pid)
        for children in Path("/proc/self/task").glob("*/children")
        for pid in children.read_text().split()
    }


def drive_browser_off_the_main_thread(
    proof: Proof, tls: ThrowawayTls, shim_port: int, untrusted_port: int
) -> None:
    """Playwright's sync API cannot be torn down from a signal handler, so the
    main thread keeps the signals and kills the browser's driver on a stop."""
    before = own_child_pids()
    crashes: list[Exception] = []

    def work() -> None:
        try:
            drive_browser(proof, tls, shim_port, untrusted_port)
        except Exception as error:
            crashes.append(error)

    worker = threading.Thread(target=work, name="browser", daemon=True)
    worker.start()
    try:
        while worker.is_alive():
            worker.join(0.5)
    except Interrupted:
        for pid in own_child_pids() - before:
            with contextlib.suppress(ProcessLookupError):
                os.kill(pid, signal.SIGKILL)
        worker.join(WORKER_ENDS_SECONDS)
        raise
    if crashes:
        raise crashes[0]


def drive_browser(proof: Proof, tls: ThrowawayTls, shim_port: int, untrusted_port: int) -> None:
    rules = ", ".join((
        f"MAP {IDP_HOST} {LOOPBACK}:{shim_port}",
        f"MAP {APP_HOST} {LOOPBACK}:{proof.app_port}",
        f"MAP {SECOND_APP_HOST} {LOOPBACK}:{proof.app_port}",
        f"MAP {UNTRUSTED_HOST} {LOOPBACK}:{untrusted_port}",
    ))
    assert proof.browser_tmp is not None
    os.environ["TMPDIR"] = str(proof.browser_tmp)
    with sync_playwright() as playwright:
        proof.browser = playwright.chromium.launch(args=[
            f"--host-resolver-rules={rules}",
            f"--ignore-certificate-errors-spki-list={tls.leaf_spki_sha256_base64}",
        ])
        try:
            if not proof.held_or_failed(
                "CHECK issuer-document", lambda: issuer_document_is_canonical(proof)
            ):
                return
            if not proof.held_or_failed(
                "CHECK untrusted-certificate", lambda: untrusted_certificate_is_refused(proof)
            ):
                return
            origin = APP_ORIGIN
            proof.held_or_failed(f"SCENARIO 1 {WIDTH_LABEL} {origin}", lambda: login(proof))
            proof.held_or_failed(f"SCENARIO 2 {WIDTH_LABEL} {origin}", lambda: logout(proof))
        finally:
            proof.browser.close()


def stop_on_first_signal(proof: Proof) -> None:
    """The first SIGTERM or SIGINT ends the run through ``Interrupted``; the
    cleanup that follows is not interruptible, so later signals are ignored."""

    def handler(signum: int, frame: object) -> None:
        for stop_signal in STOP_SIGNALS:
            signal.signal(stop_signal, signal.SIG_IGN)
        proof.stop_requested.set()
        if not proof.winding_down:
            raise Interrupted

    for stop_signal in STOP_SIGNALS:
        signal.signal(stop_signal, handler)


def leftovers(scratch: Path) -> list[str]:
    left = []
    runtime = scratch / "runtime"
    if runtime.exists():
        left.append("runtime/ survived the run")
        try:
            shutil.rmtree(runtime)
        except OSError as error:
            left.append(f"runtime/ could not be removed: {error}")
    try:
        if containers := containers_left():
            left.append(f"containers left behind: {containers}")
    except (subprocess.SubprocessError, OSError) as error:
        left.append(f"could not look for left-over containers: {error}")
    return left


def prove(edge: Path, scratch: Path) -> int:
    if scratch.exists() and any(scratch.iterdir()):
        print(f"FAILED: --scratch {scratch} is not empty")
        return 2
    evidence_dir = scratch / "evidence"
    evidence_dir.mkdir(parents=True)
    registry = SecretRegistry()
    proof = Proof(evidence_dir, registry, NetworkLog(registry))
    stop_on_first_signal(proof)
    try:
        require_pinned_clean_edge(edge)
        with runtime_directory(scratch) as runtime:
            run_proof(proof, edge, runtime)
    except Interrupted:
        pass
    except Exception as error:
        proof.fail(f"{type(error).__name__}: {error}")
    finally:
        proof.winding_down = True
        for stop_signal in STOP_SIGNALS:
            signal.signal(stop_signal, signal.SIG_IGN)
        if proof.stop_requested.is_set():
            proof.fail("interrupted")
        for left in leftovers(scratch):
            proof.fail(left)
    return max(0 if proof.all_held else 1, keep_clean_evidence(proof))


def keep_clean_evidence(proof: Proof) -> int:
    (proof.evidence_dir / "result-table.txt").write_text("\n".join(proof.lines) + "\n")
    proof.log.write(proof.evidence_dir / "network.har")
    findings = scan_evidence(proof.evidence_dir, proof.registry)
    if findings:
        delete_contaminated(proof.evidence_dir, findings)
        for finding in findings:
            print(f"FAILED: evidence {finding.file} held {finding.label}; file deleted")
        return 1
    print(f"evidence scan clean: {proof.evidence_dir}", flush=True)
    return 0


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--edge", type=Path, required=True)
    parser.add_argument("--scratch", type=Path, required=True)
    arguments = parser.parse_args()
    return prove(arguments.edge.resolve(), arguments.scratch.resolve())


if __name__ == "__main__":
    sys.exit(main())
