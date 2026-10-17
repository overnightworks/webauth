"""Runs webauth as the relying party of the pinned OpenID conformance suite.

    flock -o /tmp/probe-stack.lock timeout --kill-after=240 900 \\
        uv run --extra dev --group e2e python e2e/oidc/conformance.py --scratch EMPTY_DIR

Read ``README.md`` beside this file first. The run lists the plan's modules as
the suite names them, drives the two it has an expectation for through the host
app in a real browser, writes one row per module (the suite's verdict beside
webauth's own decision) and exports the plan into ``SCRATCH/export/``."""

from __future__ import annotations

import argparse
import contextlib
import os
import secrets
import signal
import sys
import urllib.parse
from dataclasses import dataclass
from enum import StrEnum
from pathlib import Path
from typing import Any

import httpx
from certificates import ThrowawayTls, issue_throwaway_tls
from evidence import NetworkLog, SecretRegistry, recorded_cookie_name
from harness import (
    STOP_SIGNALS,
    Host,
    Interrupted,
    RunRecord,
    drive_browser_off_the_main_thread,
    free_port,
    host_state,
    keep_clean_evidence,
    raise_if_stop_pending,
    reset_host,
    runtime_directory,
    runtime_leftovers,
    start_host,
    stop_host,
    stop_on_first_signal,
)
from host_app import HostSettings
from playwright.sync_api import Browser, BrowserContext, sync_playwright
from shim import LOOPBACK, TlsShim
from stack import StackError
from suite import HeldSuite, SuiteApi

from webauth.oidc import OidcRefusalReason

SUITE_HOST = "conformance.example.test"
APP_HOST = "rp.example.test"
PLAN_NAME = "oidcc-client-basic-certification-test-plan"
PLAN_VARIANT = {"client_registration": "static_client", "request_type": "plain_http_request"}
EXPECTED_MODULE_COUNT = 14
ALIAS = "webauth-d2"
CLIENT_ID = "webauth-d2"
APP_ORIGIN = f"https://{APP_HOST}"
CALLBACK_URL = f"{APP_ORIGIN}/auth/callback"
URL_PARAMETERS_THAT_ARE_CREDENTIALS = ("code", "nonce", "session_state", "state")
MODULE_REACHES_WAITING_SECONDS = 60
MODULE_FINISHES_SECONDS = 30
JWKS_TIMEOUT_SECONDS = 30
PAGE_TIMEOUT_MILLISECONDS = 30_000


class Verdict(StrEnum):
    HELD = "held"
    FAILED = "FAILED"
    FAILED_AS_FOUND = "FAILED-as-found"


@dataclass(frozen=True)
class Decision:
    """What webauth's own relying party did with one module's login."""

    admitted: bool
    userinfo_called: bool = False
    refusal: str | None = None
    token_rejection: str | None = None

    @staticmethod
    def of(state: dict[str, Any]) -> Decision:
        return Decision(
            admitted=state["sessions"] > 0,
            userinfo_called=state["userinfo_calls"] > 0,
            refusal=state["last_refusal"],
            token_rejection=state["token_rejection"],
        )

    def describe(self) -> str:
        if self.admitted:
            return "admitted" + (", UserInfo called" if self.userinfo_called else "")
        reason = self.refusal or "no decision"
        return f"{reason}/{self.token_rejection}" if self.token_rejection else reason


@dataclass(frozen=True)
class Expectation:
    module: str
    decision: Decision
    suite_status: str = "FINISHED"
    suite_result: str = "PASSED"

    def judge(self, suite_status: str, suite_result: str, decision: Decision) -> Verdict:
        suite_agrees = (suite_status, suite_result) == (self.suite_status, self.suite_result)
        if decision == self.decision and suite_agrees:
            return Verdict.HELD
        library_refused_the_token = not decision.admitted and decision.token_rejection is not None
        if library_refused_the_token and decision != self.decision:
            return Verdict.FAILED_AS_FOUND
        return Verdict.FAILED


EXPECTATIONS = (
    Expectation("oidcc-client-test", Decision(admitted=True, userinfo_called=True)),
    Expectation(
        "oidcc-client-test-nonce-invalid",
        Decision(admitted=False, refusal=OidcRefusalReason.NONCE_MISMATCH),
    ),
)


def plan_configuration(client_secret: str) -> dict[str, object]:
    return {
        "alias": ALIAS,
        "description": "webauth relying party, throwaway run",
        "client": {
            "client_id": CLIENT_ID,
            "client_secret": client_secret,
            "redirect_uri": CALLBACK_URL,
        },
    }


def host_settings(
    tls: ThrowawayTls, shim: TlsShim, client_secret: str, session_secret: str
) -> HostSettings:
    exposed_at_suite = f"https://{SUITE_HOST}/test/a/{ALIAS}/"
    reached_through_shim = f"https://localhost:{shim.port}/test/a/{ALIAS}"
    return HostSettings(
        app_origins=(APP_ORIGIN,),
        port=free_port(),
        observe_port=free_port(),
        tls_certificate=str(tls.leaf_certificate),
        tls_key=str(tls.leaf_key),
        issuer=exposed_at_suite,
        authorization_endpoint=f"{exposed_at_suite}authorize",
        token_endpoint=f"{reached_through_shim}/token",
        jwks_url=f"{reached_through_shim}/jwks",
        userinfo_endpoint=f"{reached_through_shim}/userinfo",
        client_id=CLIENT_ID,
        client_secret=client_secret,
        session_secret=session_secret,
        cookie_samesite="lax",
    )


def drive_suite(run: RunRecord, runtime: Path, suite: HeldSuite, export_dir: Path) -> None:
    tls = issue_throwaway_tls(runtime, "d2", [SUITE_HOST, APP_HOST, "localhost"])
    client_secret = secrets.token_urlsafe(24)
    session_secret = secrets.token_urlsafe(48)
    run.registry.add("client secret", client_secret)
    run.registry.add("session secret", session_secret)
    with suite, TlsShim(tls, suite.port, SUITE_HOST) as shim:
        host: Host | None = None
        try:
            settings = host_settings(tls, shim, client_secret, session_secret)
            host = start_host(run, runtime, settings, tls.ca_certificate)
            drive_plan(run, runtime, suite.api, tls, shim, host, export_dir, client_secret)
        finally:
            run.winding_down = True
            if host is not None:
                stop_host(host.process)


def drive_plan(
    run: RunRecord, runtime: Path, api: SuiteApi, tls: ThrowawayTls, shim: TlsShim, host: Host,
    export_dir: Path, client_secret: str,
) -> None:
    plan = api.create_plan(PLAN_NAME, PLAN_VARIANT, plan_configuration(client_secret))
    modules = [entry["testModule"] for entry in plan["modules"]]
    for number, module in enumerate(modules, start=1):
        run.record(f"module {number}: {module}")
    if len(modules) != EXPECTED_MODULE_COUNT:
        run.fail(f"the suite lists {len(modules)} modules, expected {EXPECTED_MODULE_COUNT}")
    run.record(f"{'module':<34} | suite status/result | webauth decision | expected | verdict")
    drive_browser_off_the_main_thread(
        run, lambda: drive_modules(run, runtime, api, tls, shim, host, plan["id"])
    )
    raise_if_stop_pending(run)
    export = export_dir / f"{PLAN_NAME}-{plan['id']}.zip"
    export.write_bytes(api.export_plan(plan["id"]))
    run.record(f"export held: {export}")


def drive_modules(
    run: RunRecord, runtime: Path, api: SuiteApi, tls: ThrowawayTls, shim: TlsShim, host: Host,
    plan_id: str,
) -> None:
    browser_tmp = runtime / "tmp"
    browser_tmp.mkdir()
    os.environ["TMPDIR"] = str(browser_tmp)
    rules = ", ".join((
        f"MAP {SUITE_HOST} {LOOPBACK}:{shim.port}",
        f"MAP {APP_HOST} {LOOPBACK}:{host.app_port}",
    ))
    with sync_playwright() as playwright:
        browser = playwright.chromium.launch(args=[
            f"--host-resolver-rules={rules}",
            f"--ignore-certificate-errors-spki-list={tls.leaf_spki_sha256_base64}",
        ])
        try:
            for expectation in EXPECTATIONS:
                run_module(run, api, tls, shim, host, browser, plan_id, expectation)
        finally:
            browser.close()


def run_module(
    run: RunRecord, api: SuiteApi, tls: ThrowawayTls, shim: TlsShim, host: Host, browser: Browser,
    plan_id: str, expectation: Expectation,
) -> None:
    module_id = api.create_module(plan_id, expectation.module)
    try:
        state = api.wait_for_state(
            module_id, ["CONFIGURED", "WAITING"], MODULE_REACHES_WAITING_SECONDS
        )
        if state == "CONFIGURED":
            api.start_module(module_id)
            state = api.wait_for_state(module_id, ["WAITING"], MODULE_REACHES_WAITING_SECONDS)
        if state != "WAITING":
            run.fail(f"{expectation.module} reached {state}, expected WAITING")
            return
        check_exposed_issuer(run, expectation.module, api.module_status(module_id))
        check_key_set_through_shim(run, expectation.module, tls, shim)
        reset_host(host)
        sign_in_at_the_relying_party(run, browser)
        wait_for_the_suite_to_finish(api, module_id)
        report_row(run, expectation, api.module_info(module_id), Decision.of(host_state(host)))
    finally:
        cancel_unless_finished(api, module_id)


def sign_in_at_the_relying_party(run: RunRecord, browser: Browser) -> None:
    context = browser.new_context()
    context.set_default_timeout(PAGE_TIMEOUT_MILLISECONDS)
    context.on("request", lambda request: remember_url_credentials(run, request.url))
    context.on("request", run.log.watch)
    page = context.new_page()
    with contextlib.ExitStack() as cleanup:
        cleanup.callback(context.close)
        cleanup.callback(run.log.collect)
        cleanup.callback(remember_cookies, run, context)
        page.goto(f"{APP_ORIGIN}/login/oidc")


def remember_url_credentials(run: RunRecord, url: str) -> None:
    query = urllib.parse.parse_qs(urllib.parse.urlsplit(url).query)
    for name in URL_PARAMETERS_THAT_ARE_CREDENTIALS:
        for value in query.get(name, []):
            run.registry.add(f"url parameter {name}", value)


def remember_cookies(run: RunRecord, context: BrowserContext) -> None:
    for cookie in context.cookies():
        run.registry.add(f"cookie {recorded_cookie_name(cookie['name'])}", cookie["value"])


def wait_for_the_suite_to_finish(api: SuiteApi, module_id: str) -> None:
    """A module that never finishes is reported by its status, so the deadline is no error."""
    with contextlib.suppress(StackError):
        api.wait_for_state(module_id, ["FINISHED"], MODULE_FINISHES_SECONDS)


def cancel_unless_finished(api: SuiteApi, module_id: str) -> None:
    """The suite answers 500 to the cancel of a module that finished."""
    if api.module_info(module_id)["status"] != "FINISHED":
        api.cancel_module(module_id)


def report_row(
    run: RunRecord, expectation: Expectation, info: dict[str, Any], decision: Decision
) -> None:
    status, result = info["status"], info.get("result", "-")
    verdict = expectation.judge(status, result, decision)
    row = (
        f"{expectation.module:<34} | {status}/{result} | {decision.describe()} | "
        f"{expectation.decision.describe()} | {verdict}"
    )
    if verdict is Verdict.FAILED:
        run.fail(row)
    else:
        run.record(row)


def check_exposed_issuer(run: RunRecord, module: str, status: dict[str, object]) -> None:
    expected = f"https://{SUITE_HOST}/test/a/{ALIAS}/"
    exposed = status.get("exposed")
    issuer = exposed.get("issuer") if isinstance(exposed, dict) else None
    if issuer == expected:
        run.record(f"{module} WAITING, issuer held: {issuer}")
    else:
        run.fail(f"{module} exposes issuer {issuer!r}, expected {expected!r}")


def check_key_set_through_shim(
    run: RunRecord, module: str, tls: ThrowawayTls, shim: TlsShim
) -> None:
    answer = httpx.get(
        f"https://localhost:{shim.port}/test/a/{ALIAS}/jwks",
        verify=str(tls.ca_certificate), timeout=JWKS_TIMEOUT_SECONDS,
    )
    answer.raise_for_status()
    run.record(f"{module} key set through the shim held: {len(answer.json()['keys'])} keys")


def error_chain(error: BaseException) -> list[BaseException]:
    chain = []
    link: BaseException | None = error
    while link is not None and link not in chain:
        chain.append(link)
        link = link.__cause__ or link.__context__
    return chain


def suite_leftovers(suite: HeldSuite) -> list[str]:
    return suite.leftovers if suite.down_completed else suite.remove_everything()


def conform(scratch: Path) -> int:
    if scratch.exists() and any(scratch.iterdir()):
        print(f"FAILED: --scratch {scratch} is not empty")
        return 2
    evidence_dir = scratch / "evidence"
    export_dir = scratch / "export"
    evidence_dir.mkdir(parents=True)
    export_dir.mkdir()
    registry = SecretRegistry()
    run = RunRecord(evidence_dir, registry, NetworkLog(registry))
    suite = HeldSuite(SUITE_HOST, lambda: raise_if_stop_pending(run))
    stop_on_first_signal(run)
    try:
        with runtime_directory(scratch) as runtime:
            drive_suite(run, runtime, suite, export_dir)
    except Interrupted:
        pass
    except Exception as error:
        for link in error_chain(error):
            run.fail(f"{type(link).__name__}: {link}")
    finally:
        run.winding_down = True
        for stop_signal in STOP_SIGNALS:
            signal.signal(stop_signal, signal.SIG_IGN)
        if run.stop_requested.is_set():
            run.fail("interrupted")
        for left in [*runtime_leftovers(scratch), *suite_leftovers(suite)]:
            run.fail(left)
    return max(0 if run.all_held else 1, keep_clean_evidence(run))


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--scratch", type=Path, required=True)
    return conform(parser.parse_args().scratch.resolve())


if __name__ == "__main__":
    sys.exit(main())
