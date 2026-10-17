"""Runs webauth as the relying party of the pinned OpenID conformance suite.

    flock -o /tmp/probe-stack.lock timeout --kill-after=240 900 \\
        uv run --extra dev --group e2e python e2e/oidc/conformance.py --scratch EMPTY_DIR

Read ``README.md`` beside this file first. The run lists the plan's modules as
the suite names them, drives the two it has an expectation for through the host
app in a real browser, writes one row per module (the suite's verdict beside
webauth's own decision) and exports the plan into ``SCRATCH/export/``."""

from __future__ import annotations

import argparse
import secrets
import signal
import sys
from dataclasses import dataclass
from enum import StrEnum
from pathlib import Path
from typing import Any

import httpx
from certificates import ThrowawayTls, issue_throwaway_tls
from evidence import NetworkLog, SecretRegistry
from harness import (
    STOP_SIGNALS,
    Host,
    Interrupted,
    RunRecord,
    drive_browser_off_the_main_thread,
    free_port,
    host_state,
    keep_clean_evidence,
    launch_pinned_chromium,
    raise_if_stop_pending,
    recording_context,
    reset_host,
    runtime_directory,
    runtime_leftovers,
    start_host,
    stop_host,
    stop_on_first_signal,
)
from host_app import HostSettings
from playwright.sync_api import Browser, sync_playwright
from shim import TlsShim
from suite import HeldSuite, SuiteApi

from webauth.jwt_verification import MAX_KEY_SET_KEYS, RejectionReason
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
ISSUER = f"https://{SUITE_HOST}/test/a/{ALIAS}/"
MODULE_REACHES_WAITING_SECONDS = 60
MODULE_FINISHES_SECONDS = 30
JWKS_TIMEOUT_SECONDS = 30


class Verdict(StrEnum):
    HELD = "held"
    FAILED = "FAILED"
    FAILED_AS_FOUND = "FAILED-as-found"


@dataclass(frozen=True)
class Decision:
    """What webauth's own relying party did with one module's login."""

    admitted: bool
    userinfo_called: bool = False
    userinfo_answered: bool = False
    refusal: str | None = None
    token_rejection: str | None = None

    @staticmethod
    def of(state: dict[str, Any]) -> Decision:
        return Decision(
            admitted=state["logins_admitted"] > 0,
            userinfo_called=state["userinfo_calls"] > 0,
            userinfo_answered=state["userinfo_answered"] > 0,
            refusal=state["last_refusal"],
            token_rejection=state["token_rejection"],
        )

    def describe(self) -> str:
        if self.admitted:
            if self.userinfo_answered:
                return "admitted, UserInfo answered"
            return "admitted, UserInfo failed" if self.userinfo_called else "admitted"
        reason = self.refusal or "no decision"
        return f"{reason}/{self.token_rejection}" if self.token_rejection else reason


@dataclass(frozen=True)
class Expectation:
    module: str
    decision: Decision
    suite_status: str = "FINISHED"
    suite_result: str = "PASSED"

    def judge(
        self, suite_status: str, suite_result: str, decision: Decision, key_count: int
    ) -> Verdict:
        suite_agrees = (suite_status, suite_result) == (self.suite_status, self.suite_result)
        if decision == self.decision and suite_agrees:
            return Verdict.HELD
        key_set_is_over_the_bound = key_count > MAX_KEY_SET_KEYS
        if decision == KNOWN_FINDING and key_set_is_over_the_bound and suite_result != "FAILED":
            return Verdict.FAILED_AS_FOUND
        return Verdict.FAILED


KNOWN_FINDING = Decision(
    admitted=False,
    refusal=OidcRefusalReason.ID_TOKEN_REJECTED,
    token_rejection=RejectionReason.KEY_SET_UNAVAILABLE,
)


EXPECTATIONS = (
    Expectation(
        "oidcc-client-test",
        Decision(admitted=True, userinfo_called=True, userinfo_answered=True),
    ),
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
    reached_through_shim = f"https://localhost:{shim.port}/test/a/{ALIAS}"
    return HostSettings(
        app_origins=(APP_ORIGIN,),
        port=free_port(),
        observe_port=free_port(),
        tls_certificate=str(tls.leaf_certificate),
        tls_key=str(tls.leaf_key),
        issuer=ISSUER,
        authorization_endpoint=f"{ISSUER}authorize",
        token_endpoint=f"{reached_through_shim}/token",
        jwks_url=f"{reached_through_shim}/jwks",
        userinfo_endpoint=f"{reached_through_shim}/userinfo",
        client_id=CLIENT_ID,
        client_secret=client_secret,
        session_secret=session_secret,
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
            drive_plan(
                run, runtime, suite.api, tls, shim, host, settings, export_dir, client_secret
            )
        finally:
            run.winding_down = True
            if host is not None:
                stop_host(host.process)


def drive_plan(
    run: RunRecord, runtime: Path, api: SuiteApi, tls: ThrowawayTls, shim: TlsShim, host: Host,
    settings: HostSettings, export_dir: Path, client_secret: str,
) -> None:
    plan = api.create_plan(PLAN_NAME, PLAN_VARIANT, plan_configuration(client_secret))
    modules = [entry["testModule"] for entry in plan["modules"]]
    for number, module in enumerate(modules, start=1):
        run.record(f"module {number}: {module}")
    if len(modules) != EXPECTED_MODULE_COUNT:
        run.fail(f"the suite lists {len(modules)} modules, expected {EXPECTED_MODULE_COUNT}")
    run.record(f"{'module':<34} | suite status/result | webauth decision | expected | verdict")
    drive_browser_off_the_main_thread(
        run, lambda: drive_modules(run, runtime, api, tls, shim, host, settings, plan["id"])
    )
    raise_if_stop_pending(run)
    export = export_dir / f"{PLAN_NAME}-{plan['id']}.zip"
    export.write_bytes(api.export_plan(plan["id"]))
    run.record(f"export held: {export}")


def drive_modules(
    run: RunRecord, runtime: Path, api: SuiteApi, tls: ThrowawayTls, shim: TlsShim, host: Host,
    settings: HostSettings, plan_id: str,
) -> None:
    with sync_playwright() as playwright:
        browser = launch_pinned_chromium(
            playwright, runtime,
            {SUITE_HOST: shim.port, APP_HOST: host.app_port},
            tls.leaf_spki_sha256_base64,
        )
        try:
            for expectation in EXPECTATIONS:
                if run.stop_requested.is_set():
                    return
                run_module(run, api, tls, host, settings, browser, plan_id, expectation)
        finally:
            browser.close()


def run_module(
    run: RunRecord, api: SuiteApi, tls: ThrowawayTls, host: Host, settings: HostSettings,
    browser: Browser, plan_id: str, expectation: Expectation,
) -> None:
    module_id = api.create_module(plan_id, expectation.module)
    try:
        state = api.state_within(
            module_id, ["CONFIGURED", "WAITING"], MODULE_REACHES_WAITING_SECONDS,
            run.stop_requested.is_set,
        )
        if state == "CONFIGURED":
            api.start_module(module_id)
            state = api.state_within(
                module_id, ["WAITING"], MODULE_REACHES_WAITING_SECONDS, run.stop_requested.is_set
            )
        if state != "WAITING":
            run.fail(f"{expectation.module} reached {state}, expected WAITING")
            return
        check_exposed_issuer(run, expectation.module, api.module_status(module_id))
        key_count = count_keys_at_jwks_url(run, expectation.module, tls, settings)
        reset_host(host)
        sign_in_at_the_relying_party(run, browser)
        api.state_within(
            module_id, ["FINISHED"], MODULE_FINISHES_SECONDS, run.stop_requested.is_set
        )
        if run.stop_requested.is_set():
            return
        report_row(
            run, expectation, api.module_info(module_id), Decision.of(host_state(host)), key_count
        )
    finally:
        cancel_unless_finished(api, module_id)


def sign_in_at_the_relying_party(run: RunRecord, browser: Browser) -> None:
    with recording_context(run, browser) as context:
        context.new_page().goto(f"{APP_ORIGIN}/login/oidc")


def cancel_unless_finished(api: SuiteApi, module_id: str) -> None:
    """The suite answers 500 to the cancel of a module that finished."""
    if api.module_info(module_id)["status"] != "FINISHED":
        api.cancel_module(module_id)


def report_row(
    run: RunRecord, expectation: Expectation, info: dict[str, Any], decision: Decision,
    key_count: int,
) -> None:
    status, result = info["status"], info.get("result", "-")
    verdict = expectation.judge(status, result, decision, key_count)
    row = (
        f"{expectation.module:<34} | {status}/{result} | {decision.describe()} | "
        f"{expectation.decision.describe()} | {verdict}"
    )
    if verdict is Verdict.FAILED:
        run.fail(row)
    else:
        run.record(row)


def check_exposed_issuer(run: RunRecord, module: str, status: dict[str, object]) -> None:
    exposed = status.get("exposed")
    issuer = exposed.get("issuer") if isinstance(exposed, dict) else None
    if issuer == ISSUER:
        run.record(f"{module} WAITING, issuer held: {issuer}")
    else:
        run.fail(f"{module} exposes issuer {issuer!r}, expected {ISSUER!r}")


def count_keys_at_jwks_url(
    run: RunRecord, module: str, tls: ThrowawayTls, settings: HostSettings
) -> int:
    answer = httpx.get(
        settings.jwks_url, verify=str(tls.ca_certificate), timeout=JWKS_TIMEOUT_SECONDS
    )
    answer.raise_for_status()
    count = len(answer.json()["keys"])
    run.record(f"{module} key set at the host's jwks_url held: {count} keys")
    return count


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
