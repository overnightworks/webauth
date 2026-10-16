"""Brings the pinned OpenID conformance suite up behind a TLS shim and plans a Basic RP run.

    flock -o /tmp/probe-stack.lock timeout --kill-after=240 900 \\
        uv run --extra dev --group e2e python e2e/oidc/conformance.py --scratch EMPTY_DIR

Read ``README.md`` beside this file first. The run lists the plan's modules as
the suite names them, brings the first to WAITING, checks the issuer the suite
exposes, cancels it and exports the plan into ``SCRATCH/export/``."""

from __future__ import annotations

import argparse
import secrets
import signal
import sys
from pathlib import Path

import httpx
from certificates import ThrowawayTls, issue_throwaway_tls
from evidence import NetworkLog, SecretRegistry
from harness import (
    STOP_SIGNALS,
    Interrupted,
    RunRecord,
    keep_clean_evidence,
    leftovers,
    raise_if_stop_pending,
    runtime_directory,
    stop_on_first_signal,
)
from shim import TlsShim
from suite import HeldSuite, SuiteApi

SUITE_HOST = "conformance.example.test"
APP_HOST = "rp.example.test"
PLAN_NAME = "oidcc-client-basic-certification-test-plan"
PLAN_VARIANT = {"client_registration": "static_client", "request_type": "plain_http_request"}
EXPECTED_MODULE_COUNT = 14
ALIAS = "webauth-d2"
CLIENT_ID = "webauth-d2"
CALLBACK_URL = f"https://{APP_HOST}/auth/callback"
MODULE_REACHES_WAITING_SECONDS = 60
JWKS_TIMEOUT_SECONDS = 30


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


def drive_suite(run: RunRecord, runtime: Path, suite: HeldSuite, export_dir: Path) -> None:
    tls = issue_throwaway_tls(runtime, "d2", [SUITE_HOST, APP_HOST, "localhost"])
    client_secret = secrets.token_urlsafe(24)
    run.registry.add("client secret", client_secret)
    with suite, TlsShim(tls, suite.port, SUITE_HOST) as shim:
        api = suite.api
        plan = api.create_plan(PLAN_NAME, PLAN_VARIANT, plan_configuration(client_secret))
        modules = [entry["testModule"] for entry in plan["modules"]]
        for number, module in enumerate(modules, start=1):
            run.record(f"module {number}: {module}")
        if len(modules) != EXPECTED_MODULE_COUNT:
            run.fail(f"the suite lists {len(modules)} modules, expected {EXPECTED_MODULE_COUNT}")
        module_id = api.create_module(plan["id"], modules[0])
        try:
            bring_to_waiting(api, module_id)
            check_exposed_issuer(run, api.module_status(module_id))
            check_key_set_through_shim(run, tls, shim)
        finally:
            api.cancel_module(module_id)
        raise_if_stop_pending(run)
        export = export_dir / f"{PLAN_NAME}-{plan['id']}.zip"
        export.write_bytes(api.export_plan(plan["id"]))
        run.record(f"export held: {export}")


def bring_to_waiting(api: SuiteApi, module_id: str) -> None:
    configured = api.wait_for_state(
        module_id, ["CONFIGURED", "WAITING"], MODULE_REACHES_WAITING_SECONDS
    )
    if configured == "CONFIGURED":
        api.start_module(module_id)
        api.wait_for_state(module_id, ["WAITING"], MODULE_REACHES_WAITING_SECONDS)


def check_exposed_issuer(run: RunRecord, status: dict[str, object]) -> None:
    expected = f"https://{SUITE_HOST}/test/a/{ALIAS}/"
    exposed = status.get("exposed")
    issuer = exposed.get("issuer") if isinstance(exposed, dict) else None
    if issuer == expected:
        run.record(f"module 1 WAITING, issuer held: {issuer}")
    else:
        run.fail(f"module 1 exposes issuer {issuer!r}, expected {expected!r}")


def check_key_set_through_shim(run: RunRecord, tls: ThrowawayTls, shim: TlsShim) -> None:
    answer = httpx.get(
        f"https://localhost:{shim.port}/test/a/{ALIAS}/jwks",
        verify=str(tls.ca_certificate), timeout=JWKS_TIMEOUT_SECONDS,
    )
    answer.raise_for_status()
    run.record(f"key set through the shim held: {len(answer.json()['keys'])} keys")


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
        run.fail(f"{type(error).__name__}: {error}")
    finally:
        run.winding_down = True
        for stop_signal in STOP_SIGNALS:
            signal.signal(stop_signal, signal.SIG_IGN)
        if run.stop_requested.is_set():
            run.fail("interrupted")
        for left in leftovers(scratch, suite.project):
            run.fail(left)
    return max(0 if run.all_held else 1, keep_clean_evidence(run))


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--scratch", type=Path, required=True)
    return conform(parser.parse_args().scratch.resolve())


if __name__ == "__main__":
    sys.exit(main())
