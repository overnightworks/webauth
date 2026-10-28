"""Runs webauth as the relying party of the pinned OpenID conformance suite.

    scripts/run_oidc_proof.sh conformance

``README.md`` beside this file is the runbook. The run creates
``oidcc-client-basic-certification-test-plan`` (OpenID Foundation conformance
suite release v5.3.3, server and mongo images pinned by digest in
``suite-compose.yaml``) with a throwaway client secret, lists the plan's 14
modules as the suite names them (a count other than 14 fails the run), and
drives every module the expectation table does not skip, with the host app
(``host_app.py``) as the relying party under test and a real Chromium following
the redirects. A module without a table row, or a row without a module, fails
the run. It writes one row per module and exports the plan into the run
directory's ``export/`` (``README.md`` says how to handle it). It needs Docker
and no edge checkout. The host's ``login_group`` and ``admin_group`` do not apply:
the suite's tokens carry no ``groups`` claim, so this driver states the value of
``EverySubject.OF_THE_BOUND_ISSUER`` and of ``NoAdmins.IN_THIS_APP``.

The suite's own nginx is not used: its certificate has no subject alternative
name, which webauth's HTTPS client rightly refuses. The driver puts the
``TlsShim`` with a throwaway certificate in front of the server's port, which
is published on ``127.0.0.1`` only (the dev-mode API has no login).

The suite's verdict alone proves nothing: a refusing module passes when no
further request arrives, whatever the reason. So every row sets the suite's
status/result beside webauth's own decision, read from the host's ``/state``
(``token_rejection``, ``logins_admitted``, ``userinfo_calls``,
``userinfo_answered``, ``access_tokens_refused``, the last refusal), and beside
the decision expected, which the table takes from the library's enums::

    module | suite status/result | webauth decision | expected | verdict | why

- ``held`` needs the decision and the suite state to agree with the table: an
  accepting module is admitted with UserInfo answered, and every module ends in
  the suite state its row names (FINISHED/PASSED, or FINISHED/SKIPPED for
  sig-none).
- ``skipped`` is a justified row that is not driven; its justification is in
  the table.
- ``FAILED-as-found`` (a finding, not a failed run) is only for a named known
  finding on its own module, and needs all three: the decision equals the
  finding's signature, the key set at the host's ``jwks_url`` holds the
  finding's number of keys that webauth's own RS256 check admits, and the suite
  is in the state the finding predicts (WAITING with no result for an accepting
  module, since the UserInfo request never comes).
- Every other row that is not ``held`` fails the run, so a wrong ``jwks_url``, a
  missing CA trust or a clock skew cannot pass as the finding.

The access token never leaves the host process except in the one UserInfo
request through the shim: it reaches no ``/state``, log or table, a token no
header can carry is not sent (and counted as refused), and a failing UserInfo
call is logged by exception type only. The host runs with the shipped default
``cookie_samesite="strict"``; the pending-login cookie is lax in any case and
the app and suite hosts are same-site.

The suite finishes an accepting module only on a UserInfo request, which
webauth never sends. The host therefore keeps the access token of the token
answer in memory and makes one UserInfo request after, and only after,
the callback route admitted the login. ``/reset`` builds the relying parties
again, as a host restarted per module would, because the suite generates new
keys per module.

Each expectation is built from the module's class in the suite's sources
(``net/openid/conformance/openid/client`` at release-v5.3.3), named in its
justification. No screenshots are kept. On every exit path the suite project is
taken down with its volumes and the run lists the containers, volumes and
networks still carrying its compose project label; every failure or timeout,
with its stderr tail, is reported as a leftover line, and the result table
still follows."""

from __future__ import annotations

import argparse
import secrets
import signal
import sys
from dataclasses import dataclass
from enum import StrEnum
from pathlib import Path
from typing import Any, NamedTuple

import httpx
from certificates import ThrowawayTls, issue_throwaway_tls
from harness import (
    STOP_SIGNALS,
    Host,
    Interrupted,
    RunRecord,
    browser_context,
    drive_browser_off_the_main_thread,
    free_port,
    host_state,
    keep_results,
    launch_pinned_chromium,
    raise_if_stop_pending,
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

from webauth.jwt_verification import RejectionReason, _is_rs256_verification_key
from webauth.oidc import OidcRefusalReason
from webauth.oidc_login import EverySubject, NoAdmins

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
MODULE_COLUMN_WIDTH = 42


class Verdict(StrEnum):
    HELD = "held"
    SKIPPED = "skipped"
    FAILED = "FAILED"
    FAILED_AS_FOUND = "FAILED-as-found"


class SuiteState(NamedTuple):
    """The suite's ``status`` and ``result`` of a module; ``result`` is None until it has one."""

    status: str
    result: str | None

    def describe(self) -> str:
        return f"{self.status}/{self.result or '-'}"


FINISHED_PASSED = SuiteState("FINISHED", "PASSED")
FINISHED_SKIPPED = SuiteState("FINISHED", "SKIPPED")


@dataclass(frozen=True)
class Decision:
    """What webauth's own relying party did with one module's login."""

    admitted: bool
    userinfo_called: bool = False
    userinfo_answered: bool = False
    refusal: str | None = None
    token_rejection: str | None = None
    access_token_refused: bool = False

    @staticmethod
    def of(state: dict[str, Any]) -> Decision:
        return Decision(
            admitted=state["logins_admitted"] > 0,
            userinfo_called=state["userinfo_calls"] > 0,
            userinfo_answered=state["userinfo_answered"] > 0,
            refusal=state["last_refusal"],
            token_rejection=state["token_rejection"],
            access_token_refused=state["access_tokens_refused"] > 0,
        )

    def describe(self) -> str:
        if self.admitted:
            if self.userinfo_answered:
                return "admitted, UserInfo answered"
            if self.userinfo_called:
                return "admitted, UserInfo failed"
            if self.access_token_refused:
                return "admitted, access token refused"
            return "admitted"
        reason = self.refusal or "no decision"
        return f"{reason}/{self.token_rejection}" if self.token_rejection else reason


ACCEPTED = Decision(admitted=True, userinfo_called=True, userinfo_answered=True)


def refused(reason: OidcRefusalReason, rejection: RejectionReason | None = None) -> Decision:
    return Decision(admitted=False, refusal=reason, token_rejection=rejection)


def token_rejected(rejection: RejectionReason) -> Decision:
    return refused(OidcRefusalReason.ID_TOKEN_REJECTED, rejection)


@dataclass(frozen=True)
class KnownFinding:
    """A defect of the library, predicted from the suite's sources: the decision it
    produces, how many RS256-eligible keys the module's key set must hold, and the suite
    state it leaves."""

    name: str
    decision: Decision
    rs256_eligible_keys: int
    suite_state: SuiteState


@dataclass(frozen=True)
class Expectation:
    module: str
    decision: Decision
    justification: str
    suite_state: SuiteState = FINISHED_PASSED
    finding: KnownFinding | None = None

    def judge(
        self, suite_state: SuiteState, decision: Decision, rs256_eligible_keys: int
    ) -> Verdict:
        if (decision, suite_state) == (self.decision, self.suite_state):
            return Verdict.HELD
        finding = self.finding
        if finding and (decision, rs256_eligible_keys, suite_state) == (
            finding.decision, finding.rs256_eligible_keys, finding.suite_state
        ):
            return Verdict.FAILED_AS_FOUND
        return Verdict.FAILED


@dataclass(frozen=True)
class Skip:
    module: str
    reason: str


PLAN_TABLE: tuple[Expectation | Skip, ...] = (
    Expectation(
        "oidcc-client-test", ACCEPTED,
        "OIDCCClientTest, the success case: a well-formed code flow must be admitted and "
        "the module finishes on the UserInfo request that follows.",
    ),
    Expectation(
        "oidcc-client-test-invalid-iss", token_rejected(RejectionReason.INVALID_ISSUER),
        "OIDCCClientTestInvalidIssuerInIdToken: the client must reject a wrong iss; "
        "the verifier's issuer check refuses it.",
    ),
    Expectation(
        "oidcc-client-test-missing-sub",
        refused(OidcRefusalReason.INVALID_IDENTITY_CLAIM),
        "OIDCCClientTestMissingSubInIdToken: the client must reject an ID token without sub; "
        "the verifier admits it, and the login refuses an identity without a subject.",
    ),
    Expectation(
        "oidcc-client-test-invalid-aud", token_rejected(RejectionReason.INVALID_AUDIENCE),
        "OIDCCClientTestInvalidAudInIdToken: the client must reject an aud that is not its "
        "client id; the verifier's audience check refuses it.",
    ),
    Expectation(
        "oidcc-client-test-missing-iat", token_rejected(RejectionReason.INVALID_CLAIM),
        "OIDCCClientTestMissingIatInIdToken: the client must reject an ID token without iat; "
        "the verifier requires an integer iat.",
    ),
    Expectation(
        "oidcc-client-test-kid-absent-single-jwks", ACCEPTED,
        "OIDCCClientTestKidAbsentSingleJwks publishes one RSA signing key and signs without "
        "a kid, and expects acceptance (OIDC Core 10.1); webauth verifies a kid-less token "
        "against a set with exactly one RS256 verification key (#160).",
    ),
    Expectation(
        "oidcc-client-test-kid-absent-multiple-jwks",
        token_rejected(RejectionReason.INVALID_KEY_ID),
        "OIDCCClientTestKidAbsentMultipleMatchingKeysInJwks accepts either answer; webauth "
        "refuses a kid-less header against several RS256 verification keys (OIDC Core 10.1, #160).",
    ),
    Expectation(
        "oidcc-client-test-idtoken-sig-rs256", ACCEPTED,
        "OIDCCClientTestIdTokenSignedUsingRS256: the client must accept an RS256 ID token, "
        "the one algorithm the verifier supports.",
    ),
    Expectation(
        "oidcc-client-test-idtoken-sig-none", token_rejected(RejectionReason.UNSUPPORTED_ALGORITHM),
        "OIDCCClientTestIdTokenSigAlgNone: clients need not support unsigned ID tokens; "
        "webauth refuses alg none, and the suite ends the module skipped after its timeout.",
        suite_state=FINISHED_SKIPPED,
    ),
    Expectation(
        "oidcc-client-test-invalid-sig-rs256",
        token_rejected(RejectionReason.INVALID_SIGNATURE),
        "OIDCCClientTestInvalidIdTokenSignatureWithRS256: the client should reject a corrupted "
        "signature even from the token endpoint; the verifier's signature check refuses it.",
    ),
    Skip(
        "oidcc-client-test-userinfo-invalid-sub",
        "OIDCCClientTestInvalidSubInUserinfoResponse: webauth takes identity only from the "
        "verified ID token and never reads a UserInfo answer, so there is no sub to compare.",
    ),
    Expectation(
        "oidcc-client-test-nonce-invalid", refused(OidcRefusalReason.NONCE_MISMATCH),
        "OIDCCClientTestNonceInvalid: the client must reject a nonce it did not send; "
        "the login refuses it.",
    ),
    Expectation(
        "oidcc-client-test-scope-userinfo-claims", ACCEPTED,
        "OIDCCClientTestScopeUserInfoClaims: the authorize request must carry one of profile, "
        "email, phone or address, which the host's scopes do; the login is admitted.",
    ),
    Expectation(
        "oidcc-client-test-client-secret-basic", ACCEPTED,
        "OIDCCClientTestClientSecretBasic: the token request must use client_secret_basic, "
        "which the library sends; the login is admitted.",
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
        login_group=EverySubject.OF_THE_BOUND_ISSUER.value,
        admin_group=NoAdmins.IN_THIS_APP.value,
        authorization_endpoint=f"{ISSUER}authorize",
        end_session_endpoint=f"{ISSUER}logout",
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
    run.record(f"the plan lists {len(modules)} modules")
    for number, module in enumerate(modules, start=1):
        run.record(f"module {number}: {module}")
    if len(modules) != EXPECTED_MODULE_COUNT:
        run.fail(f"the suite lists {len(modules)} modules, expected {EXPECTED_MODULE_COUNT}")
    rows = rows_for_plan(run, modules)
    run.record(
        table_row("module", "suite status/result", "webauth decision", "expected", "verdict", "why")
    )
    drive_browser_off_the_main_thread(
        run, lambda: drive_modules(run, runtime, api, tls, shim, host, settings, plan["id"], rows)
    )
    raise_if_stop_pending(run)
    export = export_dir / f"{PLAN_NAME}-{plan['id']}.zip"
    export.write_bytes(api.export_plan(plan["id"]))
    run.record(f"export held: {export}")


def rows_for_plan(run: RunRecord, modules: list[str]) -> list[Expectation | Skip]:
    """The table's row for each module of the plan, in plan order; a module without a row,
    or a row without a module, fails the run."""
    table = {row.module: row for row in PLAN_TABLE}
    for module in modules:
        if module not in table:
            run.fail(f"the plan lists {module}, which the expectation table has no row for")
    for module in table.keys() - set(modules):
        run.fail(f"the expectation table has a row for {module}, which the plan does not list")
    return [table[module] for module in modules if module in table]


def drive_modules(
    run: RunRecord, runtime: Path, api: SuiteApi, tls: ThrowawayTls, shim: TlsShim, host: Host,
    settings: HostSettings, plan_id: str, rows: list[Expectation | Skip],
) -> None:
    with sync_playwright() as playwright:
        browser = launch_pinned_chromium(
            playwright, runtime,
            {SUITE_HOST: shim.port, APP_HOST: host.app_port},
            tls.leaf_spki_sha256_base64,
        )
        try:
            for row in rows:
                if run.stop_requested.is_set():
                    return
                if isinstance(row, Skip):
                    run.record(skip_row(row))
                else:
                    run_module(run, api, tls, host, settings, browser, plan_id, row)
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
        if run.stop_requested.is_set():
            return
        if state == "CONFIGURED":
            api.start_module(module_id)
            state = api.state_within(
                module_id, ["WAITING"], MODULE_REACHES_WAITING_SECONDS, run.stop_requested.is_set
            )
            if run.stop_requested.is_set():
                return
        if state != "WAITING":
            run.fail(f"{expectation.module} reached {state}, expected WAITING")
            return
        check_exposed_issuer(run, expectation.module, api.module_status(module_id))
        rs256_eligible_keys = count_rs256_eligible_keys_at_jwks_url(
            run, expectation.module, tls, settings
        )
        reset_host(host)
        sign_in_at_the_relying_party(browser)
        api.state_within(
            module_id, ["FINISHED"], MODULE_FINISHES_SECONDS, run.stop_requested.is_set
        )
        if run.stop_requested.is_set():
            return
        report_row(
            run, expectation, api.module_info(module_id), Decision.of(host_state(host)),
            rs256_eligible_keys,
        )
    finally:
        cancel_unless_finished(api, module_id)


def sign_in_at_the_relying_party(browser: Browser) -> None:
    with browser_context(browser) as context:
        context.new_page().goto(f"{APP_ORIGIN}/login/oidc")


def cancel_unless_finished(api: SuiteApi, module_id: str) -> None:
    """The suite answers 500 to the cancel of a module that finished."""
    if api.module_info(module_id)["status"] != "FINISHED":
        api.cancel_module(module_id)


def report_row(
    run: RunRecord, expectation: Expectation, info: dict[str, Any], decision: Decision,
    rs256_eligible_keys: int,
) -> None:
    suite_state = SuiteState(info["status"], info.get("result"))
    verdict = expectation.judge(suite_state, decision, rs256_eligible_keys)
    row = table_row(
        expectation.module, suite_state.describe(), decision.describe(),
        expectation.decision.describe(), verdict, expectation.justification,
    )
    if verdict is Verdict.FAILED:
        run.fail(row)
    else:
        run.record(row)
    if verdict is Verdict.FAILED_AS_FOUND and expectation.finding:
        run.record(f"known finding: {expectation.finding.name}")


def skip_row(skip: Skip) -> str:
    return table_row(skip.module, "-", "not driven", "skip", Verdict.SKIPPED, skip.reason)


def table_row(module: str, *cells: str) -> str:
    return " | ".join([f"{module:<{MODULE_COLUMN_WIDTH}}", *cells])


def check_exposed_issuer(run: RunRecord, module: str, status: dict[str, object]) -> None:
    exposed = status.get("exposed")
    issuer = exposed.get("issuer") if isinstance(exposed, dict) else None
    if issuer == ISSUER:
        run.record(f"{module} WAITING, issuer held: {issuer}")
    else:
        run.fail(f"{module} exposes issuer {issuer!r}, expected {ISSUER!r}")


def count_rs256_eligible_keys_at_jwks_url(
    run: RunRecord, module: str, tls: ThrowawayTls, settings: HostSettings
) -> int:
    """Logs the key set the host's ``jwks_url`` serves and returns how many keys the library's
    own RS256 check admits: the suite pads a single-key module's set with other key types."""
    answer = httpx.get(
        settings.jwks_url, verify=str(tls.ca_certificate), timeout=JWKS_TIMEOUT_SECONDS
    )
    answer.raise_for_status()
    keys = answer.json()["keys"]
    rs256_eligible_keys = sum(1 for key in keys if _is_rs256_verification_key(key))
    run.record(
        f"{module} key set at the host's jwks_url held: {len(keys)} keys, "
        f"{rs256_eligible_keys} RS256-eligible"
    )
    return rs256_eligible_keys


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
    run = RunRecord(evidence_dir)
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
    return max(0 if run.all_held else 1, keep_results(run))


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0] if __doc__ else None)
    parser.add_argument("--scratch", type=Path, required=True)
    return conform(parser.parse_args().scratch.resolve())


if __name__ == "__main__":
    sys.exit(main())
