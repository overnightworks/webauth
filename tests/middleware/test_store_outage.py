"""STACK-16 and LOG-08: a store that cannot be reached answers 503 and logs one outage, at every
entry; a store that fails otherwise stays a loud 500."""

from __future__ import annotations

import logging
from threading import Barrier, Event, Thread
from typing import TYPE_CHECKING

import pytest
from fastapi import Depends, FastAPI
from starlette.responses import StreamingResponse

from tests.support.account_arrangement import FakeUser
from tests.support.gate_arrangement import bearing
from tests.support.log_records import fields_of
from tests.support.oidc_arrangement import a_logout_token
from tests.support.oidc_login_host import (
    BACKCHANNEL_LOGOUT_PATH,
    BOUND_ISSUER,
    CALLBACK_PATH,
    CLIENT_ID,
    LOGOUT_PATH,
    NOW,
    SAME_ORIGIN_FORM,
    START_PATH,
    SUBJECT,
    is_cleared,
    set_cookies,
)
from tests.support.request_line_arrangement import FORWARDED_CLIENT
from tests.support.web_auth_host_arrangement import (
    ME_PATH,
    ComposedHost,
    HostWorld,
    a_client_of,
    a_composed_host,
    a_composition,
    a_host_world,
    a_member_token,
    a_resource_and_person_paths,
    a_stored_session,
    the_routes_of,
)
from tests.support.webauth_arrangement import API_PATH
from webauth.dependencies import current_user
from webauth.middleware import SessionGate
from webauth.policies import PathRules
from webauth.ports import AuthenticatedUser, StoreUnavailableError

if TYPE_CHECKING:
    from collections.abc import Callable, Iterator

    from httpx import Response as HttpxResponse

FORWARDED = {"x-forwarded-for": FORWARDED_CLIENT}
A_MEMBER = FakeUser(id=SUBJECT, username="lena")
SECRET = "hunter2-session-token"
PERSON_ME_PATH = "/api/me"
STREAM_PATH = "/stream-then-fail"
OWN_STORE_PATH = "/own-store"
FAILED_EVENT = "session_store_connection.failed"
RECOVERED_EVENT = "session_store_connection.recovered"


def a_store_outage() -> StoreUnavailableError:
    return StoreUnavailableError(f"cannot reach the store holding {SECRET}")


def a_store_bug() -> Exception:
    return RuntimeError(f"the statement failed for {SECRET}")


def a_signed_in_world() -> HostWorld:
    return a_host_world(A_MEMBER, stored_session=a_stored_session(A_MEMBER))


def _routes_with_a_person_path_and_host_stores(
    world: HostWorld,
) -> Callable[[FastAPI, object], None]:
    def add(app: FastAPI, auth: object) -> None:
        the_routes_of(world)(app, auth)  # type: ignore[arg-type]

        @app.get(PERSON_ME_PATH)
        def person_me(user: AuthenticatedUser = Depends(current_user)) -> dict[str, str]:
            return {"username": user.username}

        @app.get(OWN_STORE_PATH)
        def own_store() -> None:
            raise a_store_outage()

        @app.get(STREAM_PATH)
        def stream_then_fail() -> StreamingResponse:
            def chunks() -> Iterator[bytes]:
                yield b"first"
                raise a_store_outage()

            return StreamingResponse(chunks())

    return add


def a_host(world: HostWorld, *, gate: SessionGate | None = None) -> ComposedHost:
    return a_composed_host(
        world,
        a_composition(world, gate=gate),
        routes=_routes_with_a_person_path_and_host_stores(world),
        bearer_of=a_resource_and_person_paths(),
    )


def the_host_driven(host: ComposedHost, *, raising: bool) -> ComposedHost:
    """The same host under a browser that raises what the app lets escape, so an answer built from
    a traceback shows as a failure of the test."""
    return ComposedHost(
        host.world, host.auth, host.app, a_client_of(host.app, raise_server_exceptions=raising)
    )


def the_gate() -> SessionGate:
    return SessionGate(login_redirect=None, public=())


def the_optional_gate() -> SessionGate:
    return SessionGate(
        login_redirect=None, public=(), optional=PathRules(exact=frozenset({API_PATH}))
    )


def a_gated_path(failure: Exception, *, raising: bool) -> tuple[HostWorld, HttpxResponse]:
    world = a_signed_in_world()
    host = the_host_driven(a_host(world, gate=the_gate()), raising=raising)
    world.sessions.load_failure = failure
    return world, host.client.get(API_PATH, headers={**FORWARDED, **world.signed_cookie()})


def an_optional_session_path(
    failure: Exception, *, raising: bool
) -> tuple[HostWorld, HttpxResponse]:
    world = a_signed_in_world()
    host = the_host_driven(a_host(world, gate=the_optional_gate()), raising=raising)
    world.sessions.load_failure = failure
    return world, host.client.get(API_PATH, headers={**FORWARDED, **world.signed_cookie()})


def current_user_in_a_host_route(
    failure: Exception, *, raising: bool
) -> tuple[HostWorld, HttpxResponse]:
    world = a_signed_in_world()
    host = the_host_driven(a_host(world), raising=raising)
    world.sessions.load_failure = failure
    return world, host.client.get(ME_PATH, headers={**FORWARDED, **world.signed_cookie()})


def a_bearer_person_path(failure: Exception, *, raising: bool) -> tuple[HostWorld, HttpxResponse]:
    world = a_signed_in_world()
    host = the_host_driven(a_host(world, gate=the_gate()), raising=raising)
    world.sign_in.entry_failure = failure
    token = bearing(a_member_token())[0]
    return world, host.client.get(PERSON_ME_PATH, headers={**FORWARDED, "authorization": token})


def a_sign_in_callback(failure: Exception, *, raising: bool) -> tuple[HostWorld, HttpxResponse]:
    world = a_host_world(A_MEMBER)
    host = the_host_driven(a_host(world), raising=raising)
    started = host.client.get(START_PATH, headers=FORWARDED)
    query = world.issuer.authorize(started.headers["location"])
    world.sign_in.entry_failure = failure
    return world, host.client.get(f"{CALLBACK_PATH}?{query}", headers=FORWARDED)


def a_logout(failure: Exception, *, raising: bool) -> tuple[HostWorld, HttpxResponse]:
    world = a_signed_in_world()
    host = the_host_driven(a_host(world), raising=raising)
    world.sign_in.entry_failure = failure
    headers = {**SAME_ORIGIN_FORM, **FORWARDED, **world.signed_cookie()}
    return world, host.client.post(LOGOUT_PATH, headers=headers)


def a_back_channel_logout(failure: Exception, *, raising: bool) -> tuple[HostWorld, HttpxResponse]:
    world = a_signed_in_world()
    host = the_host_driven(a_host(world), raising=raising)
    world.sign_in.entry_failure = failure
    token = a_logout_token(
        issuer=BOUND_ISSUER,
        audience=CLIENT_ID,
        subject=SUBJECT,
        now=NOW,
        key_id="issuer-key",
        key_name="issuer",
    )
    return world, host.client.post(
        BACKCHANNEL_LOGOUT_PATH, data={"logout_token": token}, headers=FORWARDED
    )


ENTRIES = [
    pytest.param(a_gated_path, 503, 500, id="session-gated-path"),
    pytest.param(an_optional_session_path, 503, 500, id="optional-session-path"),
    pytest.param(current_user_in_a_host_route, 503, 500, id="current-user-in-a-host-route"),
    pytest.param(a_bearer_person_path, 503, 500, id="bearer-person-path"),
    pytest.param(a_sign_in_callback, 503, 500, id="sign-in-callback"),
    pytest.param(a_logout, 503, 500, id="logout"),
    pytest.param(a_back_channel_logout, 400, 400, id="back-channel-logout"),
]


@pytest.mark.parametrize(("entry", "outage_status", "_bug_status"), ENTRIES)
def test_stack_16_a_store_outage_answers_503_with_retry_after_and_no_trace_of_the_failure(
    entry: Callable[..., tuple[HostWorld, HttpxResponse]],
    outage_status: int,
    _bug_status: int,
) -> None:
    world, response = entry(a_store_outage(), raising=True)

    assert response.status_code == outage_status
    assert SECRET not in response.text
    assert world.routes_ran == []
    if outage_status == 503:
        assert response.headers["retry-after"] == "5"
        assert response.json() == {"detail": "Session store unavailable"}


@pytest.mark.parametrize(("entry", "_outage_status", "bug_status"), ENTRIES)
def test_stack_16_a_store_bug_stays_a_loud_failure(
    entry: Callable[..., tuple[HostWorld, HttpxResponse]],
    _outage_status: int,
    bug_status: int,
) -> None:
    world, response = entry(a_store_bug(), raising=False)

    assert response.status_code == bug_status
    assert "retry-after" not in response.headers
    assert SECRET not in response.text
    assert world.routes_ran == []


def test_stack_16_the_callback_clears_the_pending_login_cookie_it_consumed() -> None:
    world = a_host_world(A_MEMBER)
    host = a_host(world)
    started = host.client.get(START_PATH, headers=FORWARDED)
    [pending_cookie] = host.client.cookies
    query = world.issuer.authorize(started.headers["location"])
    world.sign_in.entry_failure = a_store_outage()

    response = host.client.get(f"{CALLBACK_PATH}?{query}", headers=FORWARDED)

    assert (response.status_code, is_cleared(response, pending_cookie)) == (503, True)


def test_stack_16_the_logout_clears_no_session_cookie_so_it_can_be_retried() -> None:
    world, response = a_logout(a_store_outage(), raising=True)

    assert (response.status_code, set_cookies(response)) == (503, {})
    assert world.sessions.record is not None


def test_stack_16_a_host_route_that_cannot_reach_its_own_store_answers_503() -> None:
    host = the_host_driven(a_host(a_signed_in_world()), raising=True)

    response = host.client.get(OWN_STORE_PATH, headers=FORWARDED)

    assert (response.status_code, response.json()) == (
        503,
        {"detail": "Session store unavailable"},
    )


def test_stack_16_an_outage_after_the_response_started_is_not_answered_twice() -> None:
    host = the_host_driven(a_host(a_signed_in_world()), raising=True)

    with pytest.raises(StoreUnavailableError):
        host.client.get(STREAM_PATH, headers=FORWARDED)


def _outage_records(caplog: pytest.LogCaptureFixture) -> list[logging.LogRecord]:
    return [
        record
        for record in caplog.records
        if record.getMessage() in {FAILED_EVENT, RECOVERED_EVENT}
    ]


def test_log_08_an_outage_logs_one_failed_and_one_recovered_line_with_the_refused_count(
    caplog: pytest.LogCaptureFixture,
) -> None:
    world = a_signed_in_world()
    host = the_host_driven(a_host(world), raising=True)
    headers = {**FORWARDED, **world.signed_cookie()}
    caplog.set_level(logging.INFO)
    world.sessions.load_failure = a_store_outage()
    refused = [host.client.get(ME_PATH, headers=headers) for _ in range(3)]
    host.client.get(API_PATH, headers=FORWARDED)
    lines_during_the_outage = _outage_records(caplog)

    world.sessions.load_failure = None
    recovered = host.client.get(ME_PATH, headers=headers)
    lines = _outage_records(caplog)

    assert [response.status_code for response in refused] == [503, 503, 503]
    assert [(record.levelname, record.getMessage()) for record in lines_during_the_outage] == [
        ("ERROR", FAILED_EVENT)
    ]
    assert recovered.status_code == 200
    failed_line, recovered_line = lines
    assert fields_of(failed_line) == {"error_type": "StoreUnavailableError"}
    assert failed_line.exc_info is None
    assert (recovered_line.levelname, recovered_line.getMessage(), fields_of(recovered_line)) == (
        "INFO",
        RECOVERED_EVENT,
        {"refused_count": 3},
    )
    assert SECRET not in caplog.text


def _lines_of(caplog: pytest.LogCaptureFixture) -> list[tuple[str, dict[str, object]]]:
    return [(record.getMessage(), fields_of(record)) for record in _outage_records(caplog)]


def test_log_08_an_answer_without_an_outage_logs_nothing(caplog: pytest.LogCaptureFixture) -> None:
    world = a_signed_in_world()
    host = the_host_driven(a_host(world), raising=True)
    caplog.set_level(logging.INFO)

    answered = host.client.get(ME_PATH, headers={**FORWARDED, **world.signed_cookie()})

    assert answered.status_code == 200
    assert _lines_of(caplog) == []


def test_log_08_a_second_outage_after_a_recovery_logs_failed_and_recovered_again(
    caplog: pytest.LogCaptureFixture,
) -> None:
    world = a_signed_in_world()
    host = the_host_driven(a_host(world), raising=True)
    headers = {**FORWARDED, **world.signed_cookie()}
    caplog.set_level(logging.INFO)

    for failing in (True, False, True, False):
        world.sessions.load_failure = a_store_outage() if failing else None
        host.client.get(ME_PATH, headers=headers)

    assert _lines_of(caplog) == [
        (FAILED_EVENT, {"error_type": "StoreUnavailableError"}),
        (RECOVERED_EVENT, {"refused_count": 1}),
        (FAILED_EVENT, {"error_type": "StoreUnavailableError"}),
        (RECOVERED_EVENT, {"refused_count": 1}),
    ]


def test_log_08_concurrent_requests_refused_by_the_store_open_one_outage_and_all_count(
    caplog: pytest.LogCaptureFixture,
) -> None:
    world = a_signed_in_world()
    host = the_host_driven(a_host(world), raising=True)
    headers = {**FORWARDED, **world.signed_cookie()}
    caplog.set_level(logging.INFO)
    workers = 8
    reach_the_store_together = Barrier(workers, timeout=10)

    world.sessions.before_load = reach_the_store_together.wait
    world.sessions.load_failure = a_store_outage()
    answers: list[int] = []

    def request() -> None:
        answers.append(host.client.get(ME_PATH, headers=headers).status_code)

    threads = [Thread(target=request) for _ in range(workers)]
    for thread in threads:
        thread.start()
    for thread in threads:
        thread.join()
    world.sessions.before_load = None
    world.sessions.load_failure = None
    host.client.get(ME_PATH, headers=headers)

    assert answers == [503] * workers
    assert _lines_of(caplog) == [
        (FAILED_EVENT, {"error_type": "StoreUnavailableError"}),
        (RECOVERED_EVENT, {"refused_count": workers}),
    ]


def test_log_08_the_failed_line_names_the_class_of_the_cause_when_there_is_one(
    caplog: pytest.LogCaptureFixture,
) -> None:
    world = a_signed_in_world()
    host = the_host_driven(a_host(world), raising=True)
    caplog.set_level(logging.INFO)
    failure = a_store_outage()
    failure.__cause__ = ConnectionRefusedError(SECRET)
    world.sessions.load_failure = failure

    host.client.get(ME_PATH, headers={**FORWARDED, **world.signed_cookie()})

    assert _lines_of(caplog) == [(FAILED_EVENT, {"error_type": "ConnectionRefusedError"})]
    assert SECRET not in caplog.text


def test_log_08_a_bug_opens_no_outage(caplog: pytest.LogCaptureFixture) -> None:
    world = a_signed_in_world()
    host = the_host_driven(a_host(world), raising=False)
    caplog.set_level(logging.INFO)
    world.sessions.load_failure = a_store_bug()

    host.client.get(ME_PATH, headers={**FORWARDED, **world.signed_cookie()})

    assert _lines_of(caplog) == []


@pytest.mark.parametrize(
    "entry",
    [a_bearer_person_path, a_sign_in_callback, a_logout, a_back_channel_logout],
    ids=["bearer-person-path", "sign-in-callback", "logout", "back-channel-logout"],
)
def test_log_08_an_outage_at_the_entry_of_a_transaction_opens_one(
    entry: Callable[..., tuple[HostWorld, HttpxResponse]], caplog: pytest.LogCaptureFixture
) -> None:
    caplog.set_level(logging.INFO)

    entry(a_store_outage(), raising=True)

    assert [name for name, _fields in _lines_of(caplog)] == [FAILED_EVENT]


def test_log_08_a_failing_bug_does_not_end_an_outage(caplog: pytest.LogCaptureFixture) -> None:
    world = a_signed_in_world()
    host = the_host_driven(a_host(world), raising=False)
    headers = {**FORWARDED, **world.signed_cookie()}
    caplog.set_level(logging.INFO)
    world.sessions.load_failure = a_store_outage()
    host.client.get(ME_PATH, headers=headers)
    world.sessions.load_failure = a_store_bug()

    bug = host.client.get(ME_PATH, headers=headers)
    lines_after_the_bug = _lines_of(caplog)
    world.sessions.load_failure = None
    host.client.get(ME_PATH, headers=headers)

    assert bug.status_code == 500
    assert [name for name, _fields in lines_after_the_bug] == [FAILED_EVENT]
    assert _lines_of(caplog)[1] == (RECOVERED_EVENT, {"refused_count": 1})


@pytest.mark.parametrize("where", ["body", "exit"])
def test_log_08_an_outage_in_the_body_or_at_the_exit_of_a_transaction_opens_one(
    where: str, caplog: pytest.LogCaptureFixture
) -> None:
    world = a_signed_in_world()
    host = the_host_driven(a_host(world), raising=True)
    caplog.set_level(logging.INFO)
    if where == "body":
        world.sessions.load_failure = a_store_outage()
    else:
        world.sessions.commit_failure = a_store_outage()

    response = host.client.get(ME_PATH, headers={**FORWARDED, **world.signed_cookie()})

    assert response.status_code == 503
    assert [name for name, _fields in _lines_of(caplog)] == [FAILED_EVENT]


def test_log_08_a_clean_sign_in_transaction_ends_an_outage_the_session_gate_opened(
    caplog: pytest.LogCaptureFixture,
) -> None:
    world = a_signed_in_world()
    host = the_host_driven(a_host(world), raising=True)
    caplog.set_level(logging.INFO)
    world.sessions.load_failure = a_store_outage()
    host.client.get(ME_PATH, headers={**FORWARDED, **world.signed_cookie()})
    world.sessions.load_failure = None

    started = host.client.get(START_PATH, headers=FORWARDED)
    query = world.issuer.authorize(started.headers["location"])
    callback = host.client.get(f"{CALLBACK_PATH}?{query}", headers=FORWARDED)

    assert callback.status_code == 303
    assert [name for name, _fields in _lines_of(caplog)] == [FAILED_EVENT, RECOVERED_EVENT]


class _SlowFailedLine(logging.Handler):
    """Holds the failed line until released and lists the lines in the order they finished.

    It takes no handler lock, which would order two lines on its own.
    """

    def __init__(self) -> None:
        super().__init__(logging.INFO)
        self.writing_failed = Event()
        self.failed_line_may_finish = Event()
        self.finished: list[str] = []

    def handle(self, record: logging.LogRecord) -> bool:
        self.emit(record)
        return True

    def emit(self, record: logging.LogRecord) -> None:
        name = record.getMessage()
        if name == FAILED_EVENT:
            self.writing_failed.set()
            self.failed_line_may_finish.wait(timeout=10)
        if name in {FAILED_EVENT, RECOVERED_EVENT}:
            self.finished.append(name)


def test_log_08_a_clean_answer_waits_for_the_failed_line_still_being_written() -> None:
    world = a_signed_in_world()
    host = the_host_driven(a_host(world), raising=True)
    headers = {**FORWARDED, **world.signed_cookie()}
    handler = _SlowFailedLine()
    root = logging.getLogger()
    previous_level = root.level
    root.addHandler(handler)
    root.setLevel(logging.INFO)
    try:
        world.sessions.load_failure = a_store_outage()
        refused = Thread(target=lambda: host.client.get(ME_PATH, headers=headers))
        refused.start()
        assert handler.writing_failed.wait(timeout=10)
        world.sessions.load_failure = None
        answered = Thread(target=lambda: host.client.get(ME_PATH, headers=headers))
        answered.start()
        answered.join(timeout=0.5)
        handler.failed_line_may_finish.set()
        refused.join(timeout=10)
        answered.join(timeout=10)
    finally:
        root.removeHandler(handler)
        root.setLevel(previous_level)

    assert handler.finished == [FAILED_EVENT, RECOVERED_EVENT]
