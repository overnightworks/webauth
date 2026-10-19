"""Session administration through the same ports the hosts implement."""

from __future__ import annotations

import ast
from contextlib import nullcontext
from dataclasses import FrozenInstanceError, asdict, replace
from datetime import UTC, datetime
from pathlib import Path

import pytest
from webauth_arrangement import (
    FakeSessionRecord,
    FakeUser,
    LockNotHeldError,
    a_session_administration,
    a_web_auth_config,
    seeded_session,
)

import webauth
from webauth.cookies import session_reference
from webauth.dependencies import AuthenticatedUser
from webauth.ports import (
    AccountEventKind,
    AuditSink,
    SessionAdministrationStore,
    WriteLock,
)
from webauth.session_administration import (
    NotAnAdminError,
    SessionAdministration,
    SessionSummary,
    UnknownSessionError,
)


@pytest.fixture
def administration() -> SessionAdministration:
    config = a_web_auth_config(admin_role="operator", user_role="member")
    return a_session_administration(
        FakeUser(
            id="actor", username="administrator", role=config.admin_role,
        ),
        FakeUser(
            id="subject", username="member", role=config.user_role,
        ),
        config=config,
    )


@pytest.fixture
def actor(administration: SessionAdministration) -> AuthenticatedUser:
    return AuthenticatedUser(
        id="actor", username="administrator", role=administration.config.admin_role,
        is_active=True,
    )


@pytest.fixture
def empty_administration(administration: SessionAdministration) -> SessionAdministration:
    return a_session_administration(config=administration.config)


@pytest.fixture
def stored_sessions(administration: SessionAdministration) -> list[FakeSessionRecord]:
    return [
        seeded_session(
            administration.sessions, administration.lock.hold(),
            user_id, datetime(2030, 1, 1, tzinfo=UTC),
        )
        for user_id in ("subject", "actor", "subject")
    ]


@pytest.mark.parametrize(("offset", "limit"), [(0, None), (1, 1), (1, None), (0, 0), (9, 2)])
def test_REQ_ADMIN_12_listing_returns_only_public_fields_in_the_stores_page_order(
    administration: SessionAdministration, stored_sessions: list[FakeSessionRecord],
    offset: int, limit: int | None, caplog: pytest.LogCaptureFixture,
) -> None:

    summaries = administration.list_sessions(offset, limit)

    page = stored_sessions[offset:None if limit is None else offset + limit]
    assert [asdict(summary) for summary in summaries] == [{
        "session_ref": session_reference(record.id),
        "user_id": record.user_id,
        "username": record.user.username,
        "ip_address": record.ip_address,
        "user_agent": record.user_agent,
    } for record in page]
    assert len(administration.sessions.list_active()) == len(stored_sessions)
    assert administration.audit.account_events == []
    evidence = repr(summaries) + caplog.text
    for secret in (record.id for record in stored_sessions):
        assert secret not in evidence


def test_REQ_ADMIN_12_an_empty_store_has_no_session_summaries(
    empty_administration: SessionAdministration,
) -> None:
    assert empty_administration.list_sessions() == []
    assert empty_administration.sessions.list_active() == []


@pytest.mark.parametrize("session_index", [0, 1, 2])
def test_REQ_ADMIN_12_an_admin_revokes_one_listed_session_without_its_raw_token(
    administration: SessionAdministration, actor: AuthenticatedUser,
    stored_sessions: list[FakeSessionRecord], session_index: int,
    caplog: pytest.LogCaptureFixture,
) -> None:
    summary = administration.list_sessions(offset=session_index, limit=1)[0]

    assert administration.revoke_session(actor, summary.session_ref) is None

    for index, record in enumerate(stored_sessions):
        remains = index != session_index
        assert (administration.sessions.load(record.id) is not None) == remains
    assert len(administration.sessions.list_active()) == 2
    assert [asdict(event) for event in administration.audit.account_events] == [{
        "kind": AccountEventKind.SESSION_REVOKED,
        "actor_id": actor.id,
        "subject_id": summary.user_id,
        "role": None,
        "session_ref": summary.session_ref,
        "previous_role": None,
    }]
    evidence = repr(administration.audit.account_events) + caplog.text
    for secret in (summary.username, *(record.id for record in stored_sessions)):
        assert secret not in evidence


class HostText(str):
    """The host's own string object, equal to a reference but not the same value."""


def test_REQ_ADMIN_12_the_revocation_event_carries_the_computed_reference_not_the_hosts_input(
    administration: SessionAdministration, actor: AuthenticatedUser,
    stored_sessions: list[FakeSessionRecord],
) -> None:
    hosts_input = HostText(session_reference(stored_sessions[0].id))

    administration.revoke_session(actor, hosts_input)

    [event] = administration.audit.account_events
    assert event.session_ref == session_reference(stored_sessions[0].id)
    assert event.session_ref is not hosts_input
    assert type(event.session_ref) is str


def scopes_making_a_session_reference(source: str) -> list[str]:
    """Name the function around each call or cast that makes a SessionReference."""
    tree = ast.parse(source)
    names = {"SessionReference"} | {
        alias.asname
        for node in ast.walk(tree)
        if isinstance(node, ast.ImportFrom)
        for alias in node.names
        if alias.name == "SessionReference" and alias.asname
    }

    def names_it(node: ast.expr) -> bool:
        return any(
            (isinstance(part, ast.Name) and part.id in names)
            or (isinstance(part, ast.Attribute) and part.attr == "SessionReference")
            or (isinstance(part, ast.Constant) and part.value in names)
            for part in ast.walk(node)
        )

    def makes_it(call: ast.Call) -> bool:
        callee = call.func
        callee_name = callee.id if isinstance(callee, ast.Name) else getattr(callee, "attr", "")
        named_by_the_call = call.args[1:] if callee_name == "NewType" else call.args
        return names_it(callee) or (
            callee_name in {"cast", "NewType"} and any(names_it(arg) for arg in named_by_the_call)
        )

    def walk(node: ast.AST, scope: str) -> list[str]:
        if isinstance(node, ast.FunctionDef | ast.AsyncFunctionDef):
            scope = node.name
        found = [scope] if isinstance(node, ast.Call) and makes_it(node) else []
        return found + [
            made for child in ast.iter_child_nodes(node) for made in walk(child, scope)
        ]

    return walk(tree, "<module>")


@pytest.mark.parametrize(
    ("source", "scopes"),
    [
        ("def f(x):\n    return SessionReference(x)\n", ["f"]),
        ("def f(x):\n    return cast(SessionReference, x)\n", ["f"]),
        ("def f(x):\n    return cast('SessionReference', x)\n", ["f"]),
        ("from webauth.ports import SessionReference as Ref\nRef('x')\n", ["<module>"]),
        ("from webauth import ports\ndef f(x):\n    return ports.SessionReference(x)\n", ["f"]),
        ("Made = NewType('Made', SessionReference)\n", ["<module>"]),
        ("def f(x):\n    return str(x)\n", []),
        ("from webauth.ports import SessionReference\ndef f(x: SessionReference): ...\n", []),
    ],
)
def test_the_session_reference_guard_sees_every_way_to_make_one(
    source: str, scopes: list[str]
) -> None:
    assert scopes_making_a_session_reference(source) == scopes


def test_only_session_reference_constructs_a_session_reference_in_the_library() -> None:
    library = Path(webauth.__file__).parent
    making = {
        path.relative_to(library).as_posix(): scopes
        for path in library.rglob("*.py")
        if (scopes := scopes_making_a_session_reference(path.read_text()))
    }

    assert making == {"cookies.py": ["session_reference"]}


def test_REQ_ADMIN_12_revoking_a_consumed_reference_is_refused_without_another_event(
    administration: SessionAdministration, actor: AuthenticatedUser,
    stored_sessions: list[FakeSessionRecord],
) -> None:
    summary = administration.list_sessions(limit=1)[0]
    administration.revoke_session(actor, summary.session_ref)

    with pytest.raises(UnknownSessionError):
        administration.revoke_session(actor, summary.session_ref)

    assert administration.sessions.list_active() == stored_sessions[1:]
    assert len(administration.audit.account_events) == 1


@pytest.mark.parametrize("reference", ["unknown", "", "é", "session-1", "0" * 64])
def test_REQ_ADMIN_12_unknown_or_raw_session_references_preserve_every_session(
    administration: SessionAdministration, actor: AuthenticatedUser,
    stored_sessions: list[FakeSessionRecord], reference: str, caplog: pytest.LogCaptureFixture,
) -> None:

    with pytest.raises(UnknownSessionError) as error:
        administration.revoke_session(actor, reference)

    assert administration.sessions.list_active() == stored_sessions
    for record in stored_sessions:
        assert record.id not in str(error.value) + caplog.text
    assert administration.audit.account_events == []


@pytest.mark.parametrize(("session_id", "reference"), [
    ("", "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"),
    ("abc", "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"),
    ("é", "4a99557e4033c3539de2eb65472017cad5f9557f7a0625a09f1c3f6e2ba69c4c"),
])
def test_REQ_ADMIN_12_session_references_are_the_sha256_hex_of_utf8_identifiers(
    session_id: str, reference: str,
) -> None:
    assert session_reference(session_id) == reference


def test_REQ_ADMIN_12_session_summaries_are_immutable(
    administration: SessionAdministration, stored_sessions: list[FakeSessionRecord],
) -> None:
    summary = administration.list_sessions()[0]

    assert isinstance(summary, SessionSummary)
    with pytest.raises(FrozenInstanceError):
        summary.session_ref = "replacement"


@pytest.mark.parametrize("role", ["member", "admin", "unknown"])
def test_REQ_ADMIN_05_only_the_configured_admin_can_revoke_a_session(
    administration: SessionAdministration, actor: AuthenticatedUser,
    stored_sessions: list[FakeSessionRecord], role: str,
) -> None:
    reference = administration.list_sessions()[0].session_ref
    non_admin = replace(actor, role=role)

    with pytest.raises(NotAnAdminError):
        administration.revoke_session(non_admin, reference)

    assert administration.sessions.list_active() == stored_sessions
    assert administration.audit.account_events == []


def test_an_actor_without_the_configured_admin_role_cannot_revoke_a_session(
    administration: SessionAdministration, actor: AuthenticatedUser,
    stored_sessions: list[FakeSessionRecord],
) -> None:
    other_config = replace(administration.config, admin_role="root")
    strict = replace(administration, config=other_config)

    with pytest.raises(NotAnAdminError):
        strict.revoke_session(actor, "unknown")

    assert strict.sessions.list_active() == stored_sessions
    assert strict.audit.account_events == []


def test_revoking_without_the_write_lock_is_refused_by_the_store(
    administration: SessionAdministration, actor: AuthenticatedUser,
    stored_sessions: list[FakeSessionRecord], monkeypatch: pytest.MonkeyPatch,
) -> None:
    reference = administration.list_sessions()[0].session_ref
    monkeypatch.setattr(administration.lock, "hold", nullcontext)

    with pytest.raises(LockNotHeldError):
        administration.revoke_session(actor, reference)

    assert administration.sessions.list_active() == stored_sessions
    assert administration.audit.account_events == []


def test_the_arrangement_supplies_the_administration_protocols(
    administration: SessionAdministration,
) -> None:
    assert isinstance(administration.sessions, SessionAdministrationStore)
    assert isinstance(administration.audit, AuditSink)
    assert isinstance(administration.lock, WriteLock)
