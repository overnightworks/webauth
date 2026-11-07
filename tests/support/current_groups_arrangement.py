"""The arrangement of the ``current_groups`` tests: a live session and an issuer whose refresh
grant answers a signed ID token, over both shapes of ``SessionTransaction``: a host transaction
(``in_transaction``) and a store that commits every statement (``nullcontext``)."""

from __future__ import annotations

import sys
from contextlib import nullcontext
from dataclasses import dataclass, field
from datetime import UTC, datetime, timedelta
from typing import TYPE_CHECKING, Any

import pytest
from pydantic import SecretStr

from tests.support.oidc_arrangement import (
    ABSENT,
    APP_CLIENT_ID,
    ISSUED_REFRESH_TOKEN,
    REALM_ISSUER,
    FakeClock,
    FakeIssuer,
    a_fake_id_token,
    a_realm_client_config,
    changed,
    jws,
    rs256,
    rsa_key,
    segment,
)
from tests.support.oidc_relying_party import a_relying_party_for
from tests.support.webauth_arrangement import (
    FIXED_INSTANT,
    SESSION_IDLE_SECONDS,
    FakeSessionRecord,
    FakeUser,
    SessionRecordsInMemory,
    a_web_auth_config,
)
from webauth.oidc import OidcRefusalReason, OidcRelyingParty
from webauth.oidc_login import (
    AccessTokenRefusal,
    AccessTokenRefusalReason,
    current_groups,
)

if TYPE_CHECKING:
    from collections.abc import Callable

    from webauth.config import WebAuthConfig
    from webauth.ports import SessionTransaction

SESSION_ID = "session-under-test"
NONCE = "nonce-of-the-login"
LEEWAY = a_realm_client_config().leeway_seconds
GROUPS = ["/apps/notes", "/apps/notes/billing"]

SHAPES = pytest.mark.parametrize(
    "provider_of",
    [
        pytest.param(lambda sessions: sessions.in_transaction, id="transaction"),
        pytest.param(lambda sessions: lambda: nullcontext(sessions), id="nullcontext"),
    ],
)
ROTATIONS = pytest.mark.parametrize(
    "rotation",
    [
        pytest.param({}, id="rotated"),
        pytest.param({"refresh_token": ISSUED_REFRESH_TOKEN}, id="echoed"),
        pytest.param({"refresh_token": ABSENT}, id="omitted"),
    ],
)
SESSION_ENDED = AccessTokenRefusal(AccessTokenRefusalReason.SESSION_ENDED)
SIGN_IN_AGAIN = AccessTokenRefusal(AccessTokenRefusalReason.SIGN_IN_AGAIN)


def a_stored_id_token(**claims: Any) -> SecretStr:
    """What the login stored: a token the call never reads."""
    payload = changed({"sub": "user-1", "nonce": NONCE, "exp": 1}, claims)
    return SecretStr(f"{segment({'typ': 'JWT'})}.{segment(payload)}.signature")


STORED_ID_TOKEN = a_stored_id_token()


class _RecordThatForbidsReadingItsIdToken(FakeSessionRecord):
    """A record whose ID token the library must not read; the test store's own copies may."""

    @property
    def id_token(self) -> SecretStr | None:  # pyright: ignore[reportIncompatibleVariableOverride]
        if sys._getframe(1).f_globals["__name__"].startswith("webauth."):
            raise AssertionError("current_groups read the stored ID token")
        return None

    @id_token.setter
    def id_token(self, value: SecretStr | None) -> None:  # pyright: ignore[reportIncompatibleVariableOverride]
        """Accepts the construction's value and keeps nothing."""


def unreadable_id_token_of(record: FakeSessionRecord) -> SessionRecordsInMemory:
    return SessionRecordsInMemory(
        _RecordThatForbidsReadingItsIdToken(
            id=record.id,
            user=record.user,
            created_at=record.created_at,
            expires_at=record.expires_at,
            refresh_token=record.refresh_token,
        )
    )


@dataclass
class Arrangement:
    """A live session at ``FIXED_INSTANT`` holding ``rt-1`` and a stored ID token, and the
    issuer whose refresh grant answers a signed ID token."""

    issuer: FakeIssuer
    sessions: SessionRecordsInMemory
    clock: FakeClock
    config: WebAuthConfig
    relying_party: OidcRelyingParty
    answered_tokens: list[str] = field(default_factory=list)

    def answer_with_access_token(self) -> None:
        token = "access-token-of-the-scenario"
        self.issuer.refresh_answer_members["access_token"] = token
        self.answered_tokens.append(token)

    def answer_with_id_token(self, **claim_changes: Any) -> str:
        now = int(self.clock.now)
        claims = changed(
            {
                "iss": REALM_ISSUER,
                "aud": APP_CLIENT_ID,
                "sub": "user-1",
                "exp": now + 300,
                "iat": now,
                "groups": GROUPS,
            },
            claim_changes,
        )
        token = jws(
            {"alg": "RS256", "kid": "current-key", "typ": "JWT"},
            claims,
            rs256(rsa_key("current")),
        )
        self.issuer.refresh_answer_members["id_token"] = token
        self.answered_tokens.append(token)
        return token

    def current_groups(
        self,
        provider: SessionTransaction,
    ) -> tuple[str, ...] | AccessTokenRefusal:
        return current_groups(
            self.relying_party,
            SESSION_ID,
            session_transaction=provider,
            config=self.config,
        )

    @property
    def stored_refresh_token(self) -> str | None:
        record = self.sessions.load(SESSION_ID)
        if record is None or record.refresh_token is None:
            return None
        return record.refresh_token.get_secret_value()

    @property
    def requests_made(self) -> int:
        return len(self.issuer.requests)


def an_arrangement(
    sessions_of: Callable[[FakeSessionRecord], SessionRecordsInMemory] = SessionRecordsInMemory,
    *,
    refresh_token: str | None = ISSUED_REFRESH_TOKEN,
    id_token: SecretStr | None = STORED_ID_TOKEN,
    leeway_seconds: int = LEEWAY,
    answer: bool = True,
    clock_now: float = FIXED_INSTANT.timestamp(),
) -> Arrangement:
    clock = FakeClock(clock_now)
    issuer = FakeIssuer(mint_id_token=a_fake_id_token)
    config = a_web_auth_config(wall_clock=clock)
    now = datetime.fromtimestamp(clock.now, UTC)
    record = FakeSessionRecord(
        id=SESSION_ID,
        user=FakeUser(),
        created_at=now - timedelta(minutes=5),
        expires_at=now + timedelta(seconds=SESSION_IDLE_SECONDS),
        refresh_token=None if refresh_token is None else SecretStr(refresh_token),
        id_token=id_token,
    )
    relying_party = a_relying_party_for(
        issuer,
        a_realm_client_config(leeway_seconds=leeway_seconds),
        clock,
    )
    arrangement = Arrangement(issuer, sessions_of(record), clock, config, relying_party)
    if answer:
        arrangement.answer_with_id_token()
    return arrangement


def an_issuer_reason(outcome: object) -> OidcRefusalReason | None:
    assert isinstance(outcome, AccessTokenRefusal), outcome
    assert outcome.reason is AccessTokenRefusalReason.ISSUER_UNAVAILABLE
    assert outcome.issuer_refusal is not None
    return outcome.issuer_refusal.reason
