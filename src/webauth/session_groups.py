"""A signed-in person's current groups for an async host, fresh at each call.

``SessionGroups`` runs ``webauth.oidc_login.current_groups`` on a worker thread: one refresh
grant per call, through the host's ``SessionTransaction``, so the library commits nothing.
What a refusal means for the host, and which group it checks, stay with the host; see
``docs/host-contract.md``, "A person's current groups".
"""

from __future__ import annotations

from functools import partial
from typing import TYPE_CHECKING

from webauth.dependencies import session_id_from_request
from webauth.middleware._worker import on_worker
from webauth.oidc_login import AccessTokenRefusal, AccessTokenRefusalReason, current_groups

if TYPE_CHECKING:
    from starlette.requests import HTTPConnection

    from webauth.config import WebAuthConfig
    from webauth.oidc import OidcRelyingParty
    from webauth.ports import SessionTransaction

__all__ = ["SessionGroups"]


class SessionGroups:
    """Reads the groups the issuer holds now for a session, by one refresh grant of it.

    The grant runs on a worker thread. A caller that is cancelled while it runs gets no
    answer, but the grant still ends and stores its rotated refresh token. Overlapping
    calls take no lock; ``docs/host-contract.md`` says what the issuer must allow.
    """

    def __init__(
        self,
        relying_party: OidcRelyingParty,
        session_transaction: SessionTransaction,
        config: WebAuthConfig,
    ) -> None:
        self._relying_party = relying_party
        self._session_transaction = session_transaction
        self._config = config

    async def of_session(self, session_id: str) -> frozenset[str] | AccessTokenRefusal:
        """The group paths of ``session_id``, or the refusal ``current_groups`` answers."""
        groups = await on_worker(
            partial(
                current_groups,
                self._relying_party,
                session_id,
                session_transaction=self._session_transaction,
                config=self._config,
            )
        )
        return groups if isinstance(groups, AccessTokenRefusal) else frozenset(groups)

    async def of_connection(
        self, connection: HTTPConnection
    ) -> frozenset[str] | AccessTokenRefusal:
        """The group paths of the session the connection's cookie names; a connection that
        carries none answers ``SIGN_IN_AGAIN`` and makes no grant."""
        session_id = session_id_from_request(connection, self._config)
        if session_id is None:
            return AccessTokenRefusal(AccessTokenRefusalReason.SIGN_IN_AGAIN)
        return await self.of_session(session_id)
