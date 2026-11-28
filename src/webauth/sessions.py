"""The session a host opens after its own proof, and the sign-out that ends it.

For an app the operator ruled off the OpenID Connect provider, built with ``oidc=None``: the host
checks who someone is itself, then ``open_session`` gives the account a session and ``end_session``
takes it back. webauth runs no proof and stores no device binding. Both functions are synchronous
and enter the ``SignInTransaction`` of the installed ``WebAuth``; call them from a worker thread or
a plain ``def`` route, never on the event loop and never inside a transaction the host holds open
over the same stores, and from a state-changing route, never a GET. On a handle built with OpenID
Connect both raise ``RuntimeError``: such a host signs in through its callback and out through its
logout.

The OpenID Connect callback and logout route run the same private bodies, so the sequence of
opening and ending a session exists once. Nothing here commits: the host's transaction does.
"""

from __future__ import annotations

import secrets
from dataclasses import dataclass
from typing import TYPE_CHECKING, Final

from logline import set_sub

from webauth.config import _installed_web_auth
from webauth.cookies import _clear_session_cookies, issue_session_cookies
from webauth.dependencies import _renewed_expiry, _whole_second_now, session_id_from_request

if TYPE_CHECKING:
    from collections.abc import Callable

    from pydantic import SecretStr
    from starlette.requests import Request
    from starlette.responses import Response

    from webauth.config import WebAuthConfig, _InstalledWebAuth
    from webauth.ports import SessionRecordStore, SignInStores, SignInTransaction

__all__ = ["end_session", "new_session_id", "open_session"]

_SESSION_ID_BYTES: Final = 32
_NO_STORE: Final = "no-store"


def new_session_id() -> str:
    """The id sign-in gives a new session: 43 URL-safe characters from 32 random bytes."""
    return secrets.token_urlsafe(_SESSION_ID_BYTES)


@dataclass(frozen=True)
class _NewSession:
    """What a sign-in names inside its entry: the account, and what the new row keeps."""

    account_id: str
    refresh_token: SecretStr | None = None
    id_token: SecretStr | None = None
    account_language: str | None = None


@dataclass(frozen=True)
class _SignedIn:
    """What one sign-in wrote: the new session's id and the account it belongs to."""

    session_id: str
    person_id: str


def open_session(request: Request, response: Response, account_id: str) -> str:
    """Open the session of ``account_id``, an account the host proved itself, and return its id.

    The session the request's cookie names is ended, whoever it belongs to. Under a
    ``max_sessions`` cap the account's newest ``max_sessions - 1`` sessions stay. The new session
    has a fresh id, expires one idle period after one wall-clock reading and holds no refresh
    token, no ID token and no account language. After the sign-in entry's exit returned, the
    session cookie and ``Cache-Control: no-store`` are set on ``response``, and the request line
    carries ``account_id`` as ``sub``. A failure in the entry or at its exit sets no cookie and
    reaches the caller.

    Pass the response the route returns: FastAPI drops the cookies of an injected ``Response`` when
    the route returns its own. The account must exist in the host's store: nothing is provisioned
    or checked here, and the store's ``create`` raises for a missing account. The id is a
    credential: a host that keeps one stores its digest. Raises ``RuntimeError`` on a handle built
    with OpenID Connect.
    """
    installed = _own_proof_handle(request, "open_session")
    return _open_session(
        request,
        response,
        installed.config,
        installed.sign_in,
        max_sessions=installed.max_sessions,
        name_the_session=lambda _stores: _NewSession(account_id),
    ).session_id


def end_session(request: Request, response: Response) -> str | None:
    """End the session the request's cookie names and return its id, ``None`` when it names none.

    One sign-in entry runs only when the cookie names a session; the id comes back whether or
    not a row still stood under it. A missing, forged, oversized or duplicated cookie names none.
    After the entry's exit returned, the session cookie is cleared on ``response`` and
    ``Cache-Control: no-store`` is set; a failure in the entry or at its exit clears nothing and
    reaches the caller. A socket outlives its session: call ``authenticate_websocket`` again
    before protected work on an open socket. Raises ``RuntimeError`` on a handle built with OpenID
    Connect.
    """
    installed = _own_proof_handle(request, "end_session")
    session_id, _nothing = _end_session(
        request, installed.config, installed.sign_in, read_the_row=_read_nothing
    )
    _clear_session_cookies(response, installed.config)
    response.headers["Cache-Control"] = _NO_STORE
    return session_id


def _own_proof_handle(request: Request, function: str) -> _InstalledWebAuth:
    installed = _installed_web_auth(request.app)
    if installed.uses_oidc:
        raise RuntimeError(
            f"{function} is for an app built with oidc=None: a host on the provider signs in "
            "through its callback and out through its logout."
        )
    return installed


def _open_session(
    request: Request,
    response: Response,
    config: WebAuthConfig,
    transaction: SignInTransaction,
    *,
    max_sessions: int | None,
    name_the_session: Callable[[SignInStores], _NewSession],
) -> _SignedIn:
    """The whole opening of a session, shared by ``open_session`` and the OpenID Connect callback.

    ``name_the_session`` runs first inside the entry and names the account and what the row keeps.
    One ``config.wall_clock`` reading, the same whole second the session decider reads, then in
    order: the session the request's cookie names is ended, the account is pruned to its newest
    ``max_sessions - 1`` sessions, the new session is created. Once the exit returned, the cookie
    and ``no-store`` go on ``response`` and the account is the request line's ``sub``.
    """
    replaced_session_id = session_id_from_request(request, config)
    with transaction() as stores:
        named = name_the_session(stores)
        now = _whole_second_now(config)
        if replaced_session_id is not None:
            stores.sessions.delete(replaced_session_id)
        if max_sessions is not None:
            stores.sessions.prune_overflow(named.account_id, max_sessions - 1)
        session = stores.sessions.create(
            named.account_id,
            session_id=new_session_id(),
            now=now,
            expires_at=_renewed_expiry(config.session_lifetime, now=now, created_at=now),
            refresh_token=named.refresh_token,
            id_token=named.id_token,
            account_language=named.account_language,
        )
        signed_in = _SignedIn(session_id=session.id, person_id=named.account_id)
    issue_session_cookies(response, signed_in.session_id, config)
    response.headers["Cache-Control"] = _NO_STORE
    set_sub(request.scope, signed_in.person_id)
    return signed_in


def _end_session[ReadT](
    request: Request,
    config: WebAuthConfig,
    transaction: SignInTransaction,
    *,
    read_the_row: Callable[[SessionRecordStore, str], ReadT],
) -> tuple[str | None, ReadT | None]:
    """The whole ending of a session, shared by ``end_session`` and the logout route: the id the
    request's cookie names and what ``read_the_row`` read from its row.

    The entry runs only when the cookie names a session. ``read_the_row`` runs inside it, before
    the delete, and copies what the caller needs. Clearing the cookie is the caller's, once this
    returned.
    """
    session_id = session_id_from_request(request, config)
    if session_id is None:
        return None, None
    with transaction() as stores:
        read = read_the_row(stores.sessions, session_id)
        stores.sessions.delete(session_id)
    return session_id, read


def _read_nothing(_sessions: SessionRecordStore, _session_id: str) -> None:
    return None
