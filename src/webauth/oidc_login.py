"""The steps of signing a person in, and the issuer's logout, behind the sign-in routes.

``webauth.sign_in_routes`` serves the start, callback, logout and back-channel logout routes
over these private steps. The start step hands the browser the pending login in a signed
cookie of its own, one per login, so two tabs never overwrite each other. The
callback consumes exactly the cookie its state names and clears it on every
outcome; together with the issuer's one-time code, that makes a pending login
single-use. There is no server-side store, so this is not a replay store: a copy
of the cookie taken before the callback is stopped by the issuer refusing the
spent code, not by webauth.

The host's store is bound to one issuer — the ``issuer`` of its
``OidcClientConfig`` — and an account it provisions has the issuer's subject
as its ``id``. Moving to another issuer is therefore a migration of the
host's accounts, never a configuration change. This module builds on
``webauth.oidc``.

Admission runs inside the host's ``SignInTransaction`` and never commits: the host's
exit commits or rolls back, and a refusal writes nothing. Who gets in, and when a
change of group takes effect, is in ``docs/host-contract.md``, "What every app gets".

After the callback admits an account, ``webauth.sessions`` runs one ``SignInTransaction`` that
ends the session the request's cookie names, prunes the account to a cap, and creates its new
session, holding the login's refresh token and, when the host logs out, its ID token (the browser
keeps none), at the configured clock's instant, never committing; the cookie is issued only
after the transaction's exit returned.

The logout route's step ends the session the request's cookie names, if any, in one
``SignInTransaction`` entry and answers a page that posts the ID token hint to the issuer's
end-session endpoint, clearing the session cookie. It makes no outbound call and never
commits, so the person is signed out of the app even when the issuer is down, and a request
without a usable session still reaches the issuer. A forged, oversized or duplicated cookie
counts as missing: it ends no stored session, which leaves a duplicated cookie's session until
it expires, while the browser's own cookies are still cleared.

The step reads the login's ID token from the session row before it deletes the row and
passes it to the issuer as ``id_token_hint``, so the issuer ends its session without asking
the person to confirm. The hint is never decoded or verified here and is no credential;
without a row to read (ended, swept, pruned or stored before the host held ID tokens) the
issuer asks.

The back-channel logout route's step is the issuer's back-channel logout: it reads the
form body (one non-empty ``logout_token`` field, as the issuer posts it) and
verifies the Logout Token before entering the transaction, then, in one ``SignInTransaction``
entry, ends every session of the account the token's subject names, and records one
``BACKCHANNEL_LOGOUT`` event when a session ended. A subject without an account
is accepted and provisions nothing. It never commits, clears a cookie or calls the issuer;
a store or audit failure propagates so the host's transaction can roll back.

The production ``TokenRequestPost`` is ``webauth.oidc_transport``'s, not this
module's.
"""

from __future__ import annotations

import urllib.parse
from dataclasses import dataclass
from enum import Enum, StrEnum
from typing import TYPE_CHECKING, Final

from pydantic import SecretStr

from webauth import admission as _admission
from webauth._account_provisioning import admit_account
from webauth._end_session_page import end_session_page
from webauth._media_types import media_type_of
from webauth._paths import same_app_path
from webauth.cookies import _begin_pending_login, _clear_session_cookies
from webauth.dependencies import _is_admitted, _whole_second_now
from webauth.oidc import (
    PENDING_LOGIN_MAX_AGE_SECONDS,
    IdpErrorCode,
    OidcRefusal,
    OidcRefusalReason,
)
from webauth.ports import (
    AccountEvent,
    AccountEventKind,
)
from webauth.sessions import _end_session, _NewSession

if TYPE_CHECKING:
    from collections.abc import Callable

    from starlette.requests import Request
    from starlette.responses import Response

    from webauth.admission import AdmissionConfig, AdmissionRefusal
    from webauth.config import WebAuthConfig
    from webauth.oidc import OidcIdentity, OidcRelyingParty
    from webauth.ports import (
        SessionRecordStore,
        SessionRenewalStore,
        SessionTransaction,
        SignInStores,
        SignInTransaction,
    )

__all__ = [
    "AccessTokenRefusal",
    "AccessTokenRefusalReason",
    "current_groups",
    "fresh_access_token",
]


@dataclass(frozen=True)
class _AdmittedLogin:
    """An identity the bound issuer vouched for, admitted as ``role``."""

    identity: OidcIdentity
    role: str


def _start_login(
    relying_party: OidcRelyingParty,
    request: Request,
    response: Response,
    config: WebAuthConfig,
    *,
    return_to: str | None,
    ui_locales: str | None,
) -> str:
    """Begin a login: set its pending-login cookie on ``response`` and return
    the authorization URL the start route redirects the browser to, naming ``ui_locales`` as the
    person's language when it is not ``None``; a string that is not a language tag in shape
    raises ``ValueError`` before any cookie is set.

    ``return_to`` is the raw path and query as the app sees them, ``root_path``
    included and not the percent-decoded ``request.url.path``, that the callback
    hands back after the login. It is kept only as a
    same-origin path of this app, ASCII (other characters are percent-encoded)
    and at most 512 bytes once encoded; anything else is dropped and the login
    still succeeds, landing on the app root. Dropped are a path a
    browser reads as another host (``//x``, ``/\\x``, a tab, CR or LF between
    the slashes), an absolute URL, a bare host, a control character, the empty
    string, a ``.`` or ``..`` segment (also as ``%2e``), a literal ``#`` and a
    path outside ``root_path``. Under a ``root_path`` the path must already lie
    below it at a segment boundary and nothing is prepended: with
    ``root_path="/app"``, ``/app/albums/42`` is kept and ``/albums/42`` is
    dropped; a ``root_path`` with a character other than ASCII letters, digits,
    ``-._~`` and ``/`` keeps no return path. A login route inside a mounted
    sub-app is judged against that mount's ``root_path``. The fragment is lost,
    because browsers never send it.
    """
    authorization = relying_party.begin_login(ui_locales=ui_locales)
    pending = authorization.pending.returning_to(same_app_path(request, return_to))
    _begin_pending_login(
        request,
        response,
        pending,
        max_age_seconds=PENDING_LOGIN_MAX_AGE_SECONDS,
        config=config,
    )
    return authorization.url


def _name_the_session_of(
    admitted: _AdmittedLogin, *, keeps_id_token: bool
) -> Callable[[SignInStores], _NewSession]:
    """The step the callback runs first inside its sign-in entry: admit the account, then name it
    with the login's refresh token, its account language and, when ``keeps_id_token`` is true, its
    ID token. Raises ``UsernameTakenSignal`` before any session is touched."""

    def name_the_session(stores: SignInStores) -> _NewSession:
        account = admit_account(
            admitted.identity,
            admitted.role,
            accounts=stores.accounts,
            audit=stores.audit,
        )
        identity = admitted.identity
        return _NewSession(
            account.id,
            refresh_token=identity.refresh_token,
            id_token=SecretStr(identity.id_token) if keeps_id_token else None,
            account_language=identity.account_language,
        )

    return name_the_session


def _log_out(
    relying_party: OidcRelyingParty,
    request: Request,
    config: WebAuthConfig,
    *,
    transaction: SignInTransaction,
    language: str,
    button_label: str,
) -> Response:
    """The logout route's whole sequence: end the session the request's cookie names, if any,
    and answer the page that ends the issuer's.

    The row is read and then deleted in one ``transaction`` entry, and only when the cookie names
    a session; the ID token's value is copied inside the block. The answer clears the session
    cookie in every case. Never commits and makes no outbound call."""
    _session_id, id_token = _end_session(
        request, config, transaction, read_the_row=_id_token_of_session
    )
    form = relying_party._end_session_form(id_token_hint=id_token)
    answer = end_session_page(form, language=language, button_label=button_label)
    _clear_session_cookies(answer, config)
    return answer


def _id_token_of_session(sessions: SessionRecordStore, session_id: str) -> SecretStr | None:
    record = sessions.load(session_id)
    if record is None or record.id_token is None:
        return None
    return SecretStr(record.id_token.get_secret_value())


class AccessTokenRefusalReason(StrEnum):
    """Why a session yields no access token."""

    SESSION_ENDED = "session-ended"
    """The session is gone or outside its lifetime: the person is signed out.
    The host treats them as signed out, as after a refused request."""
    SIGN_IN_AGAIN = "sign-in-again"
    """The session holds no refresh token (it began before the host stored them,
    or the issuer gave none), or the issuer refused it as ``invalid_grant``,
    which includes a realm SSO session that ended while the app session stands.
    The host sends the person to sign in again; the app session itself stands,
    and only this call is refused."""
    ISSUER_UNAVAILABLE = "issuer-unavailable"
    """The issuer is unreachable, answered something unusable, or refused for a
    reason other than ``invalid_grant``; ``AccessTokenRefusal.issuer_refusal``
    says which. The host fails the call and logs it; the person stays signed in."""


@dataclass(frozen=True)
class AccessTokenRefusal:
    """A session that yields no access token. ``issuer_refusal`` is the issuer's
    answer for ``ISSUER_UNAVAILABLE`` (``invalid_client`` shows its cause here),
    and ``None`` otherwise."""

    reason: AccessTokenRefusalReason
    issuer_refusal: OidcRefusal | None = None


_SESSION_ENDED: Final = AccessTokenRefusal(AccessTokenRefusalReason.SESSION_ENDED)
_SIGN_IN_AGAIN: Final = AccessTokenRefusal(AccessTokenRefusalReason.SIGN_IN_AGAIN)


def fresh_access_token(
    relying_party: OidcRelyingParty,
    session_id: str,
    *,
    session_transaction: SessionTransaction,
    config: WebAuthConfig,
) -> SecretStr | AccessTokenRefusal:
    """A new access token for the person ``session_id`` signs in, in memory only.

    Reads the session in one transaction, sends its refresh token to the issuer
    with no transaction and no lock open, then reads the session again in a
    second transaction and stores the issuer's new refresh token when it
    differs from the one sent (not the one read again). The token is handed
    out only when the second transaction has been left and the session still
    stood in it; a session gone by then is ``SESSION_ENDED`` whatever the
    issuer returned. Admission's own decision judges the session both times,
    and nothing renews it: asking for a token is not the person's request.

    A call that finds the session ended or without a refresh token answers
    before the issuer is contacted; every other call costs one refresh grant at
    the issuer. The host holds the token in memory for the one call it serves
    and stores it nowhere. No session row or lock is held during the grant, so
    a slow issuer holds only the caller's thread, for as long as the
    transport's documented bounds allow (its deadline excludes the host name
    lookup and connecting).

    The second transaction is the last check: a token handed out stays valid at the
    service it is sent to, and at the issuer's own endpoints, until its own
    ``exp``, even after a logout or an expiry that lands later. No revocation
    call is made. Where the issuer lets a refresh token be used again, two
    overlapping calls for one session each get a valid token and the later
    write wins; where it revokes the token on use, the second is refused as
    ``invalid_grant`` and answers a false ``SIGN_IN_AGAIN``.

    Call it from a worker thread, outside any open session transaction and
    outside any open session or sign-in transaction. ``session_id`` is the cookie's id,
    which ``session_id_from_request`` bounds, or, when ``session_transaction`` yields a
    stored-key view (PGSTORE-11), the session's stored key. It raises when the store fails, when
    ``replace_refresh_token`` answers anything but a ``bool``, or when the
    transaction's exit fails; no token is handed out then.
    """
    held = _evidence_of_standing_session(session_id, session_transaction, config)
    if isinstance(held, AccessTokenRefusal):
        return held
    sent = held.refresh_token
    renewed = relying_party.renew_access(sent)
    if isinstance(renewed, OidcRefusal):
        return _refusal_of_grant(renewed)
    stands = _kept_after_grant(
        session_id,
        session_transaction,
        config,
        sent=sent,
        rotated=renewed.refresh_token,
    )
    return renewed.access_token if stands else _SESSION_ENDED


def _kept_after_grant(
    session_id: str,
    session_transaction: SessionTransaction,
    config: WebAuthConfig,
    *,
    sent: SecretStr,
    rotated: SecretStr | None,
) -> bool:
    """Whether the session still stands after the grant, storing the rotated refresh
    token when it does and differs from the one sent. A deleted session is never recreated."""
    with session_transaction() as sessions:
        record = sessions.load(session_id)
        stands = record is not None and _is_admitted(
            config.session_lifetime,
            record,
            _whole_second_now(config),
        )
        if stands and rotated is not None and rotated != sent:
            stands = _stored(sessions, session_id, rotated)
    return stands


@dataclass(frozen=True)
class _StandingEvidence:
    refresh_token: SecretStr
    subject: str


def current_groups(
    relying_party: OidcRelyingParty,
    session_id: str,
    *,
    session_transaction: SessionTransaction,
    config: WebAuthConfig,
) -> tuple[str, ...] | AccessTokenRefusal:
    """The group paths the issuer holds for the person ``session_id`` signs in, from the
    verified ID token of a refresh grant made in this call; ``()`` is no membership.

    It shares ``fresh_access_token``'s grant, second transaction, rotation and overlap
    behaviour, its refusals, and what ``session_id`` is: the cookie's id or, through a
    stored-key view (PGSTORE-11), the session's stored key. The stored ID token plays no
    part. A replacement refresh token is stored even when the new ID token is refused
    (``ISSUER_UNAVAILABLE`` with ``issuer_refusal`` naming why), and a session gone by then
    is ``SESSION_ENDED``."""
    held = _evidence_of_standing_session(session_id, session_transaction, config)
    if isinstance(held, AccessTokenRefusal):
        return held
    refreshed = relying_party._refreshed_groups(held.refresh_token, subject=held.subject)
    if isinstance(refreshed, OidcRefusal):
        return _refusal_of_grant(refreshed)
    if not _kept_after_grant(
        session_id,
        session_transaction,
        config,
        sent=held.refresh_token,
        rotated=refreshed.refresh_token,
    ):
        return _SESSION_ENDED
    if isinstance(refreshed.groups, OidcRefusal):
        return _refusal_of_grant(refreshed.groups)
    return refreshed.groups


def _evidence_of_standing_session(
    session_id: str,
    session_transaction: SessionTransaction,
    config: WebAuthConfig,
) -> _StandingEvidence | AccessTokenRefusal:
    with session_transaction() as sessions:
        record = sessions.load(session_id)
        if record is None or not _is_admitted(
            config.session_lifetime,
            record,
            _whole_second_now(config),
        ):
            return _SESSION_ENDED
        if record.refresh_token is None:
            return _SIGN_IN_AGAIN
        return _StandingEvidence(record.refresh_token, record.user.id)


def _refusal_of_grant(refusal: OidcRefusal) -> AccessTokenRefusal:
    if (
        refusal.reason is OidcRefusalReason.TOKEN_REQUEST_REFUSED
        and refusal.idp_error is IdpErrorCode.INVALID_GRANT
    ):
        return _SIGN_IN_AGAIN
    return AccessTokenRefusal(AccessTokenRefusalReason.ISSUER_UNAVAILABLE, refusal)


def _stored(sessions: SessionRenewalStore, session_id: str, refresh_token: SecretStr) -> bool:
    stored = sessions.replace_refresh_token(session_id, refresh_token=refresh_token)
    if type(stored) is not bool:
        raise TypeError(
            "SessionRenewalStore.replace_refresh_token must return a bool, "
            f"not {type(stored).__name__}",
        )
    return stored


class _BackchannelLogoutResult(Enum):
    ACCEPTED = "accepted"
    """The token held: the subject's sessions, if any, are deleted in the transaction."""
    REFUSED = "refused"
    """The form or the token did not hold; nothing was changed."""


def _receive_backchannel_logout(
    relying_party: OidcRelyingParty,
    form_body: bytes,
    content_type: str | None,
    *,
    transaction: SignInTransaction,
) -> _BackchannelLogoutResult:
    """End every session of the subject a verified Logout Token names.

    A request that is not one URL-encoded form with exactly one non-empty ``logout_token`` is
    refused before anything is verified, and the token is verified before the transaction is
    entered. In the one entry, a subject with no account is accepted and creates none; a known
    subject loses every session in every browser, and one ``backchannel_logout`` audit event
    with ``actor_id=None`` is emitted when at least one session ended. It never commits, rolls
    back, clears a cookie or calls the issuer: the host's transaction rolls back when this
    raises, including when the audit sink fails after the deletion.

    The verification and the stores are synchronous: run it in a worker thread, which
    creates, enters and leaves the transaction.
    """
    logout_token = _logout_token_of(form_body, content_type)
    if logout_token is None:
        return _BackchannelLogoutResult.REFUSED
    logout = relying_party.verify_logout_token(logout_token)
    if isinstance(logout, OidcRefusal):
        return _BackchannelLogoutResult.REFUSED
    with transaction() as stores:
        account = stores.accounts.get(logout.subject)
        if account is not None and stores.sessions.delete_for_user(account.id):
            stores.audit.account_event(
                AccountEvent(
                    kind=AccountEventKind.BACKCHANNEL_LOGOUT,
                    actor_id=None,
                    subject_id=account.id,
                )
            )
    return _BackchannelLogoutResult.ACCEPTED


def _logout_token_of(form_body: bytes, content_type: str | None) -> str | None:
    if media_type_of(content_type) != "application/x-www-form-urlencoded":
        return None
    try:
        fields = urllib.parse.parse_qsl(
            form_body.decode(),
            keep_blank_values=True,
            strict_parsing=True,
            errors="strict",
        )
    except ValueError:
        return None
    tokens = [value for name, value in fields if name == "logout_token"]
    return tokens[0] if len(tokens) == 1 and tokens[0] else None


def _decide_admission(
    identity: OidcIdentity,
    *,
    admission: AdmissionConfig,
) -> _AdmittedLogin | AdmissionRefusal:
    """Whether ``identity`` may sign in, and as which role. Pure: it reads nothing but its
    arguments and writes nothing.

    The role is ``"admin"`` when the identity is a member of ``admission.admin_group``
    (or below it), otherwise ``"user"``, whatever role a stored account holds. The
    order of refusals is ``FOREIGN_ISSUER``, then ``NOT_A_MEMBER`` (the identity's groups
    hold no path of ``admission.login_group``, or are missing or empty). Both write nothing and
    look up no account.

    A groups claim that is not a list of strings never reaches this function:
    ``OidcRelyingParty.complete_login`` refuses it as ``INVALID_IDENTITY_CLAIM``.
    A missing claim is an empty list of groups.
    """
    if identity.issuer != admission.bound_issuer:
        return _admission.AdmissionRefusal.FOREIGN_ISSUER
    derived = _admission.app_role(identity.groups, admission)
    if derived is None:
        return _admission.AdmissionRefusal.NOT_A_MEMBER
    return _AdmittedLogin(identity, derived.value)
