"""What the bearer gate admitted for a request, and the readers and refusals that follow from it.

The gate writes one record into the request scope; the session readers, both gates and the
CSRF check read it here. This module imports no reader, so each of them can import it.
"""

from __future__ import annotations

import hashlib
from dataclasses import dataclass, field
from typing import TYPE_CHECKING, Final

from fastapi import HTTPException

from webauth import ports
from webauth.admission import AppRole

if TYPE_CHECKING:
    from collections.abc import Callable

    from starlette.requests import HTTPConnection

    from webauth.oidc import ExchangedAccess, OidcRefusal

__all__ = []

AUTHENTICATION_REQUIRED_DETAIL: Final = "Authentication required"
ADMIN_REQUIRED_DETAIL: Final = "Admin access required"
PERSON_PATH_CHALLENGE: Final = 'Bearer realm="api"'
PERSON_PATH_INSUFFICIENT_SCOPE: Final = 'Bearer error="insufficient_scope"'


_BEARER_ADMISSION_SCOPE_KEY: Final = "webauth.bearer_gate"


@dataclass(frozen=True)
class BearerAdmission:
    """What the bearer gate admitted: this app's gate, this path, this one header.

    ``principal`` is the machine's ``BearerCaller`` on a machine path and the
    account behind the token on a person path. ``resource_method`` is the request method of
    a resource admission, at its entry point or on a marked route, which holds for that method
    alone; a person path's record leaves it unset. ``token_exchange`` is set only at a resource
    admission: the admitting relying party's grant, which is no token.

    Only a SHA-256 digest of the `Authorization` value is kept, in request
    memory, so the record does not store the token. It says the gate admitted
    the request; it is not a freshness proof, and the gate verifies the header
    again on every request it selects.
    """

    app: object
    path: str
    authorization_digest: bytes
    principal: ports.BearerCaller | ports.AuthenticatedUser
    resource_method: str | None = None
    token_exchange: Callable[[str, tuple[str, ...]], ExchangedAccess | OidcRefusal] | None = field(
        default=None, repr=False, compare=False
    )

    @property
    def machine_caller(self) -> ports.BearerCaller | None:
        """The principal on a machine path; ``None`` on a person path."""
        return self.principal if isinstance(self.principal, ports.BearerCaller) else None

    @property
    def person(self) -> ports.AuthenticatedUser | None:
        """The account behind the token on a person path; ``None`` on a machine path."""
        return self.principal if isinstance(self.principal, ports.AuthenticatedUser) else None

    @property
    def is_resource_admission(self) -> bool:
        return self.resource_method is not None


def _authorization_digest(authorization: str) -> bytes:
    return hashlib.sha256(authorization.encode("latin-1")).digest()


def record_bearer_admission(
    connection: HTTPConnection,
    principal: ports.BearerCaller | ports.AuthenticatedUser,
    *,
    resource_method: str | None = None,
    token_exchange: Callable[[str, tuple[str, ...]], ExchangedAccess | OidcRefusal] | None = None,
) -> None:
    (authorization,) = connection.headers.getlist("authorization")
    connection.scope[_BEARER_ADMISSION_SCOPE_KEY] = BearerAdmission(
        app=connection.scope["app"],
        path=connection.scope["path"],
        authorization_digest=_authorization_digest(authorization),
        principal=principal,
        resource_method=resource_method,
        token_exchange=token_exchange,
    )


def bearer_admission(connection: HTTPConnection) -> BearerAdmission | None:
    """The bearer gate's admission, only when it was made for this very request.

    The strict reader: the same app, the same decoded path and exactly one
    `Authorization` line with the digest admitted, and for a resource admission the
    method it was made for. Anything else, a value other code wrote included, is no
    admission.
    """
    record = connection.scope.get(_BEARER_ADMISSION_SCOPE_KEY)
    if type(record) is not BearerAdmission:
        return None
    authorizations = connection.headers.getlist("authorization")
    if (
        record.app is not connection.scope.get("app")
        or record.path != connection.scope["path"]
        or (
            record.is_resource_admission
            and record.resource_method != connection.scope.get("method")
        )
        or len(authorizations) != 1
        or record.authorization_digest != _authorization_digest(authorizations[0])
    ):
        return None
    return record


def is_bearer_admitted(connection: HTTPConnection) -> bool:
    """The loose reader: any admission in the scope. Refusing more can only fail closed."""
    return type(connection.scope.get(_BEARER_ADMISSION_SCOPE_KEY)) is BearerAdmission


def admitted_token_person(connection: HTTPConnection) -> ports.AuthenticatedUser | None:
    """The account the bearer gate admitted for this very request on a person path, at a
    resource's entry point or on its marked route; ``None`` where no bearer admission is
    recorded.

    Raises ``RuntimeError`` for any other recorded admission: a machine admission, and one
    that does not hold here.
    """
    admission = bearer_admission(connection)
    if admission is not None and admission.person is not None:
        return admission.person
    raise_for_bearer_admission(connection)
    return None


def raise_for_bearer_admission(connection: HTTPConnection) -> None:
    if is_bearer_admitted(connection):
        raise RuntimeError(
            "A bearer-admitted request has no session reader here: a machine route takes "
            "Depends(bearer_caller), and a person path's or a resource's account is read only "
            "on the request the gate admitted it for, not in a sub-app or after the "
            "Authorization header or, at a resource, the method changed.",
        )


_PERSON_PATH_SCOPE_KEY: Final = "webauth.person_path"


def mark_person_path(connection: HTTPConnection) -> None:
    """Note that the bearer gate selected this path as a person path.

    The mark carries no authority: it only lets the library's own refusals on the
    path answer with a ``Bearer`` challenge.
    """
    connection.scope[_PERSON_PATH_SCOPE_KEY] = True


def _is_person_path(connection: HTTPConnection) -> bool:
    return connection.scope.get(_PERSON_PATH_SCOPE_KEY) is True


def require_admin(
    connection: HTTPConnection,
    user: ports.AuthenticatedUser,
) -> ports.AuthenticatedUser:
    """The account itself when its role is ``AppRole.ADMIN``; else the 403.

    The 403 of a person a person path admitted carries ``insufficient_scope``; a resource's
    admission is capped for good, so a new sign-in cannot help and its 403 carries no challenge.
    """
    if user.role != AppRole.ADMIN:
        admission = bearer_admission(connection)
        is_person_path_token = (
            admission is not None
            and not admission.is_resource_admission
            and admission.person is not None
        )
        challenge = PERSON_PATH_INSUFFICIENT_SCOPE if is_person_path_token else None
        raise HTTPException(
            403,
            ADMIN_REQUIRED_DETAIL,
            headers=None if challenge is None else {"WWW-Authenticate": challenge},
        )
    return user


def unauthenticated_without_redirect(connection: HTTPConnection, detail: str) -> HTTPException:
    challenge = PERSON_PATH_CHALLENGE if _is_person_path(connection) else None
    return HTTPException(
        401,
        detail,
        headers=None if challenge is None else {"WWW-Authenticate": challenge},
    )
