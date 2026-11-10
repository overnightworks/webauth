"""Who gets into an app and as which role: the admission vocabulary and the group-path rule.

The module reads nothing but its arguments and imports only the standard library, so
the sign-in steps, the bearer gate and a service all apply the same decision. A host
states its ``AdmissionConfig`` and ``app_role`` answers whether a set of groups is a member
and as which ``AppRole``.
"""

from __future__ import annotations

import unicodedata
from dataclasses import dataclass
from enum import Enum, StrEnum
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from collections.abc import Collection

__all__ = [
    "AdmissionConfig",
    "AdmissionRefusal",
    "AppRole",
    "EverySubject",
    "NoAdmins",
    "app_role",
]


class EverySubject(Enum):
    """Admit every subject of the bound issuer, whatever their groups.

    That includes the issuer's people who belong to other apps, so a host
    states it on purpose and only when the issuer already limits who can sign
    in."""

    OF_THE_BOUND_ISSUER = "every-subject"


class NoAdmins(Enum):
    """This app has no admins: every account is ``"user"``, and a stored
    ``"admin"`` is demoted at the next sign-in or person-token admission."""

    IN_THIS_APP = "no-admins"


@dataclass(frozen=True, kw_only=True)
class AdmissionConfig:
    """Who may enter and who is admin: the issuer the host's store is bound to,
    the group path of the app (or ``EverySubject.OF_THE_BOUND_ISSUER``), and the
    group path of its admins (or ``NoAdmins.IN_THIS_APP``).

    ``bound_issuer`` is the ``issuer`` of the host's ``OidcClientConfig``. Whether
    a group exists at the issuer is not checked.

    ``ValueError`` at construction names a ``login_group`` or ``admin_group``
    that is not a group path: one that does not start with ``/``, ends with
    ``/``, has an empty segment, whitespace around a segment, or a control,
    format or line-separator character. Under a ``login_group`` path, the
    ``admin_group`` must lie strictly below it, such as ``/apps/notes/admin``."""

    bound_issuer: str
    login_group: str | EverySubject
    admin_group: str | NoAdmins

    def __post_init__(self) -> None:
        if not isinstance(self.login_group, EverySubject):
            if not isinstance(self.login_group, str):
                raise ValueError("login_group must be a group path or EverySubject")
            _require_group_path("login_group", self.login_group)
        if isinstance(self.admin_group, NoAdmins):
            return
        if not isinstance(self.admin_group, str):
            raise ValueError("admin_group must be a group path or NoAdmins")
        _require_group_path("admin_group", self.admin_group)
        if isinstance(self.login_group, str) and not _is_below(self.login_group, self.admin_group):
            raise ValueError(
                f"admin_group must lie below login_group, such as {self.login_group}/admin"
            )


_FORBIDDEN_PATH_CATEGORIES = frozenset({"Cc", "Cf", "Zl", "Zp"})


def _require_group_path(field: str, path: str) -> None:
    segments = path.split("/")
    if segments[0] != "" or len(segments) < 2 or not all(segments[1:]):
        raise ValueError(f"{field} must be a group path such as /apps/name")
    if any(segment != segment.strip() for segment in segments):
        raise ValueError(f"{field} must not have whitespace around a segment")
    if any(unicodedata.category(character) in _FORBIDDEN_PATH_CATEGORIES for character in path):
        raise ValueError(f"{field} must not contain control, format or line-separator characters")


def _is_below(group_path: str, group: str) -> bool:
    return group.startswith(group_path + "/")


def _is_member_of(group_path: str, groups: Collection[str]) -> bool:
    return any(group == group_path or _is_below(group_path, group) for group in groups)


class AppRole(StrEnum):
    """The role an app's groups carry. Its values, ``"admin"`` and ``"user"``, are the
    strings webauth stores and checks."""

    ADMIN = "admin"
    USER = "user"


def app_role(groups: Collection[str], admission: AdmissionConfig) -> AppRole | None:
    """The role ``groups`` carry in the app ``admission`` describes.

    ``None`` means no member: the groups hold no path of ``admission.login_group``
    (under ``EverySubject`` every set of groups is a member, the empty one
    included). ``ADMIN`` means they hold ``admission.admin_group`` or a path below
    it, which ``NoAdmins`` never matches; ``USER`` is every other member.

    It reads nothing but its arguments. It does not look at
    ``admission.bound_issuer``: the caller has checked that the groups come from
    that issuer, as the callback's admission does. The caller also validates the raw
    groups claim, refusing any shape but a list of strings as webauth's login
    does, and passes the group paths as any collection of strings: a tuple, a list or
    the ``frozenset`` that ``SessionGroups`` answers.
    """
    login_group = admission.login_group
    if isinstance(login_group, str) and not _is_member_of(login_group, groups):
        return None
    admin_group = admission.admin_group
    if isinstance(admin_group, str) and _is_member_of(admin_group, groups):
        return AppRole.ADMIN
    return AppRole.USER


class AdmissionRefusal(StrEnum):
    """Why a verified identity does not become a signed-in account."""

    FOREIGN_ISSUER = "foreign-issuer"
    NOT_A_MEMBER = "not-a-member"
    USERNAME_TAKEN = "username-taken"
