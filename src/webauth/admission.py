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
    "GroupPath",
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


_FORBIDDEN_PATH_CATEGORIES = frozenset({"Cc", "Cf", "Zl", "Zp"})


@dataclass(frozen=True, slots=True)
class GroupPath:
    """A group path of the issuer's realm, such as ``/apps/notes``.

    It starts with ``/`` and has no empty segment (so no trailing ``/``), no whitespace
    around a segment, and no control, format or line-separator character. A path that
    breaks a rule raises ``ValueError`` with a text that names the rule and never the
    value; a non-``str`` raises ``TypeError``. Whether the group exists at the issuer is
    not checked.

    It is equal by value and never equal to a ``str``, so a configured path and the
    ``str`` group paths of a token stay apart: ``str(path)`` is the text a token's
    groups claim holds. ``path.lies_below(other)`` is true only for a path strictly
    below ``other``, segment by segment."""

    path: str

    def __post_init__(self) -> None:
        if not isinstance(self.path, str):
            raise TypeError("a group path is a str")
        segments = self.path.split("/")
        if segments[0] != "" or len(segments) < 2 or not all(segments[1:]):
            raise ValueError(
                "a group path starts with / and has no empty segment, such as /apps/name"
            )
        if any(segment != segment.strip() for segment in segments):
            raise ValueError("a group path has no whitespace around a segment")
        if any(
            unicodedata.category(character) in _FORBIDDEN_PATH_CATEGORIES for character in self.path
        ):
            raise ValueError("a group path has no control, format or line-separator character")

    def __str__(self) -> str:
        return self.path

    def lies_below(self, other: GroupPath) -> bool:
        return _is_below(other.path, self.path)


@dataclass(frozen=True, kw_only=True)
class AdmissionConfig:
    """Who may enter and who is admin: the issuer the host's store is bound to,
    the group path of the app (or ``EverySubject.OF_THE_BOUND_ISSUER``), and the
    group path of its admins (or ``NoAdmins.IN_THIS_APP``).

    ``bound_issuer`` is the ``issuer`` of the host's ``OidcClientConfig``. Whether
    a group exists at the issuer is not checked.

    ``TypeError`` at construction names a ``login_group`` that is neither a
    ``GroupPath`` nor ``EverySubject``, and an ``admin_group`` that is neither a
    ``GroupPath`` nor ``NoAdmins``: a plain ``str`` is refused. ``ValueError`` names
    an ``admin_group`` that does not lie strictly below a ``login_group`` path, such as
    ``/apps/notes/admin`` below ``/apps/notes``."""

    bound_issuer: str
    login_group: GroupPath | EverySubject
    admin_group: GroupPath | NoAdmins

    def __post_init__(self) -> None:
        if not isinstance(self.login_group, GroupPath | EverySubject):
            raise TypeError("login_group must be a GroupPath or EverySubject")
        if not isinstance(self.admin_group, GroupPath | NoAdmins):
            raise TypeError("admin_group must be a GroupPath or NoAdmins")
        if (
            isinstance(self.login_group, GroupPath)
            and isinstance(self.admin_group, GroupPath)
            and not self.admin_group.lies_below(self.login_group)
        ):
            raise ValueError(
                f"admin_group must lie below login_group, such as {self.login_group}/admin"
            )


def _is_below(group_path: str, group: str) -> bool:
    return group.startswith(group_path + "/")


def _is_member_of(group_path: GroupPath, groups: Collection[str]) -> bool:
    return any(group == group_path.path or _is_below(group_path.path, group) for group in groups)


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
    if isinstance(login_group, GroupPath) and not _is_member_of(login_group, groups):
        return None
    admin_group = admission.admin_group
    if isinstance(admin_group, GroupPath) and _is_member_of(admin_group, groups):
        return AppRole.ADMIN
    return AppRole.USER


class AdmissionRefusal(StrEnum):
    """Why a verified identity does not become a signed-in account."""

    FOREIGN_ISSUER = "foreign-issuer"
    NOT_A_MEMBER = "not-a-member"
    USERNAME_TAKEN = "username-taken"
