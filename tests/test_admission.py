"""The admission vocabulary: what a config accepts and which role a set of groups carries."""

from __future__ import annotations

from dataclasses import replace

import pytest

from tests.support.oidc_login_host import ADMIN_GROUP, ADMISSION, BOUND_ISSUER, LOGIN_GROUP
from webauth.admission import AdmissionConfig, AppRole, EverySubject, NoAdmins, app_role

EVERYONE = replace(ADMISSION, login_group=EverySubject.OF_THE_BOUND_ISSUER)
NO_ADMINS = replace(ADMISSION, admin_group=NoAdmins.IN_THIS_APP)
EVERYONE_WITH_ADMIN_GROUP = replace(EVERYONE, admin_group="/apps/other/admin")


@pytest.mark.parametrize(
    ("login_group", "admin_group"),
    [
        pytest.param("/apps/lab", "/apps/lab/admin", id="a path with an admin group below it"),
        pytest.param("/apps/lab", "/apps/lab/ops/admin", id="an admin group two levels below"),
        pytest.param(
            "/apps/Team A", "/apps/Team A/~admin", id="a space and a tilde inside a segment"
        ),
        pytest.param("/apps/lab", NoAdmins.IN_THIS_APP, id="no admins in this app"),
        pytest.param(EverySubject.OF_THE_BOUND_ISSUER, "/apps/lab/admin", id="every subject"),
        pytest.param(
            EverySubject.OF_THE_BOUND_ISSUER, "/admins", id="every subject, any admin path"
        ),
        pytest.param(EverySubject.OF_THE_BOUND_ISSUER, NoAdmins.IN_THIS_APP, id="neither group"),
    ],
)
def test_a_well_formed_admission_config_is_accepted(
    login_group: str | EverySubject,
    admin_group: str | NoAdmins,
) -> None:
    assert AdmissionConfig(
        bound_issuer=BOUND_ISSUER,
        login_group=login_group,
        admin_group=admin_group,
    )


MALFORMED_GROUP_PATHS = [
    pytest.param("", id="empty"),
    pytest.param("apps/lab", id="no leading slash"),
    pytest.param("/", id="a bare slash"),
    pytest.param("/apps/lab/", id="a trailing slash"),
    pytest.param("/apps//lab", id="an empty segment"),
    pytest.param("/apps/ lab", id="leading whitespace on a segment"),
    pytest.param("/apps/lab ", id="trailing whitespace on a segment"),
    pytest.param("/apps/\tlab", id="a tab inside a segment"),
    pytest.param("/apps/la\x00b", id="a control character"),
    pytest.param("/apps/la\nb", id="a newline"),
    pytest.param("/apps/la\u200bb", id="a zero-width space"),
    pytest.param("/apps/la\u2028b", id="a line separator"),
    pytest.param("/apps/la\u2029b", id="a paragraph separator"),
]


@pytest.mark.parametrize(
    "login_group",
    [
        pytest.param(None, id="none"),
        pytest.param(7, id="an int"),
        *MALFORMED_GROUP_PATHS,
    ],
)
def test_a_malformed_login_group_fails_at_construction(login_group: object) -> None:
    with pytest.raises(ValueError):
        AdmissionConfig(
            bound_issuer=BOUND_ISSUER,
            login_group=login_group,  # pyright: ignore[reportArgumentType] -- malformed on purpose
            admin_group=NoAdmins.IN_THIS_APP,
        )


@pytest.mark.parametrize(
    "admin_group",
    [
        pytest.param(None, id="none, as an unset variable reads"),
        pytest.param(7, id="an int"),
        pytest.param(EverySubject.OF_THE_BOUND_ISSUER, id="the every-subject value"),
        *MALFORMED_GROUP_PATHS,
    ],
)
def test_a_malformed_admin_group_fails_at_construction(admin_group: object) -> None:
    with pytest.raises(ValueError):
        AdmissionConfig(
            bound_issuer=BOUND_ISSUER,
            login_group=EverySubject.OF_THE_BOUND_ISSUER,
            admin_group=admin_group,  # pyright: ignore[reportArgumentType] -- malformed on purpose
        )


@pytest.mark.parametrize(
    "admin_group",
    [
        pytest.param(LOGIN_GROUP, id="the login group itself"),
        pytest.param("/apps", id="the parent of the login group"),
        pytest.param("/apps/other/admin", id="another app's admin group"),
        pytest.param(
            f"{LOGIN_GROUP}2/admin", id="a group named like the login group with a suffix"
        ),
        pytest.param(LOGIN_GROUP.upper() + "/admin", id="another case"),
    ],
)
def test_an_admin_group_outside_the_login_group_fails_at_construction(admin_group: str) -> None:
    message = f"admin_group must lie below login_group, such as {LOGIN_GROUP}/admin"
    with pytest.raises(ValueError, match=message):
        AdmissionConfig(
            bound_issuer=BOUND_ISSUER,
            login_group=LOGIN_GROUP,
            admin_group=admin_group,
        )


@pytest.mark.parametrize(
    "settings",
    [
        pytest.param({"login_group": LOGIN_GROUP}, id="without an admin group"),
        pytest.param({"admin_group": ADMIN_GROUP}, id="without a login group"),
        pytest.param({}, id="without either"),
    ],
)
def test_an_admission_config_missing_a_required_group_setting_fails_at_construction(
    settings: dict[str, str],
) -> None:
    with pytest.raises(TypeError):
        AdmissionConfig(bound_issuer=BOUND_ISSUER, **settings)


@pytest.mark.parametrize(
    ("groups", "admission", "role"),
    [
        pytest.param((ADMIN_GROUP,), ADMISSION, AppRole.ADMIN, id="the admin group"),
        pytest.param((f"{ADMIN_GROUP}/ops",), ADMISSION, AppRole.ADMIN, id="an admin subgroup"),
        pytest.param((LOGIN_GROUP,), ADMISSION, AppRole.USER, id="the login group"),
        pytest.param((f"{LOGIN_GROUP}/staff",), ADMISSION, AppRole.USER, id="a login subgroup"),
        pytest.param(
            (f"{LOGIN_GROUP}2",), ADMISSION, None, id="a group named like the login group"
        ),
        pytest.param((), ADMISSION, None, id="no groups"),
        pytest.param((), EVERYONE, AppRole.USER, id="no groups under every subject"),
        pytest.param(
            (ADMIN_GROUP,), EVERYONE, AppRole.ADMIN, id="the admin group under every subject"
        ),
        pytest.param(
            (LOGIN_GROUP,),
            EVERYONE_WITH_ADMIN_GROUP,
            AppRole.USER,
            id="every subject without the admin group",
        ),
        pytest.param((ADMIN_GROUP,), NO_ADMINS, AppRole.USER, id="the admin path without admins"),
    ],
)
def test_app_role_names_the_role_the_groups_carry(
    groups: tuple[str, ...],
    admission: AdmissionConfig,
    role: AppRole | None,
) -> None:
    assert app_role(groups, admission) is role
