"""The admission vocabulary: what a config accepts and which role a set of groups carries."""

from __future__ import annotations

import pytest

from tests.support.oidc_login_host import (
    ADMIN_GROUP,
    ADMISSION,
    BOUND_ISSUER,
    EVERYONE,
    EVERYONE_WITH_ADMIN_GROUP,
    LOGIN_GROUP,
    NO_ADMINS,
    an_oidc_host,
)
from webauth.admission import (
    AdmissionConfig,
    AppRole,
    EverySubject,
    GroupPath,
    NoAdmins,
    app_role,
)


@pytest.mark.parametrize(
    ("login_group", "admin_group"),
    [
        pytest.param(
            GroupPath("/apps/lab"),
            GroupPath("/apps/lab/admin"),
            id="a path with an admin group below it",
        ),
        pytest.param(
            GroupPath("/apps/lab"),
            GroupPath("/apps/lab/ops/admin"),
            id="an admin group two levels below",
        ),
        pytest.param(
            GroupPath("/apps/Team A"),
            GroupPath("/apps/Team A/~admin"),
            id="a space and a tilde inside a segment",
        ),
        pytest.param(GroupPath("/apps/lab"), NoAdmins.IN_THIS_APP, id="no admins in this app"),
        pytest.param(
            EverySubject.OF_THE_BOUND_ISSUER, GroupPath("/apps/lab/admin"), id="every subject"
        ),
        pytest.param(
            EverySubject.OF_THE_BOUND_ISSUER,
            GroupPath("/admins"),
            id="every subject, any admin path",
        ),
        pytest.param(EverySubject.OF_THE_BOUND_ISSUER, NoAdmins.IN_THIS_APP, id="neither group"),
    ],
)
def test_a_well_formed_admission_config_is_accepted(
    login_group: GroupPath | EverySubject,
    admin_group: GroupPath | NoAdmins,
) -> None:
    assert AdmissionConfig(
        bound_issuer=BOUND_ISSUER,
        login_group=login_group,
        admin_group=admin_group,
    )


STARTS_WITH_A_SLASH = "a group path starts with / and has no empty segment, such as /apps/name"
NO_WHITESPACE = "a group path has no whitespace around a segment"
NO_CONTROL_CHARACTER = "a group path has no control, format or line-separator character"

MALFORMED_GROUP_PATHS = [
    pytest.param("", STARTS_WITH_A_SLASH, id="empty"),
    pytest.param("apps/lab", STARTS_WITH_A_SLASH, id="no leading slash"),
    pytest.param("/", STARTS_WITH_A_SLASH, id="a bare slash"),
    pytest.param("/apps/lab/", STARTS_WITH_A_SLASH, id="a trailing slash"),
    pytest.param("/apps//lab", STARTS_WITH_A_SLASH, id="an empty segment"),
    pytest.param("/apps/ lab", NO_WHITESPACE, id="leading whitespace on a segment"),
    pytest.param("/apps/lab ", NO_WHITESPACE, id="trailing whitespace on a segment"),
    pytest.param("/apps/\tlab", NO_WHITESPACE, id="a tab at the start of a segment"),
    pytest.param("/apps/la\x00b", NO_CONTROL_CHARACTER, id="a control character"),
    pytest.param("/apps/la\nb", NO_CONTROL_CHARACTER, id="a newline"),
    pytest.param("/apps/la\u200bb", NO_CONTROL_CHARACTER, id="a zero-width space"),
    pytest.param("/apps/la\u2028b", NO_CONTROL_CHARACTER, id="a line separator"),
    pytest.param("/apps/la\u2029b", NO_CONTROL_CHARACTER, id="a paragraph separator"),
]


def test_a_group_path_reads_back_as_the_text_it_was_built_from() -> None:
    """APP-38: `str()` of a group path is the text it was built from."""

    assert str(GroupPath("/apps/lab")) == "/apps/lab"


def test_group_paths_are_equal_by_value_and_never_equal_to_a_str() -> None:
    """APP-38: a group path is equal by value and never equal to a `str`."""

    twin = GroupPath("/apps/lab")

    assert twin == GroupPath("/apps/lab")
    assert hash(twin) == hash(GroupPath("/apps/lab"))
    assert twin != GroupPath("/apps/other")
    assert twin != "/apps/lab"
    assert "/apps/lab" != twin


@pytest.mark.parametrize(("path", "message"), MALFORMED_GROUP_PATHS)
def test_a_malformed_group_path_is_refused_with_its_rule(path: str, message: str) -> None:
    """APP-38: a malformed path is a `ValueError` naming the rule."""

    with pytest.raises(ValueError) as refused:
        GroupPath(path)

    assert str(refused.value) == message


@pytest.mark.parametrize(
    "path",
    [
        pytest.param("canary-7f3a/lab", id="the first rule"),
        pytest.param("/canary-7f3a/ lab", id="the second rule"),
        pytest.param("/canary-7f3a/l\x00ab", id="the third rule"),
    ],
)
def test_a_refused_group_path_is_not_echoed(path: str) -> None:
    """APP-38: the refusal never carries the value."""

    with pytest.raises(ValueError) as refused:
        GroupPath(path)

    assert "canary-7f3a" not in str(refused.value)


@pytest.mark.parametrize(
    "path",
    [
        pytest.param(None, id="none"),
        pytest.param(7, id="an int"),
        pytest.param(b"/apps/lab", id="bytes"),
        pytest.param(GroupPath("/apps/lab"), id="a group path"),
    ],
)
def test_a_group_path_built_from_anything_but_a_str_is_a_type_error(path: object) -> None:
    """APP-38: a non-`str` is a `TypeError`."""

    with pytest.raises(TypeError, match="a group path is a str"):
        GroupPath(path)  # pyright: ignore[reportArgumentType] -- not a str on purpose


@pytest.mark.parametrize(
    ("path", "other", "lies_below"),
    [
        pytest.param("/apps/lab/admin", "/apps/lab", True, id="a child"),
        pytest.param("/apps/lab/ops/admin", "/apps/lab", True, id="a grandchild"),
        pytest.param("/apps/lab", "/apps/lab", False, id="itself"),
        pytest.param("/apps", "/apps/lab", False, id="its parent"),
        pytest.param("/apps/lab2", "/apps/lab", False, id="a sibling with a suffix"),
        pytest.param("/other/lab", "/apps/lab", False, id="an unrelated path"),
    ],
)
def test_a_group_path_lies_below_another_only_strictly_and_by_segment(
    path: str, other: str, lies_below: bool
) -> None:
    """APP-38: `lies_below` is true only strictly below, by segment."""
    assert GroupPath(path).lies_below(GroupPath(other)) is lies_below


NOT_A_GROUP_PATH = [
    pytest.param("/apps/lab", id="a plain str, well formed"),
    pytest.param(None, id="none"),
    pytest.param(7, id="an int"),
]


@pytest.mark.parametrize("login_group", NOT_A_GROUP_PATH)
def test_a_login_group_that_is_not_a_group_path_is_a_type_error(login_group: object) -> None:
    with pytest.raises(TypeError, match="login_group must be a GroupPath or EverySubject"):
        AdmissionConfig(
            bound_issuer=BOUND_ISSUER,
            login_group=login_group,  # pyright: ignore[reportArgumentType] -- not a GroupPath on purpose
            admin_group=NoAdmins.IN_THIS_APP,
        )


@pytest.mark.parametrize(
    "admin_group",
    [
        *NOT_A_GROUP_PATH,
        pytest.param(EverySubject.OF_THE_BOUND_ISSUER, id="the every-subject value"),
    ],
)
def test_an_admin_group_that_is_not_a_group_path_is_a_type_error(admin_group: object) -> None:
    with pytest.raises(TypeError, match="admin_group must be a GroupPath or NoAdmins"):
        AdmissionConfig(
            bound_issuer=BOUND_ISSUER,
            login_group=EverySubject.OF_THE_BOUND_ISSUER,
            admin_group=admin_group,  # pyright: ignore[reportArgumentType] -- not a GroupPath on purpose
        )


@pytest.mark.parametrize(
    "admin_group",
    [
        pytest.param(LOGIN_GROUP, id="the login group itself"),
        pytest.param(GroupPath("/apps"), id="the parent of the login group"),
        pytest.param(GroupPath("/apps/other/admin"), id="another app's admin group"),
        pytest.param(
            GroupPath(f"{LOGIN_GROUP}2/admin"),
            id="a group named like the login group with a suffix",
        ),
        pytest.param(GroupPath(str(LOGIN_GROUP).upper() + "/admin"), id="another case"),
    ],
)
def test_an_admin_group_outside_the_login_group_fails_at_construction(
    admin_group: GroupPath,
) -> None:
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
    settings: dict[str, GroupPath],
) -> None:
    with pytest.raises(TypeError):
        AdmissionConfig(bound_issuer=BOUND_ISSUER, **settings)


@pytest.mark.parametrize(
    ("groups", "admission", "role"),
    [
        pytest.param((str(ADMIN_GROUP),), ADMISSION, AppRole.ADMIN, id="the admin group"),
        pytest.param((f"{ADMIN_GROUP}/ops",), ADMISSION, AppRole.ADMIN, id="an admin subgroup"),
        pytest.param((str(LOGIN_GROUP),), ADMISSION, AppRole.USER, id="the login group"),
        pytest.param((f"{LOGIN_GROUP}/staff",), ADMISSION, AppRole.USER, id="a login subgroup"),
        pytest.param(
            (f"{LOGIN_GROUP}2",), ADMISSION, None, id="a group named like the login group"
        ),
        pytest.param((), ADMISSION, None, id="no groups"),
        pytest.param((), EVERYONE, AppRole.USER, id="no groups under every subject"),
        pytest.param(
            (str(ADMIN_GROUP),), EVERYONE, AppRole.ADMIN, id="the admin group under every subject"
        ),
        pytest.param(
            (str(LOGIN_GROUP),),
            EVERYONE_WITH_ADMIN_GROUP,
            AppRole.USER,
            id="every subject without the admin group",
        ),
        pytest.param(
            (str(ADMIN_GROUP),), NO_ADMINS, AppRole.USER, id="the admin path without admins"
        ),
    ],
)
def test_app_role_names_the_role_the_groups_carry(
    groups: tuple[str, ...],
    admission: AdmissionConfig,
    role: AppRole | None,
) -> None:
    """APP-19: app_role is the role sign-in admission stores, and refuses where sign-in refuses."""
    derived = app_role(groups, admission)
    host = an_oidc_host(groups_claim=list(groups), admission=admission)

    response = host.callback(host.sign_in_at_issuer())

    assert derived is role
    assert [account.role for account in host.accounts.list()] == (
        [] if derived is None else [derived.value]
    )
    assert (response.status_code == 303) is (derived is not None)
