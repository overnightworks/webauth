"""The deployment facts the auth machinery reads, and the rules they must meet."""

from __future__ import annotations

from collections.abc import Callable
from dataclasses import replace
from decimal import Decimal

import pytest
from fastapi import Depends, FastAPI
from fastapi.testclient import TestClient
from pydantic import SecretStr

from tests.support.webauth_arrangement import (
    HTTPS_TEST_SERVER,
    MIN_SESSION_SECRET_CHARS,
    SESSION_ABSOLUTE_MAX_AGE_SECONDS,
    a_web_auth_config,
    web_auth_config_arguments,
)
from webauth.config import (
    SessionLifetime,
    WebAuthConfig,
    install_web_auth_config,
    web_auth_config,
)
from webauth.cookies import (
    DEFAULT_SESSION_COOKIE_NAME,
    PLAIN_SESSION_COOKIE_NAME,
)


def test_a_secret_shorter_than_the_floor_is_refused() -> None:
    """It signs every session cookie, so a guessable one hands out sessions."""
    short = SecretStr("s" * (MIN_SESSION_SECRET_CHARS - 1))

    with pytest.raises(ValueError, match="at least 32 characters"):
        a_web_auth_config(session_secret=short)


def test_a_secret_at_the_floor_is_accepted() -> None:
    secret = a_web_auth_config().session_secret

    assert secret.get_secret_value() == "s" * MIN_SESSION_SECRET_CHARS


def test_the_signing_key_is_the_secret_the_signatures_take() -> None:
    assert a_web_auth_config().signing_key == b"s" * MIN_SESSION_SECRET_CHARS


def test_the_secret_never_shows_up_in_the_configuration_it_belongs_to() -> None:
    """A configuration lands in logs and tracebacks; the secret must not."""
    assert "s" * MIN_SESSION_SECRET_CHARS not in repr(a_web_auth_config())


def test_names_and_roles_default_to_the_conventional_ones() -> None:
    config = a_web_auth_config()

    assert config.session_cookie_name == DEFAULT_SESSION_COOKIE_NAME == "__Host-session_id"
    assert config.cookie_samesite == "strict"
    assert config.cookie_secure is True
    assert config.admin_role == "admin"
    assert config.user_role == "user"


def test_a_configuration_built_positionally_is_refused() -> None:
    positional_arguments = list(web_auth_config_arguments().values())

    with pytest.raises(TypeError, match="positional"):
        WebAuthConfig(*positional_arguments)  # pyright: ignore[reportCallIssue] -- positional on purpose


@pytest.mark.parametrize("value", [None, "none"])
def test_a_cross_site_cookie_samesite_is_refused_at_configuration_time(
    value: str | None,
) -> None:
    with pytest.raises(ValueError, match="cross-site cookie"):
        a_web_auth_config(cookie_samesite=value)


@pytest.mark.parametrize("value", ["false", 0, None])
def test_a_cookie_secure_that_is_not_a_bool_is_refused_at_configuration_time(
    value: object,
) -> None:
    with pytest.raises(ValueError, match="cookie_secure must be True or False"):
        a_web_auth_config(cookie_secure=value)


def test_the_ipv6_budget_prefix_defaults_to_one_subscriber_network() -> None:
    assert a_web_auth_config().ipv6_budget_prefix == 64


LIFETIMES: dict[str, Callable[[object], object]] = {
    "idle_seconds": lambda seconds: SessionLifetime(
        seconds,  # pyright: ignore[reportArgumentType] -- not an int on purpose
        SESSION_ABSOLUTE_MAX_AGE_SECONDS,
    ),
    "absolute_max_age_seconds": lambda seconds: SessionLifetime(
        1,
        seconds,  # pyright: ignore[reportArgumentType] -- not an int on purpose
    ),
}


@pytest.mark.parametrize("lifetime", LIFETIMES)
@pytest.mark.parametrize("seconds", [True, 60.0, 1.5, "60", 0, -1])
def test_a_lifetime_other_than_a_positive_whole_number_of_seconds_is_refused_at_construction(
    lifetime: str,
    seconds: object,
) -> None:
    field = lifetime.split()[-1]
    with pytest.raises(ValueError, match=f"{field} must be a positive whole number of seconds"):
        LIFETIMES[lifetime](seconds)


@pytest.mark.parametrize("lifetime", LIFETIMES)
def test_a_lifetime_of_one_second_is_accepted(lifetime: str) -> None:
    LIFETIMES[lifetime](1)


def test_a_cap_of_400_days_is_accepted() -> None:
    SessionLifetime(3600, 34_560_000)


def test_a_cap_beyond_400_days_is_refused_at_construction() -> None:
    with pytest.raises(ValueError, match="absolute_max_age_seconds must not exceed 34560000"):
        SessionLifetime(3600, 34_560_001)


def test_a_lifetime_idling_as_long_as_its_cap_is_accepted() -> None:
    SessionLifetime(43200, 43200)


def test_a_lifetime_idling_longer_than_its_cap_is_refused() -> None:
    with pytest.raises(ValueError, match="idle_seconds must not exceed"):
        SessionLifetime(3600, 1800)


@pytest.mark.parametrize("prefix", [32, 128])
def test_an_ipv6_budget_prefix_at_either_bound_is_accepted(prefix: int) -> None:
    assert a_web_auth_config(ipv6_budget_prefix=prefix).ipv6_budget_prefix == prefix


@pytest.mark.parametrize("prefix", [31, 129, 64.0, Decimal(64), True])
def test_an_ipv6_budget_prefix_other_than_an_integer_within_its_bounds_is_refused(
    prefix: object,
) -> None:
    with pytest.raises(
        ValueError,
        match="ipv6_budget_prefix must be an integer between 32 and 128",
    ):
        a_web_auth_config(ipv6_budget_prefix=prefix)


@pytest.mark.parametrize("cookie_secure", [True, False])
def test_the_session_cookie_name_follows_cookie_secure_through_construction_and_replace(
    cookie_secure: bool,
) -> None:
    expected = DEFAULT_SESSION_COOKIE_NAME if cookie_secure else PLAIN_SESSION_COOKIE_NAME
    opposite = a_web_auth_config(cookie_secure=not cookie_secure)

    built = a_web_auth_config(cookie_secure=cookie_secure)
    replaced = replace(opposite, cookie_secure=cookie_secure)

    assert built.session_cookie_name == expected
    assert replaced.session_cookie_name == expected


def test_a_session_cookie_name_of_the_hosts_own_is_refused_at_construction() -> None:
    with pytest.raises(TypeError, match="session_cookie_name"):
        a_web_auth_config(session_cookie_name="sid")


@pytest.mark.parametrize(
    ("overrides", "message"),
    [
        pytest.param(
            {"admin_role": "user", "user_role": "user"},
            "admin_role and user_role must differ",
            id="equal roles",
        ),
        pytest.param({"admin_role": " "}, "admin_role must name a role", id="blank admin role"),
        pytest.param({"user_role": ""}, "user_role must name a role", id="empty user role"),
        pytest.param({"admin_role": None}, "admin_role must name a role", id="no admin role"),
        pytest.param({"user_role": 5}, "user_role must name a role", id="a numeric user role"),
    ],
)
def test_a_role_that_cannot_work_is_refused_at_configuration_time(
    overrides: dict[str, object],
    message: str,
) -> None:
    with pytest.raises(ValueError, match=message):
        a_web_auth_config(**overrides)


@pytest.mark.parametrize(
    "overrides",
    [
        pytest.param({}, id="the defaults"),
        pytest.param({"admin_role": "operator", "user_role": "member"}, id="custom roles"),
    ],
)
def test_distinct_roles_are_accepted(
    overrides: dict[str, object],
) -> None:
    a_web_auth_config(**overrides)


def test_a_request_reads_the_configuration_installed_on_its_application() -> None:
    config = a_web_auth_config()
    app = FastAPI()
    install_web_auth_config(app, config)

    @app.get("/config-secret-length")
    def config_secret_length(installed: WebAuthConfig = Depends(web_auth_config)) -> dict:
        return {"length": len(installed.signing_key)}

    with TestClient(app, base_url=HTTPS_TEST_SERVER) as client:
        assert client.get("/config-secret-length").json() == {
            "length": MIN_SESSION_SECRET_CHARS,
        }


def test_an_application_without_a_configuration_refuses_the_request() -> None:
    """Reading the deployment's facts is not optional. An application that
    never installed them must say so, because the alternative is auth
    machinery quietly deciding on defaults nobody chose."""
    app = FastAPI()

    @app.get("/config-secret-length")
    def config_secret_length(installed: WebAuthConfig = Depends(web_auth_config)) -> dict:
        return {"length": len(installed.signing_key)}

    with (
        TestClient(app, base_url=HTTPS_TEST_SERVER) as client,
        pytest.raises(RuntimeError, match="install_web_auth_config"),
    ):
        client.get("/config-secret-length")


def test_the_configuration_cannot_be_changed_after_it_is_installed() -> None:
    """Every reader must see the same facts for the life of the process."""
    config = a_web_auth_config()

    with pytest.raises(AttributeError):
        config.cookie_secure = False  # pyright: ignore[reportAttributeAccessIssue] -- frozen on purpose

    assert replace(config, cookie_secure=False).cookie_secure is False


def test_an_empty_host_list_is_refused_naming_the_field_and_the_localhost_hint() -> None:
    with pytest.raises(ValueError) as refusal:
        a_web_auth_config(allowed_hosts_exact=frozenset())

    message = str(refusal.value)
    assert "allowed_hosts_exact" in message
    assert 'allowed_hosts_exact={"localhost", "127.0.0.1"}' in message


def test_a_single_string_for_the_host_list_is_refused_naming_the_field() -> None:
    with pytest.raises(ValueError) as refusal:
        a_web_auth_config(allowed_hosts_exact="notes.example")

    assert "allowed_hosts_exact" in str(refusal.value)
