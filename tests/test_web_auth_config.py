"""The deployment facts the auth machinery reads, and the rules they must meet."""

from __future__ import annotations

from collections.abc import Callable
from dataclasses import replace
from decimal import Decimal

import pytest
from fastapi import Depends, FastAPI
from fastapi.testclient import TestClient
from pydantic import SecretStr
from webauth_arrangement import (
    HTTPS_TEST_SERVER,
    IDLE_WINDOW_SECONDS,
    SESSION_MAX_AGE_SECONDS,
    a_web_auth_config,
    web_auth_config_arguments,
)

from webauth.config import (
    MIN_SESSION_SECRET_CHARS,
    WebAuthConfig,
    install_web_auth_config,
    web_auth_config,
)
from webauth.cookies import (
    DEFAULT_CSRF_COOKIE_NAME,
    DEFAULT_SESSION_COOKIE_NAME,
    PLAIN_CSRF_COOKIE_NAME,
    PLAIN_SESSION_COOKIE_NAME,
)
from webauth.liveness import ExpiryColumnLiveness, IdleWindowLiveness


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
    assert config.csrf_cookie_name == DEFAULT_CSRF_COOKIE_NAME == "__Host-csrf_token"
    assert config.csrf_header_name == "x-csrf-token"
    assert config.cookie_samesite == "strict"
    assert config.cookie_secure is True
    assert config.admin_role == "admin"
    assert config.user_role == "user"


@pytest.mark.parametrize("removed_keyword", [
    "login_rate_limit",
    "login_lockout_threshold",
    "login_lockout_window_seconds",
    "login_rate_window_seconds",
    "password_hasher",
    "session_max_age_seconds",
])
def test_a_removed_field_is_refused_as_an_unknown_keyword(
    removed_keyword: str,
) -> None:
    with pytest.raises(TypeError, match=removed_keyword):
        a_web_auth_config(**{removed_keyword: 5})


def test_a_configuration_without_a_cookie_lifetime_is_refused() -> None:
    arguments = web_auth_config_arguments()
    del arguments["cookie_max_age_seconds"]

    with pytest.raises(TypeError, match="cookie_max_age_seconds"):
        WebAuthConfig(**arguments)


def test_a_configuration_built_positionally_is_refused() -> None:
    positional_arguments = list(web_auth_config_arguments().values())

    with pytest.raises(TypeError, match="positional"):
        WebAuthConfig(*positional_arguments)


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
    "cookie_max_age_seconds": lambda seconds: a_web_auth_config(cookie_max_age_seconds=seconds),
    "absolute_max_age_seconds": ExpiryColumnLiveness,
    "idle_window_seconds": IdleWindowLiveness,
    "idle-window absolute_max_age_seconds": lambda seconds: IdleWindowLiveness(
        IDLE_WINDOW_SECONDS, absolute_max_age_seconds=seconds,
    ),
}


@pytest.mark.parametrize("lifetime", LIFETIMES)
@pytest.mark.parametrize("seconds", [True, 60.0, 1.5, "60", 0, -1])
def test_a_lifetime_other_than_a_positive_whole_number_of_seconds_is_refused_at_construction(
    lifetime: str, seconds: object,
) -> None:
    field = lifetime.split()[-1]
    with pytest.raises(ValueError, match=f"{field} must be a positive whole number of seconds"):
        LIFETIMES[lifetime](seconds)


@pytest.mark.parametrize("lifetime", LIFETIMES)
def test_a_lifetime_of_one_second_is_accepted(lifetime: str) -> None:
    LIFETIMES[lifetime](1)


@pytest.mark.parametrize("prefix", [32, 128])
def test_an_ipv6_budget_prefix_at_either_bound_is_accepted(prefix: int) -> None:
    assert a_web_auth_config(ipv6_budget_prefix=prefix).ipv6_budget_prefix == prefix


@pytest.mark.parametrize("prefix", [31, 129, 64.0, Decimal(64), True])
def test_an_ipv6_budget_prefix_other_than_an_integer_within_its_bounds_is_refused(
    prefix: object,
) -> None:
    with pytest.raises(
        ValueError, match="ipv6_budget_prefix must be an integer between 32 and 128",
    ):
        a_web_auth_config(ipv6_budget_prefix=prefix)


@pytest.mark.parametrize("cookie_secure", [True, False])
def test_a_deployment_may_name_the_cookies_itself(cookie_secure: bool) -> None:
    config = a_web_auth_config(
        session_cookie_name="sid", csrf_cookie_name="xsrf", cookie_secure=cookie_secure,
    )

    assert config.session_cookie_name == "sid"
    assert config.csrf_cookie_name == "xsrf"


def test_unnamed_cookies_fall_back_to_plain_names_when_cookie_secure_is_off() -> None:
    """Browsers drop a ``__Host-`` cookie without ``Secure``; the plain name still works."""
    config = a_web_auth_config(cookie_secure=False)

    assert config.session_cookie_name == "session_id"
    assert config.csrf_cookie_name == "csrf_token"


@pytest.mark.parametrize("field", ["session_cookie_name", "csrf_cookie_name"])
@pytest.mark.parametrize(
    "name", ["__Host-session_id", "__host-own", "__Secure-sid", "__SECURE-sid"],
)
def test_a_host_only_cookie_name_without_cookie_secure_is_refused_at_configuration_time(
    field: str, name: str,
) -> None:
    """A browser would drop the cookie silently and the login would loop."""
    with pytest.raises(ValueError, match="needs cookie_secure=True"):
        a_web_auth_config(cookie_secure=False, **{field: name})


@pytest.mark.parametrize(
    ("built_with", "replaced_with", "session_cookie_name", "csrf_cookie_name"),
    [
        pytest.param(
            {}, {"cookie_secure": False},
            PLAIN_SESSION_COOKIE_NAME, PLAIN_CSRF_COOKIE_NAME,
            id="unnamed cookies lose __Host- when Secure is switched off",
        ),
        pytest.param(
            {"cookie_secure": False}, {"cookie_secure": True},
            DEFAULT_SESSION_COOKIE_NAME, DEFAULT_CSRF_COOKIE_NAME,
            id="unnamed cookies gain __Host- when Secure is switched on",
        ),
        pytest.param(
            {"session_cookie_name": "sid"}, {"cookie_secure": False},
            "sid", PLAIN_CSRF_COOKIE_NAME,
            id="a named cookie keeps its name while the unnamed one follows Secure",
        ),
        pytest.param(
            {}, {"session_cookie_name": "sid"},
            "sid", DEFAULT_CSRF_COOKIE_NAME,
            id="a name given while replacing becomes the host's own",
        ),
    ],
)
def test_a_replaced_configuration_resolves_unnamed_cookies_again(
    built_with: dict[str, object],
    replaced_with: dict[str, object],
    session_cookie_name: str,
    csrf_cookie_name: str,
) -> None:
    """``dataclasses.replace`` must not mistake a resolved default for the host's choice."""
    config = replace(a_web_auth_config(**built_with), **replaced_with)

    assert config.session_cookie_name == session_cookie_name
    assert config.csrf_cookie_name == csrf_cookie_name


@pytest.mark.parametrize(
    ("replaced_with", "cookie_max_age_seconds"),
    [
        pytest.param({"cookie_max_age_seconds": 60}, 60, id="replace-sets-the-lifetime"),
        pytest.param({"cookie_secure": False}, SESSION_MAX_AGE_SECONDS, id="replace-keeps-it"),
    ],
)
def test_replacing_a_field_sets_or_keeps_the_cookie_lifetime(
    replaced_with: dict[str, object], cookie_max_age_seconds: int,
) -> None:
    config = replace(a_web_auth_config(), **replaced_with)

    assert config.cookie_max_age_seconds == cookie_max_age_seconds


@pytest.mark.parametrize("field", ["session_cookie_name", "csrf_cookie_name"])
@pytest.mark.parametrize("name", ["__Host-own", "__Secure-own"])
def test_a_prefixed_cookie_name_with_cookie_secure_stays_as_named(field: str, name: str) -> None:
    config = a_web_auth_config(**{field: name})

    assert getattr(config, field) == name


@pytest.mark.parametrize(
    ("overrides", "message"),
    [
        pytest.param(
            {"admin_role": "user", "user_role": "user"}, "admin_role and user_role must differ",
            id="equal roles",
        ),
        pytest.param({"admin_role": " "}, "admin_role must name a role", id="blank admin role"),
        pytest.param({"user_role": ""}, "user_role must name a role", id="empty user role"),
        pytest.param({"admin_role": None}, "admin_role must name a role", id="no admin role"),
        pytest.param({"user_role": 5}, "user_role must name a role", id="a numeric user role"),
        pytest.param(
            {"max_user_agent_chars": -1}, "max_user_agent_chars must be a positive int",
            id="negative user-agent limit",
        ),
        pytest.param(
            {"max_user_agent_chars": 0}, "max_user_agent_chars must be a positive int",
            id="zero user-agent limit",
        ),
        pytest.param(
            {"max_user_agent_chars": True}, "max_user_agent_chars must be a positive int",
            id="boolean user-agent limit",
        ),
    ],
)
def test_a_role_or_user_agent_limit_that_cannot_work_is_refused_at_configuration_time(
    overrides: dict[str, object], message: str,
) -> None:
    with pytest.raises(ValueError, match=message):
        a_web_auth_config(**overrides)


@pytest.mark.parametrize(
    "overrides",
    [
        pytest.param({}, id="the defaults"),
        pytest.param({"admin_role": "operator", "user_role": "member"}, id="custom roles"),
        pytest.param({"max_user_agent_chars": 500}, id="a limit of 500"),
    ],
)
def test_distinct_roles_and_a_positive_user_agent_limit_are_accepted(
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
        config.cookie_max_age_seconds = 1

    assert replace(config, cookie_max_age_seconds=1).cookie_max_age_seconds == 1
