"""The language the start route names to the issuer: the host's `ui_language` callable, the
`ui_locales` parameter of the authorization request and the tags webauth refuses to send.

The expected requests come from OpenID Connect Core 1.0 section 3.1.2.1 and the host contract's
LANGUAGE- sentences, never from the implementation.
"""

from __future__ import annotations

import logging
import urllib.parse

import pytest
from fastapi import FastAPI, Request
from fastapi.routing import APIRoute
from starlette.responses import Response

from tests.support.oidc_arrangement import a_relying_party
from tests.support.oidc_login_host import (
    ADMISSION,
    SIGN_IN_PATHS,
    START_PATH,
    OidcHost,
    an_oidc_host,
)
from webauth.languages import AppLanguages, resolve_language
from webauth.oidc import OidcRelyingParty
from webauth.sign_in_routes import LogoutPageText, install_sign_in_routes

LANGUAGE_PARAMETER = "ui_locales"
MALFORMED_TAGS = [
    pytest.param("pt_BR", id="underscore"),
    pytest.param("", id="empty"),
    pytest.param("de en", id="two tags with a space"),
    pytest.param("de-", id="trailing hyphen"),
    pytest.param("de&prompt=none", id="a second parameter"),
]


def _parameters(authorization_url: str) -> list[tuple[str, str]]:
    return urllib.parse.parse_qsl(urllib.parse.urlsplit(authorization_url).query)


def _named(parameters: list[tuple[str, str]], name: str) -> list[str]:
    return [value for key, value in parameters if key == name]


def _fixed_parameters_of_the_request(host: OidcHost) -> list[tuple[str, str]]:
    """The request's parameters without the three a login draws afresh and without the language."""
    drawn_afresh = {"state", "nonce", "code_challenge", LANGUAGE_PARAMETER}
    return [(name, value) for name, value in _parameters(host.start()) if name not in drawn_afresh]


def _header_names_sent(messages: list[dict[str, object]]) -> list[bytes]:
    headers = [header for message in messages for header in message.get("headers", [])]  # pyright: ignore[reportGeneralTypeIssues]
    return [name for name, _value in headers]


@pytest.mark.parametrize("tag", ["de", "de-CH", "DE-ch", "zh-Hant-TW"])
def test_a_tag_the_host_names_is_sent_once_as_the_host_spelled_it(tag: str) -> None:
    """LANGUAGE-23: the start route sends `ui_locales=<tag>` exactly once, spelling kept."""
    host = an_oidc_host(ui_language=lambda _request: tag)

    sent = _parameters(host.start())

    assert _named(sent, LANGUAGE_PARAMETER) == [tag]


def test_no_language_sends_the_request_without_the_parameter_and_changes_no_other() -> None:
    """LANGUAGE-24: `None` sends no `ui_locales`, and the other parameters are those a tag
    leaves in place."""
    without = an_oidc_host(ui_language=lambda _request: None)
    with_tag = an_oidc_host(ui_language=lambda _request: "de")

    sent_without = _parameters(without.start())

    assert LANGUAGE_PARAMETER not in [name for name, _value in sent_without]
    assert _fixed_parameters_of_the_request(with_tag) == _fixed_parameters_of_the_request(without)


def test_the_value_is_stored_in_no_pending_cookie_no_session_and_no_log_line(
    caplog: pytest.LogCaptureFixture,
) -> None:
    """LANGUAGE-27: the named language is kept in neither the pending cookie nor the session,
    and no log line of the sign-in carries it."""
    tag = "tlh-Latn-QX"
    host = an_oidc_host(ui_language=lambda _request: tag)
    caplog.set_level(logging.DEBUG)

    query = host.sign_in_at_issuer()
    pending_cookie = host.pending_cookie(query)
    callback = host.callback(query)

    assert callback.status_code == 303
    assert host.account_language() is None
    assert tag not in pending_cookie
    assert tag not in caplog.text


def test_the_start_route_calls_the_hosts_callable_once_with_the_start_request() -> None:
    """LANGUAGE-22: the callable is called once per start request, with that request, so a host
    resolves the language from the request's headers."""
    languages = AppLanguages(offered=("en", "de"), default="en")
    received: list[Request] = []

    def ui_language(request: Request) -> str | None:
        received.append(request)
        return resolve_language(
            languages,
            account_tag=None,
            accept_language=request.headers.get("accept-language"),
        )

    host = an_oidc_host(ui_language=ui_language)

    location = host.client.get(START_PATH, headers={"accept-language": "de-AT, en;q=0.5"})

    assert [request.url.path for request in received] == [START_PATH]
    assert _named(_parameters(location.headers["location"]), LANGUAGE_PARAMETER) == ["de"]


@pytest.mark.parametrize("tag", MALFORMED_TAGS)
def test_a_malformed_tag_raises_value_error_and_nothing_goes_to_the_issuer(tag: str) -> None:
    """LANGUAGE-25: a string that is not a language tag in shape raises `ValueError` from the
    start route, which sends no redirect and sets no pending cookie."""
    host = an_oidc_host(ui_language=lambda _request: tag)

    messages, raised = host.drive_start()

    assert isinstance(raised, ValueError)
    assert b"location" not in _header_names_sent(messages)
    assert b"set-cookie" not in _header_names_sent(messages)


@pytest.mark.parametrize("tag", ["de", "de-CH", None])
def test_begin_login_alone_names_the_language_the_same_way(tag: str | None) -> None:
    """LANGUAGE-26: `begin_login(ui_locales=...)` sends the tag once as given, or no parameter
    for `None`."""
    relying_party = a_relying_party()

    sent = _parameters(relying_party.begin_login(ui_locales=tag).url)

    assert _named(sent, LANGUAGE_PARAMETER) == ([] if tag is None else [tag])


@pytest.mark.parametrize("tag", MALFORMED_TAGS)
def test_begin_login_refuses_a_malformed_tag_with_value_error(tag: str) -> None:
    """LANGUAGE-26: `begin_login` raises `ValueError` for a string that is not a language tag
    in shape, for a host that calls it directly."""
    relying_party: OidcRelyingParty = a_relying_party()

    with pytest.raises(ValueError, match="language tag"):
        relying_party.begin_login(ui_locales=tag)


def test_installing_without_naming_the_language_raises_and_registers_no_route() -> None:
    """LANGUAGE-21: `ui_language` has no default: install without it raises `TypeError`."""
    app = FastAPI()
    host = an_oidc_host()
    arguments: dict[str, object] = {
        "paths": SIGN_IN_PATHS,
        "relying_party": lambda _request: host.relying_party,
        "admission": ADMISSION,
        "transaction": host.transaction,
        "refused": lambda _request, _refusal: Response(status_code=403),
        "keeps_id_token": True,
        "max_sessions": None,
        "logout_page_text": lambda _request: LogoutPageText(language="en", button_label="Out"),
    }

    with pytest.raises(TypeError, match="ui_language"):
        install_sign_in_routes(app, **arguments)  # type: ignore[arg-type]

    assert not [route for route in app.routes if isinstance(route, APIRoute)]
