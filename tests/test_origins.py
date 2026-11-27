"""Which Origin headers name a host this application serves, judged by `origin_verdict` alone."""

from __future__ import annotations

import pytest
from starlette.datastructures import Headers

from tests.support.webauth_arrangement import ALLOWED_HOST, ALLOWED_ORIGIN, a_web_auth_config
from webauth._origins import OriginVerdict, origin_verdict

ABSENT = OriginVerdict.ABSENT
ALLOWED = OriginVerdict.ALLOWED
FOREIGN = OriginVerdict.FOREIGN

_LOCALHOST_AND_LOOPBACK = frozenset({"localhost", "127.0.0.1"})

# (allowed_hosts_exact, cookie_secure, origins sent, verdict); None keeps the default.
_VERDICT_CASES = [
    pytest.param(None, None, [], ABSENT, id="no origin"),
    pytest.param(None, None, [ALLOWED_ORIGIN], ALLOWED, id="the allowed origin"),
    pytest.param(
        None,
        None,
        [f"{ALLOWED_ORIGIN}:8000"],
        ALLOWED,
        id="the allowed host with a port",
    ),
    pytest.param(None, None, ["https://evil.test"], FOREIGN, id="a foreign origin"),
    pytest.param(
        None,
        None,
        ["https://evil.notes.example"],
        FOREIGN,
        id="an unlisted sibling of the allowed host",
    ),
    pytest.param(
        None,
        None,
        [f"https://{ALLOWED_HOST}.evil.test"],
        FOREIGN,
        id="the host as a prefix",
    ),
    pytest.param(
        None,
        None,
        [f"https://{ALLOWED_HOST}@evil.test"],
        FOREIGN,
        id="the host as userinfo",
    ),
    pytest.param(
        None,
        None,
        [f"https://{ALLOWED_HOST}:password@evil.test"],
        FOREIGN,
        id="userinfo spelling the allowed host and a password",
    ),
    pytest.param(None, None, ["null"], FOREIGN, id="a null origin"),
    pytest.param(None, None, [""], FOREIGN, id="an empty origin"),
    pytest.param(None, None, ["http://"], FOREIGN, id="an origin without a host"),
    pytest.param(None, None, ["http://[bad"], FOREIGN, id="an origin that cannot be parsed"),
    pytest.param(None, None, [f"{ALLOWED_ORIGIN}:evil"], FOREIGN, id="a non-numeric port"),
    pytest.param(
        None,
        None,
        ["https://[::1]:evil"],
        FOREIGN,
        id="an IPv6 origin with a non-numeric port",
    ),
    pytest.param(
        None,
        None,
        [ALLOWED_ORIGIN, ALLOWED_ORIGIN],
        FOREIGN,
        id="a repeated origin header, both allowed",
    ),
    pytest.param(
        None,
        None,
        [ALLOWED_ORIGIN, "https://evil.test"],
        FOREIGN,
        id="a repeated origin header, one foreign",
    ),
    pytest.param(
        {"*.example.test"},
        None,
        ["https://notes.example.test"],
        FOREIGN,
        id="a wildcard subdomain entry matches nothing",
    ),
    pytest.param(
        {"*"},
        None,
        ["https://notes.example.test"],
        FOREIGN,
        id="a bare wildcard entry matches nothing",
    ),
    pytest.param(
        {"notes.*"},
        None,
        ["https://notes.example.test"],
        FOREIGN,
        id="a wildcard suffix entry matches nothing",
    ),
    pytest.param(
        {".*"},
        None,
        ["https://notes.example.test"],
        FOREIGN,
        id="a regular expression entry matches nothing",
    ),
    pytest.param({"[::1]"}, None, ["https://[::1]"], ALLOWED, id="a bracketed IPv6 host"),
    pytest.param(
        {"[::1]:8000"},
        None,
        ["https://[::1]:8000"],
        ALLOWED,
        id="a bracketed IPv6 host with a port",
    ),
    pytest.param(
        _LOCALHOST_AND_LOOPBACK,
        False,
        ["http://localhost:8000"],
        ALLOWED,
        id="a listed localhost admits any port over http",
    ),
    pytest.param(
        _LOCALHOST_AND_LOOPBACK,
        False,
        ["http://127.0.0.1:5173"],
        ALLOWED,
        id="a listed loopback address admits any port over http",
    ),
    pytest.param(
        _LOCALHOST_AND_LOOPBACK,
        True,
        ["https://localhost:8000"],
        ALLOWED,
        id="a listed localhost admits any port over https",
    ),
    pytest.param(
        _LOCALHOST_AND_LOOPBACK,
        True,
        ["https://127.0.0.1:5173"],
        ALLOWED,
        id="a listed loopback address admits any port over https",
    ),
    pytest.param(
        {"notes.example:8443"},
        None,
        ["https://notes.example:8443"],
        ALLOWED,
        id="a host listed with a port admits that port",
    ),
    pytest.param(
        {"notes.example:8443"},
        None,
        ["https://notes.example:9443"],
        FOREIGN,
        id="a host listed with a port refuses another port",
    ),
    pytest.param(
        {"notes.example:8443"},
        None,
        ["https://notes.example"],
        FOREIGN,
        id="a host listed with a port refuses the bare host",
    ),
    pytest.param(
        None,
        True,
        [f"http://{ALLOWED_HOST}"],
        FOREIGN,
        id="an http origin while cookie_secure is on",
    ),
    pytest.param(
        None,
        True,
        [f"HTTP://{ALLOWED_HOST}"],
        FOREIGN,
        id="an upper-case http origin while cookie_secure is on",
    ),
    pytest.param(
        None,
        False,
        [f"http://{ALLOWED_HOST}"],
        ALLOWED,
        id="an http origin while cookie_secure is off",
    ),
    pytest.param(
        None,
        False,
        [ALLOWED_ORIGIN],
        ALLOWED,
        id="an https origin while cookie_secure is off",
    ),
]


@pytest.mark.parametrize(("allowed_hosts", "cookie_secure", "origins", "verdict"), _VERDICT_CASES)
def test_the_origin_verdict_of_a_request(
    allowed_hosts: set[str] | frozenset[str] | None,
    cookie_secure: bool | None,
    origins: list[str],
    verdict: OriginVerdict,
) -> None:
    """CSRF-12, CSRF-13, CSRF-14: only an exact allowed host is allowed; a repeat is foreign."""
    overrides = {
        **({} if allowed_hosts is None else {"allowed_hosts_exact": frozenset(allowed_hosts)}),
        **({} if cookie_secure is None else {"cookie_secure": cookie_secure}),
    }
    headers = Headers(raw=[(b"origin", origin.encode()) for origin in origins])

    assert origin_verdict(headers, a_web_auth_config(**overrides)) is verdict


def test_a_referer_is_no_origin() -> None:
    headers = Headers({"referer": f"{ALLOWED_ORIGIN}/page"})

    assert origin_verdict(headers, a_web_auth_config()) is ABSENT
