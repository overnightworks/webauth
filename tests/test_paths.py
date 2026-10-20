"""Which addresses a login may send a browser back to, judged by `same_app_path` alone."""

from __future__ import annotations

import pytest
from fastapi import FastAPI
from starlette.requests import Request
from webauth_arrangement import an_http_scope

from webauth._paths import same_app_path

_A_LONG_PATH = "/" + "a" * 511
_RETURN_PATH_CASES = [
    pytest.param("", "/albums/42", "/albums/42", id="a deep link"),
    pytest.param("", "/albums/42?x=1", "/albums/42?x=1", id="a deep link with its query"),
    pytest.param("", "/%2F%2Fevil.example", "/%2F%2Fevil.example", id="an encoded path"),
    pytest.param(
        "", "/lieder/%C3%BC%3Fx?y=1", "/lieder/%C3%BC%3Fx?y=1", id="encoded characters stay raw",
    ),
    pytest.param("", "/lieder/\u00fc", "/lieder/%C3%BC", id="a non-ASCII path is encoded"),
    pytest.param("", "/", "/", id="the root"),
    pytest.param("", _A_LONG_PATH, _A_LONG_PATH, id="the longest path"),
    pytest.param("/app", "/app", "/app", id="the app root"),
    pytest.param("/app", "/app/", "/app/", id="the app root with a slash"),
    pytest.param("/app", "/app/albums/42", "/app/albums/42", id="a deep link below the app"),
    pytest.param("", "//evil.example", None, id="two slashes"),
    pytest.param("", "/\\evil.example", None, id="slash backslash"),
    pytest.param("", "\\\\evil.example", None, id="two backslashes"),
    pytest.param("", "\\/evil.example", None, id="backslash slash"),
    pytest.param("", "/\t/evil.example", None, id="a tab between the slashes"),
    pytest.param("", "/\r/evil.example", None, id="a CR between the slashes"),
    pytest.param("", "/\n/evil.example", None, id="an LF between the slashes"),
    pytest.param("", "https://evil.example", None, id="an absolute URL"),
    pytest.param("", "https:/evil.example", None, id="a scheme with one slash"),
    pytest.param("", "javascript:alert(1)", None, id="a script URL"),
    pytest.param("", "evil.example", None, id="a bare host"),
    pytest.param("", "/albums/\x01", None, id="a C0 control"),
    pytest.param("", "/albums/\x7f", None, id="DEL"),
    pytest.param("", "", None, id="the empty string"),
    pytest.param("", _A_LONG_PATH + "a", None, id="one byte over the cap"),
    pytest.param("", "/\u00fc" * 74, None, id="an encoded form over the cap"),
    pytest.param("/app", "/", None, id="the root outside the app"),
    pytest.param("/app", "/other", None, id="another path outside the app"),
    pytest.param("/app", "/application", None, id="a sibling of the app's name"),
    pytest.param(
        "/café", "/caf%C3%A9/albums/42", None, id="an encoded path under a non-ASCII root",
    ),
    pytest.param("/café", "/café/albums/42", None, id="a path under a non-ASCII root"),
    pytest.param("/a%20b", "/a%20b/albums/42", None, id="a root with a percent sign"),
    pytest.param("/my-app", "/my-app/albums/42", "/my-app/albums/42", id="a root with a hyphen"),
    pytest.param("", "/albums/..x", "/albums/..x", id="dots inside a segment"),
    pytest.param("", "/albums/x.", "/albums/x.", id="a trailing dot in a segment"),
    pytest.param("/app", "/app/../other", None, id="a dot-dot segment leaving the app"),
    pytest.param("/app", "/app/%2e%2e/other", None, id="an encoded dot-dot segment"),
    pytest.param("/app", "/app/%2E%2e//evil.example", None, id="a mixed-case encoded dot-dot"),
    pytest.param("/app", "/app/..\\other", None, id="a dot-dot segment before a backslash"),
    pytest.param("", "/albums/./42", None, id="a dot segment"),
    pytest.param("", "/albums/.%2e/x", None, id="a half-encoded dot-dot segment"),
    pytest.param("", "/albums/x/..?next=1", None, id="a dot-dot segment before the query"),
    pytest.param("", "/albums?back=../x", "/albums?back=../x", id="dots in the query"),
    pytest.param("/app", "/app/..#x", None, id="a dot-dot segment before a fragment mark"),
    pytest.param("/app", "/app/%2E%2E#x", None, id="an encoded dot-dot before a fragment mark"),
    pytest.param("", "/albums/42#top", None, id="a literal fragment mark"),
    pytest.param("", "/albums/42?q=%23x", "/albums/42?q=%23x", id="an encoded fragment mark"),
]


@pytest.mark.parametrize(("root_path", "asked_for", "returned"), _RETURN_PATH_CASES)
def test_only_a_path_of_this_app_is_a_return_path(
    root_path: str, asked_for: str, returned: str | None,
) -> None:
    scope = {**an_http_scope(FastAPI()), "root_path": root_path}

    assert same_app_path(Request(scope), asked_for) == returned
