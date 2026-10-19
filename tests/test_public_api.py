"""Every module declares its public names, and the typing host imports only those."""

from __future__ import annotations

import ast
import importlib
import pkgutil
import sys
from collections.abc import Iterator
from pathlib import Path

import pytest

import webauth
from webauth import WebAuthError
from webauth.https_client import ExchangeFailure, KeySetFetchError
from webauth.oidc import TokenEndpointError
from webauth.ports import UsernameTakenError
from webauth.session_administration import NotAnAdminError, UnknownSessionError

TYPING_HOST = Path(__file__).parent / "typing" / "oidc_host.py"
WEBAUTH_MODULES = [
    "webauth",
    *(module.name for module in pkgutil.walk_packages(webauth.__path__, "webauth.")),
]
HOST_TREE = ast.parse(TYPING_HOST.read_text())


def _is_webauth_module(name: str | None) -> bool:
    return name is not None and name.split(".")[0] == "webauth"


def _names_imported_from_webauth() -> list[tuple[str, str]]:
    return [
        (statement.module or "", alias.name)
        for statement in ast.walk(HOST_TREE)
        if isinstance(statement, ast.ImportFrom) and _is_webauth_module(statement.module)
        for alias in statement.names
    ]


def _module_imports_in_the_host() -> list[str]:
    return [
        alias.name
        for statement in ast.walk(HOST_TREE)
        if isinstance(statement, ast.Import)
        for alias in statement.names
        if _is_webauth_module(alias.name)
    ]


def test_the_typing_host_imports_webauth_names_only_with_from_statements() -> None:
    assert _module_imports_in_the_host() == []
    assert _names_imported_from_webauth()


@pytest.mark.parametrize("module_name", WEBAUTH_MODULES)
def test_every_module_declares_its_public_names(module_name: str) -> None:
    assert isinstance(getattr(importlib.import_module(module_name), "__all__", None), list)


@pytest.mark.parametrize(("module", "name"), sorted(set(_names_imported_from_webauth())))
def test_every_name_the_oidc_only_host_imports_is_public(module: str, name: str) -> None:
    assert name in importlib.import_module(module).__all__


def _re_exports_of(module_name: str) -> list[tuple[str, str]]:
    module = importlib.import_module(module_name)
    return [
        (name, home)
        for name in module.__all__
        if _is_webauth_module(home := getattr(getattr(module, name), "__module__", None))
        and home != module_name
    ]


@pytest.mark.parametrize("module_name", WEBAUTH_MODULES)
def test_a_re_exported_name_is_public_in_its_defining_module_too(module_name: str) -> None:
    for name, home in _re_exports_of(module_name):
        assert name in importlib.import_module(home).__all__, f"{home} must list {name}"


def _is_webauth_or_redis_module(name: str) -> bool:
    return name.split(".")[0] in {"webauth", "redis"}


@pytest.fixture
def webauth_modules_imported_afresh_without_redis() -> Iterator[None]:
    original = {
        name: module for name, module in sys.modules.items() if _is_webauth_or_redis_module(name)
    }
    for name in original:
        del sys.modules[name]
    sys.modules["redis"] = None
    try:
        yield
    finally:
        for name in [name for name in sys.modules if _is_webauth_or_redis_module(name)]:
            del sys.modules[name]
        sys.modules.update(original)


@pytest.mark.usefixtures("webauth_modules_imported_afresh_without_redis")
def test_every_module_imports_and_the_single_process_backend_counts_without_redis() -> None:
    for module_name in WEBAUTH_MODULES:
        importlib.import_module(module_name)
    backend = sys.modules["webauth.rate_limit"].SingleProcessRateLimitBackend()

    assert backend.is_allowed("address", limit=1, window_seconds=60)
    assert not backend.is_allowed("address", limit=1, window_seconds=60)


@pytest.mark.parametrize(
    ("error", "failure"),
    [
        pytest.param(UsernameTakenError("taken"), None, id="UsernameTakenError"),
        pytest.param(NotAnAdminError("taken"), None, id="NotAnAdminError"),
        pytest.param(UnknownSessionError("taken"), None, id="UnknownSessionError"),
        pytest.param(
            KeySetFetchError("taken", ExchangeFailure.TIMED_OUT),
            ExchangeFailure.TIMED_OUT,
            id="KeySetFetchError",
        ),
        pytest.param(
            TokenEndpointError("taken", ExchangeFailure.TIMED_OUT),
            ExchangeFailure.TIMED_OUT,
            id="TokenEndpointError",
        ),
    ],
)
def test_every_public_operational_error_is_caught_as_web_auth_error_with_its_payload(
    error: Exception, failure: ExchangeFailure | None,
) -> None:
    with pytest.raises(WebAuthError) as caught:
        raise error

    assert str(caught.value) == "taken"
    assert getattr(caught.value, "failure", None) is failure
