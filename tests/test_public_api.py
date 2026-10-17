"""Every module declares its public names, and the typing host imports only those."""

from __future__ import annotations

import ast
import importlib
import pkgutil
from pathlib import Path

import pytest

import webauth

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
