"""The names the OIDC-only typing host imports are declared public by their modules."""

from __future__ import annotations

import ast
import importlib
from pathlib import Path

import pytest

TYPING_HOST = Path(__file__).parent / "typing" / "oidc_host.py"


def _names_imported_from_webauth(source: str) -> list[tuple[str, str]]:
    return [
        (statement.module, alias.name)
        for statement in ast.walk(ast.parse(source))
        if isinstance(statement, ast.ImportFrom)
        and statement.module is not None
        and statement.module.split(".")[0] == "webauth"
        for alias in statement.names
    ]


def _declared_public_names(module_name: str) -> list[str] | None:
    return getattr(importlib.import_module(module_name), "__all__", None)


# Transitional: S10d makes every module declare __all__ and drops the filter.
_DECLARED_IMPORTS = sorted(
    (module, name)
    for module, name in _names_imported_from_webauth(TYPING_HOST.read_text())
    if _declared_public_names(module) is not None
)


def test_the_typing_host_imports_from_modules_that_declare_their_public_names() -> None:
    assert _DECLARED_IMPORTS


@pytest.mark.parametrize(("module", "name"), _DECLARED_IMPORTS)
def test_every_name_the_oidc_only_host_imports_is_public(module: str, name: str) -> None:
    assert name in (_declared_public_names(module) or [])
