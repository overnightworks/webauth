"""Every module declares its public names, defines them, and consumers take only those."""

from __future__ import annotations

import ast
import functools
import importlib
import pkgutil
import sys
from collections.abc import Iterator
from dataclasses import dataclass
from pathlib import Path

import pytest

import webauth
from webauth import WebAuthError, ports
from webauth.https_client import ExchangeFailure, KeySetFetchError
from webauth.oidc import TokenEndpointError
from webauth.ports import UsernameTakenError
from webauth.session_administration import NotAnAdminError, UnknownSessionError

TESTS = Path(__file__).resolve().parent
REPOSITORY = TESTS.parent
SOURCE = REPOSITORY / "src"
WEBAUTH_MODULES = [
    "webauth",
    *(module.name for module in pkgutil.walk_packages(webauth.__path__, "webauth.")),
]
TYPING_HOSTS = sorted((TESTS / "typing").glob("*.py"))
OTHER_CONSUMERS = sorted(
    path
    for path in [*TESTS.rglob("*.py"), *(REPOSITORY / "e2e").rglob("*.py")]
    if path not in TYPING_HOSTS
)


def _relative_id(path: Path) -> str:
    return str(path.relative_to(REPOSITORY))


def _is_webauth_module(name: str | None) -> bool:
    return name is not None and name.split(".")[0] == "webauth"


def _module_file(dotted_name: str) -> Path | None:
    base = SOURCE.joinpath(*dotted_name.split("."))
    candidates = (base.with_suffix(".py"), base / "__init__.py")
    return next((file for file in candidates if file.is_file()), None)


def _bound_module(alias: ast.alias) -> tuple[str, str]:
    if alias.asname:
        return alias.asname, alias.name
    root = alias.name.split(".")[0]
    return root, root


def _imported_names(statement: ast.Import | ast.ImportFrom) -> dict[str, str]:
    if isinstance(statement, ast.Import):
        return dict(_bound_module(alias) for alias in statement.names)
    return {alias.asname or alias.name: str(statement.module) for alias in statement.names}


def _redundant_reexports(statement: ast.Import | ast.ImportFrom) -> dict[str, int]:
    if isinstance(statement, ast.Import):
        return {
            alias.asname: alias.lineno
            for alias in statement.names
            if alias.asname and alias.asname == alias.name.split(".")[-1]
        }
    if statement.module is None:
        return {alias.asname or alias.name: alias.lineno for alias in statement.names}
    return {
        alias.asname: alias.lineno for alias in statement.names if alias.asname == alias.name
    }


def _mentions_all(statement: ast.stmt) -> bool:
    return any(isinstance(node, ast.Name) and node.id == "__all__" for node in ast.walk(statement))


def _is_literal_all_assignment(statement: ast.stmt) -> bool:
    if isinstance(statement, ast.AnnAssign):
        return isinstance(statement.target, ast.Name) and isinstance(statement.value, ast.List)
    return (
        isinstance(statement, ast.Assign)
        and len(statement.targets) == 1
        and isinstance(statement.targets[0], ast.Name)
        and isinstance(statement.value, ast.List)
    )


@dataclass(frozen=True)
class ModuleSurface:
    public: dict[str, int]
    defined_callables: dict[str, int]
    defined_values: dict[str, int]
    imported_from: dict[str, str]
    redundant_reexports: dict[str, int]
    irregular_all_lines: tuple[int, ...]


@functools.cache
def _surface_of(dotted_name: str) -> ModuleSurface:
    file = _module_file(dotted_name)
    assert file is not None, dotted_name
    public: dict[str, int] = {}
    callables: dict[str, int] = {}
    values: dict[str, int] = {}
    imported: dict[str, str] = {}
    redundant: dict[str, int] = {}
    irregular_all_lines: list[int] = []
    all_declared = False
    for statement in ast.parse(file.read_text()).body:
        if _mentions_all(statement):
            if all_declared or not _is_literal_all_assignment(statement):
                irregular_all_lines.append(statement.lineno)
            else:
                all_declared = True
                public = {element.value: element.lineno for element in statement.value.elts}
            continue
        match statement:
            case ast.FunctionDef(name=name) | ast.AsyncFunctionDef(name=name):
                callables[name] = statement.lineno
            case ast.ClassDef(name=name):
                callables[name] = statement.lineno
            case ast.TypeAlias():
                values[statement.name.id] = statement.lineno
            case ast.Assign() | ast.AnnAssign():
                assigned = (
                    statement.targets if isinstance(statement, ast.Assign) else [statement.target]
                )
                for target in (t for t in assigned if isinstance(t, ast.Name)):
                    values[target.id] = statement.lineno
            case ast.Import() | ast.ImportFrom():
                imported.update(_imported_names(statement))
                redundant.update(_redundant_reexports(statement))
            case ast.If():
                for inner in statement.body:
                    if isinstance(inner, ast.Import | ast.ImportFrom):
                        imported.update(_imported_names(inner))
                        redundant.update(_redundant_reexports(inner))
    return ModuleSurface(
        public, callables, values, imported, redundant, tuple(irregular_all_lines),
    )


def _is_defined_or_forwarded_from_own_submodule(dotted_name: str, name: str) -> bool:
    surface = _surface_of(dotted_name)
    source = surface.imported_from.get(name, "")
    return (
        name in surface.defined_callables
        or name in surface.defined_values
        or (source.startswith(f"{dotted_name}.") and name in _surface_of(source).public)
    )


@pytest.mark.parametrize("module_name", WEBAUTH_MODULES)
def test_every_name_a_module_lists_in_all_is_defined_there(module_name: str) -> None:
    file = _module_file(module_name)
    assert file is not None
    offences = [
        f"{_relative_id(file)}:{line}: {name}: listed in __all__ but not defined here"
        for name, line in _surface_of(module_name).public.items()
        if not _is_defined_or_forwarded_from_own_submodule(module_name, name)
    ]

    assert offences == []


PUBLIC_MODULES = [
    name
    for name in WEBAUTH_MODULES
    if not any(part.startswith("_") for part in name.split("."))
]


@pytest.mark.parametrize("module_name", WEBAUTH_MODULES)
def test_every_module_declares_all_as_one_literal_assignment(module_name: str) -> None:
    file = _module_file(module_name)
    assert file is not None
    offences = [
        f"{_relative_id(file)}:{line}: {module_name}.__all__: "
        "must be one literal assignment, never extended or built"
        for line in _surface_of(module_name).irregular_all_lines
    ]

    assert offences == []


@pytest.mark.parametrize("module_name", PUBLIC_MODULES)
def test_a_public_module_defines_only_underscored_names_outside_all(module_name: str) -> None:
    file = _module_file(module_name)
    assert file is not None
    surface = _surface_of(module_name)
    defined = {**surface.defined_values, **surface.defined_callables}
    offences = [
        f"{_relative_id(file)}:{line}: {module_name}.{name}: "
        "defined here but neither in __all__ nor underscored"
        for name, line in defined.items()
        if name not in surface.public and not name.startswith("_")
    ] + [
        f"{_relative_id(file)}:{line}: {module_name}.{name}: "
        "re-exported by an import that __all__ does not list"
        for name, line in surface.redundant_reexports.items()
        if name not in surface.public and not name.startswith("_")
    ]

    assert offences == []


@dataclass(frozen=True)
class NameTaken:
    path: Path
    line: int
    module: str
    name: str


def _name_taken_by_chain(
    path: Path, chain: ast.Attribute, module_aliases: dict[str, str],
) -> list[NameTaken]:
    parts: list[str] = []
    root: ast.expr = chain
    while isinstance(root, ast.Attribute):
        parts.insert(0, root.attr)
        root = root.value
    if not isinstance(root, ast.Name) or root.id not in module_aliases:
        return []
    module = module_aliases[root.id]
    for part in parts:
        if _module_file(f"{module}.{part}") is None:
            return [NameTaken(path, chain.lineno, module, part)]
        module = f"{module}.{part}"
    return []


def _names_taken_from_webauth(path: Path) -> list[NameTaken]:
    module_aliases: dict[str, str] = {}
    taken: list[NameTaken] = []
    attribute_chains: list[ast.Attribute] = []
    inner_links: set[int] = set()
    for node in ast.walk(ast.parse(path.read_text())):
        if isinstance(node, ast.ImportFrom) and not node.level and _is_webauth_module(node.module):
            for alias in node.names:
                dotted = f"{node.module}.{alias.name}"
                if _module_file(dotted):
                    module_aliases[alias.asname or alias.name] = dotted
                else:
                    taken.append(NameTaken(path, alias.lineno, str(node.module), alias.name))
        elif isinstance(node, ast.Import):
            for alias in (a for a in node.names if _is_webauth_module(a.name)):
                name, module = _bound_module(alias)
                module_aliases[name] = module
        elif isinstance(node, ast.Attribute):
            attribute_chains.append(node)
            inner_links.add(id(node.value))
    for chain in (c for c in attribute_chains if id(c) not in inner_links):
        taken.extend(_name_taken_by_chain(path, chain, module_aliases))
    return taken


def _rule_broken_by(taken: NameTaken, *, only_public: bool) -> str | None:
    surface = _surface_of(taken.module)
    if taken.name in surface.public or (taken.name.startswith("__") and taken.name.endswith("__")):
        return None
    if only_public:
        return "not in __all__"
    if taken.name in surface.defined_callables:
        return None
    if taken.name in surface.defined_values:
        return "a value outside __all__; pin the literal instead"
    if taken.name in surface.imported_from:
        return "only imported there; take it from where it is defined"
    return "not defined there"


def _offences_of(path: Path, *, only_public: bool) -> list[str]:
    return [
        f"{_relative_id(path)}:{taken.line}: {taken.module}.{taken.name}: {rule}"
        for taken in _names_taken_from_webauth(path)
        if (rule := _rule_broken_by(taken, only_public=only_public))
    ]


@pytest.mark.parametrize("consumer", OTHER_CONSUMERS, ids=_relative_id)
def test_a_test_takes_only_public_names_and_functions_or_classes_a_module_defines(
    consumer: Path,
) -> None:
    assert _offences_of(consumer, only_public=False) == []


@pytest.mark.parametrize("host", TYPING_HOSTS, ids=_relative_id)
def test_a_typing_host_takes_only_public_names(host: Path) -> None:
    assert _names_taken_from_webauth(host)
    assert _offences_of(host, only_public=True) == []


@pytest.mark.parametrize("module_name", WEBAUTH_MODULES)
def test_every_module_declares_its_public_names(module_name: str) -> None:
    assert isinstance(getattr(importlib.import_module(module_name), "__all__", None), list)


@pytest.mark.parametrize(
    ("module", "name"),
    [
        ("webauth.dependencies", "AuthenticatedUser"),
        ("webauth.jwt_verification", "WallClock"),
    ],
)
def test_a_name_moved_to_ports_is_gone_from_its_old_module(module: str, name: str) -> None:
    assert hasattr(ports, name)
    assert not hasattr(importlib.import_module(module), name)


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
