"""Every rule ID of the host contract is named by the test that proves it, or marked."""

from __future__ import annotations

import ast
import re
from pathlib import Path

import pytest

_REPOSITORY = Path(__file__).resolve().parent.parent
_RULE_ID = r"[A-Z]+-\d+"
_RULE_IDS_AT_THE_START = re.compile(rf"\s*(?P<ids>{_RULE_ID}(?:\s*(?:,|and)\s*{_RULE_ID})*)")
_MARK_OF_A_RULE_PROVEN_ELSEWHERE = "**Proven elsewhere:**"


def _rule_blocks_of_the_contract() -> list[str]:
    """Blocks of the contract: a bullet with its continuation lines, or a paragraph."""
    blocks: list[list[str]] = []
    for line in (_REPOSITORY / "docs" / "host-contract.md").read_text().splitlines():
        starts_a_block = not line.strip() or line.lstrip().startswith("- ")
        if starts_a_block or not blocks:
            blocks.append([])
        blocks[-1].append(line)
    return ["\n".join(block) for block in blocks]


def _rule_ids_of_the_contract(*, marked_proven_elsewhere: bool) -> set[str]:
    return {
        rule_id
        for block in _rule_blocks_of_the_contract()
        if (_MARK_OF_A_RULE_PROVEN_ELSEWHERE in block) is marked_proven_elsewhere
        for rule_id in re.findall(rf"\*\*({_RULE_ID})\*\*", block)
    }


def _rule_ids_named_by_a_docstring(path: Path) -> set[str]:
    tree = ast.parse(path.read_text())
    named: set[str] = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.Module | ast.ClassDef | ast.FunctionDef | ast.AsyncFunctionDef):
            start = _RULE_IDS_AT_THE_START.match(ast.get_docstring(node) or "")
            if start:
                named.update(re.findall(_RULE_ID, start["ids"]))
    return named


def test_every_rule_id_of_the_contract_is_named_by_a_test_or_marked_proven_elsewhere() -> None:
    """Names each rule ID that no test docstring starts with and the contract does not mark."""
    named: set[str] = set()
    for path in (_REPOSITORY / "tests").rglob("*.py"):
        named |= _rule_ids_named_by_a_docstring(path)
    unproven = (
        _rule_ids_of_the_contract(marked_proven_elsewhere=False)
        - _rule_ids_of_the_contract(marked_proven_elsewhere=True)
        - named
    )

    assert not unproven, f"rule IDs no test names, unmarked in the contract: {sorted(unproven)}"


@pytest.mark.parametrize(
    ("docstring", "named"),
    [
        pytest.param("COMPOSE-05", {"COMPOSE-05"}, id="one ID alone"),
        pytest.param("A-1, B-2 and C-3: why.", {"A-1", "B-2", "C-3"}, id="several IDs at start"),
        pytest.param("Why it holds (A-1).", set(), id="an ID inside the text is no naming"),
        pytest.param("A-1 to A-3: a range.", {"A-1"}, id="a range names only its first end"),
    ],
)
def test_a_docstring_names_the_rule_ids_it_starts_with(
    docstring: str, named: set[str], tmp_path: Path
) -> None:
    module = tmp_path / "module.py"
    module.write_text(f'def test_x():\n    """{docstring}"""\n')

    assert _rule_ids_named_by_a_docstring(module) == named
