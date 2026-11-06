from __future__ import annotations

import re
from pathlib import Path

import webauth

CHANGELOG = Path(__file__).parent.parent / "docs" / "CHANGELOG.md"


def test_changelog_has_a_dated_heading_for_the_current_version() -> None:
    version = re.escape(webauth.__version__)
    dated_heading = re.compile(rf"^## {version} - \d{{4}}-\d{{2}}-\d{{2}}$", re.MULTILINE)

    assert dated_heading.search(CHANGELOG.read_text(encoding="utf-8"))
