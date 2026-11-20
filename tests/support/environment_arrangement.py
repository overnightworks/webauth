"""An `os.environ` stand-in for tests that prove a call reads no environment variable."""

from __future__ import annotations

import traceback
from collections.abc import Iterator, MutableMapping
from pathlib import Path

_PLUMBING = {Path(__file__).name, "os.py", "_collections_abc.py"}


class ForbiddenEnvironment(MutableMapping[str, str]):
    """An `os.environ` that fails the test on any access.

    With `only_from` it fails only when the caller lives under that directory and answers as an
    empty environment to every other caller: a library that webauth calls (pydantic reads its
    own switches while a route is added) is not webauth reading the environment.
    """

    def __init__(self, *, only_from: Path | None = None) -> None:
        self._only_from = only_from

    def _forbidden(self) -> bool:
        if self._only_from is None:
            return True
        frames = reversed(traceback.extract_stack())
        reader = next(frame for frame in frames if Path(frame.filename).name not in _PLUMBING)
        return Path(reader.filename).is_relative_to(self._only_from)

    def __getitem__(self, key: str) -> str:
        if self._forbidden():
            raise AssertionError(f"the environment was read for {key}")
        raise KeyError(key)

    def __setitem__(self, key: str, value: str) -> None:
        if self._forbidden():
            raise AssertionError(f"the environment was written for {key}")

    def __delitem__(self, key: str) -> None:
        if self._forbidden():
            raise AssertionError(f"the environment was changed for {key}")
        raise KeyError(key)

    def __iter__(self) -> Iterator[str]:
        if self._forbidden():
            raise AssertionError("the environment was listed")
        return iter(())

    def __len__(self) -> int:
        if self._forbidden():
            raise AssertionError("the environment was counted")
        return 0
