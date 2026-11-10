"""The one way webauth runs blocking work off the event loop."""

from __future__ import annotations

from typing import TYPE_CHECKING

from anyio import to_thread
from anyio.lowlevel import checkpoint_if_cancelled

if TYPE_CHECKING:
    from collections.abc import Callable

__all__ = []


async def on_worker[Result](work: Callable[[], Result]) -> Result:
    try:
        return await to_thread.run_sync(work)
    finally:
        await checkpoint_if_cancelled()
