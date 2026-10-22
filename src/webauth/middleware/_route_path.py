"""The one decider of which path a policy rule is matched against."""

from __future__ import annotations

from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from starlette.types import Scope

__all__ = []


def route_path(scope: Scope) -> str:
    """The path the application's router routes: ``root_path`` stripped at a segment boundary.

    Starlette's own rule (``get_route_path``): a path that does not start with
    the root, or whose next character is not ``/``, is returned whole. A mount
    extends ``root_path`` in place as it routes, so a middleware reads this
    once, when it is entered.
    """
    path: str = scope["path"]
    root_path: str = scope.get("root_path", "")
    if not root_path or not path.startswith(root_path):
        return path
    if path == root_path:
        return ""
    return path[len(root_path):] if path[len(root_path)] == "/" else path
