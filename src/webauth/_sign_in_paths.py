"""Where the sign-in routes live: ``SignInPaths``, defined here so the middleware stack can
name it without importing the sign-in steps. ``webauth.sign_in_routes`` is its public home."""

from __future__ import annotations

from dataclasses import dataclass

from webauth._paths import _has_dot_segment, reads_as_another_host
from webauth.dependencies import LoginRedirect

__all__ = ["SignInPaths"]

_RETURN_PATH_QUERY_NAME = "next"


@dataclass(frozen=True)
class SignInPaths:
    """Where the sign-in routes live, mount-relative like every webauth policy path.

    Every path must be absolute, name nothing a browser reads as another host, hold no
    dot segment, ``?`` or ``#``, and differ from the others; ``ValueError`` at
    construction, before any route is registered, names the first that is not.
    ``logout`` is ``None`` for a host that serves no logout route, and
    ``backchannel_logout`` for one that serves no back-channel logout route.
    ``WebAuth.install`` derives the policies for exactly these paths.
    """

    start: str
    callback: str
    logout: str | None = None
    backchannel_logout: str | None = None

    def __post_init__(self) -> None:
        for name, path in self._named_paths:
            _require_sign_in_path(name, path)
        paths = [path for _, path in self._named_paths]
        if len(set(paths)) != len(paths):
            names = ", ".join(f"SignInPaths.{name}" for name, _ in self._named_paths)
            raise ValueError(f"{names} must differ")

    @property
    def login_redirect(self) -> LoginRedirect:
        """Send a signed-out browser to the start route, carrying the address it asked for.

        The path is browser-absolute, so it is right for an app at its origin's root; a
        host below a ``root_path`` builds its own ``LoginRedirect``."""
        return LoginRedirect(self.start, _RETURN_PATH_QUERY_NAME)

    @property
    def _named_paths(self) -> tuple[tuple[str, str], ...]:
        optional = (("logout", self.logout), ("backchannel_logout", self.backchannel_logout))
        return (
            ("start", self.start),
            ("callback", self.callback),
            *((name, path) for name, path in optional if path is not None),
        )


def _require_sign_in_path(name: str, path: str) -> None:
    problem = _problem_with(path)
    if problem is not None:
        raise ValueError(f"SignInPaths.{name} {problem}: {path!r}")


def _problem_with(path: object) -> str | None:
    if not isinstance(path, str) or not path.startswith("/"):
        return "must be an absolute path"
    if reads_as_another_host(path):
        return "must not read as another host"
    if "?" in path or "#" in path:
        return "must not hold a query or a fragment"
    if _has_dot_segment(path):
        return "must not hold a dot segment"
    return None
