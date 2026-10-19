"""The one decision whether an Origin names a host this application serves."""

from __future__ import annotations

import re
from typing import TYPE_CHECKING
from urllib.parse import urlparse

if TYPE_CHECKING:
    from webauth.config import WebAuthConfig

__all__ = []


def _is_allowed_host(
    hostname: str,
    host_and_port: str,
    exact: frozenset[str],
    patterns: tuple[re.Pattern[str], ...],
) -> bool:
    if host_and_port in exact or hostname in exact:
        return True
    return any(p.fullmatch(host_and_port) for p in patterns)


def origin_is_allowed(origin: str, config: WebAuthConfig) -> bool:
    try:
        parsed = urlparse(origin)
        hostname = parsed.hostname
        port = parsed.port
    except ValueError:
        return False
    if not hostname or parsed.username is not None or parsed.password is not None:
        return False
    if ":" in hostname:
        hostname = f"[{hostname}]"
    host_and_port = hostname if port is None else f"{hostname}:{port}"
    return _is_allowed_host(
        hostname,
        host_and_port,
        config.allowed_hosts_exact,
        config.allowed_hosts_patterns,
    )
