"""The one decision whether an Origin names a host this application serves."""

from __future__ import annotations

from typing import TYPE_CHECKING
from urllib.parse import urlparse

if TYPE_CHECKING:
    from webauth.config import WebAuthConfig

__all__ = []


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
    return host_and_port in config.allowed_hosts_exact or hostname in config.allowed_hosts_exact
