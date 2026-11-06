"""The one decision whether an Origin names a host this application serves."""

from __future__ import annotations

from enum import Enum, auto
from typing import TYPE_CHECKING
from urllib.parse import urlparse

if TYPE_CHECKING:
    from starlette.datastructures import Headers

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
    if config.cookie_secure and parsed.scheme != "https":
        return False
    if ":" in hostname:
        hostname = f"[{hostname}]"
    host_and_port = hostname if port is None else f"{hostname}:{port}"
    return host_and_port in config.allowed_hosts_exact or hostname in config.allowed_hosts_exact


class OriginVerdict(Enum):
    ABSENT = auto()
    ALLOWED = auto()
    FOREIGN = auto()


def origin_verdict(headers: Headers, config: WebAuthConfig) -> OriginVerdict:
    """No ``Origin``, one allowed ``Origin``, or a foreign one; a repeated header is foreign."""
    origins = headers.getlist("origin")
    if not origins:
        return OriginVerdict.ABSENT
    if len(origins) > 1 or not origin_is_allowed(origins[0], config):
        return OriginVerdict.FOREIGN
    return OriginVerdict.ALLOWED
