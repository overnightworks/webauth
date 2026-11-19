"""The writer a host puts around its app, and the proxies it trusts, for the suites."""

from __future__ import annotations

from typing import TYPE_CHECKING

from webauth.middleware import ClientAddressMiddleware
from webauth.proxies import TrustedProxies

if TYPE_CHECKING:
    from starlette.applications import Starlette
    from starlette.types import ASGIApp

TRUSTED_PROXIES = TrustedProxies.parse("172.16.0.0/12")


def behind_the_client_address_writer(app: ASGIApp) -> ClientAddressMiddleware:
    """`app` wrapped the way a host's wiring does it, trusting the suites' proxy network."""
    return ClientAddressMiddleware(app, trusted_proxies=TRUSTED_PROXIES)


def add_the_client_address_writer(app: Starlette) -> None:
    """Add the writer outside everything `app` carries so far; a host's wrapper line does the same.

    Call it after the stack is installed and before logline's middleware, which stays outermost.
    """
    app.add_middleware(ClientAddressMiddleware, trusted_proxies=TRUSTED_PROXIES)
