"""OpenID Connect login for FastAPI applications, with sessions, CSRF and rate limits.

Owns sessions the store decides on every request, HMAC-signed cookies, CSRF, admin
checks, rate limits, and the audit events they raise, all through the host
ports in `webauth.ports`.
The user model, schema, configured role names, transaction boundaries and HTTP
routes stay with the host application, and so does every response but the
library's own refusals and its 500.

The library persists nothing itself: it holds no schema and no ORM, and the
`.importlinter` contract keeps it that way.
"""

__version__ = "0.20.0"

__all__ = ["WebAuthError", "__version__"]


class WebAuthError(Exception):
    """The common base of the operational exceptions the library's public API raises.

    ``RequestBodyTooLarge`` is not a ``WebAuthError`` on purpose, so a host's
    ``WebAuthError`` handler cannot answer in place of the 413.
    """
