"""Authentication machinery a FastAPI application should not rebuild.

Owns sessions the store decides on every request, HMAC-signed cookies, CSRF, admin
checks, rate limits, and the audit events they raise. Session administration
works through the host ports in `webauth.ports`.
The user model, schema, configured role names, transaction boundaries, and
HTTP routes and responses stay with the host application.

The library persists nothing itself: it holds no schema and no ORM, and the
`.importlinter` contract keeps it that way.
"""

__version__ = "0.14.0"

__all__ = ["__version__"]
