"""Authentication machinery a FastAPI application should not rebuild.

Owns sessions with Redis-backed expiry, HMAC-signed cookies, CSRF, admin and
owner checks, rate limits, and the audit events they raise. Application
concerns — the user model, first-run setup, roles, and the login route with
its transaction boundary — stay with the host application, which supplies
them through the ports in `webauth.ports`.

The library persists nothing itself: it holds no schema and no ORM, and the
`.importlinter` contract keeps it that way.
"""

__version__ = "0.1.0"
