"""Authentication machinery a FastAPI application should not rebuild.

Owns sessions with Redis-backed expiry, HMAC-signed cookies, CSRF, admin and
owner checks, rate limits, and the audit events they raise. User administration
and first-run setup live in `webauth.users`, whose `UserManagement` and
`complete_first_run_setup` work through the host ports in `webauth.ports`.
The user model, schema, configured role names, transaction boundaries, and
HTTP routes and responses stay with the host application.

The library persists nothing itself: it holds no schema and no ORM, and the
`.importlinter` contract keeps it that way.
"""

__version__ = "0.4.0"
