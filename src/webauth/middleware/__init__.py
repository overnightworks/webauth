"""The HTTP middleware policies and gates the library's stack reads; the stack itself is installed
only by ``WebAuth.install``."""

from __future__ import annotations

from webauth.middleware.bearer_gate import (
    BearerGate,
    MachinePaths,
    MarkedRoute,
    PersonPaths,
    ProtectedResource,
    bearer_caller,
    exchanged_access_token,
    is_resource_admission,
    resource_person,
)
from webauth.middleware.body_size import RequestBodyTooLarge
from webauth.middleware.session_gate import (
    SessionGate,
    admitted_admin,
    admitted_user,
)

__all__ = [
    "BearerGate",
    "MachinePaths",
    "MarkedRoute",
    "PersonPaths",
    "ProtectedResource",
    "RequestBodyTooLarge",
    "SessionGate",
    "admitted_admin",
    "admitted_user",
    "bearer_caller",
    "exchanged_access_token",
    "is_resource_admission",
    "resource_person",
]
