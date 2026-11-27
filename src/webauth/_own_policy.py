"""The header an answer carries to keep its own Content-Security-Policy and Cache-Control.

The page that sets it and the security-headers middleware that drops it share this token.
"""

from __future__ import annotations

from typing import Final

__all__ = ["OWN_POLICY_HEADER", "OWN_POLICY_HEADER_VALUE"]

OWN_POLICY_HEADER: Final = "webauth-own-policy"
OWN_POLICY_HEADER_VALUE: Final = "1"
