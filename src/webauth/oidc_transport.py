"""The production ``TokenRequestPost``: the token request sent over HTTPS.

``post_token_request_over_https`` is what a host gives its
``OidcRelyingParty`` as ``post_token_request``, beside ``fetch_key_set_over_https``
as its ``fetch_key_set``. It sends the request through ``webauth.https_client``;
the key-set transport stays there.

Install the ``jwt`` extra to use this module.
"""

from __future__ import annotations

from typing import Final

from webauth.https_client import (
    TOKEN_EXCHANGE_DEADLINE_SECONDS,
    _HttpsExchangeError,
    _post_form_over_https,
)
from webauth.oidc import (
    MAX_TOKEN_RESPONSE_BYTES,
    TokenEndpointAnswer,
    TokenEndpointError,
    TokenRequest,
)

__all__ = ["post_token_request_over_https"]

_TOKEN_REQUEST_TIMEOUT_SECONDS: Final = 5


def post_token_request_over_https(
    request: TokenRequest,
    *,
    timeout_seconds: float = _TOKEN_REQUEST_TIMEOUT_SECONDS,
    deadline_seconds: float = TOKEN_EXCHANGE_DEADLINE_SECONDS,
) -> TokenEndpointAnswer:
    """The production ``TokenRequestPost``: the request POSTed under the
    bounded posture of ``webauth.https_client``, reading at most one byte past
    ``MAX_TOKEN_RESPONSE_BYTES`` of the answer.

    Any answer but a redirect comes back whatever its status, so the relying
    party reads an issuer's refusal such as ``invalid_grant``. A redirect, an
    oversized answer, a refused URL, an unreachable origin, a failed TLS
    handshake, a timeout or a broken exchange raises ``TokenEndpointError`` in
    this library's words, never quoting the request.

    ``timeout_seconds`` bounds connecting and each read on its own;
    ``deadline_seconds`` bounds the exchange in total and is owned by
    ``webauth.https_client``. A ``timeout_seconds`` above ``deadline_seconds``
    raises ``ValueError`` rather than being silently capped, as does a
    ``deadline_seconds`` or ``timeout_seconds`` of zero or less.
    ``TokenEndpointError.failure`` names why the request failed."""
    if timeout_seconds > deadline_seconds > 0:
        raise ValueError(
            f"timeout_seconds ({timeout_seconds}) must not exceed"
            f" deadline_seconds ({deadline_seconds})"
        )
    try:
        answer = _post_form_over_https(
            request.url,
            request.form,
            authorization=request.authorization,
            max_body_bytes=MAX_TOKEN_RESPONSE_BYTES,
            timeout_seconds=timeout_seconds,
            deadline_seconds=deadline_seconds,
        )
    except _HttpsExchangeError as refusal:
        failure = refusal.failure
    else:
        return TokenEndpointAnswer(answer.status, answer.body)
    # Raised outside the handler so not even the exchange error is its context.
    raise TokenEndpointError(f"the token request failed: {failure}", failure)
