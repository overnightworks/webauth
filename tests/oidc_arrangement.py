"""Builders for tokens, key sets and the issuer endpoints a relying party talks to.

The keys, signed tokens and key-set documents here are what an issuer
publishes; the fakes stand in for the injected clock, key-set fetch and token
POST, so the verifier and the relying party run offline and deterministically.
"""

from __future__ import annotations

import base64
import hashlib
import json
import secrets
import threading
import urllib.parse
from collections.abc import Callable
from dataclasses import dataclass, field
from functools import cache
from typing import Any

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding, rsa
from jwt.algorithms import RSAAlgorithm

from webauth.oidc import TokenEndpointAnswer, TokenRequest

ABSENT = object()
"""A claim or header change that removes the member instead of setting it."""


@cache
def rsa_key(name: str, bits: int = 2048) -> rsa.RSAPrivateKey:
    """One generated key per name for the whole session: RSA generation is the
    slow part, and a key is immutable scenario data."""
    del name
    return rsa.generate_private_key(public_exponent=65537, key_size=bits)


def segment(value: dict[str, Any] | str) -> str:
    """A base64url segment of a JSON object, or of raw JSON text when the
    scenario needs bytes `json.dumps` cannot produce (duplicate members)."""
    text = value if isinstance(value, str) else json.dumps(value)
    return base64.urlsafe_b64encode(text.encode()).rstrip(b"=").decode()


def rs256(key: rsa.RSAPrivateKey) -> Callable[[bytes], bytes]:
    return lambda signing_input: key.sign(signing_input, padding.PKCS1v15(), hashes.SHA256())


def jws(header: dict[str, Any] | str, claims: dict[str, Any] | str, sign: Callable) -> str:
    signing_input = f"{segment(header)}.{segment(claims)}"
    signature = base64.urlsafe_b64encode(sign(signing_input.encode())).rstrip(b"=").decode()
    return f"{signing_input}.{signature}"


def changed(base: dict[str, Any], changes: dict[str, Any]) -> dict[str, Any]:
    merged = {**base, **changes}
    return {name: value for name, value in merged.items() if value is not ABSENT}


def public_jwk(key: rsa.RSAPrivateKey, key_id: str, **changes: Any) -> dict[str, Any]:
    jwk = RSAAlgorithm.to_jwk(key.public_key(), as_dict=True)
    return changed({**jwk, "kid": key_id, "alg": "RS256", "use": "sig"}, changes)


def key_set_document(*jwks: object) -> bytes:
    return json.dumps({"keys": list(jwks)}).encode()


@dataclass
class FakeClock:
    now: float

    def __call__(self) -> float:
        return self.now


@dataclass
class FakeKeySetEndpoint:
    """Answers each fetch with `response`: a document, or the error to raise."""

    response: bytes | Exception
    fetched_urls: list[str] = field(default_factory=list)
    before_answer: Callable[[], None] = lambda: None

    def __call__(self, url: str) -> bytes:
        self.fetched_urls.append(url)
        self.before_answer()
        if isinstance(self.response, Exception):
            raise self.response
        return self.response


@dataclass
class FakeTokenEndpoint:
    """Answers each token request with `answer`, or raises it when it is an
    error, and keeps every request it received."""

    answer: TokenEndpointAnswer | Exception = field(
        default_factory=lambda: TokenEndpointAnswer(500, b"")
    )
    requests: list[TokenRequest] = field(default_factory=list)

    def __call__(self, request: TokenRequest) -> TokenEndpointAnswer:
        self.requests.append(request)
        if isinstance(self.answer, Exception):
            raise self.answer
        return self.answer


def token_endpoint_answer(status: int, document: dict[str, Any] | bytes) -> TokenEndpointAnswer:
    body = document if isinstance(document, bytes) else json.dumps(document).encode()
    return TokenEndpointAnswer(status, body)


@dataclass(frozen=True)
class _IssuedCode:
    nonce: str
    code_challenge: str


@dataclass
class FakeIssuer:
    """An issuer's authorization and token endpoints that remember what they issued.

    `authorize` plays the person signing in at the issuer: it reads the
    authorization URL and answers the callback query with a fresh code bound
    to the login's nonce and PKCE challenge. Called as the token endpoint, it
    answers each code once, and only to the verifier of that challenge, with
    the ID token `mint_id_token` makes for the nonce; `before_exchange` runs
    before a code is looked up, so a test can hold two exchanges together.
    """

    mint_id_token: Callable[[str], str]
    requests: list[TokenRequest] = field(default_factory=list)
    before_exchange: Callable[[], None] = lambda: None
    _codes: dict[str, _IssuedCode] = field(default_factory=dict)
    _codes_lock: threading.Lock = field(default_factory=threading.Lock)

    def authorize(self, authorization_url: str) -> str:
        query = urllib.parse.parse_qs(urllib.parse.urlsplit(authorization_url).query)
        code = secrets.token_urlsafe(32)
        self._codes[code] = _IssuedCode(query["nonce"][0], query["code_challenge"][0])
        return urllib.parse.urlencode({"state": query["state"][0], "code": code})

    def __call__(self, request: TokenRequest) -> TokenEndpointAnswer:
        self.requests.append(request)
        self.before_exchange()
        with self._codes_lock:
            issued = self._codes.pop(request.form["code"], None)
        verifier = request.form["code_verifier"]
        if issued is None or s256_code_challenge(verifier) != issued.code_challenge:
            return token_endpoint_answer(400, {"error": "invalid_grant"})
        return token_endpoint_answer(200, {"id_token": self.mint_id_token(issued.nonce)})


def s256_code_challenge(code_verifier: str) -> str:
    digest = hashlib.sha256(code_verifier.encode()).digest()
    return base64.urlsafe_b64encode(digest).rstrip(b"=").decode()
