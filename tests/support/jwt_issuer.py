"""The remote issuer the JWT verification tests drive: its key set, clocks and verifier."""

from __future__ import annotations

from collections.abc import Callable
from dataclasses import dataclass, field
from typing import Any

from cryptography.hazmat.primitives.asymmetric import ec
from jwt.algorithms import ECAlgorithm

from tests.support.oidc_arrangement import (
    ABSENT,
    ACCESS_TOKEN_LEEWAY_SECONDS,
    APP_CLIENT_ID,
    REALM_ISSUER,
    REALM_JWKS_URL,
    FakeClock,
    FakeKeySetEndpoint,
    changed,
    jws,
    public_jwk,
    rs256,
    rsa_key,
)
from webauth.jwt_verification import (
    KEY_SET_REFRESH_COOLDOWN_SECONDS,
    JwtVerifier,
    VerifiedClaims,
)

KEY_SET_TTL_SECONDS = 60 * 60


@dataclass
class IssuerScenario:
    endpoint: FakeKeySetEndpoint
    wall_clock: FakeClock
    monotonic_clock: FakeClock
    verifier: JwtVerifier = field(init=False)
    key_id: str = "current-key"

    def __post_init__(self) -> None:
        self.verifier = self.verifier_with()

    def claims(self, changes: dict[str, Any] | None = None) -> dict[str, Any]:
        now = int(self.wall_clock.now)
        issued_claims = {
            "iss": REALM_ISSUER,
            "aud": APP_CLIENT_ID,
            "sub": "7335d417-61da-459d-899c-0a01c76a2f94",
            "exp": now + 300,
            "iat": now - 10,
            "nbf": now - 10,
            "sid": "4c2a9f0e-session",
            "preferred_username": "operator",
        }
        return changed(issued_claims, changes or {})

    def token(
        self,
        claims: dict[str, Any] | None = None,
        header: dict[str, Any] | None = None,
        sign: Callable | None = None,
    ) -> str:
        return jws(
            changed({"alg": "RS256", "kid": self.key_id, "typ": "JWT"}, header or {}),
            self.claims(claims),
            sign or rs256(rsa_key("current")),
        )

    def verified(self, claims: dict[str, Any] | None = None) -> VerifiedClaims:
        issued = self.claims(claims)
        audience = issued["aud"]
        return VerifiedClaims(
            subject=issued.get("sub"),
            issuer=REALM_ISSUER,
            audiences=(audience,) if isinstance(audience, str) else tuple(audience),
            expires_at=issued["exp"],
            issued_at=issued["iat"],
            claims=issued,
        )

    def serve(self, response: bytes | Exception) -> None:
        self.endpoint.response = response

    def after_cooldown(self) -> None:
        self.monotonic_clock.now += KEY_SET_REFRESH_COOLDOWN_SECONDS

    def verifier_with(self, **changes: Any) -> JwtVerifier:
        arguments = {
            "issuer": REALM_ISSUER,
            "audiences": [APP_CLIENT_ID],
            "jwks_url": REALM_JWKS_URL,
            "leeway_seconds": ACCESS_TOKEN_LEEWAY_SECONDS,
            "fetch_key_set": self.endpoint,
            "wall_clock": self.wall_clock,
            "monotonic_clock": self.monotonic_clock,
        }
        return JwtVerifier(**{**arguments, **changes})


def kidless_keys(count: int) -> list[dict[str, Any]]:
    return [public_jwk(rsa_key(f"kidless-{index}"), "unused", kid=ABSENT) for index in range(count)]


def passed_over_keys(count: int) -> list[dict[str, Any]]:
    """What the OpenID Foundation suite's OP publishes beside its two RS256
    keys: other signing algorithms, encryption keys, and entries no verifier
    can use."""
    p256 = ec.generate_private_key(ec.SECP256R1()).public_key()
    secp256k1 = ec.generate_private_key(ec.SECP256K1()).public_key()
    kinds = [
        {**ECAlgorithm.to_jwk(p256, as_dict=True), "use": "sig"},
        {**ECAlgorithm.to_jwk(p256, as_dict=True), "alg": "ES256"},
        {**ECAlgorithm.to_jwk(secp256k1, as_dict=True), "alg": "ES256K"},
        {"kty": "OKP", "crv": "Ed25519", "x": "A" * 43, "alg": "EdDSA"},
        public_jwk(rsa_key("encryption"), "unused", alg="RSA-OAEP", use="enc"),
        {**ECAlgorithm.to_jwk(p256, as_dict=True), "alg": "ECDH-ES", "use": "enc"},
        {"kty": "AKP", "alg": "ML-DSA-9999", "pub": "AAAA"},
        {"kty": "UNKNOWN"},
        public_jwk(rsa_key("encryption"), "unused", alg="RS9999"),
        {**ECAlgorithm.to_jwk(p256, as_dict=True), "alg": "ES9999"},
        {**ECAlgorithm.to_jwk(p256, as_dict=True), "crv": "P-9999"},
    ]
    return [{**kinds[index % len(kinds)], "kid": f"passed-over-{index}"} for index in range(count)]


def token_without_kid(issuer: IssuerScenario, sign: Callable | None = None) -> str:
    return issuer.token(header={"kid": ABSENT}, sign=sign)
