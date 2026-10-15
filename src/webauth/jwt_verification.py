"""Verification of RS256 tokens signed by a remote issuer's published keys.

`JwtVerifier.verify` takes a raw compact JWS and answers `VerifiedClaims` or
`Rejected(reason)`. The caller names the issuer, the audiences it accepts, the
URL of the issuer's key set and the clock leeway; what a protocol demands of
the claims beyond signature, issuer, audience and time — an ID token's nonce,
a logout token's events — belongs to the caller, which reads them from
`VerifiedClaims.claims`.

The token is parsed strictly by this module before PyJWT sees it: bounded
length and nesting, no duplicate JSON members, canonical base64url, an
RS256-only header naming its key by `kid`, and no header member that would let
the token choose its own key. PyJWT then verifies the signature, audience and
issuer; the time claims are checked here against the injected wall clock, so
leeway has one owner.

Signing keys come from the configured key-set URL through the injected fetch.
A fetched key set replaces the cached one only once every key in it is sound,
so a failed or poisoned refresh never evicts the last good set; that set
expires on the injected monotonic clock. Keys published for another purpose —
encryption, another algorithm or key type — are passed over, not refused,
because issuers such as Keycloak publish them beside the signing keys. They
still count toward `MAX_KEY_SET_KEYS`, which bounds every key the set
publishes: ten covers Keycloak's signing and encryption keys during a rotation.

Install the `jwt` extra to use this module.
"""

from __future__ import annotations

import base64
import json
import logging
import math
import re
import threading
from collections.abc import Callable, Collection, Mapping
from dataclasses import dataclass
from enum import StrEnum
from types import MappingProxyType
from typing import NoReturn, TypeGuard, cast

import jwt
from cryptography.hazmat.primitives.asymmetric.rsa import RSAPublicKey, RSAPublicNumbers
from jwt.types import Options

# The aliased names are re-exported: hosts imported the key-set fetch, its
# limits and its error from this module before they moved to webauth.https_client.
from webauth.https_client import KEY_SET_FETCH_TIMEOUT_SECONDS as KEY_SET_FETCH_TIMEOUT_SECONDS
from webauth.https_client import MAX_KEY_SET_BYTES as MAX_KEY_SET_BYTES
from webauth.https_client import KeySetFetchError as KeySetFetchError
from webauth.https_client import fetch_key_set_over_https as fetch_key_set_over_https
from webauth.https_client import is_https_url

log = logging.getLogger(__name__)

MAX_TOKEN_CHARACTERS = 8 * 1024
MAX_JSON_NESTING_DEPTH = 8
MAX_KEY_ID_CHARACTERS = 128
KEY_SET_TTL_SECONDS = 60 * 60
KEY_SET_REFRESH_COOLDOWN_SECONDS = 30
MAX_KEY_SET_KEYS = 10
MIN_RSA_KEY_BITS = 2048

_ALGORITHM = "RS256"
_JWS_COMPACT_SEGMENTS = 3
_BASE64URL = re.compile(r"[A-Za-z0-9_-]*")
# Members through which a token could name, embed or constrain its own key,
# and `b64`, which would change how PyJWT reads the payload segment.
_FORBIDDEN_HEADER_MEMBERS = frozenset({"crit", "jwk", "jku", "x5u", "x5c", "b64"})
# Private RSA members, and `k`, a symmetric key: a key set publishing either
# has leaked a secret and is not trusted for any of its keys.
_SECRET_KEY_MEMBERS = frozenset({"d", "p", "q", "dp", "dq", "qi", "oth", "k"})

WallClock = Callable[[], float]
"""Seconds since the epoch, compared with the token's `exp`, `iat` and `nbf`."""
MonotonicClock = Callable[[], float]
"""Seconds on a clock that never jumps; ages the key set and its cooldown."""
KeySetFetch = Callable[[str], bytes]
"""Fetches the key set document at the URL, raising `KeySetFetchError` on failure."""


class RejectionReason(StrEnum):
    TOKEN_TOO_LONG = "token-too-long"
    MALFORMED_TOKEN = "malformed-token"
    DUPLICATE_MEMBER = "duplicate-member"
    NESTING_TOO_DEEP = "nesting-too-deep"
    FORBIDDEN_HEADER = "forbidden-header"
    UNSUPPORTED_ALGORITHM = "unsupported-algorithm"
    INVALID_KEY_ID = "invalid-key-id"
    UNKNOWN_KEY_ID = "unknown-key-id"
    KEY_SET_UNAVAILABLE = "key-set-unavailable"
    INVALID_SIGNATURE = "invalid-signature"
    INVALID_AUDIENCE = "invalid-audience"
    INVALID_ISSUER = "invalid-issuer"
    INVALID_CLAIM = "invalid-claim"
    EXPIRED = "expired"
    ISSUED_IN_FUTURE = "issued-in-future"
    NOT_YET_VALID = "not-yet-valid"


@dataclass(frozen=True)
class VerifiedClaims:
    """A token whose signature, issuer, audience and time claims held.

    `subject` is the `sub` claim, absent from some tokens (a logout token may
    name only a session); `audiences` is `aud` as a tuple whether the token
    carried one string or a list; `claims` holds every claim as parsed."""

    subject: str | None
    issuer: str
    audiences: tuple[str, ...]
    expires_at: int
    issued_at: int
    claims: Mapping[str, object]


@dataclass(frozen=True)
class Rejected:
    reason: RejectionReason


class _RefusalError(Exception):
    def __init__(self, reason: RejectionReason) -> None:
        super().__init__(reason)
        self.reason = reason


class _RefreshFailure(StrEnum):
    """Why a key-set refresh failed, in codes this module owns: the issuer,
    the URL and the remote key IDs stay out of the log."""

    FETCH_FAILED = "fetch-failed"
    TOO_LARGE = "too-large"
    NOT_STRICT_JSON = "not-strict-json"
    KEY_COUNT_OUT_OF_RANGE = "key-count-out-of-range"
    KEY_NOT_AN_OBJECT = "key-not-an-object"
    SECRET_KEY_PUBLISHED = "secret-key-published"
    DUPLICATE_KEY_ID = "duplicate-key-id"
    NO_RS256_SIGNING_KEY = "no-rs256-signing-key"
    MALFORMED_KEY = "malformed-key"
    INVALID_RSA_KEY = "invalid-rsa-key"
    KEY_TOO_SHORT = "key-too-short"


class _InvalidKeySetError(Exception):
    """A fetched key set that must not replace the cached one."""

    def __init__(self, failure: _RefreshFailure) -> None:
        super().__init__(failure)
        self.failure = failure


@dataclass(frozen=True)
class _ParsedToken:
    key_id: str
    claims: Mapping[str, object]


@dataclass(frozen=True)
class _KeySet:
    keys: Mapping[str, RSAPublicKey]
    fetched_at: float


class JwtVerifier:
    """Verifies RS256 tokens of one issuer for the audiences one caller accepts.

    Safe to share between request threads: the cached key set is an immutable
    snapshot swapped in whole, and one refresh runs at a time.
    """

    def __init__(
        self,
        *,
        issuer: str,
        audiences: Collection[str],
        jwks_url: str,
        leeway_seconds: int,
        fetch_key_set: KeySetFetch,
        wall_clock: WallClock,
        monotonic_clock: MonotonicClock,
    ) -> None:
        if not isinstance(issuer, str) or not issuer:
            raise ValueError("the issuer must be one non-empty string")
        if (
            isinstance(audiences, str)
            or not audiences
            or not all(isinstance(each, str) and each for each in audiences)
        ):
            raise ValueError("the accepted audiences must be one or more non-empty strings")
        if not is_https_url(jwks_url):
            raise ValueError(
                "the key set URL must be an https URL naming a host, a valid port if any,"
                " and no control character, space or credentials"
            )
        if isinstance(leeway_seconds, bool) or not isinstance(leeway_seconds, int):
            raise ValueError("the leeway must be a whole number of seconds")
        if leeway_seconds < 0:
            raise ValueError("the leeway must not be negative")
        self._issuer = issuer
        self._audiences = sorted(audiences)
        self._jwks_url = jwks_url
        self._leeway_seconds = leeway_seconds
        self._fetch_key_set = fetch_key_set
        self._wall_clock = wall_clock
        self._monotonic_clock = monotonic_clock
        self._key_set: _KeySet | None = None
        self._last_refresh_at: float | None = None
        self._refresh_lock = threading.Lock()

    def verify(self, token: str) -> VerifiedClaims | Rejected:
        try:
            return self._verified_claims(token)
        except _RefusalError as refusal:
            return Rejected(refusal.reason)

    def _verified_claims(self, token: str) -> VerifiedClaims:
        parsed = _parse_token(token)
        self._verify_signature_audience_and_issuer(token, self._signing_key(parsed.key_id))
        claims = parsed.claims
        expires_at, issued_at = self._checked_time_claims(claims)
        return VerifiedClaims(
            subject=_subject(claims),
            issuer=self._issuer,
            audiences=_audiences(claims),
            expires_at=expires_at,
            issued_at=issued_at,
            claims=claims,
        )

    def _verify_signature_audience_and_issuer(self, token: str, key: RSAPublicKey) -> None:
        try:
            jwt.decode(
                token,
                key=key,
                algorithms=[_ALGORITHM],
                audience=self._audiences,
                issuer=self._issuer,
                options=_library_checks(),
            )
        except jwt.InvalidSignatureError as error:
            raise _RefusalError(RejectionReason.INVALID_SIGNATURE) from error
        # After InvalidSignatureError, which subclasses it. `_parse_token`
        # already refuses what PyJWT cannot decode; this keeps a disagreement
        # between the two parses a rejection rather than an exception.
        except jwt.DecodeError as error:
            raise _RefusalError(RejectionReason.MALFORMED_TOKEN) from error
        except jwt.InvalidAudienceError as error:
            raise _RefusalError(RejectionReason.INVALID_AUDIENCE) from error
        except jwt.InvalidIssuerError as error:
            raise _RefusalError(RejectionReason.INVALID_ISSUER) from error
        except jwt.MissingRequiredClaimError as error:
            raise _RefusalError(RejectionReason.INVALID_CLAIM) from error

    def _checked_time_claims(self, claims: Mapping[str, object]) -> tuple[int, int]:
        expires_at = _integer_claim(claims, "exp")
        issued_at = _integer_claim(claims, "iat")
        not_before = _integer_claim(claims, "nbf") if "nbf" in claims else None
        now = self._wall_clock()
        if now >= expires_at + self._leeway_seconds:
            raise _RefusalError(RejectionReason.EXPIRED)
        if issued_at > now + self._leeway_seconds:
            raise _RefusalError(RejectionReason.ISSUED_IN_FUTURE)
        if not_before is not None and not_before > now + self._leeway_seconds:
            raise _RefusalError(RejectionReason.NOT_YET_VALID)
        return expires_at, issued_at

    def _signing_key(self, key_id: str) -> RSAPublicKey:
        key_set = self._key_set
        if not self._is_current(key_set) or key_id not in key_set.keys:
            self._refresh_key_set()
            key_set = self._key_set
        if not self._is_current(key_set):
            raise _RefusalError(RejectionReason.KEY_SET_UNAVAILABLE)
        key = key_set.keys.get(key_id)
        if key is None:
            raise _RefusalError(RejectionReason.UNKNOWN_KEY_ID)
        return key

    def _is_current(self, key_set: _KeySet | None) -> TypeGuard[_KeySet]:
        return (
            key_set is not None
            and self._monotonic_clock() - key_set.fetched_at < KEY_SET_TTL_SECONDS
        )

    def _refresh_key_set(self) -> None:
        # A request arriving while another refreshes does not wait for it: it
        # fails closed on the snapshot it already holds, so a flood of unknown
        # `kid`s costs one fetch and no blocked request threads.
        if not self._refresh_lock.acquire(blocking=False):
            return
        try:
            now = self._monotonic_clock()
            if (
                self._last_refresh_at is not None
                and now - self._last_refresh_at < KEY_SET_REFRESH_COOLDOWN_SECONDS
            ):
                return
            self._last_refresh_at = now
            try:
                keys = _parse_key_set(self._fetch_key_set(self._jwks_url))
            # The injected fetch's message is not this module's to vouch for:
            # it may quote the key-set URL, and that URL may hold a secret.
            except KeySetFetchError:
                failure = _RefreshFailure.FETCH_FAILED
            except _InvalidKeySetError as refusal:
                failure = refusal.failure
            else:
                self._key_set = _KeySet(keys=keys, fetched_at=now)
                return
            log.warning("Refreshing the key set failed: %s", failure)
        finally:
            self._refresh_lock.release()


def _library_checks() -> Options:
    """PyJWT's options, built fresh for every call so no caller can alter a
    shared one. Time claims and `sub` are off here because this module checks
    them itself; `jti` belongs to the caller's protocol."""
    return {
        "verify_signature": True,
        "verify_aud": True,
        "verify_iss": True,
        "verify_exp": False,
        "verify_iat": False,
        "verify_nbf": False,
        "verify_sub": False,
        "verify_jti": False,
    }


def _parse_token(token: str) -> _ParsedToken:
    if len(token) > MAX_TOKEN_CHARACTERS:
        raise _RefusalError(RejectionReason.TOKEN_TOO_LONG)
    segments = token.split(".")
    if len(segments) != _JWS_COMPACT_SEGMENTS:
        raise _RefusalError(RejectionReason.MALFORMED_TOKEN)
    try:
        header_bytes, claims_bytes, _signature = (_base64url_decode(part) for part in segments)
    except ValueError as error:
        raise _RefusalError(RejectionReason.MALFORMED_TOKEN) from error
    header = _strict_json_object(header_bytes)
    claims = _strict_json_object(claims_bytes)
    return _ParsedToken(key_id=_header_key_id(header), claims=MappingProxyType(claims))


def _header_key_id(header: Mapping[str, object]) -> str:
    if _FORBIDDEN_HEADER_MEMBERS & header.keys():
        raise _RefusalError(RejectionReason.FORBIDDEN_HEADER)
    if header.get("alg") != _ALGORITHM:
        raise _RefusalError(RejectionReason.UNSUPPORTED_ALGORITHM)
    key_id = header.get("kid")
    if not _is_key_id(key_id):
        raise _RefusalError(RejectionReason.INVALID_KEY_ID)
    return key_id


def _is_key_id(value: object) -> TypeGuard[str]:
    return isinstance(value, str) and 0 < len(value) <= MAX_KEY_ID_CHARACTERS


def _integer_claim(claims: Mapping[str, object], name: str) -> int:
    value = claims.get(name)
    if isinstance(value, bool) or not isinstance(value, int):
        raise _RefusalError(RejectionReason.INVALID_CLAIM)
    return value


def _subject(claims: Mapping[str, object]) -> str | None:
    if "sub" not in claims:
        return None
    subject = claims["sub"]
    if not isinstance(subject, str) or not subject:
        raise _RefusalError(RejectionReason.INVALID_CLAIM)
    return subject


def _audiences(claims: Mapping[str, object]) -> tuple[str, ...]:
    """`aud` as PyJWT accepted it: one string, or a list of strings."""
    audience = claims["aud"]
    return (audience,) if isinstance(audience, str) else tuple(cast(list[str], audience))


def _base64url_decode(segment: str) -> bytes:
    """Decodes unpadded base64url, refusing what the lenient stdlib decoder
    would silently skip or round off, so this parse accepts exactly the
    canonical segments PyJWT accepts and both read the same bytes."""
    if not _BASE64URL.fullmatch(segment):
        raise ValueError("not base64url")
    decoded = base64.urlsafe_b64decode(segment + "=" * (-len(segment) % 4))
    if base64.urlsafe_b64encode(decoded).rstrip(b"=") != segment.encode():
        raise ValueError("not canonical base64url")
    return decoded


def _strict_json_object(document: bytes) -> dict[str, object]:
    try:
        text = document.decode("utf-8")
    except UnicodeDecodeError as error:
        raise _RefusalError(RejectionReason.MALFORMED_TOKEN) from error
    # Measured before parsing: the stdlib parser recurses per level and would
    # raise RecursionError on hostile nesting rather than a parse error.
    if _nesting_depth(text) > MAX_JSON_NESTING_DEPTH:
        raise _RefusalError(RejectionReason.NESTING_TOO_DEEP)
    try:
        parsed = json.loads(
            text,
            object_pairs_hook=_object_without_duplicates,
            parse_constant=_refuse_non_json_constant,
            parse_float=_finite_number,
        )
    except ValueError as error:
        raise _RefusalError(RejectionReason.MALFORMED_TOKEN) from error
    if not isinstance(parsed, dict):
        raise _RefusalError(RejectionReason.MALFORMED_TOKEN)
    return parsed


def _nesting_depth(text: str) -> int:
    depth = deepest = 0
    in_string = escaped = False
    for character in text:
        if in_string:
            if escaped:
                escaped = False
            elif character == "\\":
                escaped = True
            elif character == '"':
                in_string = False
        elif character == '"':
            in_string = True
        elif character in "[{":
            depth += 1
            deepest = max(deepest, depth)
        elif character in "]}":
            depth -= 1
    return deepest


def _object_without_duplicates(members: list[tuple[str, object]]) -> dict[str, object]:
    parsed = dict(members)
    if len(parsed) != len(members):
        raise _RefusalError(RejectionReason.DUPLICATE_MEMBER)
    return parsed


def _refuse_non_json_constant(constant: str) -> NoReturn:
    """The stdlib parser reads `NaN`, `Infinity` and `-Infinity`; JSON has none."""
    raise ValueError(f"{constant} is not JSON")


def _finite_number(literal: str) -> float:
    """A literal such as `1e999999` is valid JSON that `float` rounds to an
    infinity, the value `_refuse_non_json_constant` keeps out."""
    number = float(literal)
    if not math.isfinite(number):
        raise ValueError(f"{literal} overflows to a non-finite number")
    return number


def _parse_key_set(document: bytes) -> Mapping[str, RSAPublicKey]:
    if len(document) > MAX_KEY_SET_BYTES:
        raise _InvalidKeySetError(_RefreshFailure.TOO_LARGE)
    try:
        parsed = _strict_json_object(document)
    except _RefusalError:
        raise _InvalidKeySetError(_RefreshFailure.NOT_STRICT_JSON) from None
    jwks = parsed.get("keys")
    if not isinstance(jwks, list) or not 0 < len(jwks) <= MAX_KEY_SET_KEYS:
        raise _InvalidKeySetError(_RefreshFailure.KEY_COUNT_OUT_OF_RANGE)
    keys: dict[str, RSAPublicKey] = {}
    for jwk in jwks:
        if not isinstance(jwk, dict):
            raise _InvalidKeySetError(_RefreshFailure.KEY_NOT_AN_OBJECT)
        if _SECRET_KEY_MEMBERS & jwk.keys():
            raise _InvalidKeySetError(_RefreshFailure.SECRET_KEY_PUBLISHED)
        if not _is_rs256_verification_key(jwk):
            continue
        key_id, key = _public_signing_key(jwk)
        if key_id in keys:
            raise _InvalidKeySetError(_RefreshFailure.DUPLICATE_KEY_ID)
        keys[key_id] = key
    if not keys:
        raise _InvalidKeySetError(_RefreshFailure.NO_RS256_SIGNING_KEY)
    return MappingProxyType(keys)


def _is_rs256_verification_key(jwk: Mapping[str, object]) -> bool:
    """An RSA key may limit itself by `alg`, `use` and `key_ops`; each it
    names must allow verifying an RS256 signature."""
    key_operations = jwk.get("key_ops", ["verify"])
    return (
        jwk.get("kty") == "RSA"
        and jwk.get("alg", _ALGORITHM) == _ALGORITHM
        and jwk.get("use", "sig") == "sig"
        and isinstance(key_operations, list)
        and "verify" in key_operations
    )


def _public_signing_key(jwk: Mapping[str, object]) -> tuple[str, RSAPublicKey]:
    key_id = jwk.get("kid")
    modulus, exponent = jwk.get("n"), jwk.get("e")
    if not _is_key_id(key_id) or not isinstance(modulus, str) or not isinstance(exponent, str):
        raise _InvalidKeySetError(_RefreshFailure.MALFORMED_KEY)
    try:
        key = RSAPublicNumbers(
            e=_base64url_unsigned(exponent), n=_base64url_unsigned(modulus)
        ).public_key()
    except ValueError as error:
        raise _InvalidKeySetError(_RefreshFailure.INVALID_RSA_KEY) from error
    if key.key_size < MIN_RSA_KEY_BITS:
        raise _InvalidKeySetError(_RefreshFailure.KEY_TOO_SHORT)
    return key_id, key


def _base64url_unsigned(value: str) -> int:
    return int.from_bytes(_base64url_decode(value), byteorder="big")
