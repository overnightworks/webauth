"""Verification of RS256 tokens signed by a remote issuer's published keys.

`JwtVerifier.verify` takes a raw compact JWS and answers `VerifiedClaims` or
`Rejected(reason)`. The caller names the issuer, the audiences it accepts, the
URL of the issuer's key set and the clock leeway; what a protocol demands of
the claims beyond signature, issuer, audience and time — an ID token's nonce,
a logout token's events — belongs to the caller, which reads them from
`VerifiedClaims.claims`.

PyJWT reads the token. This module bounds the token length and the header
segment before PyJWT parses anything, accepts an RS256-only header whose
`kid`, when present, is a bounded string, and lets PyJWT verify the
signature, audience and issuer; the time claims are checked here against the
injected wall clock, so leeway has one owner.

Signing keys come from the configured key-set URL through the injected fetch.
A fetched key set replaces the cached one only once every key in it is sound,
so a failed or poisoned refresh never evicts the last good set; that set
expires one hour after it was fetched, on the injected monotonic clock. Keys
published for another purpose — encryption, another algorithm or key type — are
passed over, not refused, because issuers such as Keycloak publish them beside
the signing keys. They do not count toward `MAX_KEY_SET_KEYS`, which bounds the
RS256 verification keys, named or not, the only ones that cost key construction
and cache space. The size of the whole document is bounded by `MAX_KEY_SET_BYTES`, so
passed-over entries cost a few lookups each and nothing more. Each entry is
checked in this order: an object without a secret member, then RS256
eligibility, then the count, then the key itself.

A token without a `kid` member is read against the key set's only RS256
verification key, whether or not that key carries a `kid`; against several
eligible keys it is refused as `INVALID_KEY_ID`, as OIDC Core 10.1 requires.
An eligible key may lack `kid`; beside other eligible keys it is admitted but
unreachable, because a named `kid` looks up only named keys. An explicit
`"kid": null` is malformed, and a duplicate named `kid` is refused. A token
without `kid` triggers no refresh of its own, so a rotation of a sole key, or a
change between one and several keys, can stay unseen for up to that hour,
unless a token naming an unfamiliar `kid` triggers an earlier refresh
(OIDC Core 10.1.1: an unfamiliar `kid` is the rotation signal).

A token naming an unfamiliar `kid` triggers a refresh, but not on every such
token: a refresh is skipped for `KEY_SET_REFRESH_COOLDOWN_SECONDS` after the
last attempt and while another request is refreshing. The refusal then depends
on the last refresh attempt: `UNKNOWN_KEY_ID` when it succeeded and the key set
it fetched lacks the `kid`, `KEY_SET_UNAVAILABLE` when it failed, because the
`kid` may belong to a rotated key. A token that passes the header checks while
no current key set remains after the refresh attempt is refused as
`KEY_SET_UNAVAILABLE`.
"""

from __future__ import annotations

import base64
import json
import logging
import re
import threading
from collections.abc import Callable, Collection, Iterator, Mapping
from dataclasses import dataclass
from enum import StrEnum
from types import MappingProxyType
from typing import TYPE_CHECKING, TypeGuard, cast

import jwt
from cryptography.hazmat.primitives.asymmetric.rsa import RSAPublicKey, RSAPublicNumbers
from jwt.types import Options

from webauth._validation import _is_whole_number, require_non_negative_whole_number
from webauth.https_client import (
    MAX_KEY_SET_BYTES,
    KeySetFetchError,
    is_https_url,
)

if TYPE_CHECKING:
    from webauth.ports import WallClock

_log = logging.getLogger(__name__)

MAX_TOKEN_CHARACTERS = 8 * 1024
_MAX_HEADER_SEGMENT_CHARACTERS = 512
_MAX_KEY_ID_CHARACTERS = 128
_KEY_SET_TTL_SECONDS = 60 * 60
KEY_SET_REFRESH_COOLDOWN_SECONDS = 30
MAX_KEY_SET_KEYS = 10
_MIN_RSA_KEY_BITS = 2048

_ALGORITHM = "RS256"
_BASE64URL = re.compile(r"[A-Za-z0-9_-]*")
# Private RSA members, and `k`, a symmetric key: a key set publishing either
# has leaked a secret and is not trusted for any of its keys.
_SECRET_KEY_MEMBERS = frozenset({"d", "p", "q", "dp", "dq", "qi", "oth", "k"})

MonotonicClock = Callable[[], float]
"""Seconds on a clock that never jumps; ages the key set and its cooldown."""
KeySetFetch = Callable[[str], bytes]
"""Fetches the key set document at the URL, raising `KeySetFetchError` on failure."""

__all__ = [
    "KEY_SET_REFRESH_COOLDOWN_SECONDS",
    "MAX_KEY_SET_KEYS",
    "MAX_TOKEN_CHARACTERS",
    "JwtVerifier",
    "KeySetFetch",
    "MonotonicClock",
    "Rejected",
    "RejectionReason",
    "VerifiedClaims",
]


class RejectionReason(StrEnum):
    # A refusal reason, not a credential
    TOKEN_TOO_LONG = "token-too-long"  # noqa: S105
    MALFORMED_TOKEN = "malformed-token"  # noqa: S105
    UNSUPPORTED_ALGORITHM = "unsupported-algorithm"
    INVALID_KEY_ID = "invalid-key-id"
    INVALID_TOKEN_TYPE = "invalid-token-type"  # noqa: S105
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


class _VerificationRefusal(Exception):
    def __init__(self, reason: RejectionReason) -> None:
        super().__init__(reason)
        self.reason = reason


class _RefreshFailure(StrEnum):
    """Why a key-set refresh failed, in codes this module owns: the issuer,
    the URL and the remote key IDs stay out of the log."""

    FETCH_FAILED = "fetch-failed"
    TOO_LARGE = "too-large"
    NOT_JSON = "not-json"
    KEY_COUNT_OUT_OF_RANGE = "key-count-out-of-range"
    KEY_NOT_AN_OBJECT = "key-not-an-object"
    # A refusal reason, not a credential
    SECRET_KEY_PUBLISHED = "secret-key-published"  # noqa: S105
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
class _KeySet:
    named: Mapping[str, RSAPublicKey]
    sole: RSAPublicKey | None
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
        require_non_negative_whole_number("leeway_seconds", leeway_seconds, unit="seconds")
        self._issuer = issuer
        self._audiences = sorted(audiences)
        self._jwks_url = jwks_url
        self._leeway_seconds = leeway_seconds
        self._fetch_key_set = fetch_key_set
        self._wall_clock = wall_clock
        self._monotonic_clock = monotonic_clock
        self._key_set: _KeySet | None = None
        self._last_refresh_at: float | None = None
        self._last_refresh_failed = False
        self._refresh_lock = threading.Lock()

    def verify(
        self,
        token: str,
        *,
        expected_type: str | None = None,
        expected_media_types: frozenset[str] | None = None,
    ) -> VerifiedClaims | Rejected:
        """Verify ``token``; when ``expected_type`` is given, its header's
        ``typ`` must equal it exactly. ``expected_media_types`` instead compares
        ``typ`` as a media type (RFC 7515 section 4.1.9): an ASCII string whose
        ASCII-lowercase form is a member. It must be a ``frozenset`` of non-empty
        lowercase ASCII strings and exclude ``expected_type``, or ``ValueError``.

        A token over ``MAX_TOKEN_CHARACTERS`` is refused as ``TOKEN_TOO_LONG``.
        A token whose encoded header segment, the part before the first dot,
        exceeds 512 characters is refused as ``MALFORMED_TOKEN`` even when the
        whole token fits that limit; an issuer whose headers carry more than
        that cannot be verified."""
        _require_comparable_types(expected_type, expected_media_types)
        try:
            return self._verified_claims(token, expected_type, expected_media_types)
        except _VerificationRefusal as refusal:
            return Rejected(refusal.reason)

    def _verified_claims(
        self,
        token: str,
        expected_type: str | None,
        expected_media_types: frozenset[str] | None,
    ) -> VerifiedClaims:
        if len(token) > MAX_TOKEN_CHARACTERS:
            raise _VerificationRefusal(RejectionReason.TOKEN_TOO_LONG)
        # RFC 7515's compact serialization is ASCII; PyJWT raises on a lone surrogate.
        if not token.isascii():
            raise _VerificationRefusal(RejectionReason.MALFORMED_TOKEN)
        # PyJWT parses the header with `json.loads` before it checks anything,
        # and hostile nesting within the token cap crashes a thread whose stack
        # is small (musl's default); the bound keeps the depth far below that.
        if len(token.split(".", 1)[0]) > _MAX_HEADER_SEGMENT_CHARACTERS:
            raise _VerificationRefusal(RejectionReason.MALFORMED_TOKEN)
        try:
            header = jwt.get_unverified_header(token)  # NOSONAR(S5659) picks key and refusal only
        except jwt.InvalidTokenError as error:
            raise _VerificationRefusal(RejectionReason.MALFORMED_TOKEN) from error
        if header.get("alg") != _ALGORITHM:
            raise _VerificationRefusal(RejectionReason.UNSUPPORTED_ALGORITHM)
        if not _has_expected_type(header, expected_type, expected_media_types):
            raise _VerificationRefusal(RejectionReason.INVALID_TOKEN_TYPE)
        key_id = _header_key_id(header)
        claims = self._verified_payload(token, self._signing_key(key_id))
        expires_at, issued_at = self._checked_time_claims(claims)
        return VerifiedClaims(
            subject=_subject(claims),
            issuer=self._issuer,
            audiences=_audiences(claims),
            expires_at=expires_at,
            issued_at=issued_at,
            claims=claims,
        )

    def _verified_payload(self, token: str, key: RSAPublicKey) -> Mapping[str, object]:
        try:
            claims = jwt.decode(
                token,
                key=key,
                algorithms=[_ALGORITHM],
                audience=self._audiences,
                issuer=self._issuer,
                options=_library_checks(),
            )
        except jwt.InvalidSignatureError as error:
            raise _VerificationRefusal(RejectionReason.INVALID_SIGNATURE) from error
        except jwt.InvalidAudienceError as error:
            raise _VerificationRefusal(RejectionReason.INVALID_AUDIENCE) from error
        except jwt.InvalidIssuerError as error:
            raise _VerificationRefusal(RejectionReason.INVALID_ISSUER) from error
        except jwt.MissingRequiredClaimError as error:
            raise _VerificationRefusal(RejectionReason.INVALID_CLAIM) from error
        except jwt.InvalidTokenError as error:
            raise _VerificationRefusal(RejectionReason.MALFORMED_TOKEN) from error
        return MappingProxyType(claims)

    def _checked_time_claims(self, claims: Mapping[str, object]) -> tuple[int, int]:
        expires_at = _integer_claim(claims, "exp")
        issued_at = _integer_claim(claims, "iat")
        not_before = _integer_claim(claims, "nbf") if "nbf" in claims else None
        now = self._wall_clock()
        if now >= expires_at + self._leeway_seconds:
            raise _VerificationRefusal(RejectionReason.EXPIRED)
        if issued_at > now + self._leeway_seconds:
            raise _VerificationRefusal(RejectionReason.ISSUED_IN_FUTURE)
        if not_before is not None and not_before > now + self._leeway_seconds:
            raise _VerificationRefusal(RejectionReason.NOT_YET_VALID)
        return expires_at, issued_at

    def _signing_key(self, key_id: str | None) -> RSAPublicKey:
        key_set = self._key_set
        if not self._is_current(key_set) or (key_id is not None and key_id not in key_set.named):
            self._refresh_key_set()
            key_set = self._key_set
        if not self._is_current(key_set):
            raise _VerificationRefusal(RejectionReason.KEY_SET_UNAVAILABLE)
        if key_id is None:
            if key_set.sole is None:
                raise _VerificationRefusal(RejectionReason.INVALID_KEY_ID)
            return key_set.sole
        key = key_set.named.get(key_id)
        if key is None:
            # An unknown `kid` is only a forged one when the key set could be
            # fetched; after a failed refresh it may be a rotated key.
            if self._last_refresh_failed:
                raise _VerificationRefusal(RejectionReason.KEY_SET_UNAVAILABLE)
            raise _VerificationRefusal(RejectionReason.UNKNOWN_KEY_ID)
        return key

    def _is_current(self, key_set: _KeySet | None) -> TypeGuard[_KeySet]:
        return (
            key_set is not None
            and self._monotonic_clock() - key_set.fetched_at < _KEY_SET_TTL_SECONDS
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
                named, sole = _parse_key_set(self._fetch_key_set(self._jwks_url))
            # The injected fetch's message is not this module's to vouch for:
            # it may quote the key-set URL, and that URL may hold a secret.
            except KeySetFetchError:
                failure = _RefreshFailure.FETCH_FAILED
            except _InvalidKeySetError as refusal:
                failure = refusal.failure
            else:
                self._key_set = _KeySet(named=named, sole=sole, fetched_at=now)
                self._last_refresh_failed = False
                return
            self._last_refresh_failed = True
            _log.warning("Refreshing the key set failed: %s", failure)
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


def _require_comparable_types(
    expected_type: str | None, expected_media_types: frozenset[str] | None,
) -> None:
    if expected_media_types is None:
        return
    if expected_type is not None:
        raise ValueError("expected_type and expected_media_types exclude each other")
    if type(expected_media_types) is not frozenset or not all(
        isinstance(media_type, str)
        and media_type
        and media_type.isascii()
        and media_type == media_type.lower()
        for media_type in expected_media_types
    ):
        raise ValueError("expected_media_types must be a frozenset of non-empty lowercase ASCII strings")


def _has_expected_type(
    header: Mapping[str, object],
    expected_type: str | None,
    expected_media_types: frozenset[str] | None,
) -> bool:
    declared = header.get("typ")
    if expected_media_types is not None:
        return (
            isinstance(declared, str)
            and declared.isascii()
            and declared.lower() in expected_media_types
        )
    return expected_type is None or declared == expected_type


def _header_key_id(header: Mapping[str, object]) -> str | None:
    if "kid" not in header:
        return None
    key_id = header["kid"]
    if not _is_key_id(key_id):
        raise _VerificationRefusal(RejectionReason.INVALID_KEY_ID)
    return key_id


def _is_key_id(value: object) -> TypeGuard[str]:
    return isinstance(value, str) and 0 < len(value) <= _MAX_KEY_ID_CHARACTERS


def _integer_claim(claims: Mapping[str, object], name: str) -> int:
    value = claims.get(name)
    if not _is_whole_number(value):
        raise _VerificationRefusal(RejectionReason.INVALID_CLAIM)
    return value


def _subject(claims: Mapping[str, object]) -> str | None:
    if "sub" not in claims:
        return None
    subject = claims["sub"]
    if not isinstance(subject, str) or not subject:
        raise _VerificationRefusal(RejectionReason.INVALID_CLAIM)
    return subject


def _audiences(claims: Mapping[str, object]) -> tuple[str, ...]:
    """`aud` as PyJWT accepted it: one string, or a list of strings."""
    audience = claims["aud"]
    return (audience,) if isinstance(audience, str) else tuple(cast(list[str], audience))


def _base64url_decode(segment: str) -> bytes:
    """Decodes unpadded base64url (a JWK's `n` and `e`), refusing what the
    lenient stdlib decoder would silently skip or round off."""
    if not _BASE64URL.fullmatch(segment):
        raise ValueError("not base64url")
    decoded = base64.urlsafe_b64decode(segment + "=" * (-len(segment) % 4))
    if base64.urlsafe_b64encode(decoded).rstrip(b"=") != segment.encode():
        raise ValueError("not canonical base64url")
    return decoded


def _json_object(document: bytes) -> dict[str, object] | None:
    """The JSON object `document` holds, or `None` for anything else. The
    issuer is trusted for what it serves, so the stdlib parser reads it as is:
    a member named twice keeps its last value."""
    try:
        parsed = json.loads(document)
    except (ValueError, RecursionError):
        return None
    return parsed if isinstance(parsed, dict) else None


def _parse_key_set(
    document: bytes,
) -> tuple[Mapping[str, RSAPublicKey], RSAPublicKey | None]:
    if len(document) > MAX_KEY_SET_BYTES:
        raise _InvalidKeySetError(_RefreshFailure.TOO_LARGE)
    parsed = _json_object(document)
    if parsed is None:
        raise _InvalidKeySetError(_RefreshFailure.NOT_JSON)
    jwks = parsed.get("keys")
    if not isinstance(jwks, list) or not jwks:
        raise _InvalidKeySetError(_RefreshFailure.KEY_COUNT_OUT_OF_RANGE)
    named, sole = _rs256_verification_keys(jwks)
    return MappingProxyType(named), sole


def _rs256_verification_keys(
    jwks: list[object],
) -> tuple[dict[str, RSAPublicKey], RSAPublicKey | None]:
    named: dict[str, RSAPublicKey] = {}
    eligible = 0
    last_key: RSAPublicKey | None = None
    for jwk in _rs256_verification_jwks(jwks):
        if eligible == MAX_KEY_SET_KEYS:
            raise _InvalidKeySetError(_RefreshFailure.KEY_COUNT_OUT_OF_RANGE)
        key_id, last_key = _public_signing_key(jwk)
        eligible += 1
        if key_id is None:
            continue
        if key_id in named:
            raise _InvalidKeySetError(_RefreshFailure.DUPLICATE_KEY_ID)
        named[key_id] = last_key
    if not eligible:
        raise _InvalidKeySetError(_RefreshFailure.NO_RS256_SIGNING_KEY)
    return named, last_key if eligible == 1 else None


def _rs256_verification_jwks(jwks: list[object]) -> Iterator[dict[str, object]]:
    for jwk in jwks:
        if not isinstance(jwk, dict):
            raise _InvalidKeySetError(_RefreshFailure.KEY_NOT_AN_OBJECT)
        if _SECRET_KEY_MEMBERS & jwk.keys():
            raise _InvalidKeySetError(_RefreshFailure.SECRET_KEY_PUBLISHED)
        if _is_rs256_verification_key(jwk):
            yield jwk


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


def _declared_key_id(jwk: Mapping[str, object]) -> str | None:
    if "kid" not in jwk:
        return None
    key_id = jwk["kid"]
    if not _is_key_id(key_id):
        raise _InvalidKeySetError(_RefreshFailure.MALFORMED_KEY)
    return key_id


def _public_signing_key(jwk: Mapping[str, object]) -> tuple[str | None, RSAPublicKey]:
    key_id = _declared_key_id(jwk)
    modulus, exponent = jwk.get("n"), jwk.get("e")
    if not isinstance(modulus, str) or not isinstance(exponent, str):
        raise _InvalidKeySetError(_RefreshFailure.MALFORMED_KEY)
    try:
        key = RSAPublicNumbers(
            e=_base64url_unsigned(exponent), n=_base64url_unsigned(modulus)
        ).public_key()
    except ValueError as error:
        raise _InvalidKeySetError(_RefreshFailure.INVALID_RSA_KEY) from error
    if key.key_size < _MIN_RSA_KEY_BITS:
        raise _InvalidKeySetError(_RefreshFailure.KEY_TOO_SHORT)
    return key_id, key


def _base64url_unsigned(value: str) -> int:
    return int.from_bytes(_base64url_decode(value), byteorder="big")
