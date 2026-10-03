"""Password hashing and the strength rules a chosen password must satisfy."""

from __future__ import annotations

import unicodedata
from typing import Final

from argon2 import Parameters, Type
from argon2 import PasswordHasher as Argon2PasswordHasher
from argon2.exceptions import VerifyMismatchError

OWASP_ARGON2ID: Final = Parameters(
    type=Type.ID,
    version=19,
    salt_len=16,
    hash_len=32,
    time_cost=2,
    memory_cost=19 * 1024,
    parallelism=1,
)
_ARGON2ID_HASH_PREFIX: Final = "$argon2id$"
MIN_PASSWORD_LENGTH: Final = 8
MIN_UNIQUE_CHARS: Final = 4

_COMMON_PASSWORDS = frozenset({
    "password", "12345678", "123456789", "1234567890", "qwerty123",
    "password1", "iloveyou", "sunshine1", "princess1", "football1",
    "trustno1", "letmein1", "baseball1", "abc12345", "monkey123",
    "dragon12", "michael1", "jennifer1", "superman1", "shadow12",
    "password123", "admin123", "welcome1", "changeme1", "passw0rd",
    "p@ssw0rd", "p@ssword", "abcd1234", "1q2w3e4r", "qwer1234",
    "asdfghjk", "zxcvbnm1", "11111111", "00000000", "12341234",
    "abcdefgh", "87654321", "master12", "access14", "charlie1",
    "qwerty12", "iloveu12", "starwars", "whatever", "computer",
    "corvette", "maverick", "steelers",
    "admin1234", "welcome123", "password12", "letmein12", "master123",
    "login123", "welcome12", "mustang1", "jordan23", "buster12",
    "ranger12", "batman12", "thomas12", "robert12", "soccer12",
    "hockey12", "hunter12", "george12", "andrew12", "harley12",
    "daniel12", "matthew1", "jessica1", "william1", "anthony1",
    "summer12", "winter12", "spring12", "autumn12", "january1",
    "february", "december", "saturday", "thursday", "midnight",
    "sunshine", "princess", "football", "baseball", "trustno12",
    "qwerty1234", "asdf1234", "zxcv1234", "q1w2e3r4", "1234qwer",
    "pass1234", "test1234", "temp1234", "user1234", "guest1234",
    "default1", "system12", "server12", "network1", "internet",
    "security", "password1234", "admin12345", "root1234", "toor1234",
    "samsung1", "ferrari1", "porsche1", "mercedes", "corvett1",
    "elephant", "giraffe1", "dolphins", "predator", "scorpion",
    "spiderman", "ironman1", "avengers", "deadpool", "thanos12",
    "iloveyou1", "iloveyou2", "loveyou1", "mylove12", "forever1",
    "diamond1", "crystal1", "rainbow1", "butterfly", "angelica",
    "carolina", "virginia", "colorado", "portland", "california",
    "newyork1", "london12", "paris123", "tokyo123", "berlin12",
    "samsung123", "apple123", "google12", "amazon12", "facebook",
    "twitter1", "youtube1", "spotify1", "netflix1", "linkedin",
    "sunshine123", "chocolate", "strawberry", "blueberry", "mountain",
    "password!", "p@ss1234", "p@$$w0rd", "pa$$word", "pa55word",
    "trustme1", "believe1", "freedom1", "justice1", "liberty1",
    "american", "patriots", "yankees1", "lakers12", "cowboys1",
    "packers1", "arsenal1", "chelsea1", "liverpool", "barcelona",
    "realmadrid", "juventus", "manchester",
    "summer2024", "summer2025", "summer2026", "winter2024", "winter2025",
    "spring2024", "spring2025", "spring2026", "welcome2024", "welcome2025",
    "january2024", "january2025", "january2026",
    "qwertyui", "asdfghjkl", "zxcvbnm12", "1qaz2wsx", "2wsx3edc",
    "qazwsxed", "q1w2e3r4t5", "1q2w3e4r5t",
})


class UnknownHashFormatError(ValueError):
    """A stored hash that is not Argon2id, so no password can be checked against it."""


def _normalized_password(password: str) -> str:
    """The NFC form of a password: one spelling for what looks like one text.

    "Größe" typed with a composed "ö" and with "o" plus a combining diaeresis
    must count, hash and match as the same password.
    """
    return unicodedata.normalize("NFC", password)


class Argon2idPasswordHasher:
    """The Argon2id ``PasswordHasher`` this library provides out of the box.

    New hashes use ``parameters`` (OWASP's m=19 MiB, t=2, p=1 by default); a
    stored Argon2id hash is verified with the parameters written inside it, so
    hashes made with other costs stay checkable. Every other format — bcrypt,
    Argon2i, Argon2d, an empty or garbled string — raises
    ``UnknownHashFormatError`` rather than reading as a wrong password. A
    stored hash that starts like Argon2id but cannot be decoded raises
    ``argon2.exceptions.VerificationError``.
    """

    def __init__(self, parameters: Parameters = OWASP_ARGON2ID) -> None:
        if parameters.type is not Type.ID:
            raise ValueError(f"Argon2idPasswordHasher needs Type.ID, got {parameters.type!r}")
        self._argon2 = Argon2PasswordHasher.from_parameters(parameters)
        # Hashed once with the same parameters, so verifying a username nobody
        # holds costs what verifying a wrong password costs.
        self._dummy_hash = self._argon2.hash("no account has this password")

    def hash(self, password: str) -> str:
        return self._argon2.hash(_normalized_password(password))

    def verify(self, password: str, stored_hash: str | None) -> bool:
        if stored_hash is None:
            self._matches(password, self._dummy_hash)
            return False
        if not stored_hash.startswith(_ARGON2ID_HASH_PREFIX):
            raise UnknownHashFormatError("stored password hash is not Argon2id")
        return self._matches(password, stored_hash)

    def _matches(self, password: str, stored_hash: str) -> bool:
        try:
            return self._argon2.verify(stored_hash, _normalized_password(password))
        except VerifyMismatchError:
            return False


def check_password_strength(value: str | None) -> str | None:
    """Reject a short, common or low-entropy password; return its NFC form.

    Usable directly and as a Pydantic ``field_validator``. ``None`` passes
    through untouched, so an optional password field may stay unset.
    """
    if value is None:
        return None
    password = _normalized_password(value)
    if len(password) < MIN_PASSWORD_LENGTH:
        raise ValueError(
            f"Password must be at least {MIN_PASSWORD_LENGTH} characters long"
        )
    if password.lower() in _COMMON_PASSWORDS:
        raise ValueError("Password is too common — choose something less predictable")
    if len(set(password)) < MIN_UNIQUE_CHARS:
        raise ValueError(
            f"Password must contain at least {MIN_UNIQUE_CHARS} unique characters"
        )
    return password
