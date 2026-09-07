"""Password hashing and the strength rules a chosen password must satisfy."""

from __future__ import annotations

import pytest
from webauth_arrangement import Argon2idStyleHasher, FakeUser

from webauth.login import password_admits_account
from webauth.passwords import (
    _DUMMY_HASH,
    BCRYPT_ROUNDS,
    MIN_PASSWORD_LENGTH,
    BcryptPasswordHasher,
    check_password_strength,
    hash_password,
    verify_password,
    verify_password_constant_time,
)


def test_hash_and_verify_password() -> None:
    hashed = hash_password("testpassword123")
    assert hashed != "testpassword123"
    assert verify_password("testpassword123", hashed)


def test_verify_wrong_password() -> None:
    hashed = hash_password("correct-password")
    assert not verify_password("wrong-password", hashed)


def test_hash_produces_different_hashes() -> None:
    h1 = hash_password("same-password")
    h2 = hash_password("same-password")
    assert h1 != h2


def test_a_missing_hash_is_still_compared() -> None:
    """An unknown username must cost the same as a known one, or the timing
    difference tells an attacker which accounts exist."""
    assert verify_password_constant_time("any-password", None) is False


def test_cost_and_length_floor() -> None:
    assert BCRYPT_ROUNDS == 12
    assert MIN_PASSWORD_LENGTH == 8


def test_common_password_rejected() -> None:
    with pytest.raises(ValueError, match="too common"):
        check_password_strength("password")


def test_low_entropy_rejected() -> None:
    with pytest.raises(ValueError, match="unique characters"):
        check_password_strength("aaaaaaaa")


def test_strong_password_accepted() -> None:
    assert check_password_strength("s3cur3P@ss!") == "s3cur3P@ss!"


def test_none_password_passes() -> None:
    assert check_password_strength(None) is None


def test_an_injected_hasher_admits_the_account_it_signed() -> None:
    hasher = Argon2idStyleHasher()
    user = FakeUser(password_hash=hasher.hash("open-sesame-42"))
    assert password_admits_account("open-sesame-42", user, hasher=hasher) is True
    assert password_admits_account("not-the-password", user, hasher=hasher) is False


def test_bcrypt_hasher_round_trips_a_password() -> None:
    hasher = BcryptPasswordHasher()
    stored = hasher.hash("s3cur3P@ss!")
    assert hasher.verify("s3cur3P@ss!", stored) is True
    assert hasher.verify("wrong-password", stored) is False


def test_bcrypt_verify_with_no_hash_still_pays_the_full_cost(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """A missing hash must be checked against the dummy, or the timing gap
    tells an attacker the account does not exist."""
    verified_against: list[str] = []

    def spy(password: str, password_hash: str) -> bool:
        verified_against.append(password_hash)
        return False

    monkeypatch.setattr("webauth.passwords.verify_password", spy)

    assert BcryptPasswordHasher().verify("any-password", None) is False
    assert verified_against == [_DUMMY_HASH]
