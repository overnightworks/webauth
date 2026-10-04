"""Password hashing and the strength rules a chosen password must satisfy."""

from __future__ import annotations

import unicodedata
from dataclasses import replace

import pytest
from argon2 import Parameters, Type, extract_parameters
from argon2 import PasswordHasher as Argon2PasswordHasher
from argon2.profiles import CHEAPEST
from webauth_arrangement import Argon2idStyleHasher, FakeUser, a_cheap_argon2id_hasher

from webauth.login import LoginOutcome, judge_credentials
from webauth.passwords import (
    Argon2idPasswordHasher,
    UnknownHashFormatError,
    check_password_strength,
)

A_PASSWORD = "s3cur3P@ss!"
COMPOSED_GROESSE = unicodedata.normalize("NFC", "Größe1")
DECOMPOSED_GROESSE = unicodedata.normalize("NFD", "Größe1")
COMPOSED_LONG_GROESSE = unicodedata.normalize("NFC", "Größe-42-Meter")
DECOMPOSED_LONG_GROESSE = unicodedata.normalize("NFD", "Größe-42-Meter")
# Longer than bcrypt's 72-byte limit, which made bcrypt 5 raise (#28, finding 2).
AN_80_BYTE_PASSWORD = "a-long-passphrase-" + "x" * 62
A_200_BYTE_PASSWORD = "ä" * 100
PRESENTATOR_64_MIB_HASH = (
    "$argon2id$v=19$m=65536,t=3,p=4$fm5te1qOTc8XSDynEXXiCw"
    "$Jx711Mq9d9fFUAQYVoa5R8YsLdZP6Z4pClBwlpvB50Y"
)


def _cheap_hash_with(**changed_parameters: object) -> str:
    return Argon2PasswordHasher.from_parameters(replace(CHEAPEST, **changed_parameters)).hash(
        A_PASSWORD,
    )


def _differing_after_byte_72(password: str) -> str:
    return password[:-1] + ("y" if password[-1] != "y" else "z")


def _with_salt_and_digest(stored_hash: str, salt: str, digest: str) -> str:
    """The hash with its salt and digest replaced, every other field kept."""
    head = stored_hash.split("$")[:4]
    return "$".join([*head, salt, digest])


A_CHEAP_HASH = a_cheap_argon2id_hasher().hash(A_PASSWORD)
A_CHEAP_SALT, A_CHEAP_DIGEST = A_CHEAP_HASH.split("$")[4:]


def test_a_new_hash_is_argon2id_at_owasp_costs_by_default() -> None:
    stored = Argon2idPasswordHasher().hash(A_PASSWORD)

    assert stored.startswith("$argon2id$")
    assert extract_parameters(stored) == Parameters(
        type=Type.ID, version=19, salt_len=16, hash_len=32,
        time_cost=2, memory_cost=19 * 1024, parallelism=1,
    )


def test_a_host_sets_its_own_argon2id_costs_through_the_constructor() -> None:
    host_costs = Parameters(
        type=Type.ID, version=19, salt_len=16, hash_len=32,
        time_cost=1, memory_cost=64, parallelism=2,
    )

    stored = Argon2idPasswordHasher(host_costs).hash(A_PASSWORD)

    assert extract_parameters(stored) == host_costs


@pytest.mark.parametrize(("parameters", "reason"), [
    pytest.param(replace(CHEAPEST, type=Type.I), "Type.ID", id="argon2i"),
    pytest.param(replace(CHEAPEST, version=16), "version 19", id="argon2_version_1_0"),
])
def test_a_hasher_refuses_parameters_it_cannot_hash_with(
    parameters: Parameters, reason: str,
) -> None:
    with pytest.raises(ValueError, match=reason):
        Argon2idPasswordHasher(parameters)


@pytest.mark.parametrize(("hashed", "attempt", "matches"), [
    pytest.param(A_PASSWORD, A_PASSWORD, True, id="the_password_it_hashed"),
    pytest.param(A_PASSWORD, "wrong-password", False, id="any_other_password"),
    pytest.param(AN_80_BYTE_PASSWORD, AN_80_BYTE_PASSWORD, True, id="80_bytes"),
    pytest.param(
        AN_80_BYTE_PASSWORD, _differing_after_byte_72(AN_80_BYTE_PASSWORD), False,
        id="80_bytes_differing_after_byte_72",
    ),
    pytest.param(A_200_BYTE_PASSWORD, A_200_BYTE_PASSWORD, True, id="200_multibyte_bytes"),
    pytest.param(
        A_200_BYTE_PASSWORD, _differing_after_byte_72(A_200_BYTE_PASSWORD), False,
        id="200_multibyte_bytes_differing_after_byte_72",
    ),
])
def test_a_hash_matches_only_the_password_it_was_made_from(
    hashed: str, attempt: str, matches: bool,
) -> None:
    hasher = a_cheap_argon2id_hasher()

    assert hasher.verify(attempt, hasher.hash(hashed)) is matches


def test_hashing_the_same_password_twice_gives_different_hashes() -> None:
    hasher = a_cheap_argon2id_hasher()

    assert hasher.hash(A_PASSWORD) != hasher.hash(A_PASSWORD)


@pytest.mark.parametrize(("hashed", "typed"), [
    pytest.param(COMPOSED_LONG_GROESSE, DECOMPOSED_LONG_GROESSE, id="stored_composed"),
    pytest.param(DECOMPOSED_LONG_GROESSE, COMPOSED_LONG_GROESSE, id="stored_decomposed"),
])
def test_composed_and_decomposed_spellings_match_the_same_hash(hashed: str, typed: str) -> None:
    hasher = a_cheap_argon2id_hasher()

    assert hasher.verify(typed, hasher.hash(hashed)) is True


@pytest.mark.parametrize("stored_hash", [
    pytest.param("$2b$12$abcdefghijklmnopqrstuuJ1Y5mA6OZ3qG0tJ1cB/6H2p0q7tq1a", id="bcrypt"),
    pytest.param(_cheap_hash_with(type=Type.I), id="argon2i"),
    pytest.param(_cheap_hash_with(type=Type.D), id="argon2d"),
    pytest.param("", id="empty"),
    pytest.param("not a hash at all", id="garbage"),
    pytest.param(PRESENTATOR_64_MIB_HASH, id="argon2id_at_64_mib"),
    pytest.param(_cheap_hash_with(memory_cost=16), id="argon2id_at_more_memory"),
    pytest.param(_cheap_hash_with(time_cost=2), id="argon2id_at_more_passes"),
    pytest.param(_cheap_hash_with(parallelism=2, memory_cost=16), id="argon2id_at_more_lanes"),
    pytest.param(_cheap_hash_with(salt_len=16), id="argon2id_with_longer_salt"),
    pytest.param(_cheap_hash_with(hash_len=32), id="argon2id_with_longer_digest"),
    pytest.param(A_CHEAP_HASH.replace("$v=19$", "$v=16$"), id="argon2id_version_1_0"),
    pytest.param(
        _with_salt_and_digest(A_CHEAP_HASH, "!" * len(A_CHEAP_SALT), A_CHEAP_DIGEST),
        id="argon2id_salt_not_base64",
    ),
    pytest.param(
        _with_salt_and_digest(A_CHEAP_HASH, "ä" * len(A_CHEAP_SALT), A_CHEAP_DIGEST),
        id="argon2id_salt_not_ascii",
    ),
    pytest.param(
        _with_salt_and_digest(A_CHEAP_HASH, A_CHEAP_SALT, "\x00" * len(A_CHEAP_DIGEST)),
        id="argon2id_digest_of_nul_bytes",
    ),
])
def test_a_hash_outside_the_hosts_argon2id_profile_fails_loudly(stored_hash: str) -> None:
    with pytest.raises(UnknownHashFormatError):
        a_cheap_argon2id_hasher().verify(A_PASSWORD, stored_hash)


def test_a_hash_cheaper_than_the_hosts_profile_fails_loudly() -> None:
    """A downgraded hash would let a host check passwords below its own costs."""
    host = Argon2idPasswordHasher(replace(CHEAPEST, memory_cost=16, time_cost=2))

    with pytest.raises(UnknownHashFormatError):
        host.verify(A_PASSWORD, A_CHEAP_HASH)


def test_an_unknown_user_is_verified_at_the_cost_of_a_wrong_password(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """A missing hash is checked against an Argon2id dummy with the hasher's own
    costs, or the timing gap tells an attacker which accounts exist."""
    hasher = a_cheap_argon2id_hasher()
    known_hash = hasher.hash(A_PASSWORD)
    costs_paid: list[Parameters] = []
    real_verify = Argon2PasswordHasher.verify

    def recording_verify(self: Argon2PasswordHasher, stored: str, password: str) -> bool:
        costs_paid.append(extract_parameters(stored))
        return real_verify(self, stored, password)

    monkeypatch.setattr(Argon2PasswordHasher, "verify", recording_verify)

    assert hasher.verify("wrong-password", known_hash) is False
    assert hasher.verify("wrong-password", None) is False
    assert costs_paid == [extract_parameters(known_hash)] * 2


@pytest.mark.parametrize(("password", "message"), [
    pytest.param("a1b2", "at least 8 characters", id="four_chars"),
    pytest.param("Sonne-4", "at least 8 characters", id="seven_chars"),
    pytest.param(COMPOSED_GROESSE, "at least 8 characters", id="six_chars_composed"),
    pytest.param(DECOMPOSED_GROESSE, "at least 8 characters", id="six_chars_decomposed"),
    pytest.param("password", "too common", id="common"),
    pytest.param("aaaaaaaa", "unique characters", id="low_entropy"),
])
def test_a_weak_password_is_rejected_with_its_reason(password: str, message: str) -> None:
    with pytest.raises(ValueError, match=message):
        check_password_strength(password)


@pytest.mark.parametrize(("password", "returned"), [
    pytest.param("Sonne-42", "Sonne-42", id="eight_chars"),
    pytest.param(A_PASSWORD, A_PASSWORD, id="mixed_symbols"),
    pytest.param(DECOMPOSED_LONG_GROESSE, COMPOSED_LONG_GROESSE, id="decomposed_returns_nfc"),
])
def test_a_strong_password_is_accepted_in_its_nfc_form(password: str, returned: str) -> None:
    assert check_password_strength(password) == returned


def test_an_unset_password_passes_the_strength_check() -> None:
    assert check_password_strength(None) is None


def test_an_injected_hasher_admits_the_account_it_signed() -> None:
    hasher = Argon2idStyleHasher()
    user = FakeUser(password_hash=hasher.hash("open-sesame-42"))
    assert (
        judge_credentials("open-sesame-42", user, hasher=hasher)
        is LoginOutcome.ADMITTED
    )
    assert (
        judge_credentials("not-the-password", user, hasher=hasher)
        is LoginOutcome.WRONG_PASSWORD
    )
