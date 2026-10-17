"""What a login refuses, and whether a password admits an account."""

from __future__ import annotations

from dataclasses import dataclass

import pytest
from webauth_arrangement import (
    PasswordlessUser,
    a_cheap_argon2id_hasher,
    a_web_auth_config,
)

from webauth.config import WebAuthConfig
from webauth.login import (
    ACCOUNT_LOCKED_DETAIL,
    INVALID_CREDENTIALS_DETAIL,
    RETRY_AFTER_HEADER,
    TOO_MANY_LOGIN_ATTEMPTS_DETAIL,
    LoginOutcome,
    LoginRefusal,
    http_refusal,
    judge_credentials,
    login_attempt_budget,
)
from webauth.ports import PasswordHasher

CLIENT_ADDRESS = "203.0.113.7"
USERNAME = "alice"

A_CORRECT_PASSWORD = "the-correct-password"
A_WRONG_PASSWORD = "something-else-entirely"


@dataclass
class FailuresInMemory:
    """Recent failures, counted the way each budget asks for them."""

    lockout_window_seconds: int
    for_the_account_over_the_lockout_window: int = 0
    from_the_address: int = 0
    for_the_account: int = 0

    def count_recent_failures(
        self, *, ip_address: str, window_seconds: int, username: str | None = None,
    ) -> int:
        if window_seconds == self.lockout_window_seconds:
            return self.for_the_account_over_the_lockout_window
        return self.for_the_account if username else self.from_the_address


def a_login_limit(**failures: int) -> tuple[FailuresInMemory, WebAuthConfig]:
    config = a_web_auth_config(
        login_rate_limit=5, login_lockout_threshold=15,
        login_lockout_window_seconds=3600, login_rate_window_seconds=300,
    )
    return FailuresInMemory(config.login_lockout_window_seconds, **failures), config


def budget_for(attempts: FailuresInMemory, config: WebAuthConfig) -> LoginRefusal | None:
    return login_attempt_budget(
        attempts, ip_address=CLIENT_ADDRESS, username=USERNAME, config=config,
    )


def test_an_attempt_within_both_budgets_is_allowed_to_proceed() -> None:
    attempts, config = a_login_limit(
        for_the_account_over_the_lockout_window=14, from_the_address=4, for_the_account=4,
    )

    assert budget_for(attempts, config) is None


def test_an_account_that_kept_failing_is_locked_for_the_lockout_window() -> None:
    attempts, config = a_login_limit(for_the_account_over_the_lockout_window=15)

    assert budget_for(attempts, config) == LoginRefusal(
        LoginOutcome.ACCOUNT_LOCKED,
        retry_after_seconds=config.login_lockout_window_seconds,
    )


@pytest.mark.parametrize(
    "spent",
    [
        pytest.param({"from_the_address": 5}, id="an address that keeps guessing"),
        pytest.param({"for_the_account": 5}, id="one account guessed at repeatedly"),
    ],
)
def test_a_spent_rate_budget_is_refused_for_the_rate_window(spent: dict[str, int]) -> None:
    attempts, config = a_login_limit(**spent)

    assert budget_for(attempts, config) == LoginRefusal(
        LoginOutcome.RATE_LIMITED,
        retry_after_seconds=config.login_rate_window_seconds,
    )


def test_a_locked_account_hears_about_the_lockout_not_the_rate_limit() -> None:
    attempts, config = a_login_limit(
        for_the_account_over_the_lockout_window=15, from_the_address=5, for_the_account=5,
    )

    refusal = budget_for(attempts, config)

    assert refusal is not None
    assert refusal.outcome is LoginOutcome.ACCOUNT_LOCKED


def test_a_locked_refusal_maps_to_todays_429_and_retry_after() -> None:
    _, config = a_login_limit()
    refusal = LoginRefusal(
        LoginOutcome.ACCOUNT_LOCKED,
        retry_after_seconds=config.login_lockout_window_seconds,
    )

    error = http_refusal(refusal)

    assert error.status_code == 429
    assert error.detail == ACCOUNT_LOCKED_DETAIL
    assert error.headers[RETRY_AFTER_HEADER] == str(config.login_lockout_window_seconds)


def test_a_rate_limited_refusal_maps_to_todays_429_and_retry_after() -> None:
    _, config = a_login_limit()
    refusal = LoginRefusal(
        LoginOutcome.RATE_LIMITED,
        retry_after_seconds=config.login_rate_window_seconds,
    )

    error = http_refusal(refusal)

    assert error.status_code == 429
    assert error.detail == TOO_MANY_LOGIN_ATTEMPTS_DETAIL
    assert error.headers[RETRY_AFTER_HEADER] == str(config.login_rate_window_seconds)


@pytest.mark.parametrize(
    "outcome",
    [LoginOutcome.UNKNOWN_USER, LoginOutcome.WRONG_PASSWORD, LoginOutcome.DEACTIVATED],
    ids=["a username nobody holds", "a wrong password", "a deactivated account"],
)
def test_a_credential_refusal_maps_to_one_indistinguishable_401(
    outcome: LoginOutcome,
) -> None:
    error = http_refusal(LoginRefusal(outcome))

    assert error.status_code == 401
    assert error.detail == INVALID_CREDENTIALS_DETAIL
    assert error.headers is None


def test_an_admission_is_never_a_refusal() -> None:
    with pytest.raises(ValueError, match="admission"):
        LoginRefusal(LoginOutcome.ADMITTED)


@dataclass(frozen=True)
class StoredAccount:
    password_hash: str
    is_active: bool = True
    id: str = "user-1"
    username: str = USERNAME
    role: str = "user"


A_HASHER = a_cheap_argon2id_hasher()
AN_ACCOUNT = StoredAccount(password_hash=A_HASHER.hash(A_CORRECT_PASSWORD))
A_DEACTIVATED_ACCOUNT = StoredAccount(
    password_hash=AN_ACCOUNT.password_hash, is_active=False,
)
A_PASSWORD_SET_BEFORE_THE_LENGTH_RULE = "abc1234"
AN_ACCOUNT_WITH_A_SHORT_PASSWORD = StoredAccount(
    password_hash=A_HASHER.hash(A_PASSWORD_SET_BEFORE_THE_LENGTH_RULE),
)
A_PASSWORDLESS_ACCOUNT = PasswordlessUser()


@dataclass
class VerificationSpy:
    """A hasher that counts how many full verifications a decision runs."""

    delegate: PasswordHasher
    verify_calls: int = 0

    def hash(self, password: str) -> str:
        return self.delegate.hash(password)

    def verify(self, password: str, stored_hash: str | None) -> bool:
        self.verify_calls += 1
        return self.delegate.verify(password, stored_hash)


@pytest.mark.parametrize(
    ("password", "user", "outcome"),
    [
        pytest.param(
            A_CORRECT_PASSWORD, AN_ACCOUNT, LoginOutcome.ADMITTED,
            id="the account's own password",
        ),
        pytest.param(
            A_WRONG_PASSWORD, AN_ACCOUNT, LoginOutcome.WRONG_PASSWORD,
            id="a password that is not it",
        ),
        pytest.param(
            A_CORRECT_PASSWORD, None, LoginOutcome.UNKNOWN_USER,
            id="a username nobody holds",
        ),
        pytest.param(
            A_CORRECT_PASSWORD, A_DEACTIVATED_ACCOUNT, LoginOutcome.DEACTIVATED,
            id="a deactivated account and its right password",
        ),
        pytest.param(
            A_PASSWORD_SET_BEFORE_THE_LENGTH_RULE, AN_ACCOUNT_WITH_A_SHORT_PASSWORD,
            LoginOutcome.ADMITTED,
            id="a stored password shorter than today's minimum",
        ),
        pytest.param(
            A_CORRECT_PASSWORD, A_PASSWORDLESS_ACCOUNT, LoginOutcome.WRONG_PASSWORD,
            id="an account that signs in only through its identity provider",
        ),
    ],
)
def test_judge_credentials_names_the_outcome_of_each_attempt(
    password: str, user: StoredAccount | PasswordlessUser | None, outcome: LoginOutcome,
) -> None:
    assert judge_credentials(password, user, hasher=A_HASHER) is outcome


@pytest.mark.parametrize(
    ("password", "user"),
    [
        pytest.param(A_CORRECT_PASSWORD, None, id="a username nobody holds"),
        pytest.param(A_WRONG_PASSWORD, AN_ACCOUNT, id="a wrong password"),
        pytest.param(A_CORRECT_PASSWORD, A_PASSWORDLESS_ACCOUNT, id="no password at all"),
    ],
)
def test_a_refused_credential_runs_exactly_one_full_verification(
    password: str, user: StoredAccount | PasswordlessUser | None,
) -> None:
    spy = VerificationSpy(A_HASHER)

    judge_credentials(password, user, hasher=spy)

    assert spy.verify_calls == 1


@dataclass
class HasherAnsweringYes:
    """A host hasher that wrongly reports a match for every password and hash."""

    def hash(self, password: str) -> str:
        return password

    def verify(self, password: str, stored_hash: str | None) -> bool:
        return True


def test_no_password_admits_a_passwordless_account_even_when_the_hasher_says_yes() -> None:
    outcome = judge_credentials(
        A_CORRECT_PASSWORD, A_PASSWORDLESS_ACCOUNT, hasher=HasherAnsweringYes(),
    )

    assert outcome is LoginOutcome.WRONG_PASSWORD
