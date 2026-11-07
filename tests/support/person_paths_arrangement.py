"""What the bearer gate's person-path suites share: tokens, parametrizations and the app."""

from __future__ import annotations

from collections.abc import Iterator
from contextlib import AbstractContextManager, contextmanager
from dataclasses import dataclass
from typing import Any

import pytest
from httpx import Response

from tests.support.gate_arrangement import (
    A_TOKEN,
    PERSON_ADMIN_ME_PATH,
    PERSON_ADMITTED_ADMIN_PATH,
    PERSON_PATHS,
    BearerApp,
    a_bearer_app,
    a_token,
)
from tests.support.oidc_arrangement import OPERATOR_SUBJECT
from tests.support.oidc_login_host import (
    StoreDown,
    TransactionKind,
)
from tests.support.webauth_arrangement import (
    MEMBER_ROLE,
    FakeUser,
)
from webauth.ports import SignInStores

ADMIN_TOKEN = A_TOKEN
MEMBER_TOKEN = a_token(groups=["/apps/x"])
OUTSIDER_TOKEN = a_token(groups=["/apps/elsewhere"])
LENA_TOKEN = a_token(preferred_username="lena")
OPTIONAL_PATH = "/optional"
UNGATED_ME_PATH = "/me"

BOTH_HOSTS = pytest.mark.parametrize(
    "session_gate",
    [pytest.param(True, id="SG"), pytest.param(False, id="NG")],
)
BOTH_TRANSACTIONS = pytest.mark.parametrize(
    "kind",
    [
        pytest.param(TransactionKind.PER_CALL, id="PC"),
        pytest.param(TransactionKind.ROLLING_BACK, id="RB"),
    ],
)


@dataclass
class DisabledUser(FakeUser):
    """A stored account whose record marks it disabled: webauth reads no such flag."""

    is_active: bool = False


def a_lena() -> FakeUser:
    return FakeUser(id=OPERATOR_SUBJECT, username="lena", role=MEMBER_ROLE)


def a_transaction_failing_to_be_created() -> AbstractContextManager[SignInStores]:
    raise StoreDown


def a_transaction_failing_to_be_entered() -> AbstractContextManager[SignInStores]:
    @contextmanager
    def never_entered() -> Iterator[SignInStores]:
        raise StoreDown
        yield  # pragma: no cover

    return never_entered()


def a_person_app(**keywords: Any) -> BearerApp:
    return a_bearer_app(person_paths=PERSON_PATHS, **keywords)


def the_account(app: BearerApp) -> Any:
    assert app.accounts is not None
    return next((user for user in app.accounts.list() if user.id == OPERATOR_SUBJECT), None)


def the_challenge(response: Response) -> str | None:
    return response.headers.get("www-authenticate")


def ran(app: BearerApp) -> list[str]:
    return app.auth.route_runs


ADMIN_READERS = pytest.mark.parametrize(
    ("session_gate", "path"),
    [
        pytest.param(True, PERSON_ADMITTED_ADMIN_PATH, id="SG-admitted_admin"),
        pytest.param(True, PERSON_ADMIN_ME_PATH, id="SG-admin_user"),
        pytest.param(False, PERSON_ADMIN_ME_PATH, id="NG-admin_user"),
    ],
)
