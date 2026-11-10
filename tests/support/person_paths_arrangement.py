"""What the bearer gate's person-path suites share: tokens, parametrizations and the app."""

from __future__ import annotations

from collections.abc import Iterator
from contextlib import AbstractContextManager, contextmanager
from dataclasses import dataclass
from typing import Any

import pytest
from fastapi import Response as AppResponse
from httpx import Response

from tests.support.gate_arrangement import (
    A_TOKEN,
    ADMISSION,
    PERSON_ADMIN_ME_PATH,
    PERSON_ADMITTED_ADMIN_PATH,
    PERSON_PATHS,
    BearerApp,
    a_bearer_app,
    a_token,
)
from tests.support.oidc_arrangement import (
    OPERATOR_SUBJECT,
    FakeClock,
    a_key_set_endpoint,
    a_relying_party,
)
from tests.support.oidc_login_host import (
    LOGOUT_PAGE_TEXT,
    NOW,
    SIGN_IN_PATHS,
    StoreDown,
    TransactionKind,
    a_client_config,
)
from tests.support.webauth_arrangement import (
    MEMBER_ROLE,
    FakeUser,
)
from webauth.ports import SignInStores
from webauth.sign_in_routes import install_sign_in_routes

ADMIN_TOKEN = A_TOKEN
MEMBER_TOKEN = a_token(groups=["/apps/x"])
OUTSIDER_TOKEN = a_token(groups=["/apps/elsewhere"])
LENA_TOKEN = a_token(preferred_username="lena")
OPTIONAL_PATH = "/optional"
UNGATED_ME_PATH = "/me"
UNGATED_ADMIN_PATH = "/admin"

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


def a_person_app_serving_back_channel_logout() -> BearerApp:
    """A person-path app that also serves the library's logout and back-channel logout routes."""
    app = a_person_app(
        policies={"sign_in_paths": SIGN_IN_PATHS},
    )
    assert app.transaction is not None
    relying_party = a_relying_party(
        config=a_client_config(),
        fetch_key_set=a_key_set_endpoint("issuer"),
        wall_clock=FakeClock(float(NOW)),
    )
    install_sign_in_routes(
        app.auth.app,
        paths=SIGN_IN_PATHS,
        relying_party=lambda _request: relying_party,
        admission=ADMISSION,
        transaction=app.transaction,
        refused=lambda _request, _refusal: AppResponse(status_code=403),
        keeps_id_token=True,
        max_sessions=None,
        logout_page_text=lambda _request: LOGOUT_PAGE_TEXT,
    )
    return app


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
