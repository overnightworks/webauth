import pytest

pytest.register_assert_rewrite("webauth_arrangement")


@pytest.fixture
def anyio_backend() -> str:
    return "asyncio"
