import pytest

pytest.register_assert_rewrite("tests.support")


@pytest.fixture
def anyio_backend() -> str:
    return "asyncio"
