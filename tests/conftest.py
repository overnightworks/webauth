import pytest

pytest.register_assert_rewrite("tests")


@pytest.fixture
def anyio_backend() -> str:
    return "asyncio"
