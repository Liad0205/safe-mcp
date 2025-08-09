import asyncio
import pytest


@pytest.mark.tryfirst
def pytest_configure(config):
    config.addinivalue_line(
        "markers", "asyncio: mark test to run in event loop"
    )


def pytest_pyfunc_call(pyfuncitem):
    if pyfuncitem.get_closest_marker("asyncio"):
        asyncio.run(pyfuncitem.obj(**pyfuncitem.funcargs))
        return True

