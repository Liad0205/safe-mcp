import asyncio

import pytest


@pytest.hookimpl(tryfirst=True)
def pytest_pyfunc_call(pyfuncitem):
    if pyfuncitem.get_closest_marker("asyncio"):
        func = pyfuncitem.obj
        loop = asyncio.new_event_loop()
        kwargs = {
            k: v for k, v in pyfuncitem.funcargs.items() if k != "request"
        }
        loop.run_until_complete(func(**kwargs))
        loop.close()
        return True
    return None
