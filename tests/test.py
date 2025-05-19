import pytest
from safe_mcp.decorators import safe
from safe_mcp.core import SecuredResponse, TrustLevel


@pytest.mark.asyncio
async def test_safe_decorator_wraps_result():
    @safe
    async def trusted_func():
        return "trusted data"

    result = await trusted_func()
    assert isinstance(result, SecuredResponse)
    assert result.data == "trusted data"
    assert result.trust_level == TrustLevel.TRUSTED
    assert result.warnings == []


@pytest.mark.asyncio
async def test_safe_decorator_passthrough_securedresponse():
    @safe
    async def already_secured():
        return SecuredResponse(
            data="already", trust_level=TrustLevel.UNTRUSTED, warnings=["foo"]
        )

    result = await already_secured()
    assert isinstance(result, SecuredResponse)
    assert result.data == "already"
    assert result.trust_level == TrustLevel.UNTRUSTED
    assert result.warnings == ["foo"]


@pytest.mark.asyncio
async def test_safe_decorator_with_args_kwargs():
    @safe
    async def add(a, b=0):
        return a + b

    result = await add(2, b=3)
    assert isinstance(result, SecuredResponse)
    assert result.data == 5
    assert result.trust_level == TrustLevel.TRUSTED
