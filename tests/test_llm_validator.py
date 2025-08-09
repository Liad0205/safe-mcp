import asyncio
from unittest.mock import AsyncMock

import pytest

from safe_mcp.core import TrustLevel
from safe_mcp.decorators import secure
from safe_mcp.llm_validator import LLMValidator, MCPConfig


@pytest.mark.asyncio
async def test_secure_caching(monkeypatch):
    cache: dict = {}
    config = MCPConfig(provider="openai", api_key="k", cache_provider=cache)
    validator = LLMValidator(config)

    validate_mock = AsyncMock(return_value=True)
    monkeypatch.setattr(type(validator.provider), "validate", validate_mock)

    @secure(validator, modules=("mod1",))
    async def tool():
        return "hello"

    result1 = await tool()
    assert result1.trust_level == TrustLevel.TRUSTED
    assert validate_mock.call_count == 1

    # Second call should hit cache and not call provider again
    result2 = await tool()
    assert result2.trust_level == TrustLevel.TRUSTED
    assert validate_mock.call_count == 1

    # Different content -> cache miss
    @secure(validator, modules=("mod1",))
    async def tool_diff():
        return "different"

    await tool_diff()
    assert validate_mock.call_count == 2

    # Same content but different modules -> cache miss
    @secure(validator, modules=("mod2",))
    async def tool_mod():
        return "hello"

    await tool_mod()
    assert validate_mock.call_count == 3


@pytest.mark.asyncio
async def test_secure_without_cache(monkeypatch):
    config = MCPConfig(provider="openai", api_key="k")
    validator = LLMValidator(config)

    validate_mock = AsyncMock(return_value=False)
    monkeypatch.setattr(type(validator.provider), "validate", validate_mock)

    @secure(validator, modules=("mod1",))
    async def tool():
        return "data"

    res1 = await tool()
    res2 = await tool()
    assert validate_mock.call_count == 2
    assert res1.trust_level == TrustLevel.UNTRUSTED
    assert res2.trust_level == TrustLevel.UNTRUSTED

