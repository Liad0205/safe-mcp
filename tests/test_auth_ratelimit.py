import asyncio
import pytest

from safe_mcp.decorators import require_auth, ratelimit
from safe_mcp.core import SecuredResponse, TrustLevel
from safe_mcp.config import config
from safe_mcp.utils.patterns import (
    WARNING_AUTH_TOKEN_INVALID,
    WARNING_AUTH_TOKEN_MISSING,
    WARNING_RATE_LIMIT_EXCEEDED,
)


@pytest.mark.asyncio
async def test_require_auth_successful_authorization():
    config.auth_validator = lambda token: token == "valid"

    @require_auth
    async def secured(context=None):
        return "secret"

    result = await secured(context={"token": "valid"})
    assert result == "secret"

    config.auth_validator = None


@pytest.mark.asyncio
async def test_require_auth_invalid_token():
    config.auth_validator = lambda token: token == "valid"

    @require_auth
    async def secured(context=None):
        return "secret"

    result = await secured(context={"token": "invalid"})
    assert isinstance(result, SecuredResponse)
    assert result.trust_level == TrustLevel.UNTRUSTED
    assert WARNING_AUTH_TOKEN_INVALID in result.warnings

    config.auth_validator = None


@pytest.mark.asyncio
async def test_require_auth_missing_token():
    config.auth_validator = lambda token: token == "valid"

    @require_auth
    async def secured(context=None):
        return "secret"

    result = await secured(context={})
    assert isinstance(result, SecuredResponse)
    assert result.trust_level == TrustLevel.UNTRUSTED
    assert WARNING_AUTH_TOKEN_MISSING in result.warnings

    config.auth_validator = None


@pytest.mark.asyncio
async def test_ratelimit_hits_and_refills():
    config.ratelimit_capacity = 2
    config.ratelimit_refill_rate = 1  # token per second

    @ratelimit
    async def limited():
        return "ok"

    # Use up available tokens
    first = await limited()
    second = await limited()

    assert first == "ok"
    assert second == "ok"

    # Next call should be rate limited
    third = await limited()
    assert isinstance(third, SecuredResponse)
    assert third.trust_level == TrustLevel.UNTRUSTED
    assert WARNING_RATE_LIMIT_EXCEEDED in third.warnings

    # Wait for refill
    await asyncio.sleep(1.1)
    fourth = await limited()
    assert fourth == "ok"

    # Reset to defaults
    config.ratelimit_capacity = 60
    config.ratelimit_refill_rate = 1.0
