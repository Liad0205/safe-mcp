"""
Decorators for securing MCP tool functions.
"""

import functools
from typing import Any, Callable, Optional, TypeVar, List, Tuple

from .core import SecuredResponse, TrustLevel
from .utils.utils import determine_trust_level
from .sanitizers.basic import BasicSanitizer
from .utils.patterns import (
    WARNING_UNSAFE_DECORATOR_DEFAULT,
    WARNING_SANITIZATION_SKIPPED,
    WARNING_INPUT_VALIDATION_FAILED,
    WARNING_AUTH_TOKEN_MISSING,
    WARNING_AUTH_TOKEN_INVALID,
    WARNING_RATE_LIMIT_EXCEEDED,
)
from .config import config
import asyncio
import time


T = TypeVar("T", bound=Callable[..., Any])


def safe(func: T) -> T:
    """
    Mark responses from this function as coming from trusted sources.

    Use this decorator for MCP tools that access internal, verified data sources
    that you have complete control over.

    Args:
        func: The function to decorate

    Returns:
        Decorated function that returns a SecuredResponse with TRUSTED trust level
    """

    @functools.wraps(func)
    async def wrapper(*args, **kwargs):
        result = await func(*args, **kwargs)
        # If result is already a SecuredResponse, return it as is
        if isinstance(result, SecuredResponse):
            return result
        return SecuredResponse(data=result, trust_level=TrustLevel.TRUSTED)

    return wrapper


def unsafe(func: T) -> T:
    """
    Mark responses as coming from untrusted external sources.

    Use this decorator for MCP tools that access external APIs or user-provided
    data that could contain malicious content.

    Args:
        func: The function to decorate

    Returns:
        Decorated function that returns a SecuredResponse with UNTRUSTED trust level
    """

    @functools.wraps(func)
    async def wrapper(*args, **kwargs):
        result = await func(*args, **kwargs)
        # If result is already a SecuredResponse, return it as is for consistency
        # This will allow annotation chaining
        if isinstance(result, SecuredResponse):
            return result
        return SecuredResponse(
            data=result,
            trust_level=TrustLevel.UNTRUSTED,
            warnings=[WARNING_UNSAFE_DECORATOR_DEFAULT],
        )

    return wrapper


def sanitize(
    sanitizer_func: Optional[
        Callable[[Any], Tuple[Any, List[str]]]
    ] = BasicSanitizer.sanitize,
):
    """
    Apply sanitization to function results and adjust trust level.

    This decorator applies the specified sanitization function to the
    result of the decorated function and returns a SecuredResponse with
    appropriate trust level and warnings.

    Args:
        sanitizer_func: Function that takes content and returns (sanitized_content, warnings).
            If None is explicitly passed, no sanitization is performed but the result is
            still wrapped and a warning is added.
            Defaults to BasicSanitizer.sanitize with default settings.

    Returns:
        Decorator function that applies sanitization
    """

    def decorator(func: T) -> T:
        @functools.wraps(func)
        async def wrapper(*args, **kwargs):
            result = await func(*args, **kwargs)

            if isinstance(result, SecuredResponse):
                data = result.data
                existing_warnings = result.warnings
                original_trust = result.trust_level
            else:
                data = result
                existing_warnings = []
                original_trust = TrustLevel.UNTRUSTED  # Default to untrusted

            warnings = list(existing_warnings)
            if sanitizer_func:
                sanitized_data, new_warnings = sanitizer_func(data)
                warnings.extend(new_warnings)

                trust_level = determine_trust_level(original_trust, new_warnings)

                return SecuredResponse(
                    data=sanitized_data,
                    trust_level=trust_level,
                    warnings=warnings,
                )
            else:
                # This path is taken if sanitizer_func is explicitly set to None
                return SecuredResponse(
                    data=data,
                    trust_level=original_trust,
                    warnings=warnings + [WARNING_SANITIZATION_SKIPPED],
                )

        return wrapper

    return decorator


def validate_inputs(validator_func: Callable):
    """
    Apply custom validation to function inputs.

    This decorator runs the provided validator function on the inputs
    before executing the decorated function. If validation fails,
    returns an UNSAFE response.

    Args:
        validator_func: Function that validates inputs and returns bool

    Returns:
        Decorator function that applies input validation
    """

    def decorator(func: T) -> T:
        @functools.wraps(func)
        async def wrapper(*args, **kwargs):
            valid = validator_func(*args, **kwargs)

            if not valid:
                return SecuredResponse(
                    data=None,  # Block response on input validation failure
                    trust_level=TrustLevel.UNTRUSTED,
                    warnings=[WARNING_INPUT_VALIDATION_FAILED],
                )

            result = await func(*args, **kwargs)

            if not isinstance(result, SecuredResponse):
                result = SecuredResponse(data=result, trust_level=TrustLevel.UNTRUSTED)

            return result

        return wrapper

    return decorator


def _extract_token(obj: Any) -> Optional[str]:
    """Attempt to extract an auth token from various object types."""

    if obj is None:
        return None

    # Dictionary-like objects
    if isinstance(obj, dict):
        for key in ("token", "auth", "authorization"):
            if key in obj and obj[key]:
                return obj[key]
        headers = obj.get("headers")
        if isinstance(headers, dict):
            for key in ("Authorization", "authorization", "token", "auth"):
                if headers.get(key):
                    return headers[key]
        return None

    # Objects with attributes
    for key in ("token", "auth", "authorization"):
        if hasattr(obj, key):
            value = getattr(obj, key)
            if value:
                return value
    if hasattr(obj, "headers"):
        headers = getattr(obj, "headers")
        if isinstance(headers, dict):
            for key in ("Authorization", "authorization", "token", "auth"):
                if headers.get(key):
                    return headers[key]
    return None


def require_auth(func: T) -> T:
    """Require a valid authentication token before executing the function."""

    @functools.wraps(func)
    async def wrapper(*args, **kwargs):
        token = None

        # Check common locations for context or request objects
        for key in ("context", "request"):
            if key in kwargs:
                token = _extract_token(kwargs[key])
                if token:
                    break

        if token is None and args:
            # Fallback: inspect positional arguments
            for arg in args:
                token = _extract_token(arg)
                if token:
                    break

        if token is None:
            return SecuredResponse(
                data=None,
                trust_level=TrustLevel.UNTRUSTED,
                warnings=[WARNING_AUTH_TOKEN_MISSING],
            )

        validator = config.auth_validator
        valid = False
        if callable(validator):
            try:
                valid = bool(validator(token))
            except Exception:
                valid = False

        if not valid:
            return SecuredResponse(
                data=None,
                trust_level=TrustLevel.UNTRUSTED,
                warnings=[WARNING_AUTH_TOKEN_INVALID],
            )

        return await func(*args, **kwargs)

    return wrapper


def ratelimit(func: T) -> T:
    """Apply a simple token bucket rate limiter to the decorated function."""

    bucket = {"tokens": config.ratelimit_capacity, "last_refill": time.monotonic()}
    lock = asyncio.Lock()

    @functools.wraps(func)
    async def wrapper(*args, **kwargs):
        async with lock:
            now = time.monotonic()
            capacity = config.ratelimit_capacity
            rate = config.ratelimit_refill_rate

            # Refill tokens based on elapsed time
            elapsed = now - bucket["last_refill"]
            if elapsed > 0:
                bucket["tokens"] = min(
                    capacity, bucket["tokens"] + elapsed * rate
                )
                bucket["last_refill"] = now

            if bucket["tokens"] < 1:
                return SecuredResponse(
                    data=None,
                    trust_level=TrustLevel.UNTRUSTED,
                    warnings=[WARNING_RATE_LIMIT_EXCEEDED],
                )

            bucket["tokens"] -= 1

        return await func(*args, **kwargs)

    return wrapper
