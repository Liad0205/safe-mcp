"""
Decorators for securing MCP tool functions.
"""

import functools
import time
from typing import Any, Callable, Dict, Optional, TypeVar

from src.core import SecuredResponse, TrustLevel

# Type variable for functions
T = TypeVar("T", bound=Callable[..., Any])


def safe(func: T) -> T:
    """
    Mark responses from this function as coming from trusted sources.

    Use this decorator for MCP tools that access internal, verified data sources
    that you have complete control over.

    Args:
        func: The function to decorate

    Returns:
        Decorated function that returns a SecuredResponse with SAFE trust level
    """

    @functools.wraps(func)
    async def wrapper(*args, **kwargs):
        result = await func(*args, **kwargs)
        # If result is already a SecuredResponse, return it as is
        if isinstance(result, SecuredResponse):
            return result
        return SecuredResponse(data=result, trust_level=TrustLevel.SAFE)

    return wrapper


def unsafe(func: T) -> T:
    """
    Mark responses as coming from untrusted external sources.

    Use this decorator for MCP tools that access external APIs or user-provided
    data that could contain malicious content.

    Args:
        func: The function to decorate

    Returns:
        Decorated function that returns a SecuredResponse with UNSAFE trust level
    """

    @functools.wraps(func)
    async def wrapper(*args, **kwargs):
        result = await func(*args, **kwargs)
        # If result is already a SecuredResponse, return it as is
        if isinstance(result, SecuredResponse):
            return result
        return SecuredResponse(
            data=result,
            trust_level=TrustLevel.UNSAFE,
            warnings=["Data from untrusted external source"],
        )

    return wrapper


def sanitize(sanitizer_func: Optional[Callable] = None):
    """
    Apply sanitization to function results and adjust trust level.

    This decorator applies the specified sanitization function to the
    result of the decorated function and returns a SecuredResponse with
    appropriate trust level and warnings.

    Args:
        sanitizer_func: Function that takes content and returns (sanitized_content, warnings)
            If None, no sanitization is performed but result is still wrapped

    Returns:
        Decorator function that applies sanitization
    """

    def decorator(func: T) -> T:
        @functools.wraps(func)
        async def wrapper(*args, **kwargs):
            result = await func(*args, **kwargs)

            # If already a SecuredResponse, extract the data
            if isinstance(result, SecuredResponse):
                data = result.data
                existing_warnings = result.warnings
            else:
                data = result
                existing_warnings = []

            # Apply sanitization if a sanitizer was provided
            warnings = list(existing_warnings)
            if sanitizer_func:
                sanitized_data, new_warnings = sanitizer_func(data)
                warnings.extend(new_warnings)

                return SecuredResponse(
                    data=sanitized_data,
                    trust_level=TrustLevel.CAUTION if new_warnings else TrustLevel.SAFE,
                    warnings=warnings,
                )
            else:
                # No sanitization applied
                return SecuredResponse(
                    data=data,
                    trust_level=TrustLevel.CAUTION,
                    warnings=warnings + ["No sanitization applied"],
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
            # Run validation
            valid = validator_func(*args, **kwargs)

            if not valid:
                return SecuredResponse(
                    data=None,
                    trust_level=TrustLevel.UNSAFE,
                    warnings=["Input validation failed"],
                )

            # Proceed with function execution
            result = await func(*args, **kwargs)

            # If not already a SecuredResponse, wrap it
            if not isinstance(result, SecuredResponse):
                result = SecuredResponse(data=result, trust_level=TrustLevel.SAFE)

            return result

        return wrapper

    return decorator


# Per-function rate limiting state
_rate_limit_state: Dict[str, Dict[str, Any]] = {}


def rate_limited(max_calls: int = 10, time_period: int = 60):
    """
    Prevent abuse by limiting frequency of tool calls.

    Args:
        max_calls: Maximum number of calls allowed in the time period
        time_period: Time period in seconds

    Returns:
        Decorator function that applies rate limiting
    """

    def decorator(func: T) -> T:
        func_id = f"{func.__module__}.{func.__qualname__}"

        # Initialize state for this function
        if func_id not in _rate_limit_state:
            _rate_limit_state[func_id] = {
                "calls": [],
                "max_calls": max_calls,
                "time_period": time_period,
            }

        @functools.wraps(func)
        async def wrapper(*args, **kwargs):
            # Get current time
            now = time.time()
            state = _rate_limit_state[func_id]

            # Clean up old calls
            state["calls"] = [
                t for t in state["calls"] if now - t <= state["time_period"]
            ]

            # Check if rate limit exceeded
            if len(state["calls"]) >= state["max_calls"]:
                return SecuredResponse(
                    data=None,
                    trust_level=TrustLevel.UNSAFE,
                    warnings=[
                        f"Rate limit exceeded: {max_calls} calls per {time_period} seconds"
                    ],
                )

            # Record this call
            state["calls"].append(now)

            # Execute function
            result = await func(*args, **kwargs)

            # If not already a SecuredResponse, wrap it
            if not isinstance(result, SecuredResponse):
                result = SecuredResponse(data=result, trust_level=TrustLevel.SAFE)

            return result

        return wrapper

    return decorator
