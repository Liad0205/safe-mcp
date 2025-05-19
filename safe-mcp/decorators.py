"""
Decorators for securing MCP tool functions.
"""

import functools
from typing import Any, Callable, Optional, TypeVar, List, Tuple

from .core import SecuredResponse, TrustLevel
from .utils.utils import determine_trust_level
from .sanitizers.basic import BasicSanitizer


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
            warnings=["Data from untrusted external source"],
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
                    warnings=warnings + ["Sanitization explicitly skipped."],
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
                    warnings=["Input validation failed"],
                )

            result = await func(*args, **kwargs)

            if not isinstance(result, SecuredResponse):
                result = SecuredResponse(data=result, trust_level=TrustLevel.UNTRUSTED)

            return result

        return wrapper

    return decorator
