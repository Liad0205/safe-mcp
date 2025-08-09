"""
Decorators for securing MCP tool functions.
"""

import functools
from typing import Any, Callable, List, Optional, Tuple, TypeVar

from .config import GLOBAL_CONFIG, MCPConfig
from .core import SecuredResponse, TrustLevel
from .logger import get_logger
from .sanitizers.basic import BasicSanitizer
from .utils.patterns import (
    WARNING_INPUT_VALIDATION_FAILED,
    WARNING_SANITIZATION_SKIPPED,
    WARNING_UNSAFE_DECORATOR_DEFAULT,
)
from .utils.utils import determine_trust_level

T = TypeVar("T", bound=Callable[..., Any])


def safe(func: T = None, *, config: MCPConfig | None = None) -> T:
    """
    Mark responses from this function as coming from trusted sources.

    Use this decorator for MCP tools that access internal, verified data sources
    that you have complete control over.

    Args:
        func: The function to decorate

    Returns:
        Decorated function that returns a SecuredResponse with TRUSTED trust level
    """

    def decorator(fn: T) -> T:
        @functools.wraps(fn)
        async def wrapper(*args, **kwargs):
            result = await fn(*args, **kwargs)
            logger = get_logger(config or GLOBAL_CONFIG)
            # If result is already a SecuredResponse, return it as is
            if isinstance(result, SecuredResponse):
                logger.info(
                    "safe_passthrough",
                    extra={"trust_level": result.trust_level.value},
                )
                return result
            logger.info("safe_wrap", extra={"trust_level": TrustLevel.TRUSTED.value})
            return SecuredResponse(data=result, trust_level=TrustLevel.TRUSTED)

        return wrapper  # type: ignore[return-value]

    if func is not None:
        return decorator(func)
    return decorator


def unsafe(func: T = None, *, config: MCPConfig | None = None) -> T:
    """
    Mark responses as coming from untrusted external sources.

    Use this decorator for MCP tools that access external APIs or user-provided
    data that could contain malicious content.

    Args:
        func: The function to decorate

    Returns:
        Decorated function that returns a SecuredResponse with UNTRUSTED trust level
    """

    def decorator(fn: T) -> T:
        @functools.wraps(fn)
        async def wrapper(*args, **kwargs):
            result = await fn(*args, **kwargs)
            logger = get_logger(config or GLOBAL_CONFIG)
            # If result is already a SecuredResponse, return it as is for consistency
            if isinstance(result, SecuredResponse):
                logger.info(
                    "unsafe_passthrough",
                    extra={"trust_level": result.trust_level.value},
                )
                return result
            logger.info(
                "unsafe_wrap",
                extra={
                    "trust_level": TrustLevel.UNTRUSTED.value,
                    "warnings": [WARNING_UNSAFE_DECORATOR_DEFAULT],
                },
            )
            return SecuredResponse(
                data=result,
                trust_level=TrustLevel.UNTRUSTED,
                warnings=[WARNING_UNSAFE_DECORATOR_DEFAULT],
            )

        return wrapper  # type: ignore[return-value]

    if func is not None:
        return decorator(func)
    return decorator


def sanitize(
    sanitizer_func: Optional[
        Callable[[Any], Tuple[Any, List[str]]]
    ] = BasicSanitizer.sanitize,
    *,
    config: MCPConfig | None = None,
):
    """
    Apply sanitization to function results and adjust trust level.

    This decorator applies the specified sanitization function to the
    result of the decorated function and returns a SecuredResponse with
    appropriate trust level and warnings.

    Args:
        sanitizer_func: Function that takes content and returns
            ``(sanitized_content, warnings)``. If ``None`` is explicitly
            passed, no sanitization is performed but the result is still
            wrapped and a warning is added. Defaults to
            :func:`BasicSanitizer.sanitize` with default settings.

    Returns:
        Decorator function that applies sanitization
    """

    def decorator(func: T) -> T:
        @functools.wraps(func)
        async def wrapper(*args, **kwargs):
            result = await func(*args, **kwargs)
            cfg = config or GLOBAL_CONFIG
            logger = get_logger(cfg)

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
                logger.info(
                    "sanitize",
                    extra={
                        "trust_level": trust_level.value,
                        "warnings": warnings,
                    },
                )
                return SecuredResponse(
                    data=sanitized_data,
                    trust_level=trust_level,
                    warnings=warnings,
                )
            else:
                # This path is taken if sanitizer_func is explicitly set to None
                result_sr = SecuredResponse(
                    data=data,
                    trust_level=original_trust,
                    warnings=warnings + [WARNING_SANITIZATION_SKIPPED],
                )
                logger.info(
                    "sanitize_skipped",
                    extra={
                        "trust_level": result_sr.trust_level.value,
                        "warnings": result_sr.warnings,
                    },
                )
                return result_sr

        return wrapper

    return decorator


def validate_inputs(validator_func: Callable, *, config: MCPConfig | None = None):
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
            cfg = config or GLOBAL_CONFIG
            logger = get_logger(cfg)
            valid = validator_func(*args, **kwargs)

            if not valid:
                logger.info(
                    "input_validation_failed",
                    extra={"trust_level": TrustLevel.UNTRUSTED.value},
                )
                return SecuredResponse(
                    data=None,  # Block response on input validation failure
                    trust_level=TrustLevel.UNTRUSTED,
                    warnings=[WARNING_INPUT_VALIDATION_FAILED],
                )

            result = await func(*args, **kwargs)

            if not isinstance(result, SecuredResponse):
                result = SecuredResponse(data=result, trust_level=TrustLevel.UNTRUSTED)
            logger.info(
                "input_validation_passed",
                extra={"trust_level": result.trust_level.value},
            )
            return result

        return wrapper

    return decorator
