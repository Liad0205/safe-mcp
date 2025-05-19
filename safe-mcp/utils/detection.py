"""
Utilities for detecting and sanitizing common attack patterns.
These functions will modify the input string by replacing detected patterns
and return the sanitized string along with warnings.
"""

import re
import unicodedata
from typing import List, Tuple

from .patterns import (
    PROMPT_INJECTION_PATTERNS,
    JAILBREAK_PATTERNS,
    ENCODING_PATTERNS,
    FILTERED_PLACEHOLDER,
)


def sanitize_prompt_injection(content: str) -> Tuple[str, List[str]]:
    """
    Detects and sanitizes common prompt injection patterns after NFKC normalization
    by replacing them with '[FILTERED]'.

    Args:
        content: Text content to check and sanitize.

    Returns:
        Tuple of (sanitized_content, warnings).
    """
    if not isinstance(content, str):
        return content, []

    try:
        sanitized_content = unicodedata.normalize("NFKC", content)
    except TypeError:
        return content, [
            "Error during Unicode normalization in prompt injection sanitization"
        ]

    warnings = []
    for pattern in PROMPT_INJECTION_PATTERNS:
        # Search and replace
        if re.search(pattern, sanitized_content, re.IGNORECASE):
            warnings.append(
                f"Potential prompt injection sanitized: matched '{pattern}'"
            )
            sanitized_content = re.sub(
                pattern, FILTERED_PLACEHOLDER, sanitized_content, flags=re.IGNORECASE
            )
    return sanitized_content, warnings


def sanitize_jailbreak_attempts(content: str) -> Tuple[str, List[str]]:
    """
    Detects and sanitizes common jailbreak patterns after NFKC normalization
    by replacing them with '[FILTERED]'.

    Args:
        content: Text content to check and sanitize.

    Returns:
        Tuple of (sanitized_content, warnings).
    """
    if not isinstance(content, str):
        return content, []

    try:
        sanitized_content = unicodedata.normalize("NFKC", content)
    except TypeError:
        return content, ["Error during Unicode normalization in jailbreak sanitization"]

    warnings = []
    for pattern in JAILBREAK_PATTERNS:
        if re.search(pattern, sanitized_content, re.IGNORECASE):
            warnings.append(
                f"Potential jailbreak attempt sanitized: matched '{pattern}'"
            )
            sanitized_content = re.sub(
                pattern, FILTERED_PLACEHOLDER, sanitized_content, flags=re.IGNORECASE
            )
    return sanitized_content, warnings


def sanitize_hidden_encoding(
    content: str, filter_encoded: bool = False
) -> Tuple[str, List[str]]:
    """
    Detects potentially hidden/encoded content after NFKC normalization.
    Optionally filters detected patterns with '[FILTERED]'.

    Args:
        content: Text content to check and potentially sanitize.
        filter_encoded: If True, replaces detected encoding patterns with '[FILTERED]'.
                        Defaults to False (detect and warn only for encoding).

    Returns:
        Tuple of (sanitized_content, warnings).
    """
    if not isinstance(content, str):
        return content, []

    try:
        sanitized_content = unicodedata.normalize("NFKC", content)
    except TypeError:
        return content, ["Error during Unicode normalization in encoding sanitization"]

    warnings = []

    for pattern in ENCODING_PATTERNS:
        if re.search(pattern, sanitized_content):
            warning_msg = f"Potentially encoded content detected: matches '{pattern}'."
            if filter_encoded:
                sanitized_content = re.sub(
                    pattern, FILTERED_PLACEHOLDER, sanitized_content
                )
                warning_msg += " Content was filtered."
            else:
                warning_msg += " Manual review recommended."
            warnings.append(warning_msg)

            if not filter_encoded:  # If only warning, one is enough
                break
    return sanitized_content, warnings


def contains_control_characters(content: str) -> bool:
    """
    Checks if the content contains control characters (excluding tab, LF, CR)
    after NFKC normalization. (Remains a pure detection function)

    Args:
        content: Text content to check.

    Returns:
        True if control characters are present.
    """
    if not isinstance(content, str):
        return False
    try:
        normalized_content = unicodedata.normalize("NFKC", content)
    except TypeError:
        return False
    return any(ord(c) < 32 and c not in "\n\r\t" for c in normalized_content)


def remove_control_characters(content: str) -> str:
    """
    Removes control characters from content (excluding tab, LF, CR)
    after NFKC normalization. (This is already a sanitization utility)

    Args:
        content: Text content to clean.

    Returns:
        Content with control characters removed.
    """
    if not isinstance(content, str):
        return content
    try:
        normalized_content = unicodedata.normalize("NFKC", content)
    except TypeError:
        return content  # Or raise an error
    return "".join(c for c in normalized_content if ord(c) >= 32 or c in "\n\r\t")
