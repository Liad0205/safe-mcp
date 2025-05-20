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
    PROBLEM_UNICODE_CHARS,
    CONFUSABLES_MAP,
    WARNING_PROMPT_INJECTION_SANITIZED,
    WARNING_JAILBREAK_SANITIZED,
    WARNING_ENCODED_CONTENT_DETECTED,
    WARNING_ENCODED_CONTENT_FILTERED,
    WARNING_ENCODED_CONTENT_MANUAL_REVIEW,
    WARNING_INPUT_NOT_VALID_STRING,
    WARNING_UNICODE_NORMALIZATION_ERROR_CONTROL_CHAR,
    WARNING_CONTROL_CHARACTERS_REMOVED,
    WARNING_CONFUSABLE_CHARACTERS_REPLACED,
)


def normalize_and_sanitize_confusables(content: str) -> Tuple[str, List[str]]:
    """
    Performs NFKC normalization and replaces known confusable characters
    with their Latin equivalents.

    Args:
        content: Text content to normalize and sanitize for confusables.

    Returns:
        Tuple of (normalized_content, warnings).
    """
    if not isinstance(content, str):
        return content, [WARNING_INPUT_NOT_VALID_STRING]

    warnings = []
    normalized_content = content
    try:
        normalized_content = unicodedata.normalize("NFKC", content)
    except TypeError:
        # If NFKC normalization itself fails (e.g., on non-string types if not caught above)
        warnings.append(WARNING_UNICODE_NORMALIZATION_ERROR_CONTROL_CHAR)
        return content, warnings

    # Replace confusable characters
    # This is a simple string replacement loop. For very long strings or huge maps,
    # a regex approach might be more performant, but this is clearer for a moderate map.
    temp_content = list(normalized_content)
    confusables_replaced = False
    for i, char in enumerate(temp_content):
        if char in CONFUSABLES_MAP:
            temp_content[i] = CONFUSABLES_MAP[char]
            confusables_replaced = True

    if confusables_replaced:
        normalized_content = "".join(temp_content)
        warnings.append(WARNING_CONFUSABLE_CHARACTERS_REPLACED)

    return normalized_content, warnings


def sanitize_prompt_injection(content: str) -> Tuple[str, List[str]]:
    """
    Detects and sanitizes common prompt injection patterns.
    Assumes content is already normalized.

    Args:
        content: Pre-normalized text content to check and sanitize.

    Returns:
        Tuple of (sanitized_content, warnings).
    """
    if not isinstance(content, str):
        return content, []  # Or specific warning/error

    # Content is assumed to be normalized by the caller (e.g., BasicSanitizer)
    sanitized_content = content
    warnings = []
    for pattern in PROMPT_INJECTION_PATTERNS:
        if re.search(pattern, sanitized_content, re.IGNORECASE):
            warnings.append(WARNING_PROMPT_INJECTION_SANITIZED.format(pattern))
            sanitized_content = re.sub(
                pattern, FILTERED_PLACEHOLDER, sanitized_content, flags=re.IGNORECASE
            )
    return sanitized_content, warnings


def sanitize_jailbreak_attempts(content: str) -> Tuple[str, List[str]]:
    """
    Detects and sanitizes common jailbreak patterns.
    Assumes content is already normalized.

    Args:
        content: Pre-normalized text content to check and sanitize.

    Returns:
        Tuple of (sanitized_content, warnings).
    """
    if not isinstance(content, str):
        return content, []

    # Content is assumed to be normalized by the caller
    sanitized_content = content
    warnings = []
    for pattern in JAILBREAK_PATTERNS:
        if re.search(pattern, sanitized_content, re.IGNORECASE):
            warnings.append(WARNING_JAILBREAK_SANITIZED.format(pattern))
            sanitized_content = re.sub(
                pattern, FILTERED_PLACEHOLDER, sanitized_content, flags=re.IGNORECASE
            )
    return sanitized_content, warnings


def sanitize_hidden_encoding(
    content: str, filter_encoded: bool = False
) -> Tuple[str, List[str]]:
    """
    Detects potentially hidden/encoded content.
    Assumes content is already normalized.

    Args:
        content: Pre-normalized text content to check and potentially sanitize.
        filter_encoded: If True, replaces detected encoding patterns with '[FILTERED]'.

    Returns:
        Tuple of (sanitized_content, warnings).
    """
    if not isinstance(content, str):
        return content, []

    # Content is assumed to be normalized by the caller
    sanitized_content = content
    warnings = []

    for pattern in ENCODING_PATTERNS:
        if re.search(pattern, sanitized_content):
            warning_msg = WARNING_ENCODED_CONTENT_DETECTED.format(pattern)
            if filter_encoded:
                sanitized_content = re.sub(
                    pattern, FILTERED_PLACEHOLDER, sanitized_content
                )
                warning_msg += WARNING_ENCODED_CONTENT_FILTERED
            else:
                warning_msg += WARNING_ENCODED_CONTENT_MANUAL_REVIEW
            warnings.append(warning_msg)

            if not filter_encoded:
                break
    return sanitized_content, warnings


def contains_control_characters(content: str) -> bool:
    """
    Checks if the content contains C0/C1 control characters (excluding common
    whitespace) or specific problematic Unicode format characters.
    Assumes content is already normalized.

    Args:
        content: Pre-normalized text content to check.

    Returns:
        True if such characters are present.
    """
    if not isinstance(content, str):
        return False

    # Content is assumed to be normalized by the caller
    # No try-except for normalization here anymore
    for char in content:  # Iterate directly over the pre-normalized content
        if char in PROBLEM_UNICODE_CHARS:
            return True
        category = unicodedata.category(char)
        if category == "Cc" and char not in "\n\r\t ":
            return True
    return False


def remove_control_characters(content: str) -> Tuple[str, List[str]]:
    """
    Removes most C0/C1 control characters (excluding common whitespace)
    and specific problematic Unicode format characters from content.
    Assumes content is already normalized.

    Args:
        content: Pre-normalized text content to clean.

    Returns:
        Tuple of (cleaned_content, warnings).
    """
    if not isinstance(content, str):
        return content, [WARNING_INPUT_NOT_VALID_STRING]

    # Content is assumed to be normalized by the caller
    # No try-except for normalization here anymore

    cleaned_chars = []
    modified = False
    for char in content:  # Iterate directly over the pre-normalized content
        category = unicodedata.category(char)
        if char not in PROBLEM_UNICODE_CHARS and (
            category != "Cc" or char in "\n\r\t "
        ):
            cleaned_chars.append(char)
        else:
            modified = True

    cleaned_content = "".join(cleaned_chars)

    current_warnings = []
    if modified:
        current_warnings.append(WARNING_CONTROL_CHARACTERS_REMOVED)

    return cleaned_content, current_warnings
