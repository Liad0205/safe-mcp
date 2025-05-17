"""
Utilities for detecting common attack patterns.
"""

import re
from typing import List, Tuple


def detect_prompt_injection(content: str) -> Tuple[bool, List[str]]:
    """
    Detect common prompt injection patterns.

    Args:
        content: Text content to check

    Returns:
        Tuple of (detected_bool, warnings)
    """
    injection_patterns = [
        r"ignore previous (instructions|prompts)",
        r"disregard (earlier|previous|above)",
        r"new instructions",
        r"system prompt",
        r"you are now",
        r"do not (follow|obey) the",
        r"forget (your|previous|all) instructions",
    ]

    warnings = []
    for pattern in injection_patterns:
        if re.search(pattern, content, re.IGNORECASE):
            warnings.append(f"Potential prompt injection detected: matches '{pattern}'")

    return bool(warnings), warnings


def detect_jailbreak_attempts(content: str) -> Tuple[bool, List[str]]:
    """
    Detect common jailbreak patterns.

    Args:
        content: Text content to check

    Returns:
        Tuple of (detected_bool, warnings)
    """
    jailbreak_patterns = [
        r"DAN mode",
        r"do anything now",
        r"ignore (ethics|restrictions|limitations)",
        r"pretend to be",
        r"hypothetically speaking",
        r"ignore your programming",
        r"bypass (your|all) (restrictions|filters)",
    ]

    warnings = []
    for pattern in jailbreak_patterns:
        if re.search(pattern, content, re.IGNORECASE):
            warnings.append(
                f"Potential jailbreak attempt detected: matches '{pattern}'"
            )

    return bool(warnings), warnings


def detect_hidden_encoding(content: str) -> Tuple[bool, List[str]]:
    """
    Check for obfuscated or encoded content.

    Args:
        content: Text content to check

    Returns:
        Tuple of (detected_bool, warnings)
    """
    encoding_patterns = [
        # Base64-like pattern
        r"[A-Za-z0-9+/]{20,}={0,2}",
        # Hex encoding
        r"\\x[0-9A-Fa-f]{2}",
        # Unicode escapes
        r"\\u[0-9A-Fa-f]{4}",
        # HTML entities
        r"&[#a-zA-Z0-9]{2,};",
    ]

    warnings = []
    for pattern in encoding_patterns:
        if re.search(pattern, content):
            warnings.append(
                f"Potentially encoded content detected: matches '{pattern}'"
            )
            break

    return bool(warnings), warnings


def contains_control_characters(content: str) -> bool:
    """
    Check if the content contains control characters.

    Args:
        content: Text content to check

    Returns:
        True if control characters are present
    """
    return any(ord(c) < 32 and c not in "\n\r\t" for c in content)


def remove_control_characters(content: str) -> str:
    """
    Remove control characters from content.

    Args:
        content: Text content to clean

    Returns:
        Content with control characters removed
    """
    return "".join(c for c in content if ord(c) >= 32 or c in "\n\r\t")
