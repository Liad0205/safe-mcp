"""
Basic sanitizer for detecting common attacks.
"""

import re
from typing import Any, List, Tuple

from ..sanitizers import SanitizerBase


class BasicSanitizer(SanitizerBase):
    """
    Basic sanitization for common attack patterns.

    This sanitizer checks for:
    - Prompt injection attempts
    - Hidden instructions
    - Encoded content
    - Control characters
    """

    def __init__(self):
        """Initialize the basic sanitizer."""
        # Common prompt injection patterns
        self.injection_patterns = [
            r"ignore previous (instructions|prompts)",
            r"disregard (earlier|previous|above)",
            r"new instructions",
            r"system prompt",
            r"you are now",
            r"do not (follow|obey) the",
            r"forget (your|previous|all) instructions",
        ]

        # Patterns for detecting potentially encoded content
        self.encoding_patterns = [
            # Base64-like pattern
            r"[A-Za-z0-9+/]{20,}={0,2}",
            # Hex encoding
            r"\\x[0-9A-Fa-f]{2}",
            # Unicode escapes
            r"\\u[0-9A-Fa-f]{4}",
            # HTML entities
            r"&[#a-zA-Z0-9]{2,};",
        ]

    def sanitize(self, content: Any) -> Tuple[Any, List[str]]:
        """
        Apply basic sanitization to the content.

        Args:
            content: Text content to sanitize

        Returns:
            Tuple of (sanitized_content, warnings)
        """
        # Only process string content
        if not isinstance(content, str):
            return content, []

        warnings = []
        sanitized = content

        # Check for prompt injection
        for pattern in self.injection_patterns:
            if re.search(pattern, content, re.IGNORECASE):
                warnings.append(f"Potential prompt injection detected")
                # Replace suspicious patterns with [FILTERED]
                sanitized = re.sub(
                    pattern, "[FILTERED]", sanitized, flags=re.IGNORECASE
                )

        # Check for potentially encoded content
        for pattern in self.encoding_patterns:
            if re.search(pattern, content):
                warnings.append("Potentially encoded content detected")
                break

        # Remove control characters
        if any(ord(c) < 32 and c not in "\n\r\t" for c in content):
            warnings.append("Control characters removed")
            sanitized = "".join(c for c in sanitized if ord(c) >= 32 or c in "\n\r\t")

        return sanitized, warnings


class ContentPolicySanitizer(SanitizerBase):
    """
    Apply custom content policies to filter content.

    This sanitizer allows defining custom rules for filtering content
    that violates specific policies.
    """

    def __init__(self, policy_rules: List[dict]):
        """
        Initialize with policy rules.

        Args:
            policy_rules: List of dictionaries with keys:
                - pattern: Regex pattern to match
                - replacement: Replacement text
                - description: Description of the rule
        """
        self.policy_rules = policy_rules

    def sanitize(self, content: Any) -> Tuple[Any, List[str]]:
        """
        Apply content policy rules.

        Args:
            content: Text content to sanitize

        Returns:
            Tuple of (sanitized_content, warnings)
        """
        # Only process string content
        if not isinstance(content, str):
            return content, []

        warnings = []
        sanitized = content

        for rule in self.policy_rules:
            if re.search(rule["pattern"], content, re.IGNORECASE):
                warnings.append(f"Content policy violation: {rule['description']}")
                sanitized = re.sub(
                    rule["pattern"], rule["replacement"], sanitized, flags=re.IGNORECASE
                )

        return sanitized, warnings
