"""
Basic sanitizer for detecting common attacks.
"""

from typing import Any, List, Tuple

from ..sanitizers import SanitizerBase
from ..utils.detection import (
    sanitize_prompt_injection,
    sanitize_jailbreak_attempts,
    sanitize_hidden_encoding,
    remove_control_characters,
)


class BasicSanitizer(SanitizerBase):
    """
    Basic sanitization using a sequence of core sanitization routines.
    Provides a static `sanitize` method for default sanitization.

    The static `sanitize` method applies in order:
    - Control character removal
    - Prompt injection sanitization (filters matches)
    - Jailbreak attempt sanitization (filters matches)
    - Hidden encoding detection (warns, optionally filters if configured via parameter)

    It relies on Unicode normalization (NFKC) performed within some routines.
    """

    @staticmethod
    def sanitize(
        content: Any, filter_detected_encodings: bool = False
    ) -> Tuple[Any, List[str]]:
        """
        Apply a sequence of basic sanitization routines to the content.

        Args:
            content: Text content to sanitize.
            filter_detected_encodings: If True, detected encoding patterns will
                                       also be filtered with '[FILTERED]'.
                                       Defaults to False (warn only).
        Returns:
            Tuple of (sanitized_content, warnings).
        """
        if not isinstance(content, str):
            return content, []

        all_warnings: List[str] = []
        sanitized_content = content

        # 1. Remove Control Characters (first, to clean input for subsequent regex)
        # Assuming remove_control_characters now returns (str, List[str])
        sanitized_content, cc_warnings = remove_control_characters(sanitized_content)
        all_warnings.extend(cc_warnings)

        # 2. Sanitize Prompt Injection
        sanitized_content, pi_warnings = sanitize_prompt_injection(sanitized_content)
        all_warnings.extend(pi_warnings)

        # 3. Sanitize Jailbreak Attempts
        sanitized_content, jb_warnings = sanitize_jailbreak_attempts(sanitized_content)
        all_warnings.extend(jb_warnings)

        # 4. Sanitize/Detect Hidden Encoding
        # By default, this will only warn about detected encodings.
        sanitized_content, enc_warnings = sanitize_hidden_encoding(
            sanitized_content, filter_encoded=filter_detected_encodings
        )
        all_warnings.extend(enc_warnings)

        return sanitized_content, all_warnings
