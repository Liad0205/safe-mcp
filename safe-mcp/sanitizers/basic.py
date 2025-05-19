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

    This sanitizer applies in order:
    - Control character removal
    - Prompt injection sanitization (filters matches)
    - Jailbreak attempt sanitization (filters matches)
    - Hidden encoding detection (warns, optionally filters if configured)

    It relies on Unicode normalization (NFKC) performed within each routine.
    """

    def __init__(self, filter_detected_encodings: bool = False):
        """
        Initialize the basic sanitizer.

        Args:
            filter_detected_encodings: If True, detected encoding patterns will
                                       also be filtered with '[FILTERED]'.
                                       Defaults to False (warn only).
        """
        self.filter_detected_encodings = filter_detected_encodings

    def sanitize(self, content: Any) -> Tuple[Any, List[str]]:
        """
        Apply a sequence of basic sanitization routines to the content.

        Args:
            content: Text content to sanitize.

        Returns:
            Tuple of (sanitized_content, warnings).
        """
        if not isinstance(content, str):
            return content, []

        all_warnings: List[str] = []
        sanitized_content = content

        # 1. Remove Control Characters (first, to clean input for subsequent regex)
        content_before_control_removal = sanitized_content
        sanitized_content = remove_control_characters(sanitized_content)
        if sanitized_content != content_before_control_removal:
            all_warnings.append("Control characters removed.")

        # 2. Sanitize Prompt Injection
        sanitized_content, pi_warnings = sanitize_prompt_injection(sanitized_content)
        all_warnings.extend(pi_warnings)

        # 3. Sanitize Jailbreak Attempts
        sanitized_content, jb_warnings = sanitize_jailbreak_attempts(sanitized_content)
        all_warnings.extend(jb_warnings)

        # 4. Sanitize/Detect Hidden Encoding
        sanitized_content, enc_warnings = sanitize_hidden_encoding(
            sanitized_content, filter_encoded=self.filter_detected_encodings
        )
        all_warnings.extend(enc_warnings)

        return sanitized_content, all_warnings
