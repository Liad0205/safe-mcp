"""
Base sanitizer classes for content security.
"""

from abc import ABC, abstractmethod
from typing import Any, List, Tuple


class SanitizerBase(ABC):
    """
    Abstract base class for all sanitizers.

    Sanitizers process potentially untrusted content and return
    a sanitized version along with any warnings.
    """

    @abstractmethod
    def sanitize(self, content: Any) -> Tuple[Any, List[str]]:
        """
        Sanitize the provided content.

        Args:
            content: The content to sanitize

        Returns:
            Tuple of (sanitized_content, warnings)
        """
        pass
