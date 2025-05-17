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


class CompositeSanitizer(SanitizerBase):
    """
    Apply multiple sanitizers in sequence.
    
    This sanitizer applies each of its component sanitizers in order,
    passing the output of each to the next.
    """
    
    def __init__(self, sanitizers: List[SanitizerBase]):
        """
        Initialize with a list of sanitizers.
        
        Args:
            sanitizers: List of sanitizer instances to apply in sequence
        """
        self.sanitizers = sanitizers
        
    def sanitize(self, content: Any) -> Tuple[Any, List[str]]:
        """
        Apply all sanitizers in sequence.
        
        Args:
            content: The content to sanitize
            
        Returns:
            Tuple of (sanitized_content, warnings)
        """
        warnings = []
        result = content
        
        for sanitizer in self.sanitizers:
            result, new_warnings = sanitizer.sanitize(result)
            warnings.extend(new_warnings)
            
        return result, warnings