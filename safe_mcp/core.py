"""Core types and classes for safe-mcp."""

from dataclasses import dataclass, field
from enum import Enum
from typing import Any, List


class TrustLevel(str, Enum):
    """
    Trust level indicators for LLM responses.

    These levels help the LLM understand how much to trust data from MCP tools.
    """

    TRUSTED = "trusted"  # Developer-verified trusted source
    CAUTION = "caution"  # Use with care - potentially problematic
    UNTRUSTED = "untrusted"  # Unknown or external source, likely unsafe


@dataclass
class SecuredResponse:
    """Container for MCP tool responses with security metadata."""

    data: Any
    trust_level: TrustLevel
    warnings: List[str] = field(default_factory=list)

    def __post_init__(self) -> None:
        """Validate the response after initialization."""
        if self.trust_level == TrustLevel.UNTRUSTED and not self.warnings:
            self.warnings = ["Data from untrusted source"]
