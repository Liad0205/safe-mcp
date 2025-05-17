"""
Core types and classes for safe-mcp.
"""

from enum import Enum
from typing import Any, List
from pydantic import BaseModel, Field


class TrustLevel(str, Enum):
    """
    Trust level indicators for LLM responses.

    These levels help the LLM understand how much to trust data from MCP tools.
    """

    SAFE = "safe"  # Developer-verified trusted source
    CAUTION = "caution"  # Use with care - potentially problematic
    UNSAFE = "unsafe"  # Known problematic source


class SecuredResponse(BaseModel):
    """
    Container for MCP tool responses with security metadata.

    This wrapper provides LLMs with context about how much to trust
    the data returned by MCP tools.
    """

    data: Any
    trust_level: TrustLevel
    warnings: List[str] = Field(default_factory=list)

    def model_post_init(self, __context):
        """
        Validate the response after initialization.

        Ensures that unsafe responses always have warnings explaining why.
        """
        if self.trust_level == TrustLevel.UNSAFE and not self.warnings:
            self.warnings = ["Data from untrusted source"]
