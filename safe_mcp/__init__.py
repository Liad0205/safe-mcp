"""
safe-mcp: Security framework for Model Context Protocol (MCP) servers

This package provides tools to protect LLM systems from context poisoning
and other security threats when using external data.
"""

from .core import SecuredResponse, TrustLevel
from .decorators import safe, unsafe, sanitize, validate_inputs

__all__ = [
    "SecuredResponse",
    "TrustLevel",
    "safe",
    "unsafe",
    "sanitize",
    "validate_inputs",
]

__version__ = "0.1.0"
