"""
safe-mcp: Security framework for Model Context Protocol (MCP) servers

This package provides tools to protect LLM systems from context poisoning 
and other security threats when using external data.
"""

from safe_mcp.core import SecuredResponse, TrustLevel
from safe_mcp.decorators import safe, unsafe, sanitize, validate_inputs, rate_limited

__all__ = [
    "SecuredResponse",
    "TrustLevel",
    "safe",
    "unsafe",
    "sanitize",
    "validate_inputs",
    "rate_limited",
]

__version__ = "0.1.0"