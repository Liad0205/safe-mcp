"""
safe-mcp: Security framework for Model Context Protocol (MCP) servers

This package provides tools to protect LLM systems from context poisoning
and other security threats when using external data.
"""

from .core import SecuredResponse, TrustLevel
from .decorators import safe, secure, unsafe, sanitize, validate_inputs
from .llm_validator import LLMValidator, MCPConfig

__all__ = [
    "SecuredResponse",
    "TrustLevel",
    "safe",
    "secure",
    "unsafe",
    "sanitize",
    "validate_inputs",
    "LLMValidator",
    "MCPConfig",
]

__version__ = "0.1.0"
