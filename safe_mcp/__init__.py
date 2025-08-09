"""
safe-mcp: Security framework for Model Context Protocol (MCP) servers

This package provides tools to protect LLM systems from context poisoning
and other security threats when using external data.
"""

from .config import GLOBAL_CONFIG, MCPConfig
from .core import SecuredResponse, TrustLevel
from .decorators import safe, sanitize, unsafe, validate_inputs
from .logger import get_logger

__all__ = [
    "SecuredResponse",
    "TrustLevel",
    "safe",
    "unsafe",
    "sanitize",
    "validate_inputs",
    "MCPConfig",
    "GLOBAL_CONFIG",
    "get_logger",
]

__version__ = "0.1.0"
