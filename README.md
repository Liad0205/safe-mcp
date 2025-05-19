# safe-mcp

Secure your Model Context Protocol (MCP) servers against context poisoning, prompt injection, and untrusted data.

## Overview

**safe-mcp** is a Python security library for LLM tool developers and MCP server operators. It provides a robust set of decorators and utilities to help you:

- Mark and track the trustworthiness of tool outputs
- Detect and mitigate prompt injection, jailbreaks, and encoding attacks
- Sanitize and validate both inputs and outputs
- Enforce input validation and (optionally) rate limiting

## Features

- **Trust Level Enforcement:** Type-safe responses with explicit trust levels (`TRUSTED`, `CAUTION`, `UNTRUSTED`)
- **Security Decorators:** Mark tools as trusted/untrusted, sanitize outputs, and validate inputs with simple decorators
- **Pluggable Sanitization:** Use or extend the built-in sanitizers to filter or warn on malicious content
- **Attack Pattern Detection:** Detect prompt injection, jailbreak attempts, and hidden encodings
- **Input Validation:** Enforce custom validation logic on tool inputs
- **Composable:** Chain decorators for layered security

## Installation

> **Note:**  
> `safe-mcp` is not yet published on PyPI.  
> You can install it directly from the repository:

```bash
uv pip install git+https://github.com/Liad0205/safe-mcp
```

Or, if you have a local copy:

```bash
uv pip install /path/to/safe-mcp
```

## Quick Start

```python
from safe_mcp.decorators import safe, unsafe, sanitize, validate_inputs
from safe_mcp.sanitizers.basic import BasicSanitizer

# Mark a tool as trusted (internal data)
@safe
async def get_internal_data(user_id: str):
    return {"user_id": user_id, "info": "internal only"}

# Mark a tool as untrusted (external API)
@unsafe
async def fetch_external_api(query: str):
    return {"query": query, "result": "external data"}

# Sanitize output from an untrusted source
@sanitize  # Uses BasicSanitizer.sanitize by default
@unsafe
async def search_user_content(query: str):
    return {"query": query, "content": "<script>alert('xss')</script>"}

# Input validation example
def is_positive(a: int, b: int) -> bool:
    return a > 0 and b > 0

@validate_inputs(is_positive)
@safe
async def add_positive_numbers(a: int, b: int):
    return a + b

# Custom sanitizer example (e.g., filter encodings)
import functools

@sanitize(sanitizer_func=functools.partial(BasicSanitizer.sanitize, filter_detected_encodings=True))
@unsafe
async def process_text(text: str):
    return {"processed": text}
```

## Example: Using with MCP Tools

```python
from mcp.server.fastmcp import FastMCP
from safe_mcp.decorators import safe, unsafe, sanitize

mcp = FastMCP("Demo")

@mcp.tool()
@safe
async def get_internal_data(user_id: str):
    return {"user_id": user_id, "info": "internal only"}

@mcp.tool()
@sanitize
@unsafe
async def search_user_content(query: str):
    return {"query": query, "content": "<script>alert('xss')</script>"}
```

## Why safe-mcp?

- **Defense in Depth:** Layer trust marking, sanitization, and validation for robust protection.
- **Easy Integration:** Add security to your MCP tools with a single decorator.
- **Extensible:** Plug in your own sanitizers or validation logic.
- **Transparent:** All responses are wrapped with trust level and warnings for downstream handling.

## License

MIT
