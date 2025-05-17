# safe-mcp

Secure your Model Context Protocol (MCP) servers against context poisoning attacks.

## Overview

`safe-mcp` is a Python library that provides decorators and utilities to protect LLM tools from various attack vectors including prompt injection, data poisoning, and context manipulation.

## Features

- Type-safe responses with trust level indicators
- Decorators for marking trusted/untrusted data sources
- Sanitization framework for detecting and mitigating malicious content
- Input validation and rate limiting utilities
- Attack vector detection for common LLM exploit patterns

## Installation

```bash
uv pip install safe-mcp
```

## Basic Usage

```python
from safe_mcp import safe, unsafe, sanitize
from safe_mcp.sanitizers import BasicSanitizer

@safe
async def get_internal_data():
    # Retrieves data from a trusted internal source
    return data

@unsafe
async def fetch_external_api(query):
    # Gets data from an untrusted external source
    return response

@sanitize(BasicSanitizer().sanitize)
async def process_user_input(user_input):
    # Processes potentially unsafe user input
    return processed_result
```

## License

MIT
