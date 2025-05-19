# server.py
from mcp.server.fastmcp import FastMCP
from safe_mcp.decorators import safe, unsafe, sanitize, validate_inputs
from safe_mcp.core import SecuredResponse


mcp = FastMCP("Demo")


# Example 1: Marking a trusted internal tool
@mcp.tool()
@safe
async def get_internal_data(user_id: str) -> SecuredResponse:
    # Fetch data from a trusted internal source
    return {"user_id": user_id, "info": "internal only"}


# Example 2: Marking an untrusted external tool
@mcp.tool()
@unsafe
async def fetch_external_api(query: str) -> SecuredResponse:
    # Fetch data from an external API
    return {"query": query, "result": "external data"}


# Example 3: Sanitizing output from an untrusted source
@mcp.tool()
@sanitize  # Uses BasicSanitizer.sanitize by default
@unsafe
async def search_user_content(query: str) -> SecuredResponse:
    # Simulate user-generated content search
    return {"query": query, "content": "<script>alert('xss')</script>"}


# Example 4: Custom input validation
def is_positive(a: int, b: int) -> bool:
    return a > 0 and b > 0


@mcp.tool()
@validate_inputs(is_positive)
@safe
async def add_positive_numbers(a: int, b: int) -> SecuredResponse:
    return a + b


# Example 5: Custom sanitizer (e.g., filter encodings)
import functools
from safe_mcp.sanitizers.basic import BasicSanitizer


@mcp.tool()
@sanitize(
    sanitizer_func=functools.partial(
        BasicSanitizer.sanitize, filter_detected_encodings=True
    )
)
@unsafe
async def process_text(text: str) -> dict:
    return {"processed": text}


# Example 6: Chaining decorators for maximum security
@mcp.tool()
@sanitize
@validate_inputs(lambda x: isinstance(x, str) and len(x) < 100)
@unsafe
async def handle_user_input(x: str) -> SecuredResponse:
    return {"echo": x}
