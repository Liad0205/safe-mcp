from dataclasses import dataclass
from typing import Callable, Optional


@dataclass
class MCPConfig:
    """Configuration for authentication and rate limiting."""

    auth_validator: Optional[Callable[[str], bool]] = None
    ratelimit_capacity: int = 60
    ratelimit_refill_rate: float = 1.0  # tokens per second


# Global configuration instance
config = MCPConfig()
