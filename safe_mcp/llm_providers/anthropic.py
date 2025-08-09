from typing import Tuple

from .base import LLMProvider


class AnthropicProvider(LLMProvider):
    """Concrete ``LLMProvider`` for Anthropic's Claude API."""

    def __init__(self, api_key: str, model: str = "claude-3-sonnet-20240229") -> None:
        self.api_key = api_key
        self.model = model

    async def validate(self, content: str, modules: Tuple[str, ...]) -> bool:  # pragma: no cover - network call placeholder
        raise NotImplementedError

