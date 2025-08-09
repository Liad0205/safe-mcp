from typing import Tuple

from .base import LLMProvider


class GoogleProvider(LLMProvider):
    """Concrete ``LLMProvider`` for Google's generative AI offerings."""

    def __init__(self, api_key: str, model: str = "gemini-pro") -> None:
        self.api_key = api_key
        self.model = model

    async def validate(self, content: str, modules: Tuple[str, ...]) -> bool:  # pragma: no cover - network call placeholder
        raise NotImplementedError

