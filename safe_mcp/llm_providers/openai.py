from typing import Tuple

from .base import LLMProvider


class OpenAIProvider(LLMProvider):
    """Concrete ``LLMProvider`` for OpenAI's API.

    The implementation is intentionally lightweight – network calls are not
    performed in the library itself.  The ``validate`` method should be mocked
    during testing or extended in real deployments to call the OpenAI API.
    """

    def __init__(self, api_key: str, model: str = "gpt-4o-mini") -> None:
        self.api_key = api_key
        self.model = model

    async def validate(self, content: str, modules: Tuple[str, ...]) -> bool:  # pragma: no cover - network call placeholder
        raise NotImplementedError

