"""Utilities for validating content using LLM providers."""

from dataclasses import dataclass
from typing import MutableMapping, Optional, Tuple

from .llm_providers import (
    AnthropicProvider,
    GoogleProvider,
    LLMProvider,
    OpenAIProvider,
)


@dataclass
class MCPConfig:
    """Configuration for the :class:`LLMValidator`.

    Attributes:
        provider: Name of the LLM provider (``openai``, ``anthropic`` or ``google``)
        api_key:  API key used for authentication.
        model:    Optional model identifier understood by the provider.
        cache_provider: Optional mutable mapping used for caching validation
            results.  Keys should be tuples of ``(content_hash, modules)``.
    """

    provider: str
    api_key: str
    model: str | None = None
    cache_provider: Optional[MutableMapping] = None


class LLMValidator:
    """High level interface that dispatches validation requests to a provider."""

    def __init__(self, config: MCPConfig) -> None:
        self.config = config
        self.cache_provider = config.cache_provider
        self.provider = self._select_provider(config)

    def _select_provider(self, config: MCPConfig) -> LLMProvider:
        name = config.provider.lower()
        if name == "openai":
            return OpenAIProvider(config.api_key, config.model or "gpt-4o-mini")
        if name == "anthropic":
            return AnthropicProvider(
                config.api_key, config.model or "claude-3-sonnet-20240229"
            )
        if name == "google":
            return GoogleProvider(config.api_key, config.model or "gemini-pro")
        raise ValueError(f"Unknown LLM provider: {config.provider}")

    async def validate(self, content: str, modules: Tuple[str, ...]) -> bool:
        """Validate ``content`` using the configured provider."""

        return await self.provider.validate(content, modules)

