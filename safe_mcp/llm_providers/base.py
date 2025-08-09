from abc import ABC, abstractmethod
from typing import Tuple


class LLMProvider(ABC):
    """Abstract interface for LLM-based validation providers."""

    @abstractmethod
    async def validate(self, content: str, modules: Tuple[str, ...]) -> bool:
        """Validate ``content`` using the provider.

        Implementations should return ``True`` when the content is considered
        safe.  The ``modules`` argument provides contextual information about
        which code modules were involved in producing the content and can be
        used to craft provider specific prompts.
        """

        raise NotImplementedError

