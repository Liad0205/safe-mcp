"""Configuration system for safe-mcp."""

from __future__ import annotations

import os
from pathlib import Path
from typing import Any, Dict, Optional

import tomllib

try:  # pragma: no cover - exercised in environments with pydantic available
    from pydantic import BaseModel, ConfigDict  # type: ignore
except ModuleNotFoundError:  # pragma: no cover - fallback when pydantic missing
    class BaseModel:  # minimal stand-in for pydantic.BaseModel
        model_config: Dict[str, Any] = {}

        def __init__(self, **data: Any) -> None:
            for key, value in data.items():
                setattr(self, key, value)

        def model_dump(self) -> Dict[str, Any]:
            return self.__dict__.copy()

    def ConfigDict(**kwargs: Any) -> Dict[str, Any]:  # type: ignore
        return kwargs


class MCPConfig(BaseModel):
    """Configuration model for safe-mcp.

    The configuration can be loaded from multiple layers with the following
    order of precedence (highest first):

    1. Direct instantiation/overrides passed to :meth:`load`
    2. Environment variables prefixed with ``SAFE_MCP_``
    3. ``[tool.safe_mcp]`` section in ``pyproject.toml``
    4. Library defaults defined on this model
    """

    log_level: str = "INFO"

    model_config = ConfigDict(extra="allow")

    @classmethod
    def _load_pyproject(cls, path: Optional[Path] = None) -> Dict[str, Any]:
        """Load configuration from ``pyproject.toml`` if available."""
        if path is None:
            path = Path("pyproject.toml")
        if not path.exists():
            return {}
        try:
            data = tomllib.loads(path.read_text())
        except Exception:
            return {}
        tool = data.get("tool", {})
        cfg = tool.get("safe_mcp", {})
        if not isinstance(cfg, dict):
            return {}
        return cfg

    @classmethod
    def _load_env(cls) -> Dict[str, Any]:
        """Load configuration from environment variables."""
        prefix = "SAFE_MCP_"
        result: Dict[str, Any] = {}
        for key, value in os.environ.items():
            if key.startswith(prefix):
                name = key[len(prefix) :].lower()
                result[name] = value
        return result

    @classmethod
    def load(
        cls,
        *,
        overrides: Optional[Dict[str, Any]] = None,
        pyproject_path: Optional[Path] = None,
    ) -> "MCPConfig":
        """Load configuration using layered precedence."""
        file_cfg = cls._load_pyproject(pyproject_path)
        env_cfg = cls._load_env()
        overrides = overrides or {}
        data = cls().model_dump()
        data.update(file_cfg)
        data.update(env_cfg)
        data.update(overrides)
        return cls(**data)


GLOBAL_CONFIG = MCPConfig.load()
