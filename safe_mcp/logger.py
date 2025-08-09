"""Simple JSON structured logger for safe-mcp."""

from __future__ import annotations

import json
import logging
from typing import Any, Dict

from .config import GLOBAL_CONFIG, MCPConfig


class JsonFormatter(logging.Formatter):
    """Format log records as single-line JSON."""

    def format(self, record: logging.LogRecord):
        data: Dict[str, Any] = {
            "level": record.levelname,
            "message": record.getMessage(),
            "module": record.module,
            "func": record.funcName,
        }
        extra_keys = set(record.__dict__.keys()) - {
            "name",
            "msg",
            "args",
            "levelname",
            "levelno",
            "pathname",
            "filename",
            "module",
            "exc_info",
            "exc_text",
            "stack_info",
            "lineno",
            "funcName",
            "created",
            "msecs",
            "relativeCreated",
            "thread",
            "threadName",
            "processName",
            "process",
        }
        for key in extra_keys:
            data[key] = getattr(record, key)
        return json.dumps(data)


def get_logger(config: MCPConfig | None = None) -> logging.Logger:
    """Return a configured logger instance."""
    cfg = config or GLOBAL_CONFIG
    logger = logging.getLogger("safe_mcp")
    if not logger.handlers:
        handler = logging.StreamHandler()
        handler.setFormatter(JsonFormatter())
        logger.addHandler(handler)
        logger.propagate = False
    logger.setLevel(getattr(logging, cfg.log_level.upper(), logging.INFO))
    return logger
