import json

import pytest

from safe_mcp.config import MCPConfig
from safe_mcp.decorators import sanitize
from safe_mcp.logger import get_logger


@pytest.mark.asyncio
async def test_json_logger_structure(capsys):
    cfg = MCPConfig(log_level="INFO")
    logger = get_logger(cfg)
    logger.handlers.clear()

    @sanitize(config=cfg)
    async def sample():
        return "data"

    await sample()
    captured = capsys.readouterr()
    record = json.loads(captured.err.strip())
    assert record["message"] == "sanitize"
    assert record["trust_level"] == "untrusted"
    assert record["warnings"] == []
