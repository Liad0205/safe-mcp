from pathlib import Path

from safe_mcp.config import MCPConfig


def test_config_loading_precedence(tmp_path: Path, monkeypatch):
    pyproject = tmp_path / "pyproject.toml"
    pyproject.write_text(
        """
[tool.safe_mcp]
log_level = "WARNING"
"""
    )
    monkeypatch.chdir(tmp_path)
    monkeypatch.setenv("SAFE_MCP_LOG_LEVEL", "ERROR")

    cfg_env = MCPConfig.load()
    assert cfg_env.log_level == "ERROR"

    cfg_override = MCPConfig.load(overrides={"log_level": "DEBUG"})
    assert cfg_override.log_level == "DEBUG"
