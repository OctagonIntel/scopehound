"""Tests for settings loading and overrides."""

from __future__ import annotations

from scopehound.config import DEFAULT_TOOLS, Settings


def test_defaults():
    settings = Settings()
    assert settings.tool("nmap") == "nmap"
    assert settings.timeout("nmap") == 1800
    assert 443 in settings.web_ports
    assert settings.use_amass is False


def test_unknown_tool_falls_back_to_its_name():
    settings = Settings()
    assert settings.tool("whatever") == "whatever"


def test_load_none_returns_defaults():
    settings = Settings.load(None)
    assert settings.tools == DEFAULT_TOOLS


def test_load_overrides(tmp_path):
    path = tmp_path / "config.yaml"
    path.write_text(
        """
tools:
  httpx: /opt/pdtools/httpx
nmap_top_ports: 200
use_amass: true
web_ports: [80, 443]
""",
        encoding="utf-8",
    )
    settings = Settings.load(path)
    assert settings.tool("httpx") == "/opt/pdtools/httpx"
    assert settings.tool("nmap") == "nmap"  # untouched default preserved
    assert settings.nmap_top_ports == 200
    assert settings.use_amass is True
    assert settings.web_ports == [80, 443]
