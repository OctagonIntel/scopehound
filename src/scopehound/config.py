"""Runtime settings: which binaries to call, timeouts, and ports to probe.

Defaults are sensible for a typical engagement. Anything here can be overridden
from a YAML config file (``--config``) so operators don't have to touch code.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path

import yaml

# Ports we treat as "probably HTTP(S)" when building URLs for the probe phase.
DEFAULT_WEB_PORTS: list[int] = [80, 443, 8080, 8443, 8000, 8888, 3000, 5000]

# Logical tool name -> default binary name on PATH.
DEFAULT_TOOLS: dict[str, str] = {
    "subfinder": "subfinder",
    "amass": "amass",
    "nmap": "nmap",
    # NOTE: ProjectDiscovery's httpx, NOT the Python `httpx` library CLI, which
    # shares the same name. `scopehound doctor` warns if they collide on PATH.
    "httpx": "httpx",
}

# Per-tool subprocess timeouts in seconds.
DEFAULT_TIMEOUTS: dict[str, int] = {
    "subfinder": 300,
    "amass": 600,
    "nmap": 1800,
    "httpx": 300,
}


@dataclass
class Settings:
    tools: dict[str, str] = field(default_factory=lambda: dict(DEFAULT_TOOLS))
    timeouts: dict[str, int] = field(default_factory=lambda: dict(DEFAULT_TIMEOUTS))
    web_ports: list[int] = field(default_factory=lambda: list(DEFAULT_WEB_PORTS))
    nmap_top_ports: int = 1000
    use_amass: bool = False  # amass passive is slow; opt-in
    screenshot_timeout_ms: int = 15000

    def tool(self, name: str) -> str:
        return self.tools.get(name, name)

    def timeout(self, name: str) -> int:
        return self.timeouts.get(name, 300)

    @classmethod
    def load(cls, path: str | Path | None) -> Settings:
        settings = cls()
        if path is None:
            return settings
        data = yaml.safe_load(Path(path).read_text(encoding="utf-8")) or {}
        if tools := data.get("tools"):
            settings.tools.update(tools)
        if timeouts := data.get("timeouts"):
            settings.timeouts.update(timeouts)
        if web_ports := data.get("web_ports"):
            settings.web_ports = list(web_ports)
        if "nmap_top_ports" in data:
            settings.nmap_top_ports = int(data["nmap_top_ports"])
        if "use_amass" in data:
            settings.use_amass = bool(data["use_amass"])
        if "screenshot_timeout_ms" in data:
            settings.screenshot_timeout_ms = int(data["screenshot_timeout_ms"])
        return settings
