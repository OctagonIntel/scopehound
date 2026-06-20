"""Shared run state passed from one phase to the next.

A :class:`RunContext` is created once per run and mutated in place by each
phase. Subdomain enum appends to ``subdomains``; port scan reads those and
fills ``hosts``; fingerprinting enriches the ports; HTTP probing reads hosts
and fills ``http_services``; screenshots annotate those services. The report
phase serialises the whole thing.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path

from scopehound.config import Settings
from scopehound.models import Host, HttpService, PhaseResult, Subdomain
from scopehound.scope import Scope


@dataclass
class RunContext:
    target: str
    output_dir: Path
    scope: Scope
    settings: Settings
    subdomains: list[Subdomain] = field(default_factory=list)
    hosts: list[Host] = field(default_factory=list)
    http_services: list[HttpService] = field(default_factory=list)
    phase_results: list[PhaseResult] = field(default_factory=list)

    @property
    def raw_dir(self) -> Path:
        """Directory for raw tool output (XML, JSON-lines, etc.)."""

        path = self.output_dir / "raw"
        path.mkdir(parents=True, exist_ok=True)
        return path

    @property
    def screenshot_dir(self) -> Path:
        path = self.output_dir / "screenshots"
        path.mkdir(parents=True, exist_ok=True)
        return path

    def get_host(self, ip: str) -> Host | None:
        for host in self.hosts:
            if host.ip == ip:
                return host
        return None

    def upsert_host(self, ip: str, hostname: str | None = None) -> Host:
        """Get the host for ``ip`` or create it, recording ``hostname``."""

        host = self.get_host(ip)
        if host is None:
            host = Host(ip=ip)
            self.hosts.append(host)
        if hostname and hostname not in host.hostnames:
            host.hostnames.append(hostname)
        return host

    def all_hostnames(self) -> list[str]:
        """Every candidate hostname known so far (target + subdomains)."""

        names = {self.target}
        names.update(s.host for s in self.subdomains)
        return sorted(names)
