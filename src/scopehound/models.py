"""Plain data structures that flow between recon phases.

These are deliberately dependency-free dataclasses so that any phase can read
the output of an earlier phase without coupling to how it was produced, and so
the whole run state serialises cleanly to JSON for the report.
"""

from __future__ import annotations

from dataclasses import dataclass, field


@dataclass
class Subdomain:
    """A hostname discovered during subdomain enumeration."""

    host: str
    sources: list[str] = field(default_factory=list)
    resolved_ips: list[str] = field(default_factory=list)

    def to_dict(self) -> dict:
        return {
            "host": self.host,
            "sources": sorted(self.sources),
            "resolved_ips": sorted(self.resolved_ips),
        }


@dataclass
class Port:
    """A single open port on a host, optionally with service detail."""

    number: int
    protocol: str = "tcp"
    state: str = "open"
    service: str = ""
    product: str = ""
    version: str = ""

    def to_dict(self) -> dict:
        return {
            "number": self.number,
            "protocol": self.protocol,
            "state": self.state,
            "service": self.service,
            "product": self.product,
            "version": self.version,
        }


@dataclass
class Host:
    """A network host (keyed by IP) with the hostnames pointing at it."""

    ip: str
    hostnames: list[str] = field(default_factory=list)
    ports: list[Port] = field(default_factory=list)

    def get_port(self, number: int, protocol: str = "tcp") -> Port | None:
        for port in self.ports:
            if port.number == number and port.protocol == protocol:
                return port
        return None

    def to_dict(self) -> dict:
        return {
            "ip": self.ip,
            "hostnames": sorted(self.hostnames),
            "ports": [p.to_dict() for p in sorted(self.ports, key=lambda x: x.number)],
        }


@dataclass
class HttpService:
    """A live HTTP(S) endpoint discovered during probing."""

    url: str
    status_code: int | None = None
    title: str = ""
    webserver: str = ""
    technologies: list[str] = field(default_factory=list)
    content_length: int | None = None
    screenshot: str = ""  # path relative to the run output directory

    def to_dict(self) -> dict:
        return {
            "url": self.url,
            "status_code": self.status_code,
            "title": self.title,
            "webserver": self.webserver,
            "technologies": self.technologies,
            "content_length": self.content_length,
            "screenshot": self.screenshot,
        }


@dataclass
class PhaseResult:
    """The outcome of running a single phase, for the run manifest."""

    name: str
    status: str  # "ok" | "skipped" | "error"
    started_at: str
    finished_at: str
    detail: str = ""

    def to_dict(self) -> dict:
        return {
            "name": self.name,
            "status": self.status,
            "started_at": self.started_at,
            "finished_at": self.finished_at,
            "detail": self.detail,
        }
