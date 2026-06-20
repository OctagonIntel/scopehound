"""Phase 2 - port scanning.

Resolves the in-scope hostnames to IP addresses, re-checks each resolved IP
against the scope (a hostname can resolve to an out-of-scope address), then
runs a single nmap top-ports scan across the unique in-scope IPs. Open ports
are recorded on :class:`~scopehound.models.Host` objects keyed by IP.
"""

from __future__ import annotations

import socket
import xml.etree.ElementTree as ET

from scopehound.context import RunContext
from scopehound.models import Port
from scopehound.phases.base import Phase
from scopehound.runner import run


class PortScanPhase(Phase):
    name = "portscan"
    description = "Resolve hosts and scan top ports with nmap"
    required_tools = ["nmap"]

    def execute(self, ctx: RunContext) -> str:
        self._resolve_hosts(ctx)
        if not ctx.hosts:
            return "no in-scope IPs resolved; nothing to scan"

        targets = sorted({h.ip for h in ctx.hosts})
        xml_path = ctx.raw_dir / "nmap-portscan.xml"
        command = [
            ctx.settings.tool("nmap"),
            "-T4",
            "-Pn",
            "--top-ports",
            str(ctx.settings.nmap_top_ports),
            "-oX",
            str(xml_path),
            *targets,
        ]
        run(command, timeout=ctx.settings.timeout("nmap"))
        open_count = self._parse_nmap_xml(ctx, xml_path)
        return f"{open_count} open ports across {len(targets)} host(s)"

    def _resolve_hosts(self, ctx: RunContext) -> None:
        for hostname in ctx.all_hostnames():
            for ip in self._resolve(hostname):
                # A hostname may resolve to an address outside the engagement.
                if ctx.scope.in_scope(ip):
                    ctx.upsert_host(ip, hostname)

    @staticmethod
    def _resolve(hostname: str) -> set[str]:
        try:
            infos = socket.getaddrinfo(hostname, None)
        except OSError:
            return set()
        return {info[4][0] for info in infos}

    def _parse_nmap_xml(self, ctx: RunContext, xml_path) -> int:
        if not xml_path.exists():
            return 0
        tree = ET.parse(xml_path)
        open_count = 0
        for host_el in tree.findall("host"):
            addr_el = host_el.find("address[@addrtype='ipv4']") or host_el.find("address")
            if addr_el is None:
                continue
            ip = addr_el.get("addr", "")
            host = ctx.get_host(ip) or ctx.upsert_host(ip)
            for port_el in host_el.findall("ports/port"):
                state_el = port_el.find("state")
                if state_el is None or state_el.get("state") != "open":
                    continue
                number = int(port_el.get("portid", "0"))
                if host.get_port(number) is not None:
                    continue
                service_el = port_el.find("service")
                host.ports.append(
                    Port(
                        number=number,
                        protocol=port_el.get("protocol", "tcp"),
                        state="open",
                        service=service_el.get("name", "") if service_el is not None else "",
                    )
                )
                open_count += 1
        return open_count
