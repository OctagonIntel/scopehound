"""Phase 3 - service fingerprinting.

Takes the open ports discovered by the port-scan phase and runs nmap's version
detection (``-sV``) against exactly those ports, enriching each
:class:`~scopehound.models.Port` with service / product / version detail.
Scanning only known-open ports keeps this fast and quiet.
"""

from __future__ import annotations

import xml.etree.ElementTree as ET

from scopehound.context import RunContext
from scopehound.phases.base import Phase
from scopehound.runner import run


class FingerprintPhase(Phase):
    name = "fingerprint"
    description = "Service/version detection on open ports (nmap -sV)"
    required_tools = ["nmap"]

    def execute(self, ctx: RunContext) -> str:
        hosts_with_ports = [h for h in ctx.hosts if h.ports]
        if not hosts_with_ports:
            return "no open ports to fingerprint"

        enriched = 0
        for host in hosts_with_ports:
            port_list = ",".join(str(p.number) for p in host.ports)
            xml_path = ctx.raw_dir / f"nmap-version-{host.ip.replace(':', '_')}.xml"
            command = [
                ctx.settings.tool("nmap"),
                "-sV",
                "-Pn",
                "-p",
                port_list,
                "-oX",
                str(xml_path),
                host.ip,
            ]
            run(command, timeout=ctx.settings.timeout("nmap"))
            enriched += self._apply_versions(ctx, host.ip, xml_path)

        return f"fingerprinted {enriched} service(s)"

    def _apply_versions(self, ctx: RunContext, ip: str, xml_path) -> int:
        if not xml_path.exists():
            return 0
        host = ctx.get_host(ip)
        if host is None:
            return 0
        tree = ET.parse(xml_path)
        count = 0
        for port_el in tree.findall(".//port"):
            number = int(port_el.get("portid", "0"))
            port = host.get_port(number)
            service_el = port_el.find("service")
            if port is None or service_el is None:
                continue
            port.service = service_el.get("name", port.service)
            port.product = service_el.get("product", "")
            port.version = service_el.get("version", "")
            count += 1
        return count
