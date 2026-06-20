"""Phase 4 - HTTP probing.

Builds candidate URLs two ways - from the web-ish ports found by the port-scan
phase, and by probing every in-scope hostname directly on the standard web
ports (80/443) - then feeds them to ProjectDiscovery's httpx over stdin and
records every live endpoint with its status code, title, server banner and
detected technologies.

The direct-probe path means HTTP analysis still works when no port scan ran
(``-p httpprobe``) or when the scan was filtered - common for hardened and
cloud-hosted targets, where a raw port scan is dropped but the site answers
normal HTTP requests fine.

Note the binary name collision: ``httpx`` is also the Python HTTP library's
CLI. We always invoke the configured binary (default ``httpx``) and
``scopehound doctor`` warns if PATH resolves to the Python one instead.
"""

from __future__ import annotations

import json

from scopehound.context import RunContext
from scopehound.models import HttpService
from scopehound.phases.base import Phase
from scopehound.runner import run


class HttpProbePhase(Phase):
    name = "httpprobe"
    description = "Probe live HTTP(S) services with httpx"
    required_tools = ["httpx"]

    def execute(self, ctx: RunContext) -> str:
        urls = self._candidate_urls(ctx)
        if not urls:
            return "no candidate web URLs to probe"

        command = [
            ctx.settings.tool("httpx"),
            "-json",
            "-silent",
            "-title",
            "-status-code",
            "-tech-detect",
            "-web-server",
            "-content-length",
            "-no-color",
        ]
        result = run(
            command,
            timeout=ctx.settings.timeout("httpx"),
            stdin="\n".join(sorted(urls)),
        )
        (ctx.raw_dir / "httpx.jsonl").write_text(result.stdout, encoding="utf-8")
        live = self._parse(ctx, result.stdout)
        return f"{live} live HTTP service(s) from {len(urls)} candidate URL(s)"

    @staticmethod
    def _format_url(scheme: str, host: str, port: int) -> str:
        # Drop the port for scheme defaults so direct and port-scan-derived
        # URLs for the same endpoint de-duplicate cleanly.
        if (scheme, port) in (("http", 80), ("https", 443)):
            return f"{scheme}://{host}"
        return f"{scheme}://{host}:{port}"

    def _candidate_urls(self, ctx: RunContext) -> set[str]:
        web_ports = set(ctx.settings.web_ports)
        urls: set[str] = set()

        # (a) Web-ish ports discovered by the port-scan phase (also covers
        #     non-standard ports like 8080/8443).
        for host in ctx.hosts:
            names = host.hostnames or [host.ip]
            for port in host.ports:
                is_web = port.number in web_ports or "http" in port.service.lower()
                if not is_web:
                    continue
                scheme = "https" if port.number in (443, 8443) else "http"
                for name in names:
                    urls.add(self._format_url(scheme, name, port.number))

        # (b) Direct probe of in-scope hostnames on the standard web ports, so
        #     HTTP analysis works even with no (or a filtered) port scan.
        for hostname in ctx.all_hostnames():
            if not ctx.scope.in_scope(hostname):
                continue
            urls.add(f"http://{hostname}")
            urls.add(f"https://{hostname}")

        return urls

    def _parse(self, ctx: RunContext, stdout: str) -> int:
        count = 0
        for line in stdout.splitlines():
            line = line.strip()
            if not line:
                continue
            try:
                record = json.loads(line)
            except json.JSONDecodeError:
                continue
            ctx.http_services.append(
                HttpService(
                    url=record.get("url", ""),
                    status_code=record.get("status_code"),
                    title=record.get("title", ""),
                    webserver=record.get("webserver", ""),
                    technologies=record.get("tech", []) or record.get("technologies", []),
                    content_length=record.get("content_length"),
                )
            )
            count += 1
        return count
