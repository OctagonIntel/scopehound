"""Phase 4 - HTTP probing.

Builds candidate URLs from the open web-ish ports found earlier, feeds them to
ProjectDiscovery's httpx over stdin, and records every live endpoint with its
status code, title, server banner and detected technologies.

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

    def _candidate_urls(self, ctx: RunContext) -> set[str]:
        web_ports = set(ctx.settings.web_ports)
        urls: set[str] = set()
        for host in ctx.hosts:
            names = host.hostnames or [host.ip]
            for port in host.ports:
                is_web = port.number in web_ports or "http" in port.service.lower()
                if not is_web:
                    continue
                scheme = "https" if port.number in (443, 8443) else "http"
                for name in names:
                    urls.add(f"{scheme}://{name}:{port.number}")
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
