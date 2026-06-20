"""Phase 1 - subdomain enumeration.

Runs subfinder (always) and optionally amass in passive mode, merges and
de-duplicates the hostnames, drops anything out of scope, and records the
result on the context. Out-of-scope filtering happens here so that no later
phase ever sees a host it shouldn't touch.
"""

from __future__ import annotations

from scopehound.context import RunContext
from scopehound.models import Subdomain
from scopehound.phases.base import Phase
from scopehound.runner import run


class SubdomainPhase(Phase):
    name = "subdomains"
    description = "Passive subdomain enumeration (subfinder, optional amass)"
    required_tools = ["subfinder"]

    def execute(self, ctx: RunContext) -> str:
        found: dict[str, set[str]] = {}

        for host in self._run_subfinder(ctx):
            found.setdefault(host, set()).add("subfinder")

        if ctx.settings.use_amass:
            for host in self._run_amass(ctx):
                found.setdefault(host, set()).add("amass")

        # Always include the apex target itself as a candidate.
        found.setdefault(ctx.target, set()).add("seed")

        kept = 0
        dropped = 0
        for host, sources in sorted(found.items()):
            if not ctx.scope.in_scope(host):
                dropped += 1
                continue
            ctx.subdomains.append(Subdomain(host=host, sources=sorted(sources)))
            kept += 1

        return f"{kept} in-scope subdomains ({dropped} out-of-scope dropped)"

    def _run_subfinder(self, ctx: RunContext) -> list[str]:
        result = run(
            [ctx.settings.tool("subfinder"), "-d", ctx.target, "-silent"],
            timeout=ctx.settings.timeout("subfinder"),
        )
        (ctx.raw_dir / "subfinder.txt").write_text(result.stdout, encoding="utf-8")
        return [line.strip() for line in result.stdout.splitlines() if line.strip()]

    def _run_amass(self, ctx: RunContext) -> list[str]:
        result = run(
            [ctx.settings.tool("amass"), "enum", "-passive", "-d", ctx.target, "-silent"],
            timeout=ctx.settings.timeout("amass"),
        )
        (ctx.raw_dir / "amass.txt").write_text(result.stdout, encoding="utf-8")
        return [line.strip() for line in result.stdout.splitlines() if line.strip()]
