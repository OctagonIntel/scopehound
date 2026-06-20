"""Tests for HTTP-probe candidate-URL construction (no httpx needed)."""

from __future__ import annotations

from scopehound.config import Settings
from scopehound.context import RunContext
from scopehound.models import Host, Port, Subdomain
from scopehound.phases.httpprobe import HttpProbePhase
from scopehound.scope import Scope


def _ctx(tmp_path) -> RunContext:
    return RunContext(
        target="example.com",
        output_dir=tmp_path,
        scope=Scope.single_domain("example.com"),
        settings=Settings(),
    )


def test_direct_probe_without_portscan(tmp_path):
    # No hosts/ports (port scan didn't run or was filtered): the target and
    # in-scope subdomains must still be probed on both schemes.
    ctx = _ctx(tmp_path)
    ctx.subdomains.append(Subdomain(host="api.example.com"))
    urls = HttpProbePhase()._candidate_urls(ctx)
    assert "http://example.com" in urls
    assert "https://example.com" in urls
    assert "https://api.example.com" in urls


def test_portscan_ports_included_and_deduped(tmp_path):
    ctx = _ctx(tmp_path)
    host = Host(ip="93.184.216.34", hostnames=["example.com"])
    host.ports = [Port(number=80, service="http"), Port(number=8080, service="http")]
    ctx.hosts.append(host)
    urls = HttpProbePhase()._candidate_urls(ctx)
    assert "http://example.com" in urls  # port 80 normalized (no :80)
    assert "http://example.com:8080" in urls  # non-standard port kept
    assert "http://example.com:80" not in urls  # not duplicated


def test_out_of_scope_hostname_not_probed(tmp_path):
    ctx = _ctx(tmp_path)
    ctx.subdomains.append(Subdomain(host="evil.com"))
    urls = HttpProbePhase()._candidate_urls(ctx)
    assert not any("evil.com" in u for u in urls)
