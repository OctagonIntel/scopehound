"""Tests for report serialisation (no external tools required)."""

from __future__ import annotations

import json

from scopehound import report
from scopehound.config import Settings
from scopehound.context import RunContext
from scopehound.models import Host, HttpService, PhaseResult, Port, Subdomain
from scopehound.scope import Scope


def _ctx(tmp_path) -> RunContext:
    ctx = RunContext(
        target="example.com",
        output_dir=tmp_path,
        scope=Scope.single_domain("example.com"),
        settings=Settings(),
    )
    ctx.subdomains.append(Subdomain(host="www.example.com", sources=["subfinder"]))
    host = Host(ip="192.0.2.10", hostnames=["www.example.com"])
    host.ports.append(Port(number=443, service="https", product="nginx", version="1.25"))
    ctx.hosts.append(host)
    ctx.http_services.append(
        HttpService(
            url="https://www.example.com",
            status_code=200,
            title="Example",
            webserver="nginx",
            technologies=["nginx"],
        )
    )
    ctx.phase_results.append(
        PhaseResult(name="subdomains", status="ok", started_at="t0", finished_at="t1", detail="1")
    )
    return ctx


def test_to_dict_structure(tmp_path):
    data = report.to_dict(_ctx(tmp_path))
    assert data["manifest"]["target"] == "example.com"
    assert data["manifest"]["summary"]["http_services"] == 1
    assert data["hosts"][0]["ports"][0]["number"] == 443


def test_write_json_is_valid(tmp_path):
    path = report.write_json(_ctx(tmp_path))
    loaded = json.loads((tmp_path / "results.json").read_text(encoding="utf-8"))
    assert path.endswith("results.json")
    assert loaded["manifest"]["tool"] == "scopehound"


def test_write_markdown_contains_sections(tmp_path):
    report.write_markdown(_ctx(tmp_path))
    md = (tmp_path / "report.md").read_text(encoding="utf-8")
    assert "# Recon report - example.com" in md
    assert "## Hosts & open ports" in md
    assert "https://www.example.com" in md


def test_write_html_is_self_contained(tmp_path):
    path = report.write_html(_ctx(tmp_path))
    html_doc = (tmp_path / "report.html").read_text(encoding="utf-8")
    assert path.endswith("report.html")
    assert html_doc.startswith("<!doctype html>")
    # inline styles, no external asset references
    assert "<style>" in html_doc
    assert "https://www.example.com" in html_doc
    # screenshot referenced by relative path
    assert 'src="screenshots/' not in html_doc or "screenshots/" in html_doc


def test_write_all_emits_three_files(tmp_path):
    json_path, md_path, html_path = report.write_all(_ctx(tmp_path))
    assert (tmp_path / "results.json").exists()
    assert (tmp_path / "report.md").exists()
    assert (tmp_path / "report.html").exists()


def test_html_escapes_untrusted_fields(tmp_path):
    ctx = _ctx(tmp_path)
    ctx.http_services[0].title = '<script>alert(1)</script>'
    report.write_html(ctx)
    html_doc = (tmp_path / "report.html").read_text(encoding="utf-8")
    assert "<script>alert(1)</script>" not in html_doc
    assert "&lt;script&gt;" in html_doc
