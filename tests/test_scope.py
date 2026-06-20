"""Tests for the scope engine - the safety-critical part of the tool."""

from __future__ import annotations

import pytest

from scopehound.scope import Scope, ScopeError


@pytest.fixture
def scope_file(tmp_path):
    path = tmp_path / "scope.yaml"
    path.write_text(
        """
in_scope:
  domains:
    - example.com
    - "*.example.com"
  ips:
    - 192.0.2.0/24
out_scope:
  domains:
    - admin.example.com
  ips:
    - 192.0.2.1
""",
        encoding="utf-8",
    )
    return path


def test_apex_and_subdomains_in_scope(scope_file):
    scope = Scope.from_file(scope_file)
    assert scope.in_scope("example.com")
    assert scope.in_scope("www.example.com")
    assert scope.in_scope("deep.sub.example.com")


def test_unrelated_domain_out_of_scope(scope_file):
    scope = Scope.from_file(scope_file)
    assert not scope.in_scope("notexample.com")
    assert not scope.in_scope("example.com.evil.com")


def test_out_of_scope_beats_in_scope(scope_file):
    scope = Scope.from_file(scope_file)
    # admin.example.com matches *.example.com but is explicitly excluded.
    assert not scope.in_scope("admin.example.com")


def test_ip_ranges(scope_file):
    scope = Scope.from_file(scope_file)
    assert scope.in_scope("192.0.2.50")
    assert not scope.in_scope("192.0.2.1")  # excluded gateway
    assert not scope.in_scope("198.51.100.10")  # different range


def test_wildcard_does_not_match_apex_only_pattern(tmp_path):
    path = tmp_path / "scope.yaml"
    path.write_text(
        'in_scope:\n  domains:\n    - "*.example.com"\n',
        encoding="utf-8",
    )
    scope = Scope.from_file(path)
    assert scope.in_scope("www.example.com")
    assert not scope.in_scope("example.com")  # apex not covered by wildcard alone


def test_single_domain_helper():
    scope = Scope.single_domain("example.com")
    assert scope.in_scope("example.com")
    assert scope.in_scope("api.example.com")
    assert not scope.in_scope("example.org")


def test_permits_resolved_ip_by_domain_association(scope_file):
    scope = Scope.from_file(scope_file)
    # An arbitrary IP an in-scope domain resolves to is permitted for scanning,
    # even though it matches no in-scope IP rule...
    assert scope.permits_resolved_ip("203.0.113.99")
    # ...unless it is explicitly excluded.
    assert not scope.permits_resolved_ip("192.0.2.1")


def test_single_domain_permits_its_resolved_ip():
    # Regression: with the default no-file scope, a domain target must still be
    # scannable at the IP it resolves to (the "no in-scope IPs resolved" bug).
    scope = Scope.single_domain("scanme.nmap.org")
    assert scope.permits_resolved_ip("45.33.32.156")


def test_filter_returns_only_in_scope(scope_file):
    scope = Scope.from_file(scope_file)
    targets = ["www.example.com", "admin.example.com", "evil.com"]
    assert scope.filter(targets) == ["www.example.com"]


def test_missing_file_raises():
    with pytest.raises(ScopeError):
        Scope.from_file("does-not-exist.yaml")


def test_empty_scope_raises(tmp_path):
    path = tmp_path / "scope.yaml"
    path.write_text("in_scope:\n  domains: []\n", encoding="utf-8")
    with pytest.raises(ScopeError):
        Scope.from_file(path)


def test_bad_cidr_raises(tmp_path):
    path = tmp_path / "scope.yaml"
    path.write_text("in_scope:\n  ips:\n    - not-an-ip\n", encoding="utf-8")
    with pytest.raises(ScopeError):
        Scope.from_file(path)
