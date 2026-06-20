"""Scope enforcement.

This is the ethical heart of the tool. Nothing active happens against a host
until it has been cleared by :class:`Scope`. The rule is simple and matches how
real engagement scopes are written: an explicit out-of-scope rule always beats
an in-scope rule, so you can authorise a broad range and then carve out the
hosts the client told you to leave alone.
"""

from __future__ import annotations

import ipaddress
from dataclasses import dataclass, field
from pathlib import Path

import yaml


class ScopeError(Exception):
    """Raised when a scope file is missing or malformed."""


def _looks_like_ip(value: str) -> bool:
    try:
        ipaddress.ip_address(value)
        return True
    except ValueError:
        return False


def _domain_matches(host: str, pattern: str) -> bool:
    """Match a hostname against a domain pattern.

    ``example.com`` matches only that host. ``*.example.com`` matches any
    subdomain but not the apex (list the apex separately if you want both).
    """

    host = host.lower().rstrip(".")
    pattern = pattern.lower().rstrip(".")
    if pattern.startswith("*."):
        suffix = pattern[1:]  # ".example.com"
        return host.endswith(suffix) and host != suffix.lstrip(".")
    return host == pattern


@dataclass
class _RuleSet:
    """One side (in or out) of the scope: domain patterns + IP networks."""

    domains: list[str] = field(default_factory=list)
    networks: list[ipaddress._BaseNetwork] = field(default_factory=list)

    def matches(self, target: str) -> bool:
        if _looks_like_ip(target):
            addr = ipaddress.ip_address(target)
            return any(addr in net for net in self.networks)
        return any(_domain_matches(target, pat) for pat in self.domains)


def _build_ruleset(raw: dict | None) -> _RuleSet:
    raw = raw or {}
    domains = [str(d).strip() for d in (raw.get("domains") or [])]
    networks: list[ipaddress._BaseNetwork] = []
    for entry in raw.get("ips") or []:
        try:
            networks.append(ipaddress.ip_network(str(entry).strip(), strict=False))
        except ValueError as exc:
            raise ScopeError(f"invalid IP/CIDR in scope: {entry!r} ({exc})") from exc
    return _RuleSet(domains=domains, networks=networks)


class Scope:
    """Decides whether a domain or IP is authorised for active testing."""

    def __init__(self, in_scope: _RuleSet, out_scope: _RuleSet) -> None:
        self._in = in_scope
        self._out = out_scope

    @classmethod
    def from_file(cls, path: str | Path) -> Scope:
        path = Path(path)
        if not path.exists():
            raise ScopeError(f"scope file not found: {path}")
        try:
            data = yaml.safe_load(path.read_text(encoding="utf-8")) or {}
        except yaml.YAMLError as exc:
            raise ScopeError(f"could not parse scope file {path}: {exc}") from exc
        if not isinstance(data, dict):
            raise ScopeError(f"scope file {path} must be a YAML mapping")
        in_set = _build_ruleset(data.get("in_scope"))
        out_set = _build_ruleset(data.get("out_scope"))
        if not in_set.domains and not in_set.networks:
            raise ScopeError("scope file defines no in-scope domains or IPs")
        return cls(in_set, out_set)

    @classmethod
    def single_domain(cls, domain: str) -> Scope:
        """Convenience scope: a domain and all its subdomains, no exclusions.

        Used when the operator passes a target but no scope file. We still
        force every host through the same gate rather than scanning blindly.
        """

        in_set = _RuleSet(domains=[domain, f"*.{domain}"])
        return cls(in_set, _RuleSet())

    def in_scope(self, target: str) -> bool:
        """True only if ``target`` is in-scope and not explicitly excluded."""

        if self._out.matches(target):
            return False
        return self._in.matches(target)

    def filter(self, targets: list[str]) -> list[str]:
        return [t for t in targets if self.in_scope(t)]
