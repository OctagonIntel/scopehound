"""Recon phases, in pipeline order.

``ALL_PHASES`` is the canonical ordered registry. The CLI uses it both to run
the full pipeline and to let an operator run any subset by name, while
preserving order so a subset still feeds forward correctly.
"""

from __future__ import annotations

from scopehound.phases.base import Phase
from scopehound.phases.fingerprint import FingerprintPhase
from scopehound.phases.httpprobe import HttpProbePhase
from scopehound.phases.portscan import PortScanPhase
from scopehound.phases.screenshots import ScreenshotPhase
from scopehound.phases.subdomains import SubdomainPhase

ALL_PHASES: list[type[Phase]] = [
    SubdomainPhase,
    PortScanPhase,
    FingerprintPhase,
    HttpProbePhase,
    ScreenshotPhase,
]

PHASE_NAMES: list[str] = [p.name for p in ALL_PHASES]


def get_phases(names: list[str] | None = None) -> list[Phase]:
    """Instantiate phases, optionally filtered to ``names`` (order preserved)."""

    if names is None:
        return [cls() for cls in ALL_PHASES]
    wanted = set(names)
    unknown = wanted - set(PHASE_NAMES)
    if unknown:
        raise ValueError(f"unknown phase(s): {', '.join(sorted(unknown))}")
    return [cls() for cls in ALL_PHASES if cls.name in wanted]
