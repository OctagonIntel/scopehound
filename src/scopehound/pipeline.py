"""Pipeline orchestration: build the run context and execute phases in order."""

from __future__ import annotations

from datetime import datetime, timezone
from pathlib import Path

from scopehound import report
from scopehound.config import Settings
from scopehound.context import RunContext
from scopehound.models import PhaseResult
from scopehound.phases import get_phases
from scopehound.scope import Scope


def _default_output_dir(target: str) -> Path:
    stamp = datetime.now(timezone.utc).strftime("%Y%m%d-%H%M%S")
    safe = target.replace("/", "_").replace(":", "_")
    return Path("output") / f"{safe}-{stamp}"


def build_context(
    target: str,
    scope: Scope,
    settings: Settings,
    output_dir: str | Path | None = None,
) -> RunContext:
    out = Path(output_dir) if output_dir else _default_output_dir(target)
    out.mkdir(parents=True, exist_ok=True)
    return RunContext(target=target, output_dir=out, scope=scope, settings=settings)


def run_pipeline(
    ctx: RunContext,
    phases: list[str] | None = None,
    on_phase_start=None,
    on_phase_done=None,
) -> RunContext:
    """Run the selected phases in canonical order, then write reports.

    ``on_phase_start`` / ``on_phase_done`` are optional callbacks for UI
    feedback; they receive the phase instance and (for done) its result.
    """

    for phase in get_phases(phases):
        if on_phase_start:
            on_phase_start(phase)
        result: PhaseResult = phase.run(ctx)
        if on_phase_done:
            on_phase_done(phase, result)

    report.write_all(ctx)
    return ctx
