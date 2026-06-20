"""Phase contract shared by every recon stage."""

from __future__ import annotations

from abc import ABC, abstractmethod
from datetime import datetime, timezone

from scopehound.context import RunContext
from scopehound.models import PhaseResult
from scopehound.runner import find_binary


def _now() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


class Phase(ABC):
    """Base class for a single, independently-runnable recon phase.

    Subclasses set :attr:`name` / :attr:`description`, declare which external
    binaries they need in :attr:`required_tools`, and implement :meth:`execute`.
    The :meth:`run` wrapper handles timing, missing-tool skips, and turning
    exceptions into an ``error`` result so one bad phase can't crash the run.
    """

    name: str = "phase"
    description: str = ""
    required_tools: list[str] = []

    def missing_tools(self, ctx: RunContext) -> list[str]:
        """Required tools that are not resolvable on PATH."""

        return [t for t in self.required_tools if find_binary(ctx.settings.tool(t)) is None]

    @abstractmethod
    def execute(self, ctx: RunContext) -> str:
        """Do the work, mutating ``ctx``. Return a short human summary."""

    def run(self, ctx: RunContext) -> PhaseResult:
        started = _now()
        missing = self.missing_tools(ctx)
        if missing:
            result = PhaseResult(
                name=self.name,
                status="skipped",
                started_at=started,
                finished_at=_now(),
                detail=f"missing tool(s): {', '.join(missing)}",
            )
            ctx.phase_results.append(result)
            return result
        try:
            detail = self.execute(ctx)
            status = "ok"
        except Exception as exc:  # noqa: BLE001 - one phase must not kill the run
            detail = f"{type(exc).__name__}: {exc}"
            status = "error"
        result = PhaseResult(
            name=self.name,
            status=status,
            started_at=started,
            finished_at=_now(),
            detail=detail,
        )
        ctx.phase_results.append(result)
        return result
