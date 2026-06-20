"""Command-line interface (Typer + Rich)."""

from __future__ import annotations

from pathlib import Path

import typer
from rich.console import Console
from rich.panel import Panel
from rich.table import Table

from scopehound import __version__
from scopehound.config import Settings
from scopehound.doctor import check_environment
from scopehound.phases import PHASE_NAMES
from scopehound.pipeline import build_context, run_pipeline
from scopehound.scope import Scope, ScopeError

app = typer.Typer(
    add_completion=False,
    help="Scope-aware recon automation for authorized web pentests.",
    no_args_is_help=True,
)
console = Console()

_BANNER = f"[bold cyan]scopehound[/] [dim]v{__version__}[/] - authorized-recon use only"

_STATUS_STYLE = {"ok": "green", "skipped": "yellow", "error": "red"}


@app.command()
def version() -> None:
    """Print the version and exit."""

    console.print(f"scopehound {__version__}")


@app.command()
def doctor(
    config: Path | None = typer.Option(None, "--config", help="Settings YAML file."),
) -> None:
    """Check which external tools are installed and ready."""

    settings = Settings.load(config)
    table = Table(title="scopehound environment", show_lines=False)
    table.add_column("Tool")
    table.add_column("Status")
    table.add_column("Path / note")

    all_ok = True
    for status in check_environment(settings):
        if status.installed:
            mark = "[green]ok[/]"
            detail = status.path or ""
        else:
            mark = "[red]missing[/]"
            detail = status.note or "not found on PATH"
            all_ok = False
        if status.note and status.installed:
            mark = "[yellow]warning[/]"
            detail = f"{status.path}  -  {status.note}"
            all_ok = False
        table.add_row(status.name, mark, detail)

    console.print(table)
    if all_ok:
        console.print("[green]All tools present.[/]")
    else:
        console.print(
            "[yellow]Some tools are missing or ambiguous.[/] Phases needing them "
            "will be skipped automatically."
        )


@app.command()
def run(
    target: str = typer.Argument(..., help="Target apex domain, e.g. example.com"),
    scope: Path | None = typer.Option(
        None, "--scope", "-s", help="Scope YAML file. If omitted, target + its subdomains."
    ),
    output: Path | None = typer.Option(
        None, "--output", "-o", help="Output directory (default: output/<target>-<timestamp>)."
    ),
    phases: list[str] | None = typer.Option(
        None, "--phase", "-p", help=f"Run only these phases. Choices: {', '.join(PHASE_NAMES)}"
    ),
    config: Path | None = typer.Option(None, "--config", help="Settings YAML file."),
    use_amass: bool = typer.Option(False, "--amass", help="Also run amass passive enum."),
) -> None:
    """Run the recon pipeline (or a subset of phases) against TARGET."""

    console.print(Panel(_BANNER, expand=False))

    # Resolve scope first - we refuse to do anything without one.
    try:
        scope_obj = Scope.from_file(scope) if scope else Scope.single_domain(target)
    except ScopeError as exc:
        console.print(f"[red]Scope error:[/] {exc}")
        raise typer.Exit(code=2) from exc

    if scope is None:
        console.print(
            f"[yellow]No scope file given[/] - defaulting to [bold]{target}[/] and its "
            "subdomains. Pass --scope for explicit in/out-of-scope control."
        )
    if not scope_obj.in_scope(target):
        console.print(f"[red]Refusing to run:[/] target {target!r} is not in scope.")
        raise typer.Exit(code=2)

    settings = Settings.load(config)
    if use_amass:
        settings.use_amass = True

    try:
        selected = phases or None
        if selected:
            unknown = set(selected) - set(PHASE_NAMES)
            if unknown:
                console.print(f"[red]Unknown phase(s):[/] {', '.join(sorted(unknown))}")
                raise typer.Exit(code=2)
    except typer.Exit:
        raise

    ctx = build_context(target, scope_obj, settings, output)
    console.print(f"Output: [bold]{ctx.output_dir}[/]\n")

    def _start(phase):
        console.print(f"[cyan]>[/] {phase.name}: {phase.description}")

    def _done(phase, result):
        style = _STATUS_STYLE.get(result.status, "white")
        console.print(f"  [{style}]{result.status}[/] - {result.detail}")

    run_pipeline(ctx, phases=selected, on_phase_start=_start, on_phase_done=_done)

    console.print()
    console.print(
        Panel.fit(
            f"[green]Done.[/]\n"
            f"JSON:     {ctx.output_dir / 'results.json'}\n"
            f"Markdown: {ctx.output_dir / 'report.md'}\n"
            f"HTML:     {ctx.output_dir / 'report.html'}",
            title="Reports",
        )
    )


def main() -> None:
    app()


if __name__ == "__main__":
    main()
