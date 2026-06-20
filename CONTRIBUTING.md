# Contributing to scopehound

Thanks for your interest! scopehound is a recon-automation tool for
**authorized** security testing. Please keep contributions aligned with that
purpose — features that exist purely to evade detection, attack out-of-scope
systems, or otherwise enable abuse are out of scope for this project.

## Development setup

```bash
git clone https://github.com/OctagonIntel/scopehound
cd scopehound

python -m venv .venv
.venv\Scripts\activate          # Windows
# source .venv/bin/activate     # macOS / Linux

pip install -e ".[dev]"
```

## Before you push

```bash
ruff check .        # lint (and `ruff check --fix .` to auto-fix)
ruff format .       # format
pytest -q           # tests
```

CI runs the same `ruff` + `pytest` checks on Python 3.10–3.13. The test suite
intentionally needs **no external recon binaries**, so it stays fast and
hermetic; tests exercise the scope engine, config loading, and report
serialisation.

## Architecture in one minute

Each recon stage is a `Phase` subclass under `src/scopehound/phases/`. Phases
read from and write to a shared `RunContext` (`context.py`), so they stay
decoupled and can run independently or as a chained pipeline.

```
RunContext  ── shared state threaded through every phase
Phase (ABC) ── run(): handles timing, missing-tool skips, error capture
              execute(ctx): the actual work, implemented per phase
ToolRunner  ── single subprocess wrapper (timeouts, missing-binary detection)
Scope       ── gates every active action (out-of-scope always wins)
report.py   ── serialises RunContext to results.json + report.md
```

## Adding a new phase

1. Create `src/scopehound/phases/<name>.py` with a `Phase` subclass.
2. Set `name`, `description`, and `required_tools` (binaries it shells out to).
3. Implement `execute(self, ctx)` — read what earlier phases produced, do the
   work, mutate `ctx`, and return a short human-readable summary string.
4. Register the class in `ALL_PHASES` in `phases/__init__.py` (order matters —
   it defines pipeline order).
5. Add a test if the phase has parsing/logic that can be tested without the
   external tool (parse a fixture of real tool output, for example).

## Guidelines

- Keep external-tool invocation inside `runner.run()` so timeout and
  missing-binary handling stays consistent.
- Never let one phase crash the run — `Phase.run` already converts exceptions
  into an `error` result; don't swallow errors silently inside `execute`.
- Anything that touches a host must be reachable only for in-scope targets.
- Match the surrounding style: type hints, docstrings, `ruff`-clean.
