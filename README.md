# scopehound

**Scope-aware recon automation for authorized web penetration testing engagements.**

scopehound chains the standard recon phases into one repeatable pipeline —
subdomain enumeration → port scanning → service fingerprinting → HTTP probing →
screenshot capture — and emits structured output (`results.json`) plus a
human-readable `report.md`. Each phase feeds the next automatically, but any
phase can also be run on its own.

The defining feature is **scope enforcement**: every host is checked against an
explicit in/out-of-scope policy *before* any active action. Out-of-scope rules
always win, so you can authorize a broad range and carve out exclusions.

> ⚠️ **Authorized use only.** Only run scopehound against systems you have
> explicit, written permission to test. You are responsible for staying within
> your engagement scope and the law.

---

## How it works

```
            ┌─────────────┐
  target ──▶│ scope gate  │◀── scope.yaml (in/out of scope)
            └──────┬──────┘
                   ▼
  subdomains ─▶ portscan ─▶ fingerprint ─▶ httpprobe ─▶ screenshots
   (subfinder)   (nmap)      (nmap -sV)      (httpx)     (Playwright)
                   │
                   ▼
        results.json  +  report.md  (+ raw/ tool output, screenshots/)
```

| Phase | Tool | What it does |
| --- | --- | --- |
| `subdomains` | subfinder (+ optional amass) | Passive subdomain enumeration, scope-filtered |
| `portscan` | nmap | Resolves hosts to IPs, re-checks scope, scans top ports |
| `fingerprint` | nmap `-sV` | Version detection on the open ports only |
| `httpprobe` | ProjectDiscovery **httpx** | Finds live HTTP(S) services, titles, tech, status |
| `screenshots` | Playwright (Chromium) | Captures a screenshot of every live host |

## Install

scopehound is Python (3.10+). The recon binaries are external and wrapped via
subprocess — install whichever phases you need; missing tools cause that phase
to be **skipped**, not fail.

```bash
# 1. The Python package
python -m venv .venv
.venv\Scripts\activate          # Windows
# source .venv/bin/activate     # macOS/Linux
pip install -e .

# 2. Screenshot engine (Playwright Chromium)
playwright install chromium

# 3. External recon tools (pick your platform's method)
#    subfinder, httpx:  https://github.com/projectdiscovery
#    nmap:              https://nmap.org/download
#    amass (optional):  https://github.com/owasp-amass/amass
```

Check what's wired up:

```bash
scopehound doctor
```

> **httpx name collision:** the Python `httpx` HTTP library also ships a CLI
> called `httpx`. scopehound wants *ProjectDiscovery's* httpx. `doctor` detects
> the collision and warns you; point it at the right binary with a config file
> (`tools.httpx: /path/to/pd-httpx`).

## Usage

```bash
# Full pipeline against a single target (target + its subdomains in scope)
scopehound run example.com

# With an explicit engagement scope file (recommended)
scopehound run example.com --scope scope.yaml -o ./engagement-output

# Run only specific phases (still feed forward in order)
scopehound run example.com -p subdomains -p portscan

# Include amass passive enumeration
scopehound run example.com --amass
```

### Scope file

See [`scope.example.yaml`](scope.example.yaml). Out-of-scope always beats
in-scope:

```yaml
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
```

If you omit `--scope`, scopehound defaults to the target and its subdomains and
tells you it did so — it never scans without a scope gate in place.

## Output

```
output/example.com-20260620-101500/
├── results.json        # full structured run state (source of truth)
├── report.md           # human-readable summary with embedded screenshots
├── raw/                # raw tool output (subfinder.txt, nmap XML, httpx.jsonl)
└── screenshots/        # one PNG per live host
```

## Configuration (optional)

Override binary paths, timeouts and ports with `--config settings.yaml`:

```yaml
tools:
  httpx: /opt/pd/httpx        # disambiguate from the Python httpx CLI
timeouts:
  nmap: 3600
nmap_top_ports: 2000
web_ports: [80, 443, 8080, 8443]
use_amass: true
screenshot_timeout_ms: 20000
```

## Development

```bash
pip install -e ".[dev]"
pytest                  # logic tests (scope/config/report) need no external tools
ruff check .
```

The architecture is intentionally modular: each phase is a `Phase` subclass in
[`src/scopehound/phases/`](src/scopehound/phases) that reads from and writes to
a shared `RunContext`. Adding a phase is: subclass `Phase`, implement
`execute()`, register it in `phases/__init__.py`.

## License

MIT — see [LICENSE](LICENSE).
