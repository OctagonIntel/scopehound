"""Environment diagnostics: what's installed, what's missing, what's ambiguous.

``scopehound doctor`` calls :func:`check_environment` and renders the result.
It also detects the classic httpx name collision (ProjectDiscovery's recon
tool vs the Python `httpx` library's CLI), which is easy to trip over.
"""

from __future__ import annotations

from dataclasses import dataclass

from scopehound.config import Settings
from scopehound.runner import find_binary, run


@dataclass
class ToolStatus:
    name: str
    binary: str
    path: str | None
    note: str = ""

    @property
    def installed(self) -> bool:
        return self.path is not None


def _looks_like_python_httpx(path: str) -> bool:
    """Heuristic: is this httpx the Python library CLI rather than PD httpx?"""

    lowered = path.lower()
    if "python" in lowered and "scripts" in lowered:
        return True
    if "site-packages" in lowered:
        return True
    try:
        result = run([path, "--version"], timeout=10)
        blob = (result.stdout + result.stderr).lower()
        # ProjectDiscovery httpx prints a "projectdiscovery" banner / version.
        if blob and "projectdiscovery" not in blob and "httpx" in blob:
            return True
    except Exception:  # noqa: BLE001 - diagnostics must never raise
        pass
    return False


def check_environment(settings: Settings | None = None) -> list[ToolStatus]:
    settings = settings or Settings()
    statuses: list[ToolStatus] = []

    for logical, binary in settings.tools.items():
        path = find_binary(binary)
        note = ""
        if logical == "httpx" and path and _looks_like_python_httpx(path):
            note = (
                "this looks like the Python 'httpx' library CLI, not "
                "ProjectDiscovery httpx - set tools.httpx to the right binary"
            )
        statuses.append(ToolStatus(name=logical, binary=binary, path=path, note=note))

    # Playwright is a Python dependency rather than a PATH binary.
    try:
        import playwright  # noqa: F401

        statuses.append(
            ToolStatus(name="playwright", binary="(python package)", path="installed")
        )
    except ImportError:
        statuses.append(
            ToolStatus(
                name="playwright",
                binary="(python package)",
                path=None,
                note="pip install playwright && playwright install chromium",
            )
        )

    return statuses
