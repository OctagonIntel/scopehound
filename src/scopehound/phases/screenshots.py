"""Phase 5 - screenshot capture.

Drives a headless Chromium via Playwright to capture a screenshot of every
live HTTP service found in the probe phase. Playwright is imported lazily so
the rest of scopehound works (and ``doctor`` can report) even when it isn't
installed yet. If it's missing, this phase reports itself as skipped rather
than erroring.
"""

from __future__ import annotations

import re

from scopehound.context import RunContext
from scopehound.phases.base import Phase


def _playwright_available() -> bool:
    try:
        import playwright.sync_api  # noqa: F401

        return True
    except ImportError:
        return False


def _safe_name(url: str) -> str:
    return re.sub(r"[^A-Za-z0-9._-]+", "_", url).strip("_")


class ScreenshotPhase(Phase):
    name = "screenshots"
    description = "Capture screenshots of live hosts (Playwright/Chromium)"
    required_tools: list[str] = []  # Playwright is a Python dep, checked below

    def missing_tools(self, ctx: RunContext) -> list[str]:
        return [] if _playwright_available() else ["playwright"]

    def execute(self, ctx: RunContext) -> str:
        from playwright.sync_api import sync_playwright

        services = [s for s in ctx.http_services if s.url]
        if not services:
            return "no live HTTP services to screenshot"

        captured = 0
        failed = 0
        with sync_playwright() as pw:
            browser = pw.chromium.launch(headless=True)
            context = browser.new_context(ignore_https_errors=True)
            try:
                for service in services:
                    filename = f"{_safe_name(service.url)}.png"
                    out_path = ctx.screenshot_dir / filename
                    if self._capture(context, service.url, out_path, ctx):
                        service.screenshot = f"screenshots/{filename}"
                        captured += 1
                    else:
                        failed += 1
            finally:
                browser.close()

        return f"captured {captured} screenshot(s), {failed} failed"

    def _capture(self, browser_context, url, out_path, ctx: RunContext) -> bool:
        page = browser_context.new_page()
        try:
            page.goto(
                url,
                timeout=ctx.settings.screenshot_timeout_ms,
                wait_until="domcontentloaded",
            )
            page.screenshot(path=str(out_path), full_page=False)
            return True
        except Exception:  # noqa: BLE001 - a dead/slow host shouldn't stop the run
            return False
        finally:
            page.close()
