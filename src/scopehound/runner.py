"""Thin, well-behaved wrapper around external command-line tools.

Every phase that shells out goes through here so we get consistent timeout
handling, missing-binary detection, and captured output in one place.
"""

from __future__ import annotations

import shutil
import subprocess
import time
from dataclasses import dataclass


class ToolNotFoundError(Exception):
    """Raised when a required binary is not on PATH."""


@dataclass
class CommandResult:
    command: list[str]
    returncode: int
    stdout: str
    stderr: str
    duration: float

    @property
    def ok(self) -> bool:
        return self.returncode == 0


def find_binary(name: str) -> str | None:
    """Return the resolved path of ``name`` on PATH, or None."""

    return shutil.which(name)


def run(
    command: list[str],
    *,
    timeout: int = 300,
    stdin: str | None = None,
    check: bool = False,
) -> CommandResult:
    """Run ``command`` and capture its output.

    Raises :class:`ToolNotFoundError` if the binary is missing, and propagates
    :class:`subprocess.TimeoutExpired` so callers can mark a phase as errored
    rather than hanging the whole pipeline.
    """

    binary = find_binary(command[0])
    if binary is None:
        raise ToolNotFoundError(command[0])

    start = time.monotonic()
    proc = subprocess.run(
        command,
        input=stdin,
        capture_output=True,
        text=True,
        timeout=timeout,
        check=False,
    )
    duration = time.monotonic() - start

    result = CommandResult(
        command=command,
        returncode=proc.returncode,
        stdout=proc.stdout or "",
        stderr=proc.stderr or "",
        duration=duration,
    )
    if check and not result.ok:
        raise subprocess.CalledProcessError(
            result.returncode, command, result.stdout, result.stderr
        )
    return result
