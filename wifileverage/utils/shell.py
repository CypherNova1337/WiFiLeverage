"""Thin, safe wrapper around external command execution.

External wireless/network tooling (``ip``, ``iw``, ``nmcli`` ...) is invoked
here so that the rest of the codebase never touches ``subprocess`` directly.
All commands are passed as argument *lists* (never a shell string) to avoid
shell-injection, and every invocation is logged.
"""

from __future__ import annotations

import logging
import shutil
import subprocess
from dataclasses import dataclass
from typing import List, Optional, Sequence

log = logging.getLogger(__name__)


@dataclass
class CommandResult:
    """Outcome of an external command."""

    argv: List[str]
    returncode: int
    stdout: str
    stderr: str
    available: bool = True

    @property
    def ok(self) -> bool:
        return self.available and self.returncode == 0


def tool_available(name: str) -> bool:
    """Return ``True`` if *name* is on ``PATH``."""
    return shutil.which(name) is not None


def run(
    argv: Sequence[str],
    timeout: float = 30.0,
    check: bool = False,
) -> CommandResult:
    """Run *argv* and capture its output.

    The command is never executed through a shell. If the binary is missing,
    a ``CommandResult`` with ``available=False`` is returned instead of
    raising, so modules can degrade gracefully on hosts that lack a tool.
    """
    argv = [str(a) for a in argv]
    binary = argv[0]

    if not tool_available(binary):
        log.debug("tool unavailable: %s", binary)
        return CommandResult(argv=argv, returncode=127, stdout="", stderr=f"{binary}: not found", available=False)

    log.debug("exec: %s", " ".join(argv))
    try:
        proc = subprocess.run(
            argv,
            capture_output=True,
            text=True,
            timeout=timeout,
        )
    except subprocess.TimeoutExpired as exc:
        log.warning("command timed out after %ss: %s", timeout, " ".join(argv))
        return CommandResult(argv=argv, returncode=124, stdout=exc.stdout or "", stderr="timeout", available=True)

    result = CommandResult(
        argv=argv,
        returncode=proc.returncode,
        stdout=proc.stdout or "",
        stderr=proc.stderr or "",
    )
    if check and not result.ok:
        raise RuntimeError(f"command failed ({result.returncode}): {' '.join(argv)}\n{result.stderr}")
    return result


def first_available(*names: str) -> Optional[str]:
    """Return the first tool in *names* present on ``PATH``, else ``None``."""
    for name in names:
        if tool_available(name):
            return name
    return None
