"""Logging configuration for the CLI."""

from __future__ import annotations

import logging
import sys


def configure(verbosity: int = 0) -> None:
    """Configure root logging. ``verbosity`` 0=INFO-ish, 1=INFO, 2+=DEBUG."""
    if verbosity >= 2:
        level = logging.DEBUG
    elif verbosity == 1:
        level = logging.INFO
    else:
        level = logging.WARNING

    handler = logging.StreamHandler(sys.stderr)
    handler.setFormatter(logging.Formatter("%(asctime)s %(levelname)-7s %(name)s: %(message)s", "%H:%M:%S"))

    root = logging.getLogger()
    root.handlers.clear()
    root.addHandler(handler)
    root.setLevel(level)
