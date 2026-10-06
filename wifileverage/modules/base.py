"""Base class and phase constants for assessment modules."""

from __future__ import annotations

import abc
import logging

from ..context import Context
from ..models import ModuleResult

PASSIVE = "passive"
ACTIVE = "active"


class Module(abc.ABC):
    """A unit of assessment work.

    Subclasses set :attr:`name`, :attr:`phase` and :attr:`description`, and
    implement :meth:`run`. Modules in the ``ACTIVE`` phase send packets to
    targets and only execute when the engagement was started with
    ``active=True``; ``PASSIVE`` modules only observe the local host and the
    airwaves.
    """

    name: str = "module"
    phase: str = PASSIVE
    description: str = ""

    def __init__(self) -> None:
        self.log = logging.getLogger(f"wifileverage.{self.name}")

    @property
    def is_active(self) -> bool:
        return self.phase == ACTIVE

    def new_result(self) -> ModuleResult:
        return ModuleResult(module=self.name)

    @abc.abstractmethod
    def run(self, ctx: Context) -> ModuleResult:  # pragma: no cover - interface
        """Perform the work and return a result."""
        raise NotImplementedError
