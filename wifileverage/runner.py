"""Engagement orchestration: select modules, run them, build the report."""

from __future__ import annotations

import logging
from typing import List, Optional

from .analysis.assemble import assemble
from .analysis.policy import PolicyMatrix, Observation
from .context import Context
from .models import Finding, ModuleResult, Severity
from .modules import REGISTRY
from .modules.base import ACTIVE, Module
from .report import Report
from .scope import Scope

log = logging.getLogger(__name__)

# Named intensity profiles -> ordered module names.
PROFILES = {
    "passive": ["recon", "segment"],
    "standard": ["recon", "segment", "reach"],
    "deep": ["recon", "segment", "reach", "isolation"],
}

# Phase -> module names (for --phases).
PHASES = {
    "passive": ["recon", "segment"],
    "active": ["reach", "isolation"],
}


def resolve_modules(
    profile: str = "standard",
    phases: Optional[List[str]] = None,
    only: Optional[List[str]] = None,
) -> List[Module]:
    """Resolve the ordered list of module instances to run."""
    if only:
        names = [n for n in only if n in REGISTRY]
    elif phases:
        names = []
        for ph in phases:
            names.extend(PHASES.get(ph, []))
    else:
        names = PROFILES.get(profile, PROFILES["standard"])

    # Preserve canonical order and de-duplicate.
    canonical = ["recon", "segment", "reach", "isolation"]
    chosen = [n for n in canonical if n in names]
    return [REGISTRY[n]() for n in chosen]


class Runner:
    def __init__(
        self,
        scope: Scope,
        interface: Optional[str] = None,
        active: bool = False,
        port_list: Optional[List[int]] = None,
        timeout: float = 1.5,
        host_limit: int = 256,
        workers: int = 64,
    ) -> None:
        self.ctx = Context(
            scope=scope,
            interface=interface,
            active=active,
            timeout=timeout,
            host_limit=host_limit,
            workers=workers,
        )
        if port_list:
            self.ctx.port_list = port_list
        self.report = Report(scope=scope, interface=interface, active=active)

    def run(self, modules: List[Module]) -> Report:
        active_requested = any(m.phase == ACTIVE for m in modules)
        if active_requested and not self.ctx.active:
            log.warning(
                "active modules selected but --active not set; they will be skipped. "
                "Pass --active to send probes to in-scope targets."
            )
        for module in modules:
            log.info("[%s] %s", module.name, module.description)
            try:
                result = module.run(self.ctx)
            except Exception as exc:  # keep one bad module from killing the run
                log.exception("module %s crashed: %s", module.name, exc)
                result = module.new_result()
                result.ok = False
                result.skipped_reason = f"module error: {exc}"
            if result.skipped_reason:
                log.info("[%s] skipped: %s", module.name, result.skipped_reason)
            self.report.add(result)

        self._analyse()
        return self.report

    def _analyse(self) -> None:
        """Build the segmentation graph / policy matrix from module output."""
        segment = self.ctx.current_segment
        analysis = assemble(self.ctx.scope, self.report.results, segment)
        self.report.analysis = analysis

        # Surface policy violations as first-class CRITICAL findings.
        if analysis.get("policy_findings"):
            pol = ModuleResult(module="policy")
            for raw in analysis["policy_findings"]:
                pol.add(
                    Finding(
                        module="policy",
                        title=raw["title"],
                        severity=Severity(raw["severity"]),
                        description=raw["description"],
                        target=raw.get("target"),
                        evidence=raw.get("evidence", {}),
                        recommendation=raw.get("recommendation"),
                    )
                )
            pol.data = {"matrix": analysis.get("matrix")}
            self.report.add(pol)
            if analysis.get("matrix"):
                log.info("policy matrix evaluated: %d violation(s)", analysis["matrix"]["violations"])
