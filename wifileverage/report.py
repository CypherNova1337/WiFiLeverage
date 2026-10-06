"""Engagement reporting — JSON (machine) and Markdown (human)."""

from __future__ import annotations

import json
import time
from pathlib import Path
from typing import Dict, List

from .models import Finding, ModuleResult, Severity
from .scope import Scope
from .version import __version__

_SEV_ORDER = [Severity.CRITICAL, Severity.HIGH, Severity.MEDIUM, Severity.LOW, Severity.INFO]
_SEV_BADGE = {
    Severity.CRITICAL: "🟥 CRITICAL",
    Severity.HIGH: "🟧 HIGH",
    Severity.MEDIUM: "🟨 MEDIUM",
    Severity.LOW: "🟦 LOW",
    Severity.INFO: "⬜ INFO",
}


class Report:
    """Collects module results and renders them."""

    def __init__(self, scope: Scope, interface: str | None, active: bool) -> None:
        self.scope = scope
        self.interface = interface
        self.active = active
        self.started = time.time()
        self.results: List[ModuleResult] = []

    def add(self, result: ModuleResult) -> None:
        self.results.append(result)

    # ---- aggregation --------------------------------------------------
    @property
    def findings(self) -> List[Finding]:
        out: List[Finding] = []
        for r in self.results:
            out.extend(r.findings)
        return sorted(out, key=lambda f: f.severity.rank, reverse=True)

    def counts(self) -> Dict[str, int]:
        counts = {s.value: 0 for s in Severity}
        for f in self.findings:
            counts[f.severity.value] += 1
        return counts

    # ---- serialisation ------------------------------------------------
    def to_dict(self) -> dict:
        return {
            "tool": "WiFiLeverage",
            "version": __version__,
            "generated": time.strftime("%Y-%m-%dT%H:%M:%S%z", time.localtime(self.started)),
            "interface": self.interface,
            "active": self.active,
            "scope": {
                "engagement": self.scope.engagement,
                "client": self.scope.client,
                "ssids": self.scope.ssids,
                "target_cidrs": self.scope.target_cidrs,
                "exclude_cidrs": self.scope.exclude_cidrs,
            },
            "summary": self.counts(),
            "modules": [r.to_dict() for r in self.results],
        }

    def to_json(self, indent: int = 2) -> str:
        return json.dumps(self.to_dict(), indent=indent, sort_keys=False)

    def to_markdown(self) -> str:
        c = self.counts()
        lines: List[str] = []
        lines.append("# WiFiLeverage assessment report")
        lines.append("")
        eng = self.scope.engagement or "(unnamed engagement)"
        lines.append(f"**Engagement:** {eng}  ")
        if self.scope.client:
            lines.append(f"**Client:** {self.scope.client}  ")
        lines.append(f"**Interface:** {self.interface or '-'}  ")
        lines.append(f"**Mode:** {'active' if self.active else 'passive'}  ")
        lines.append(f"**Generated:** {time.strftime('%Y-%m-%d %H:%M:%S', time.localtime(self.started))}")
        lines.append("")
        lines.append("## Summary")
        lines.append("")
        lines.append("| Severity | Count |")
        lines.append("|---|---|")
        for s in _SEV_ORDER:
            lines.append(f"| {_SEV_BADGE[s]} | {c[s.value]} |")
        lines.append("")
        lines.append("## Findings")
        lines.append("")
        findings = self.findings
        if not findings:
            lines.append("_No findings recorded._")
        for i, f in enumerate(findings, 1):
            lines.append(f"### {i}. {f.title}")
            lines.append("")
            lines.append(f"- **Severity:** {_SEV_BADGE[f.severity]}")
            lines.append(f"- **Module:** `{f.module}`")
            if f.target:
                lines.append(f"- **Target:** `{f.target}`")
            lines.append("")
            lines.append(f.description)
            if f.recommendation:
                lines.append("")
                lines.append(f"> **Recommendation:** {f.recommendation}")
            lines.append("")
        return "\n".join(lines)

    # ---- writing ------------------------------------------------------
    def write(self, out_dir: str | Path) -> Dict[str, str]:
        out = Path(out_dir)
        out.mkdir(parents=True, exist_ok=True)
        stamp = time.strftime("%Y%m%d-%H%M%S", time.localtime(self.started))
        base = f"wifileverage-{stamp}"
        json_path = out / f"{base}.json"
        md_path = out / f"{base}.md"
        json_path.write_text(self.to_json())
        md_path.write_text(self.to_markdown())
        return {"json": str(json_path), "markdown": str(md_path)}
