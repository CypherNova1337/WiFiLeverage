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
        self.analysis: dict = {}

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
            "analysis": self.analysis,
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

        lines.extend(self._markdown_analysis())
        return "\n".join(lines)

    def _markdown_analysis(self) -> List[str]:
        a = self.analysis
        if not a:
            return []
        lines: List[str] = ["## Segmentation analysis", ""]
        lines.append(f"**Foothold zone:** `{a.get('foothold_zone', '-')}`")
        lines.append("")

        if a.get("matrix_ascii"):
            lines.append("### Policy matrix")
            lines.append("")
            lines.append("```")
            lines.append(a["matrix_ascii"])
            lines.append("```")
            lines.append("")

        if a.get("graph_mermaid"):
            lines.append("### Segmentation graph")
            lines.append("")
            lines.append("```mermaid")
            lines.append(a["graph_mermaid"])
            lines.append("```")
            lines.append("")

        paths = a.get("leverage_paths") or {}
        multi = [p for plist in paths.values() for p in plist if len(p) > 2]
        if multi:
            lines.append("### Multi-hop leverage paths")
            lines.append("")
            lines.append("Chains that cross a boundary via one or more pivots:")
            lines.append("")
            for p in multi:
                lines.append(f"- `{' → '.join(p)}`")
            lines.append("")
        return lines

    def to_html(self) -> str:
        """Self-contained HTML report with a live Mermaid segmentation graph."""
        a = self.analysis or {}
        c = self.counts()
        mermaid = a.get("graph_mermaid", "")
        rows = "".join(
            f"<tr><td>{_SEV_BADGE[s]}</td><td>{c[s.value]}</td></tr>" for s in _SEV_ORDER
        )
        finding_cards = []
        for f in self.findings:
            rec = f"<p class='rec'>Recommendation: {_esc(f.recommendation)}</p>" if f.recommendation else ""
            finding_cards.append(
                f"<div class='card sev-{f.severity.value}'>"
                f"<h3>{_esc(f.title)}</h3>"
                f"<p class='meta'>{f.severity.value.upper()} · {_esc(f.module)}"
                f"{(' · ' + _esc(f.target)) if f.target else ''}</p>"
                f"<p>{_esc(f.description)}</p>{rec}</div>"
            )
        matrix_html = f"<pre class='matrix'>{_esc(a.get('matrix_ascii') or '')}</pre>" if a.get("matrix_ascii") else ""
        eng = _esc(self.scope.engagement or "(unnamed engagement)")
        graph_block = (
            f"<div class='mermaid'>{mermaid}</div>" if mermaid else "<p>(no graph)</p>"
        )
        return _HTML_TEMPLATE.format(
            engagement=eng,
            mode="active" if self.active else "passive",
            iface=_esc(self.interface or "-"),
            generated=time.strftime("%Y-%m-%d %H:%M:%S", time.localtime(self.started)),
            rows=rows,
            matrix=matrix_html,
            graph=graph_block,
            findings="".join(finding_cards) or "<p>No findings recorded.</p>",
        )

    # ---- writing ------------------------------------------------------
    def write(self, out_dir: str | Path, html: bool = False) -> Dict[str, str]:
        out = Path(out_dir)
        out.mkdir(parents=True, exist_ok=True)
        stamp = time.strftime("%Y%m%d-%H%M%S", time.localtime(self.started))
        base = f"wifileverage-{stamp}"
        json_path = out / f"{base}.json"
        md_path = out / f"{base}.md"
        json_path.write_text(self.to_json())
        md_path.write_text(self.to_markdown())
        paths = {"json": str(json_path), "markdown": str(md_path)}
        if html:
            html_path = out / f"{base}.html"
            html_path.write_text(self.to_html())
            paths["html"] = str(html_path)
        return paths


def _esc(text) -> str:
    import html

    return html.escape(str(text if text is not None else ""))


_HTML_TEMPLATE = """<!doctype html>
<html lang="en"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>WiFiLeverage report</title>
<style>
 :root {{ --bg:#0d1117; --fg:#e6edf3; --muted:#8b949e; --card:#161b22; --line:#30363d; }}
 body {{ font-family: ui-sans-serif, system-ui, -apple-system, Segoe UI, Roboto, sans-serif;
   margin:0; background:var(--bg); color:var(--fg); }}
 header {{ padding:24px; border-bottom:1px solid var(--line); }}
 h1 {{ margin:0 0 4px; font-size:20px; }}
 .muted {{ color:var(--muted); font-size:13px; }}
 main {{ padding:24px; max-width:960px; margin:0 auto; }}
 table {{ border-collapse:collapse; }}
 td,th {{ padding:4px 12px; border:1px solid var(--line); }}
 .card {{ background:var(--card); border:1px solid var(--line); border-left:4px solid var(--muted);
   border-radius:8px; padding:12px 16px; margin:12px 0; }}
 .card h3 {{ margin:0 0 6px; font-size:15px; }}
 .card .meta {{ color:var(--muted); font-size:12px; margin:0 0 8px; }}
 .rec {{ color:#58a6ff; font-size:13px; }}
 .sev-critical {{ border-left-color:#f85149; }}
 .sev-high {{ border-left-color:#db6d28; }}
 .sev-medium {{ border-left-color:#d29922; }}
 .sev-low {{ border-left-color:#388bfd; }}
 .sev-info {{ border-left-color:#3fb950; }}
 pre.matrix {{ background:var(--card); padding:16px; border-radius:8px; overflow:auto; }}
 .mermaid {{ background:#fff; border-radius:8px; padding:16px; }}
</style></head>
<body>
<header>
 <h1>WiFiLeverage — {engagement}</h1>
 <div class="muted">{mode} mode · interface {iface} · generated {generated}</div>
</header>
<main>
 <h2>Summary</h2>
 <table><tr><th>Severity</th><th>Count</th></tr>{rows}</table>
 <h2>Segmentation matrix</h2>
 {matrix}
 <h2>Segmentation graph</h2>
 {graph}
 <h2>Findings</h2>
 {findings}
</main>
<script src="https://cdnjs.cloudflare.com/ajax/libs/mermaid/10.9.1/mermaid.min.js"></script>
<script>try {{ mermaid.initialize({{ startOnLoad:true }}); }} catch (e) {{}}</script>
</body></html>"""
