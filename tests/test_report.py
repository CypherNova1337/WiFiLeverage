import json

from wifileverage.models import Finding, ModuleResult, Severity
from wifileverage.report import Report
from wifileverage.scope import Scope


def _report():
    rep = Report(scope=Scope.from_dict({"engagement": "e", "client": "c"}), interface="wlan0", active=True)
    r = ModuleResult(module="reach")
    r.add(Finding(module="reach", title="High thing", severity=Severity.HIGH, description="d"))
    r.add(Finding(module="reach", title="Info thing", severity=Severity.INFO, description="d"))
    rep.add(r)
    return rep


def test_findings_sorted_by_severity():
    rep = _report()
    sev = [f.severity for f in rep.findings]
    assert sev == [Severity.HIGH, Severity.INFO]


def test_counts():
    rep = _report()
    c = rep.counts()
    assert c["high"] == 1
    assert c["info"] == 1
    assert c["critical"] == 0


def test_json_roundtrip():
    rep = _report()
    data = json.loads(rep.to_json())
    assert data["tool"] == "WiFiLeverage"
    assert data["summary"]["high"] == 1
    assert data["scope"]["engagement"] == "e"


def test_markdown_contains_findings():
    rep = _report()
    md = rep.to_markdown()
    assert "# WiFiLeverage assessment report" in md
    assert "High thing" in md
    assert "HIGH" in md


def test_write(tmp_path):
    rep = _report()
    paths = rep.write(tmp_path)
    assert (tmp_path / "wifileverage" ).exists() is False  # it writes files, not a dir of that name
    assert paths["json"].endswith(".json")
    assert paths["markdown"].endswith(".md")
