"""Passive wireless reconnaissance.

Enumerates the access points / BSSes in range using whatever standard Linux
wireless tooling is present (``nmcli`` first, then ``iw``). This is the same
scan your desktop does to populate its Wi-Fi list; it is read-only and sends
no frames of our own beyond the normal scan request.

The purpose in a segmentation engagement is to map the wireless surface:
which SSIDs exist, how they are secured, and which of them are in scope as
candidate footholds (guest vs. corporate vs. IoT networks that *should* be
isolated from one another).
"""

from __future__ import annotations

import re
from typing import List, Optional

from ..context import Context
from ..models import AccessPoint, Finding, ModuleResult, Severity
from ..utils import shell
from .base import Module, PASSIVE

_OPEN_HINTS = ("", "--", "open", "none")


class WirelessRecon(Module):
    name = "recon"
    phase = PASSIVE
    description = "Enumerate in-range access points and their security"

    def run(self, ctx: Context) -> ModuleResult:
        result = self.new_result()

        aps = self._scan_nmcli(ctx.interface)
        if aps is None:
            aps = self._scan_iw(ctx.interface)

        if aps is None:
            result.ok = False
            result.skipped_reason = "no supported scanner found (need 'nmcli' or 'iw' on PATH)"
            self.log.warning(result.skipped_reason)
            return result

        # Record and classify.
        for ap in aps:
            in_scope = ctx.scope.ssid_in_scope(ap.ssid) if ap.ssid else False
            ctx.access_points.append(ap)
            if ap.ssid and in_scope and self._is_open(ap.security):
                result.add(
                    Finding(
                        module=self.name,
                        title=f"Open (unencrypted) in-scope network: {ap.ssid}",
                        severity=Severity.MEDIUM,
                        description=(
                            "An in-scope SSID advertises no link-layer encryption. Traffic on "
                            "this network can be observed passively, and any client isolation is "
                            "the only thing separating associated stations."
                        ),
                        target=ap.ssid,
                        evidence=ap.to_dict(),
                        recommendation="Require WPA2/WPA3 and verify station isolation on open-style networks.",
                    )
                )

        result.data["access_points"] = [ap.to_dict() for ap in aps]
        result.data["count"] = len(aps)
        in_scope_ssids = sorted({ap.ssid for ap in aps if ap.ssid and ctx.scope.ssid_in_scope(ap.ssid)})
        result.data["in_scope_ssids"] = in_scope_ssids
        self.log.info("observed %d access points (%d in-scope SSIDs)", len(aps), len(in_scope_ssids))
        return result

    # ---- scanners -----------------------------------------------------
    def _scan_nmcli(self, interface: Optional[str]) -> Optional[List[AccessPoint]]:
        if not shell.tool_available("nmcli"):
            return None
        argv = ["nmcli", "-t", "-f", "SSID,BSSID,CHAN,FREQ,SIGNAL,SECURITY", "device", "wifi", "list"]
        if interface:
            argv += ["ifname", interface]
        res = shell.run(argv, timeout=20)
        if not res.ok:
            return None
        aps: List[AccessPoint] = []
        for line in res.stdout.splitlines():
            if not line.strip():
                continue
            # nmcli -t escapes ':' inside the BSSID as '\:' — split on unescaped ':'.
            fields = re.split(r"(?<!\\):", line)
            fields = [f.replace("\\:", ":") for f in fields]
            if len(fields) < 6:
                continue
            ssid, bssid, chan, freq, signal, security = fields[:6]
            aps.append(
                AccessPoint(
                    ssid=ssid,
                    bssid=bssid,
                    channel=_to_int(chan),
                    frequency_mhz=_to_int(freq.replace("MHz", "").strip()),
                    signal_dbm=_to_float(signal),
                    security=security.strip() or "open",
                )
            )
        return aps

    def _scan_iw(self, interface: Optional[str]) -> Optional[List[AccessPoint]]:
        if not shell.tool_available("iw") or not interface:
            return None
        res = shell.run(["iw", "dev", interface, "scan"], timeout=25)
        if not res.ok:
            return None
        return self.parse_iw_scan(res.stdout)

    # ---- parsing (pure, unit-tested) ---------------------------------
    @staticmethod
    def parse_iw_scan(output: str) -> List[AccessPoint]:
        """Parse the text output of ``iw dev <iface> scan`` into APs."""
        aps: List[AccessPoint] = []
        cur: Optional[dict] = None

        def flush() -> None:
            if cur and cur.get("bssid"):
                aps.append(
                    AccessPoint(
                        ssid=cur.get("ssid", ""),
                        bssid=cur["bssid"],
                        channel=cur.get("channel"),
                        frequency_mhz=cur.get("freq"),
                        signal_dbm=cur.get("signal"),
                        security=cur.get("security", "open"),
                    )
                )

        for raw in output.splitlines():
            line = raw.strip()
            m = re.match(r"BSS ([0-9a-fA-F:]{17})", line)
            if m:
                flush()
                cur = {"bssid": m.group(1).lower(), "security": "open"}
                continue
            if cur is None:
                continue
            if line.startswith("SSID:"):
                cur["ssid"] = line.split("SSID:", 1)[1].strip()
            elif line.startswith("freq:"):
                cur["freq"] = _to_int(line.split("freq:", 1)[1].strip())
            elif line.startswith("signal:"):
                cur["signal"] = _to_float(line.split("signal:", 1)[1].replace("dBm", "").strip())
            elif "DS Parameter set: channel" in line:
                cur["channel"] = _to_int(line.split("channel", 1)[1].strip())
            elif "RSN:" in line:
                cur["security"] = "WPA2"
            elif "WPA:" in line:
                cur["security"] = cur.get("security", "WPA")
        flush()
        return aps

    @staticmethod
    def _is_open(security: Optional[str]) -> bool:
        return (security or "").strip().lower() in _OPEN_HINTS


def _to_int(value: str) -> Optional[int]:
    try:
        return int(float(value))
    except (TypeError, ValueError):
        return None


def _to_float(value: str) -> Optional[float]:
    try:
        return float(value)
    except (TypeError, ValueError):
        return None
