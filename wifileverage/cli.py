"""Command-line interface for WiFiLeverage."""

from __future__ import annotations

import argparse
import sys
from typing import List, Optional

from . import logging_setup
from .modules import REGISTRY
from .report import Report
from .runner import PROFILES, Runner, resolve_modules
from .scope import Scope, ScopeError
from .version import __version__


def _parse_ports(value: str) -> List[int]:
    ports: List[int] = []
    for chunk in value.split(","):
        chunk = chunk.strip()
        if not chunk:
            continue
        if "-" in chunk:
            lo, hi = chunk.split("-", 1)
            ports.extend(range(int(lo), int(hi) + 1))
        else:
            ports.append(int(chunk))
    return sorted(set(ports))


def _load_scope(args) -> Scope:
    scope = Scope.load(args.scope) if getattr(args, "scope", None) else Scope.empty()
    return scope.merge_inline(
        include=getattr(args, "include", None),
        exclude=getattr(args, "exclude", None),
        ssids=getattr(args, "ssid", None),
    )


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="wifileverage",
        description="Authorized network-segmentation assessment for wireless engagements.",
    )
    p.add_argument("--version", action="version", version=f"WiFiLeverage {__version__}")
    p.add_argument("-v", "--verbose", action="count", default=0, help="-v for info, -vv for debug")
    sub = p.add_subparsers(dest="command", required=True)

    # ---- shared scope options ----
    def add_scope_opts(sp):
        sp.add_argument("-S", "--scope", help="Path to a scope file (YAML)")
        sp.add_argument("-i", "--include", action="append", metavar="CIDR", help="Add an in-scope CIDR (repeatable)")
        sp.add_argument("-x", "--exclude", action="append", metavar="CIDR", help="Add an out-of-scope CIDR (repeatable)")
        sp.add_argument("--ssid", action="append", metavar="SSID", help="Restrict to this SSID (repeatable)")

    # ---- run ----
    run = sub.add_parser("run", help="Run a segmentation assessment")
    add_scope_opts(run)
    run.add_argument("--iface", help="Wireless/network interface to assess")
    run.add_argument("--active", action="store_true", help="Enable active probing (reach/isolation). Off by default.")
    run.add_argument("-p", "--profile", choices=sorted(PROFILES), default="standard", help="Intensity profile")
    run.add_argument("--phases", help="Comma-separated phases: passive,active")
    run.add_argument("--only", help="Comma-separated module names (see 'modules')")
    run.add_argument("--ports", type=_parse_ports, default="22,80,443,445,3389,8080", help="TCP ports for connect probes")
    run.add_argument("--timeout", type=float, default=1.5, help="Per-probe timeout in seconds")
    run.add_argument("--host-limit", type=int, default=256, help="Max hosts to enumerate per target CIDR")
    run.add_argument("-o", "--output", default="reports", help="Directory for JSON/Markdown reports")
    run.add_argument("--no-save", action="store_true", help="Print to stdout only; do not write report files")
    run.set_defaults(func=cmd_run)

    # ---- scan ----
    scan = sub.add_parser("scan", help="Passive wireless recon only (list in-range APs)")
    add_scope_opts(scan)
    scan.add_argument("--iface", help="Wireless interface to scan")
    scan.set_defaults(func=cmd_scan)

    # ---- scope ----
    scope = sub.add_parser("scope", help="Load and display the effective scope without probing")
    add_scope_opts(scope)
    scope.set_defaults(func=cmd_scope)

    # ---- modules ----
    mods = sub.add_parser("modules", help="List available modules")
    mods.set_defaults(func=cmd_modules)

    return p


# ---- command handlers -------------------------------------------------
def cmd_run(args) -> int:
    scope = _load_scope(args)
    phases = args.phases.split(",") if args.phases else None
    only = args.only.split(",") if args.only else None
    modules = resolve_modules(profile=args.profile, phases=phases, only=only)
    if not modules:
        print("No modules selected.", file=sys.stderr)
        return 2

    ports = args.ports if isinstance(args.ports, list) else _parse_ports(str(args.ports))
    runner = Runner(
        scope=scope,
        interface=args.iface,
        active=args.active,
        port_list=ports,
        timeout=args.timeout,
        host_limit=args.host_limit,
    )
    report = runner.run(modules)
    _emit(report, args)
    # Exit non-zero if any HIGH/CRITICAL finding, useful in CI-style harnesses.
    counts = report.counts()
    return 1 if (counts["high"] or counts["critical"]) else 0


def cmd_scan(args) -> int:
    scope = _load_scope(args)
    modules = resolve_modules(only=["recon"])
    runner = Runner(scope=scope, interface=args.iface, active=False)
    report = runner.run(modules)
    print(report.to_markdown())
    return 0


def cmd_scope(args) -> int:
    scope = _load_scope(args)
    print(scope.summary())
    if scope.ssids:
        print("  SSIDs:")
        for s in scope.ssids:
            print(f"    - {s}")
    if scope.target_cidrs:
        print("  In scope:")
        for c in scope.target_cidrs:
            print(f"    + {c}")
    if scope.exclude_cidrs:
        print("  Excluded:")
        for c in scope.exclude_cidrs:
            print(f"    - {c}")
    return 0


def cmd_modules(args) -> int:
    print(f"{'NAME':<12} {'PHASE':<8} DESCRIPTION")
    for name in ["recon", "segment", "reach", "isolation"]:
        cls = REGISTRY[name]
        print(f"{cls.name:<12} {cls.phase:<8} {cls.description}")
    return 0


def _emit(report: Report, args) -> None:
    print(report.to_markdown())
    if not getattr(args, "no_save", False):
        paths = report.write(args.output)
        print(f"\nReports written:\n  {paths['markdown']}\n  {paths['json']}", file=sys.stderr)


def main(argv: Optional[List[str]] = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    logging_setup.configure(args.verbose)
    try:
        return args.func(args)
    except ScopeError as exc:
        print(f"scope error: {exc}", file=sys.stderr)
        return 2
    except KeyboardInterrupt:  # pragma: no cover
        print("\ninterrupted", file=sys.stderr)
        return 130


if __name__ == "__main__":  # pragma: no cover
    sys.exit(main())
