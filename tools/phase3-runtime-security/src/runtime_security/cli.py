"""CLI: runtime-security --config runtime-security.yaml [--output DIR] [--format json|markdown|both]

The safety gate (Target / Environment / Production flag) is printed before any
request. Production targets are refused; this slice has no override.
"""

from __future__ import annotations

import argparse
import sys
from pathlib import Path

from . import TOOL_NAME, __version__
from .config import ConfigError, load
from .models import SEVERITY_ORDER
from .reporting import json_report, markdown_report
from .runner import run_all
from .utils import safety
from .utils.redaction import clean

EXIT_FAILURE = 3


class _Parser(argparse.ArgumentParser):
    def error(self, message: str) -> None:  # type: ignore[override]
        self.print_usage(sys.stderr)
        print(f"{self.prog}: error: {message}", file=sys.stderr)
        raise SystemExit(EXIT_FAILURE)


def main(argv: list[str] | None = None) -> int:
    p = _Parser(prog="runtime-security", description="Read-only runtime security checks for local/staging targets.",
                epilog="Exit codes: 0 clean, 1 non-blocking findings, 2 blocking findings, 3 refused/config error/incomplete.")
    p.add_argument("--config", required=True, help="runtime-security.yaml")
    p.add_argument("--output", default="reports", help="report directory (default ./reports)")
    p.add_argument("--format", choices=["json", "markdown", "both"], default="both")
    p.add_argument("--verbose", action="store_true")
    p.add_argument("--version", action="version", version=f"{TOOL_NAME} {__version__}")
    args = p.parse_args(argv)

    try:
        cfg = load(Path(args.config))
    except ConfigError as exc:
        print(f"runtime-security: config error: {clean(str(exc))}", file=sys.stderr)
        return EXIT_FAILURE

    print("=== Safety gate ===")
    print(safety.gate_text(cfg))
    decision = safety.evaluate(cfg)
    if not decision.allowed:
        print(f"STOP: {decision.reason}. No requests were sent.")
    else:
        print(f"Allowed: {decision.reason}")
    print()

    out = Path(args.output)
    report = run_all(cfg, zap_output_dir=out / "zap")
    written = []
    try:
        if args.format in ("json", "both"):
            written.append(json_report.write(report, out))
        if args.format in ("markdown", "both"):
            written.append(markdown_report.write(report, out))
    except OSError as exc:
        print(f"runtime-security: cannot write reports: {exc.__class__.__name__}", file=sys.stderr)
        return EXIT_FAILURE

    if not report.refused:
        for run in report.runs:
            state = "disabled" if not run.enabled else (f"ERROR ({run.error})" if run.error else f"{len(run.findings)} finding(s)")
            print(f"[{run.name}] {state}")
        print()
        for sev in SEVERITY_ORDER:
            print(f"{sev.value.title()}: {report.counts[sev.value]}")
        print(f"Blocking: {len(report.blocking)}")
        if args.verbose:
            for f in report.findings:
                print(clean(f"  {f.id} [{f.severity.value}/{f.confidence.value}] {f.title} @ {f.endpoint}", 300))
    zb = report.zap_baseline or {}
    if zb.get("enabled"):
        state = "executed" if zb.get("executed") else "not executed"
        print(f"ZAP baseline (passive): {state} - {clean(str(zb.get('reason', '')))}; exit code {zb.get('exit_code')}")
    for path in written:
        print(f"Report: {path}")
    print(f"Result: {report.summary}")
    return report.exit_code


if __name__ == "__main__":
    sys.exit(main())
