"""Command-line interface.

    python -m phase2.cli --project PATH [--format json|markdown|both] ...
    phase2-scan PATH

Exit codes: 0 no blocking findings / nothing actionable, 1 non-blocking findings,
2 Critical/High (blocking) findings, 3 scanner/tool failure or usage error.
Usage errors deliberately exit 3 (argparse's default of 2 would be confused
with "blocking findings").
"""

from __future__ import annotations

import argparse
import sys
from pathlib import Path

from . import TOOL_NAME, __version__
from .baseline.manager import BaselineError
from .models import Severity
from .orchestrator import ConfigError, ScanOptions, run_scan
from .reporting import json_report, markdown_report
from .severity import EXIT_FAILURE, SEVERITY_ORDER, parse_severity
from .utils.redaction import strip_control


class _Parser(argparse.ArgumentParser):
    def error(self, message: str) -> None:  # type: ignore[override]
        self.print_usage(sys.stderr)
        print(f"{self.prog}: error: {message}", file=sys.stderr)
        raise SystemExit(EXIT_FAILURE)


def build_parser() -> argparse.ArgumentParser:
    p = _Parser(
        prog="phase2-scan",
        description="Read-only static security scanner (secrets, dangerous code, dependencies, configuration, Git).",
        epilog="Exit codes: 0 clean, 1 non-blocking findings, 2 Critical/High findings, 3 scanner/tool failure.",
    )
    p.add_argument("path", nargs="?", help="project directory (alternative to --project)")
    p.add_argument("--project", help="project directory to scan")
    p.add_argument("--output", default="reports", help="directory for security-report.json/.md (default: ./reports)")
    p.add_argument("--format", choices=["json", "markdown", "both"], default="both")
    p.add_argument("--baseline", help="path to security-baseline.json (read; written only with --update-baseline)")
    p.add_argument("--update-baseline", action="store_true", help="write current non-critical findings to --baseline")
    p.add_argument("--severity", default="informational", type=str.lower,
                   choices=[s.value.lower() for s in SEVERITY_ORDER] + ["info"],
                   help="minimum severity included in reports (does not change counts or exit code)")
    p.add_argument("--config", help="optional scanner config YAML (never auto-loaded from the target project)")
    p.add_argument("--git-history-depth", type=int, default=100, help="recent commits to scan for secrets (0 disables)")
    p.add_argument("--no-external-tools", action="store_true", help="do not run gitleaks/npm/pnpm/pip-audit/cargo-audit/govulncheck")
    p.add_argument("--verbose", action="store_true", help="print findings and scanner errors to the console")
    p.add_argument("--version", action="version", version=f"{TOOL_NAME} {__version__}")
    return p


def _print_findings(report, min_severity: Severity) -> None:
    from .orchestrator import reported_findings

    for f in reported_findings(report, min_severity):
        loc = f"{f.file}:{f.line}" if f.file and f.line else (f.file or "-")
        print(strip_control(f"  [{f.severity.value}/{f.confidence.value}/{f.status.value}] {f.title} @ {loc}"))


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    project = args.project or args.path
    if not project:
        print("phase2-scan: error: a project path is required (--project PATH or positional PATH)", file=sys.stderr)
        return EXIT_FAILURE
    if args.update_baseline and not args.baseline:
        print("phase2-scan: error: --update-baseline requires --baseline PATH", file=sys.stderr)
        return EXIT_FAILURE
    if args.git_history_depth < 0:
        print("phase2-scan: error: --git-history-depth must be >= 0", file=sys.stderr)
        return EXIT_FAILURE

    min_sev = parse_severity(args.severity)
    output = Path(args.output).resolve()
    opts = ScanOptions(
        project=Path(project),
        use_external_tools=not args.no_external_tools,
        baseline_path=Path(args.baseline) if args.baseline else None,
        update_baseline=args.update_baseline,
        min_severity=min_sev,
        config_path=Path(args.config) if args.config else None,
        output_dir=output,
        verbose=args.verbose,
        git_history_depth=args.git_history_depth,
        progress=lambda msg: print(msg, flush=True),
    )
    try:
        report = run_scan(opts)
    except (ConfigError, BaselineError) as exc:
        print(f"phase2-scan: error: {strip_control(str(exc))}", file=sys.stderr)
        return EXIT_FAILURE
    except KeyboardInterrupt:
        return EXIT_FAILURE
    except Exception as exc:  # noqa: BLE001 - never exit 0/1/2 on an internal crash
        print(f"phase2-scan: internal error: {exc.__class__.__name__}", file=sys.stderr)
        return EXIT_FAILURE

    written = []
    try:
        if args.format in ("json", "both"):
            written.append(json_report.write(report, output, min_sev))
        if args.format in ("markdown", "both"):
            written.append(markdown_report.write(report, output, min_sev))
    except OSError as exc:
        print(f"phase2-scan: error: cannot write reports: {exc.__class__.__name__}", file=sys.stderr)
        return EXIT_FAILURE

    counts = report.counts
    print()
    for sev in SEVERITY_ORDER:
        label = "Informational" if sev == Severity.INFORMATIONAL else sev.value.title()
        print(f"{label}: {counts[sev.value]}")
    print(f"Blocking: {len(report.blocking)}")
    failed = [t.name for t in report.tools if t.failed] + [s["name"] for s in report.scanners if s["status"] == "failed" and s["errors"]]
    if failed:
        print("Tool/scanner failures: " + ", ".join(sorted(set(failed))))
    if args.verbose:
        print()
        _print_findings(report, min_sev)
    print()
    for path in written:
        print(f"Report: {path}")
    if report.baseline and report.baseline.get("updated"):
        print(f"Baseline written: {args.baseline}")
    print(f"Status: {report.release_status}")
    return report.exit_code


if __name__ == "__main__":
    sys.exit(main())
