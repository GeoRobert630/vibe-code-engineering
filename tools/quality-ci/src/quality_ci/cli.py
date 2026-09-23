"""quality-ci CLI.

    quality-ci a11y  [--config quality-ci.yaml] --output DIR [--format json|markdown|both] [--sarif OUT.sarif] [--anchor PATH]
    quality-ci sarif --report accessibility-report.json --sarif OUT.sarif [--anchor PATH]
    quality-ci gate  --report accessibility-report.json [--fail-on release|critical|high|medium|low]
                     [--allow-incomplete] [--require-configured]

``a11y`` without ``--config`` writes a NOT CONFIGURED report (nothing is scanned).
a11y exit codes: 0 no active findings, 1 non-blocking findings, 2 blocking findings, 3 refused/incomplete/config error.
gate exit codes: 0 pass, 1 fail, 3 input/usage error.
"""

from __future__ import annotations

import argparse
import sys
from pathlib import Path

from . import TOOL_NAME, __version__
from . import gate as gate_mod
from . import reporting
from . import sarif as sarif_mod
from .config import ConfigError, load
from .redaction import clean
from .runner import EXIT_ERROR, not_configured, run


class _Parser(argparse.ArgumentParser):
    def error(self, message: str) -> None:  # type: ignore[override]
        self.print_usage(sys.stderr)
        print(f"{self.prog}: error: {message}", file=sys.stderr)
        raise SystemExit(EXIT_ERROR)


def _anchor_ok(anchor: str | None) -> bool:
    return not anchor or not (anchor.startswith(("/", "\\")) or ":" in anchor or ".." in anchor)


def main(argv: list[str] | None = None, engine_factory=None) -> int:
    p = _Parser(prog="quality-ci", description="Quality CI: accessibility scan (axe-core), SARIF export and gate.")
    p.add_argument("--version", action="version", version=f"{TOOL_NAME} {__version__}")
    sub = p.add_subparsers(dest="command", required=True, parser_class=_Parser)
    a = sub.add_parser("a11y", help="scan the configured pages")
    a.add_argument("--config", type=Path)
    a.add_argument("--output", type=Path, required=True)
    a.add_argument("--format", choices=("json", "markdown", "both"), default="both")
    a.add_argument("--sarif", type=Path)
    a.add_argument("--anchor", help="repository-relative file used as SARIF physical location")
    s = sub.add_parser("sarif", help="write SARIF 2.1.0 from an accessibility report")
    s.add_argument("--report", type=Path, required=True)
    s.add_argument("--sarif", type=Path, required=True)
    s.add_argument("--anchor")
    g = sub.add_parser("gate", help="evaluate a CI policy (exit 0 pass, 1 fail, 3 error)")
    g.add_argument("--report", type=Path, required=True)
    g.add_argument("--fail-on", choices=gate_mod.POLICIES, default="release")
    g.add_argument("--allow-incomplete", action="store_true")
    g.add_argument("--require-configured", action="store_true")
    args = p.parse_args(argv)

    if not _anchor_ok(getattr(args, "anchor", None)):
        print("quality-ci: error: --anchor must be a repository-relative path", file=sys.stderr)
        return EXIT_ERROR

    if args.command == "a11y":
        if args.config is None:
            report = not_configured()
        else:
            try:
                cfg = load(args.config)
            except ConfigError as exc:
                print(f"quality-ci: configuration error: {clean(str(exc))}", file=sys.stderr)
                return EXIT_ERROR
            report = run(cfg, engine_factory) if engine_factory else run(cfg)
        if args.format in ("json", "both"):
            reporting.write_json(report, args.output)
        if args.format in ("markdown", "both"):
            reporting.write_markdown(report, args.output)
        data = reporting.build(report)
        if args.sarif:
            sarif_mod.write(data, args.sarif, args.anchor)
        s_ = data["summary"]
        print(f"Accessibility: {data['run']['verdict']} (run {data['run']['status']}) - pages {s_['pages_scanned']}/"
              f"{s_['pages_configured']}, rules {s_['rules_evaluated']}, findings {s_['findings']} "
              f"({s_['blocking']} blocking), needs review {s_['needs_review']}")
        print("Not proof of full WCAG compliance.")
        return report.exit_code

    try:
        data = reporting.load(args.report)
    except ValueError as exc:
        print(f"quality-ci: error: {clean(str(exc))}", file=sys.stderr)
        return EXIT_ERROR
    if args.command == "sarif":
        path = sarif_mod.write(data, args.sarif, args.anchor)
        print(f"SARIF: {path} ({len(data['findings'])} results)")
        return 0
    result = gate_mod.evaluate(data, args.fail_on, args.allow_incomplete, args.require_configured)
    print(gate_mod.render(result))
    return result.exit_code


if __name__ == "__main__":
    sys.exit(main())
