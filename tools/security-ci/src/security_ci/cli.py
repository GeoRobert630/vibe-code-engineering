"""security-ci CLI.

    security-ci sarif --phase2 REPORT --phase3 REPORT [--ai FILE] --sarif OUT.sarif [--runtime-anchor PATH]
    security-ci gate  --phase2 REPORT --phase3 REPORT [--ai FILE] [--fail-on release|critical|high|medium|low]
                      [--allow-incomplete] [--sarif OUT.sarif]

Reads existing JSON reports only; never runs scanners and never changes their exit codes.
"""

from __future__ import annotations

import argparse
import sys
from pathlib import Path

from . import TOOL_NAME, __version__
from . import gate as gate_mod
from . import sarif as sarif_mod
from .inputs import InputError, load_all
from .redaction import clean


class _Parser(argparse.ArgumentParser):
    def error(self, message: str) -> None:  # type: ignore[override]
        self.print_usage(sys.stderr)
        print(f"{self.prog}: error: {message}", file=sys.stderr)
        raise SystemExit(gate_mod.EXIT_ERROR)


def _common(p: argparse.ArgumentParser) -> None:
    p.add_argument("--phase2", type=Path, help="Phase 2 security-report.json")
    p.add_argument("--phase3", type=Path, help="Phase 3 runtime-security-report.json")
    p.add_argument("--ai", type=Path, help="AI review findings JSON (see README)")
    p.add_argument("--runtime-anchor", help="repository-relative file used as the physical location of runtime findings")


def main(argv: list[str] | None = None) -> int:
    p = _Parser(prog="security-ci", description="SARIF export and CI gate for existing security reports.")
    p.add_argument("--version", action="version", version=f"{TOOL_NAME} {__version__}")
    sub = p.add_subparsers(dest="command", required=True, parser_class=_Parser)
    s = sub.add_parser("sarif", help="write a SARIF 2.1.0 file")
    _common(s)
    s.add_argument("--sarif", type=Path, required=True, help="output .sarif path")
    g = sub.add_parser("gate", help="evaluate an explicit CI policy (exit 0 pass, 1 fail, 3 error)")
    _common(g)
    g.add_argument("--fail-on", choices=gate_mod.POLICIES, default="release")
    g.add_argument("--allow-incomplete", action="store_true", help="do not fail when a scan was incomplete or refused")
    g.add_argument("--sarif", type=Path, help="optionally also write SARIF")
    args = p.parse_args(argv)

    if args.runtime_anchor and (args.runtime_anchor.startswith(("/", "\\")) or ":" in args.runtime_anchor or ".." in args.runtime_anchor):
        print("security-ci: error: --runtime-anchor must be a repository-relative path", file=sys.stderr)
        return gate_mod.EXIT_ERROR
    try:
        bundle = load_all(args.phase2, args.phase3, args.ai)
    except InputError as exc:
        print(f"security-ci: error: {clean(str(exc))}", file=sys.stderr)
        return gate_mod.EXIT_ERROR

    if args.sarif:
        path = sarif_mod.write(bundle, args.sarif, args.runtime_anchor)
        print(f"SARIF: {path} ({len(bundle.findings)} results, {len(bundle.duplicates)} deduplicated)")
    if args.command == "sarif":
        for area, status in sorted(bundle.verification.items()):
            print(f"{area}: {status}")
        return 0
    result = gate_mod.evaluate(bundle, args.fail_on, args.allow_incomplete)
    print(gate_mod.render(result))
    return result.exit_code


if __name__ == "__main__":
    sys.exit(main())
