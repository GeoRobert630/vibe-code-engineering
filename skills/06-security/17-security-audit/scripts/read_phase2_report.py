#!/usr/bin/env python3
"""Read a Phase 2 security-report.json and print the evidence the audit needs.

Read-only, standard library only. Used by skills/06-security/17-security-audit/SKILL.md
(Layer 1 -> Layer 2 hand-off). It never modifies the report or the target project.

    python read_phase2_report.py <report-dir-or-security-report.json> [--all-medium] [--json]

Exit codes: 0 report read, 3 report missing/unreadable/unsupported.
"""

from __future__ import annotations

import argparse
import json
import re
import sys
from pathlib import Path

SUPPORTED_SCHEMA = "1.0"
REQUIRED_FIELDS = {
    "id", "scanner", "category", "severity", "confidence", "title", "file", "line", "evidence",
    "recommendation", "validation", "status", "classification", "source",
}
ACTIVE = {"OPEN", "REQUIRES_REVIEW"}
ORDER = ["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFORMATIONAL"]
# Areas the static scanner cannot prove; the skill must cover them in Layers 2-3.
OUTSIDE_PHASE2 = [
    "authentication", "authorization", "IDOR/BOLA", "business logic", "tenant isolation (runtime)",
    "CSRF behaviour", "runtime security headers", "runtime cookies", "runtime CORS", "deployed application behaviour",
]
_CONTROL = re.compile(r"[\x00-\x08\x0b-\x1f\x7f]")


def clean(value: object, limit: int = 300) -> str:
    text = _CONTROL.sub("?", "" if value is None else str(value)).replace("\n", " ")
    return text if len(text) <= limit else text[: limit - 3] + "..."


def load(path: Path) -> dict:
    if path.is_dir():
        path = path / "security-report.json"
    data = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(data, dict):
        raise ValueError("report is not a JSON object")
    if data.get("schema_version") != SUPPORTED_SCHEMA:
        raise ValueError(f"unsupported schema_version {data.get('schema_version')!r} (expected {SUPPORTED_SCHEMA})")
    for key in ("findings", "summary", "release_status", "exit_code", "limitations", "tools", "scanners"):
        if key not in data:
            raise ValueError(f"report missing key {key!r}")
    for f in data["findings"]:
        if not isinstance(f, dict):
            raise ValueError("finding is not a JSON object")
        missing = REQUIRED_FIELDS - set(f)
        if missing:
            raise ValueError(f"finding {f.get('id')} missing fields {sorted(missing)}")
    return data


def build_summary(data: dict) -> dict:
    active = [f for f in data["findings"] if f["status"] in ACTIVE]
    by_sev = {s: [f for f in active if f["severity"] == s] for s in ORDER}
    by_class: dict[str, list[str]] = {}
    for f in active:
        by_class.setdefault(f["classification"], []).append(f["id"])
    failed_tools = [t["name"] for t in data["tools"] if t.get("failed")]
    failed_scanners = [s["name"] for s in data["scanners"] if s.get("status") == "failed"]
    return {
        "project": data.get("project", {}),
        "phase2_release_status": data["release_status"],
        "phase2_exit_code": data["exit_code"],
        "phase2_complete": not data["summary"].get("tool_failure") and not failed_scanners,
        "counts_active": data["summary"]["active_by_severity"],
        "blocking": [f["id"] for f in data["findings"] if f.get("blocking")],
        "critical_high": by_sev["CRITICAL"] + by_sev["HIGH"],
        "medium": by_sev["MEDIUM"],
        "by_classification": by_class,
        "baselined": [f["id"] for f in data["findings"] if f["status"] == "BASELINED"],
        "ignored": [f["id"] for f in data["findings"] if f["status"] == "IGNORED"],
        "tools_unavailable": [t["name"] for t in data["tools"] if not t.get("available")],
        "tools_failed": failed_tools,
        "scanners_failed": failed_scanners,
        "technologies": [t["name"] for t in data.get("technologies", [])],
        "limitations": data["limitations"],
        "outside_phase2": OUTSIDE_PHASE2,
    }


def _finding_line(f: dict) -> str:
    loc = f["file"] or "(repository-wide)"
    if f.get("line"):
        loc += f":{f['line']}"
    return (
        f"- {clean(f['id'])} [{f['severity']}/{f['confidence']}/{f['classification']}/{f['status']}]"
        f"{' BLOCKING' if f.get('blocking') else ''} {clean(f['title'])} @ {clean(loc)}\n"
        f"    evidence: {clean(f['evidence'])}\n"
        f"    source: {clean(', '.join(f['source']))} | cwe: {clean(f.get('cwe') or '-')}\n"
        f"    validate: {clean(f['validation'], 200)}"
    )


def render_text(s: dict, all_medium: bool) -> str:
    out = [
        "PHASE 2 AUTOMATED EVIDENCE (Layer 1)",
        f"project: {clean(s['project'].get('name'))} ({clean(s['project'].get('path'))}), files scanned: {s['project'].get('files_scanned')}",
        f"technologies: {', '.join(s['technologies']) or 'none detected'}",
        f"phase2 status: {s['phase2_release_status']} (exit {s['phase2_exit_code']}); scan complete: {'yes' if s['phase2_complete'] else 'NO - treat audit as incomplete'}",
        "active counts: " + ", ".join(f"{k}={v}" for k, v in s["counts_active"].items()),
        f"blocking: {len(s['blocking'])}  baselined: {len(s['baselined'])}  inline-ignored: {len(s['ignored'])}",
        f"tools unavailable: {', '.join(s['tools_unavailable']) or 'none'}; failed: {', '.join(s['tools_failed'] + s['scanners_failed']) or 'none'}",
        "",
        f"CRITICAL/HIGH - review every one ({len(s['critical_high'])}):",
    ]
    out += [_finding_line(f) for f in s["critical_high"]] or ["- none"]
    medium = s["medium"] if all_medium else s["medium"][:25]
    out += ["", f"MEDIUM ({len(s['medium'])}{'' if all_medium or len(s['medium']) <= 25 else ', first 25 shown; use --all-medium'}):"]
    out += [_finding_line(f) for f in medium] or ["- none"]
    out += ["", "BY SCANNER CLASSIFICATION (active findings):"]
    out += [f"- {k}: {len(v)}" for k, v in sorted(s["by_classification"].items())] or ["- none"]
    out += ["", "PHASE 2 LIMITATIONS (must appear in the audit report):"]
    out += [f"- {clean(x, 400)}" for x in s["limitations"]]
    out += ["", "NOT COVERED BY PHASE 2 - Layer 2/3 required:"] + [f"- {x}" for x in s["outside_phase2"]]
    return "\n".join(out)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("report", help="report directory or path to security-report.json")
    parser.add_argument("--all-medium", action="store_true", help="list every MEDIUM finding")
    parser.add_argument("--json", action="store_true", help="print the summary as JSON (full finding objects)")
    args = parser.parse_args(argv)
    try:
        summary = build_summary(load(Path(args.report)))
    except (OSError, ValueError) as exc:
        print(f"read_phase2_report: error: {clean(exc)}", file=sys.stderr)
        return 3
    except (KeyError, TypeError, AttributeError) as exc:
        print(f"read_phase2_report: error: malformed report ({exc.__class__.__name__})", file=sys.stderr)
        return 3
    if args.json:
        print(json.dumps(summary, indent=2))
    else:
        print(render_text(summary, args.all_medium))
    return 0


if __name__ == "__main__":
    sys.exit(main())
