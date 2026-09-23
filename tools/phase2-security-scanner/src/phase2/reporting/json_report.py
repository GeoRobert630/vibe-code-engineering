"""Machine-readable report (security-report.json)."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from ..models import Severity, Status
from ..orchestrator import ScanReport, reported_findings, tool_info
from ..severity import count_by_severity, is_blocking

SCHEMA_VERSION = "1.0"


def build(report: ScanReport, min_severity: Severity = Severity.INFORMATIONAL) -> dict[str, Any]:
    shown = reported_findings(report, min_severity)
    by_status: dict[str, int] = {s.value: 0 for s in Status}
    for f in report.findings:
        by_status[f.status.value] += 1
    return {
        "schema_version": SCHEMA_VERSION,
        "tool": tool_info(),
        "generated_at": report.generated_at,
        "project": report.project,
        "configuration": report.configuration,
        "technologies": [t.to_dict() for t in report.technologies],
        "scanners": report.scanners,
        "tools": [t.to_dict() for t in report.tools],
        "summary": {
            "active_by_severity": report.counts,
            "all_by_severity": count_by_severity(report.findings, active_only=False),
            "by_status": by_status,
            "total": len(report.findings),
            "reported": len(shown),
            "blocking": len(report.blocking),
            "tool_failure": report.tool_failure,
        },
        "release_status": report.release_status,
        "exit_code": report.exit_code,
        "findings": [f.to_dict() | {"blocking": is_blocking(f)} for f in shown],
        "baseline": report.baseline,
        "limitations": report.limitations,
    }


def write(report: ScanReport, output_dir: Path, min_severity: Severity = Severity.INFORMATIONAL) -> Path:
    output_dir.mkdir(parents=True, exist_ok=True)
    path = output_dir / "security-report.json"
    path.write_text(json.dumps(build(report, min_severity), indent=2, ensure_ascii=False) + "\n", encoding="utf-8")
    return path
