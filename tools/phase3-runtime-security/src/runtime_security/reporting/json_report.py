"""runtime-security-report.json"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from .. import TOOL_NAME, __version__
from ..auth.status import auth_area_status, auth_config_summary, report_zap
from ..authz.status import authz_area_status
from ..models import Outcome
from ..runner import LIMITATIONS, RunReport, is_blocking

SCHEMA_VERSION = "1.0"


def build(report: RunReport) -> dict[str, Any]:
    cfg = report.cfg
    return {
        "schema_version": SCHEMA_VERSION,
        "tool": {"name": TOOL_NAME, "version": __version__},
        "generated_at": report.generated_at,
        "target": {"base_url": cfg.base_url, "http_url": cfg.http_url},
        "environment": {"name": cfg.environment, "production": cfg.production, "authorized_by": cfg.authorized_by or None},
        "safety": {"allowed": not report.refused, "reason": report.safety_reason},
        "requests_sent": report.requests_sent,
        "checks": [
            {
                "name": r.name,
                "enabled": r.enabled,
                "status": "disabled" if not r.enabled else ("error" if r.error else "completed"),
                "error": r.error,
                "results": [x.to_dict() for x in r.results],
            }
            for r in report.runs
        ],
        "summary": {
            "result": report.summary,
            "findings_by_severity": report.counts,
            "blocking": len(report.blocking),
            "passed": len(report.results(Outcome.PASSED)),
            "failed": len(report.results(Outcome.FAILED)),
            "not_verified": len(report.results(Outcome.NOT_VERIFIED)),
            "not_applicable": len(report.results(Outcome.NOT_APPLICABLE)),
        },
        "exit_code": report.exit_code,
        "findings": [f.to_dict() | {"blocking": is_blocking(f)} for f in report.findings],
        "limitations": LIMITATIONS,
        # Phase 3B plumbing: Authentication/Session areas (never PASS in this version).
        "auth_areas": auth_area_status(cfg, report.findings, report.refused, report_zap(report)),
        "zap": report_zap(report).to_dict(),
        # Passive OWASP ZAP baseline results (no active scan, no credentials).
        "zap_baseline": report.zap_baseline,
        "correlations": report.correlations,
        "authentication_config": auth_config_summary(cfg),
        # Phase 3C coverage status only: no authorization requests, no credentials, no findings generated.
        "authorization": authz_area_status(report.findings, report.refused),
    }


def write(report: RunReport, out: Path) -> Path:
    out.mkdir(parents=True, exist_ok=True)
    path = out / "runtime-security-report.json"
    path.write_text(json.dumps(build(report), indent=2, ensure_ascii=False) + "\n", encoding="utf-8")
    return path
