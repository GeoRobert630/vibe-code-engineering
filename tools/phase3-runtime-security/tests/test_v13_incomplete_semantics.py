"""v1.3 acceptance: INCOMPLETE semantics in Phase 3 (design sections 21 and 22). No network.

INCOMPLETE is a coverage failure: exit code 3 unless a blocking finding exists, in which case 2 takes precedence.
Exercised through the existing v1.2 import path, which the native verifier shares (``check_failure``).
"""

from __future__ import annotations

import json
from pathlib import Path

from runtime_security.config import parse
from runtime_security.models import Confidence, Finding, Severity
from runtime_security.reporting import json_report, markdown_report
from runtime_security.runner import RunReport, load_verification

FIX = Path(__file__).parent / "fixtures" / "verification"
BASE = "http://127.0.0.1:3000"


def _report(tmp_path: Path, doc: dict | None, extra_findings=()) -> RunReport:
    data = {"target": {"base_url": BASE, "environment": "local", "production": False}}
    if doc is not None:
        p = tmp_path / "results.json"
        p.write_text(json.dumps(doc), encoding="utf-8")
        data["verification_results"] = {"path": str(p)}
    cfg = parse(data)
    r = RunReport(cfg=cfg, safety_reason="local target", refused=False, findings=list(extra_findings))
    load_verification(cfg, r)
    return r


def _valid() -> dict:
    return json.loads((FIX / "valid.json").read_text(encoding="utf-8"))


def _blocking_3a_finding() -> Finding:
    return Finding(category="cors", severity=Severity.HIGH, confidence=Confidence.HIGH, title="Credentialed CORS reflection",
                   endpoint="GET /", expected="no reflection", actual="reflected", evidence="Origin reflected", impact="i",
                   recommendation="r", validation="v", id="RT-CORS-001")


def _rejected() -> dict:
    d = _valid()
    d["areas"]["session"]["requests_count"] = 99   # over budget: whole import rejected -> INCOMPLETE
    return d


def test_incomplete_without_blocking_finding_exits_3(tmp_path):
    r = _report(tmp_path, _rejected())
    assert r.verification.status == "INCOMPLETE" and not r.blocking
    assert r.exit_code == 3 and r.summary.startswith("INCOMPLETE")
    data = json_report.build(r)
    assert data["exit_code"] == 3 and data["verification_import"]["status"] == "INCOMPLETE"


def test_blocking_finding_takes_precedence_with_exit_2(tmp_path):
    r = _report(tmp_path, _rejected(), extra_findings=[_blocking_3a_finding()])
    assert r.verification.status == "INCOMPLETE" and r.blocking
    assert r.exit_code == 2 and r.summary.startswith("FAIL")
    # INCOMPLETE is still reported next to the blocking finding; it is not hidden by it
    data = json_report.build(r)
    assert data["verification_import"]["status"] == "INCOMPLETE"
    assert data["authorization"]["status"] == "INCOMPLETE"


def test_incomplete_area_inside_a_valid_import_is_reported_but_not_a_run_failure(tmp_path):
    """Ambiguous evidence makes one area INCOMPLETE (a coverage status); the import itself is valid."""
    d = _valid()
    d["areas"]["tenant_isolation"]["runtime_checks_executed"] = False    # PASS claimed without execution
    r = _report(tmp_path, d)
    data = json_report.build(r)
    assert data["authorization"]["subareas"]["tenant_isolation"]["status"] == "INCOMPLETE"
    assert data["authorization"]["status"] in ("FAIL", "INCOMPLETE")        # FAIL wins over INCOMPLETE (IDOR finding)
    assert data["verification_import"]["status"] == "EXECUTED"


def test_incomplete_never_rendered_as_pass(tmp_path):
    r = _report(tmp_path, _rejected())
    md = markdown_report.render(r)
    for heading in ("## Authentication\n", "## Session\n", "## Authorization\n"):
        section = md.split(heading, 1)[1].split("\n## ", 1)[0]
        assert "Status: **INCOMPLETE**" in section and "Status: **PASS**" not in section
    assert "Imported verification results: **INCOMPLETE**" in md


def test_not_configured_is_not_incomplete(tmp_path):
    r = _report(tmp_path, None)
    assert r.verification is None and r.exit_code == 0
    assert json_report.build(r)["verification_import"]["status"] == "NOT CONFIGURED"
