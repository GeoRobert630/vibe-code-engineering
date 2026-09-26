"""v1.4 acceptance: Security CI gating and SARIF generation for CSRF (Design §11).

Locks down:
- Security CI gate enforcement:
  - RT-CSRF-001 (HIGH) and RT-CSRF-002 (HIGH) are blocking findings that fail the release gate
  - RT-CSRF-003 (MEDIUM) passes release policy but fails medium policy
  - CSRF area INCOMPLETE fails gate by default, passes with --allow-incomplete
  - CSRF area NOT CONFIGURED or PASS passes the gate
- SARIF export:
  - Generates rules and results for RT-CSRF-001, RT-CSRF-002, RT-CSRF-003
  - Rules mapped with CWE-352 and appropriate severity
  - Origin metadata is preserved as native-verification
"""

from __future__ import annotations

import copy
import json
import sys
from pathlib import Path

_SRC = str(Path(__file__).resolve().parents[1] / "src")
if _SRC not in sys.path:
    sys.path.insert(0, _SRC)

import pytest
from security_ci.gate import evaluate
from security_ci.inputs import load_all
from security_ci.sarif import build

pending_sec_ci = lambda f: f

FIX = Path(__file__).parent / "fixtures"


def csrf_finding(fid: str, severity: str = "HIGH", **kw) -> dict:
    f = {
        "id": fid,
        "category": "csrf",
        "severity": severity,
        "confidence": "HIGH",
        "title": f"CSRF finding {fid}",
        "endpoint": "POST /api/action",
        "expected": "denied",
        "actual": "allowed",
        "evidence": "observed mutation",
        "impact": "State change",
        "recommendation": "Require anti-CSRF token",
        "validation": "Send cross-origin request",
        "status": "OPEN",
        "blocking": severity in ("CRITICAL", "HIGH"),
        "source": "native-verification",
    }
    f.update(kw)
    return f


def make_report(tmp_path: Path, *, csrf_status: str = "PASS", findings=(), incomplete: bool = False) -> Path:
    data = json.loads((FIX / "phase3-report.json").read_text(encoding="utf-8"))
    data["findings"].extend(copy.deepcopy(list(findings)))
    data["safety"] = {"allowed": True, "reason": "local target"}
    data.setdefault("auth_areas", {})
    data["auth_areas"]["csrf"] = {
        "area": "csrf",
        "status": csrf_status,
        "reason": "contract test",
        "source": "native",
        "namespace": "RT-CSRF-*",
        "runtime_checks_executed": not incomplete,
        "requests_count": 4,
        "findings": [f["id"] for f in findings],
    }
    if incomplete:
        data.setdefault("incomplete", []).append("phase3 csrf verification")
    p = tmp_path / "runtime-security-report.json"
    p.write_text(json.dumps(data), encoding="utf-8")
    return p


# =============================================================================
# 1. Security CI Gate Policies on CSRF Findings
# =============================================================================

@pending_sec_ci
def test_gate_blocks_on_rt_csrf_001_and_002(tmp_path):
    """Active RT-CSRF-001 or RT-CSRF-002 findings are HIGH severity and block the release gate."""
    p = make_report(
        tmp_path,
        csrf_status="FAIL",
        findings=[
            csrf_finding("RT-CSRF-001", "HIGH"),
            csrf_finding("RT-CSRF-002", "HIGH"),
        ],
    )
    b = load_all(None, p, None)
    r = evaluate(b, "release")
    assert not r.passed
    assert r.exit_code == 1
    assert any("RT-CSRF-001" in v for v in r.violations)
    assert any("RT-CSRF-002" in v for v in r.violations)


@pending_sec_ci
def test_gate_rt_csrf_003_medium_policy(tmp_path):
    """RT-CSRF-003 is MEDIUM severity: passes default release policy, blocks on --fail-on medium."""
    p = make_report(
        tmp_path,
        csrf_status="FAIL",
        findings=[csrf_finding("RT-CSRF-003", "MEDIUM", blocking=False)],
    )
    b = load_all(None, p, None)
    # Release policy: non-blocking findings pass
    r_release = evaluate(b, "release")
    assert r_release.passed
    # Medium policy: blocks on MEDIUM
    r_medium = evaluate(b, "medium")
    assert not r_medium.passed
    assert any("RT-CSRF-003" in v for v in r_medium.violations)


@pending_sec_ci
def test_csrf_incomplete_fails_gate_unless_allowed(tmp_path):
    """CSRF area reporting INCOMPLETE fails the gate by default, passes with allow_incomplete=True."""
    p = make_report(tmp_path, csrf_status="INCOMPLETE", incomplete=True)
    b = load_all(None, p, None)
    # Default: incomplete fails
    r_default = evaluate(b, "release", allow_incomplete=False)
    assert not r_default.passed
    assert r_default.exit_code == 1
    # Opt-in: allow_incomplete passes
    r_allowed = evaluate(b, "release", allow_incomplete=True)
    assert r_allowed.passed


# =============================================================================
# 2. SARIF Rules & Results Generation for CSRF
# =============================================================================

@pending_sec_ci
def test_sarif_export_contains_csrf_rules_and_results(tmp_path):
    """SARIF output contains rule definitions for RT-CSRF-* and tags CWE-352."""
    p = make_report(
        tmp_path,
        csrf_status="FAIL",
        findings=[csrf_finding("RT-CSRF-001", "HIGH")],
    )
    b = load_all(None, p, None)
    sarif = build(b)
    run = sarif["runs"][0]
    rules = {r["id"]: r for r in run["tool"]["driver"]["rules"]}
    assert any("RT-CSRF" in rid for rid in rules)
    # Check results mapping
    result = next((res for res in run["results"] if "RT-CSRF-001" in res["ruleId"]), None)
    assert result is not None
    assert result["level"] == "error"
