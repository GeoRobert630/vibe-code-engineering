"""CI gate policy tests."""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from security_ci import cli
from security_ci.gate import evaluate, render
from security_ci.inputs import load_all

FIX = Path(__file__).parent / "fixtures"


def bundle(phase2=True, phase3=True, ai=True):
    return load_all(FIX / "phase2-report.json" if phase2 else None, FIX / "phase3-report.json" if phase3 else None,
                    FIX / "ai-findings.json" if ai else None)


def test_release_policy_uses_existing_blocking_semantics():
    r = evaluate(bundle(), "release")
    assert not r.passed and r.exit_code == 1
    ids = {v.split()[0] for v in r.violations}
    assert ids == {"P2-aaaaaaaaaaa1", "P2-aaaaaaaaaaa2", "AI-01"}   # report 'blocking' flags + AI critical


@pytest.mark.parametrize("policy,expected", [
    ("critical", {"P2-aaaaaaaaaaa1", "AI-01"}),
    ("high", {"P2-aaaaaaaaaaa1", "P2-aaaaaaaaaaa2", "AI-01"}),
    ("medium", {"P2-aaaaaaaaaaa1", "P2-aaaaaaaaaaa2", "AI-01", "RT-COOKIE-001", "RT-ZAP-001", "AI-03"}),
])
def test_threshold_policies(policy, expected):
    assert {v.split()[0] for v in evaluate(bundle(), policy).violations} == expected


def test_low_is_review_only_unless_configured():
    medium = {v.split()[0] for v in evaluate(bundle(), "medium").violations}
    low = {v.split()[0] for v in evaluate(bundle(), "low").violations}
    assert "RT-ZAP-003" not in medium and "RT-ZAP-003" in low and "P2-aaaaaaaaaaa4" in low
    assert "P2-aaaaaaaaaaa3" not in low           # BASELINED never fails the gate
    assert "P2-aaaaaaaaaaa5" not in low           # INFORMATIONAL never fails the gate


def test_runtime_only_low_findings_pass_release_policy():
    r = evaluate(bundle(phase2=False, ai=False), "release")
    assert r.passed and r.exit_code == 0 and r.verification == {"Authentication": "NOT VERIFIED", "Session": "NOT VERIFIED"}
    assert "not proof of security" in render(r)


def test_incomplete_scan_fails_unless_allowed(tmp_path):
    data = json.loads((FIX / "phase3-report.json").read_text())
    data["safety"] = {"allowed": False, "reason": "production refused"}
    data["findings"], data["correlations"] = [], []
    p = tmp_path / "rt.json"
    p.write_text(json.dumps(data))
    b = load_all(None, p, None)
    assert not evaluate(b, "release").passed
    assert evaluate(b, "release", allow_incomplete=True).passed


def test_phase2_tool_failure_is_incomplete(tmp_path):
    data = json.loads((FIX / "phase2-report.json").read_text())
    data["summary"]["tool_failure"] = True
    data["findings"] = []
    p = tmp_path / "p2.json"
    p.write_text(json.dumps(data))
    r = evaluate(load_all(p, None, None), "critical")
    assert not r.passed and r.incomplete == ["phase2"]


def test_cli_gate_exit_codes(tmp_path, capsys):
    common = ["--phase2", str(FIX / "phase2-report.json"), "--phase3", str(FIX / "phase3-report.json")]
    assert cli.main(["gate", *common]) == 1
    assert cli.main(["gate", "--phase3", str(FIX / "phase3-report.json")]) == 0
    assert cli.main(["gate", *common, "--fail-on", "critical", "--sarif", str(tmp_path / "g.sarif")]) == 1
    assert (tmp_path / "g.sarif").is_file()
    out = capsys.readouterr().out
    assert "Authentication: NOT VERIFIED" in out and "Session: NOT VERIFIED" in out
    with pytest.raises(SystemExit) as exc:
        cli.main(["gate", *common, "--fail-on", "everything"])
    assert exc.value.code == 3
