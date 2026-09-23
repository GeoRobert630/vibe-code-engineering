"""security-ci: Authorization coverage status and RT-AUTHZ namespace (no synthetic findings for NOT VERIFIED)."""

from __future__ import annotations

import json
from pathlib import Path

from security_ci import cli
from security_ci.gate import evaluate
from security_ci.inputs import load_all
from security_ci.sarif import build

FIX = Path(__file__).parent / "fixtures"


def phase3_with(tmp_path, **changes) -> Path:
    data = json.loads((FIX / "phase3-report.json").read_text())
    data.update(changes)
    p = tmp_path / "runtime-security-report.json"
    p.write_text(json.dumps(data))
    return p


NOT_VERIFIED = {"area": "Authorization", "status": "NOT VERIFIED", "reason": "not executed", "scope": ["authorization"],
                "runtime_checks_executed": False, "credentials_read": False, "findings": []}


def test_status_consumed_and_carried_in_sarif(tmp_path):
    b = load_all(None, phase3_with(tmp_path, authorization=NOT_VERIFIED), None)
    assert b.verification == {"Authentication": "NOT VERIFIED", "Session": "NOT VERIFIED", "Authorization": "NOT VERIFIED"}
    doc = build(b)
    run3 = doc["runs"][0]
    assert run3["properties"]["verificationStatus"]["Authorization"] == "NOT VERIFIED"
    assert "Authorization" in run3["properties"]["notice"] and "coverage gap, not a finding" in run3["properties"]["notice"]
    assert not any(r["properties"]["findingId"].startswith("RT-AUTHZ-") for r in run3["results"])


def test_no_synthetic_finding_and_gate_unaffected(tmp_path):
    b = load_all(None, phase3_with(tmp_path, authorization=NOT_VERIFIED), None)
    ids_before = [f.id for f in load_all(None, FIX / "phase3-report.json", None).findings]
    assert [f.id for f in b.findings] == ids_before
    r = evaluate(b, "release")
    assert r.passed and r.verification["Authorization"] == "NOT VERIFIED"


def test_backward_compatible_old_report(tmp_path):
    b = load_all(None, FIX / "phase3-report.json", None)   # fixture predates the authorization block
    assert "Authorization" not in b.verification             # not guessed from an old report
    b2 = load_all(FIX / "phase2-report.json", None, None)    # no runtime report at all
    assert b2.verification["Authorization"] == "NOT VERIFIED"


def test_imported_authz_finding_metadata_preserved(tmp_path):
    authz = {"id": "RT-AUTHZ-001", "category": "authorization", "severity": "HIGH", "confidence": "HIGH",
             "title": "Cross-user resource access", "endpoint": "GET /api/documents/<redacted>", "expected": "denied",
             "actual": "allowed (200)", "evidence": "imported result; session=<redacted>", "impact": "i", "recommendation": "r",
             "validation": "v", "status": "OPEN", "cwe": "CWE-639", "blocking": True,
             "actors": ["A", "B", "user@example.invalid"], "resource": "document X",
             "notes": ["Check: actor B -> document X -> 200", "Check: actor B HEAD -> document X -> 200"]}
    data = json.loads((FIX / "phase3-report.json").read_text())
    data["findings"].append(authz)
    data["authorization"] = dict(NOT_VERIFIED, status="FAIL", findings=["RT-AUTHZ-001"])
    p = tmp_path / "rt.json"
    p.write_text(json.dumps(data))
    doc = build(load_all(None, p, None))
    res = {r["properties"]["findingId"]: r for run in doc["runs"] for r in run["results"]}
    r = res["RT-AUTHZ-001"]
    assert r["properties"]["severity"] == "HIGH" and r["properties"]["actors"] == ["A", "B"]   # labels only
    assert r["properties"]["resource"] == "document X" and r["properties"]["evidenceCount"] == 2
    assert r["locations"][0]["logicalLocations"][0]["name"] == "GET /api/documents/<redacted>"
    assert "user@example.invalid" not in json.dumps(doc)


def test_cli_prints_authorization_status(tmp_path, capsys):
    p = phase3_with(tmp_path, authorization=NOT_VERIFIED)
    assert cli.main(["sarif", "--phase3", str(p), "--sarif", str(tmp_path / "o.sarif")]) == 0
    assert "Authorization: NOT VERIFIED" in capsys.readouterr().out
    assert cli.main(["gate", "--phase3", str(p)]) == 0
    assert "Authorization: NOT VERIFIED" in capsys.readouterr().out
