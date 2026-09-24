"""security-ci: reserved RT-IDOR-* / RT-TENANT-* namespaces and authorization sub-areas (no synthetic findings)."""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from security_ci import cli
from security_ci.gate import evaluate
from security_ci.inputs import RT_ID, load_all
from security_ci.sarif import build

FIX = Path(__file__).parent / "fixtures"
SUB = {"status": "NOT VERIFIED", "reason": "not executed", "runtime_checks_executed": False, "credentials_read": False,
       "findings": []}
AUTHZ_WITH_SUBAREAS = {
    "area": "Authorization", "status": "NOT VERIFIED", "reason": "not executed", "scope": ["authorization"],
    "runtime_checks_executed": False, "credentials_read": False, "findings": [],
    "subareas": {"authorization": dict(SUB, area="Authorization", namespace="RT-AUTHZ-*"),
                 "idor_bola": dict(SUB, area="IDOR/BOLA", namespace="RT-IDOR-*"),
                 "tenant_isolation": dict(SUB, area="Tenant isolation", namespace="RT-TENANT-*")},
}


def rt(fid: str, category: str, **kw) -> dict:
    f = {"id": fid, "category": category, "severity": "HIGH", "confidence": "HIGH", "title": "Imported result",
         "endpoint": "GET /api/items/<redacted>", "expected": "denied", "actual": "allowed (200)",
         "evidence": "imported result; session=<redacted>", "impact": "i", "recommendation": "r", "validation": "v",
         "status": "OPEN", "blocking": True}
    f.update(kw)
    return f


def phase3(tmp_path, findings=(), **changes) -> Path:
    data = json.loads((FIX / "phase3-report.json").read_text())
    data["findings"].extend(findings)
    data.update(changes)
    p = tmp_path / "runtime-security-report.json"
    p.write_text(json.dumps(data))
    return p


def results(doc) -> dict:
    return {r["properties"]["findingId"]: r for run in doc["runs"] for r in run["results"]}


@pytest.mark.parametrize("fid", ["RT-IDOR-001", "RT-TENANT-001", "RT-IDOR-123", "RT-TENANT-999"])
def test_new_prefixes_accepted(fid):
    assert RT_ID.match(fid)


@pytest.mark.parametrize("fid", ["RT-IDOR-01", "RT-TENANT-0001", "RT-IDORS-001", "RT-TENANTS-001", "RT-BOLA-001",
                                 "RT-idor-001", "RT-IDOR-001 ", "IDOR-001"])
def test_invalid_prefixes_rejected(fid):
    assert not RT_ID.match(fid)


def test_invalid_ids_are_dropped_not_imported(tmp_path):
    b = load_all(None, phase3(tmp_path, [rt("RT-IDORX-001", "idor"), rt("RT-TENANT-01", "tenant_isolation")]), None)
    ids = [f.id for f in b.findings]
    assert "RT-IDORX-001" not in ids and "RT-TENANT-01" not in ids
    assert ids == [f.id for f in load_all(None, FIX / "phase3-report.json", None).findings]


def test_report_with_subareas_no_synthetic_findings(tmp_path):
    b = load_all(None, phase3(tmp_path, authorization=AUTHZ_WITH_SUBAREAS), None)
    assert [f.id for f in b.findings] == [f.id for f in load_all(None, FIX / "phase3-report.json", None).findings]
    assert b.verification == {"Authentication": "NOT VERIFIED", "Session": "NOT VERIFIED", "Authorization": "NOT VERIFIED"}
    doc = build(b)
    assert not any(k.startswith(("RT-IDOR-", "RT-TENANT-", "RT-AUTHZ-")) for k in results(doc))
    assert doc["runs"][0]["properties"]["verificationStatus"]["Authorization"] == "NOT VERIFIED"
    r = evaluate(b, "release")
    assert r.passed and r.verification["Authorization"] == "NOT VERIFIED"


def test_old_report_without_subareas_unchanged(tmp_path):
    old = load_all(None, FIX / "phase3-report.json", None)
    assert "Authorization" not in old.verification
    legacy = dict(AUTHZ_WITH_SUBAREAS)
    legacy.pop("subareas")
    b = load_all(None, phase3(tmp_path, authorization=legacy), None)
    assert b.verification["Authorization"] == "NOT VERIFIED"
    assert json.dumps(build(b)["runs"][0]["results"]) == json.dumps(build(load_all(None, phase3(tmp_path, authorization=AUTHZ_WITH_SUBAREAS), None))["runs"][0]["results"])


def test_sarif_round_trip_preserves_new_ids(tmp_path):
    p = phase3(tmp_path, [rt("RT-IDOR-001", "idor", cwe="CWE-639"), rt("RT-TENANT-001", "tenant_isolation", severity="MEDIUM")],
               authorization=AUTHZ_WITH_SUBAREAS)
    b = load_all(None, p, None)
    by_id = {f.id: f for f in b.findings}
    assert by_id["RT-IDOR-001"].layer == "phase3" and by_id["RT-TENANT-001"].layer == "phase3"
    assert by_id["RT-IDOR-001"].source == "phase3-runtime-security"
    assert by_id["RT-IDOR-001"].extra == {} and by_id["RT-TENANT-001"].extra == {}   # no RT-AUTHZ metadata path
    out = tmp_path / "o.sarif"
    assert cli.main(["sarif", "--phase3", str(p), "--sarif", str(out)]) == 0
    doc = json.loads(out.read_text(encoding="utf-8"))
    res = results(doc)
    assert res["RT-IDOR-001"]["ruleId"].startswith("RT-IDOR/") and res["RT-TENANT-001"]["ruleId"].startswith("RT-TENANT/")
    # severity semantics unchanged (same mapping as every other runtime finding)
    assert res["RT-IDOR-001"]["properties"]["severity"] == "HIGH" and res["RT-TENANT-001"]["properties"]["severity"] == "MEDIUM"
    assert res["RT-IDOR-001"]["level"] == "error" and res["RT-TENANT-001"]["level"] == "warning"
    assert doc["runs"][0]["properties"]["verificationStatus"]["Authorization"] == "NOT VERIFIED"   # still NOT VERIFIED


def test_gate_treats_new_ids_like_other_runtime_findings(tmp_path):
    p = phase3(tmp_path, [rt("RT-IDOR-001", "idor")])
    r = evaluate(load_all(None, p, None), "release")
    assert not r.passed and "RT-IDOR-001" in json.dumps(r.__dict__, default=str)


def test_no_credentials_introduced(tmp_path):
    f = rt("RT-IDOR-001", "idor", evidence="Authorization: Bearer abc.def.ghi password=hunter2-fake",
           endpoint="GET https://user:pw-fake@127.0.0.1/api/items/7?token=fake-token-value",
           actors=["A", "B", "someone@example.invalid"], credentials={"password": "hunter2-fake"})
    b = load_all(None, phase3(tmp_path, [f], authorization=AUTHZ_WITH_SUBAREAS), None)
    blob = json.dumps(build(b))
    for secret in ("hunter2-fake", "abc.def.ghi", "pw-fake", "fake-token-value", "someone@example.invalid"):
        assert secret not in blob
    assert "credentials" not in results(build(b))["RT-IDOR-001"]["properties"]
