"""security-ci: Phase 3 reports carrying imported verification results (hand-written JSON only, no network)."""

from __future__ import annotations

import copy
import json
from pathlib import Path

import pytest

from security_ci import cli
from security_ci.gate import evaluate
from security_ci.inputs import RT_ID, load_all
from security_ci.sarif import build

FIX = Path(__file__).parent / "fixtures"


def sub(status: str, count: int, findings: list[str], executed: bool = True) -> dict:
    return {"area": "x", "status": status, "reason": "imported", "source": "imported", "runtime_checks_executed": executed,
            "credentials_read": False, "requests_count": count, "findings": findings, "evidence": [], "limitations": ["declared routes only"]}


def finding(fid: str, category: str, severity: str = "HIGH", **kw) -> dict:
    f = {"id": fid, "category": category, "severity": severity, "confidence": "HIGH", "title": f"Imported {category} result",
         "endpoint": "GET /api/items/<declared>", "expected": "denied", "actual": "allowed (200)", "evidence": "declared check",
         "impact": "i", "recommendation": "r", "validation": "v", "status": "OPEN", "blocking": severity in ("CRITICAL", "HIGH"),
         "source": "imported-verification"}
    f.update(kw)
    return f


IMPORTED = [finding("RT-AUTH-001", "authentication", "MEDIUM"), finding("RT-SESSION-001", "session", "LOW"),
            finding("RT-AUTHZ-001", "authorization"), finding("RT-IDOR-001", "idor"), finding("RT-TENANT-001", "tenant_isolation", "MEDIUM")]


def report(tmp_path: Path, findings=IMPORTED, import_status: str = "EXECUTED", requests: int = 18, **area_changes) -> Path:
    data = json.loads((FIX / "phase3-report.json").read_text())
    data["findings"].extend(copy.deepcopy(findings))
    data["auth_areas"] = {"authentication": sub("FAIL", 4, ["RT-AUTH-001"]), "session": sub("FAIL", 3, ["RT-SESSION-001"])}
    subs = {"authorization": sub("FAIL", 3, ["RT-AUTHZ-001"]), "idor_bola": sub("FAIL", 4, ["RT-IDOR-001"]),
            "tenant_isolation": sub("FAIL", 4, ["RT-TENANT-001"])}
    for key, change in area_changes.items():
        (subs if key in subs else data["auth_areas"])[key].update(change)
    data["authorization"] = {"area": "Authorization", "status": "FAIL", "reason": "imported", "scope": [], "source": "imported",
                             "runtime_checks_executed": True, "credentials_read": False, "requests_count": 11,
                             "findings": ["RT-AUTHZ-001"], "subareas": subs}
    data["verification_import"] = {"status": import_status, "reason": "imported result validated", "schema_version": "1.0",
                                   "requests_count": requests, "request_budget": 20, "credentials_read": False}
    p = tmp_path / "runtime-security-report.json"
    p.write_text(json.dumps(data))
    return p


def results(doc) -> dict:
    return {r["properties"]["findingId"]: r for run in doc["runs"] for r in run["results"]}


BASE_IDS = [f.id for f in load_all(None, FIX / "phase3-report.json", None).findings]


@pytest.mark.parametrize("fid", ["RT-AUTH-001", "RT-SESSION-001", "RT-AUTHZ-001", "RT-IDOR-001", "RT-TENANT-001"])
def test_all_imported_namespaces_accepted(fid):
    assert RT_ID.match(fid)


def test_valid_imported_findings_preserved_in_sarif(tmp_path):
    b = load_all(None, report(tmp_path), None)
    ids = {f.id: f for f in b.findings}
    for f in IMPORTED:
        u = ids[f["id"]]
        assert u.layer == "phase3" and u.severity == f["severity"] and u.extra.get("origin") == "imported-verification"
    doc = build(b)
    res = results(doc)
    assert {"RT-AUTH-001", "RT-SESSION-001", "RT-AUTHZ-001", "RT-IDOR-001", "RT-TENANT-001"} <= set(res)
    assert res["RT-TENANT-001"]["ruleId"].startswith("RT-TENANT/") and res["RT-AUTH-001"]["ruleId"].startswith("RT-AUTH/")
    # existing severity mapping, no new CRITICAL semantics
    assert res["RT-IDOR-001"]["level"] == "error" and res["RT-IDOR-001"]["properties"]["security-severity"] == "8.0"
    assert res["RT-SESSION-001"]["level"] == "note" and res["RT-AUTH-001"]["level"] == "warning"
    props = doc["runs"][0]["properties"]
    assert props["verificationStatus"] == {"Authentication": "FAIL", "Session": "FAIL", "Authorization": "FAIL"}
    assert props["verificationSubareas"] == {"authorization": "FAIL", "idor_bola": "FAIL", "tenant_isolation": "FAIL"}
    assert props["importedVerification"] == {"status": "EXECUTED", "requestsCount": 18}
    r = evaluate(b, "release")
    assert not r.passed and any("RT-IDOR-001" in v for v in r.violations) and not r.incomplete


def test_invalid_ids_dropped(tmp_path):
    bad = [finding("RT-BOLA-001", "idor"), finding("RT-IDOR-01", "idor"), finding("RT-TENANTS-001", "tenant_isolation")]
    b = load_all(None, report(tmp_path, findings=bad), None)
    assert [f.id for f in b.findings] == BASE_IDS


def test_not_verified_creates_no_synthetic_finding(tmp_path):
    nv = {"status": "NOT VERIFIED", "runtime_checks_executed": False, "findings": [], "requests_count": 0}
    p = report(tmp_path, findings=[], import_status="EXECUTED", requests=0, authentication=nv, session=nv,
               authorization=nv, idor_bola=nv, tenant_isolation=nv)
    data = json.loads(p.read_text())
    data["authorization"].update(status="NOT VERIFIED", runtime_checks_executed=False, requests_count=0, findings=[])
    p.write_text(json.dumps(data))
    b = load_all(None, p, None)
    assert [f.id for f in b.findings] == BASE_IDS
    assert set(b.verification.values()) == {"NOT VERIFIED"} and set(b.verification_subareas.values()) == {"NOT VERIFIED"}
    assert evaluate(b, "release").passed


def test_incomplete_stays_incomplete(tmp_path):
    b = load_all(None, report(tmp_path, findings=[], import_status="INCOMPLETE", requests=0,
                              idor_bola={"status": "INCOMPLETE", "findings": []}), None)
    assert b.imported_verification["status"] == "INCOMPLETE" and "phase3 imported verification" in b.incomplete
    assert b.verification_subareas["idor_bola"] == "INCOMPLETE"
    assert not evaluate(b, "release").passed and evaluate(b, "release", allow_incomplete=True).passed
    assert build(b)["runs"][0]["properties"]["importedVerification"]["status"] == "INCOMPLETE"


@pytest.mark.parametrize("count", [21, -1, "5", 2.5, True])
def test_invalid_request_count_is_incomplete(tmp_path, count):
    b = load_all(None, report(tmp_path, requests=count, tenant_isolation={"requests_count": count}), None)
    assert b.imported_verification == {"status": "INCOMPLETE", "requestsCount": 0}
    assert b.verification_subareas["tenant_isolation"] == "INCOMPLETE"


@pytest.mark.parametrize("count", [0, 20])
def test_request_count_bounds(tmp_path, count):
    b = load_all(None, report(tmp_path, requests=count), None)
    assert b.imported_verification == {"status": "EXECUTED", "requestsCount": count}


def test_pass_requires_runtime_checks_executed(tmp_path):
    b = load_all(None, report(tmp_path, findings=[], authentication={"status": "PASS", "runtime_checks_executed": False, "findings": []},
                              tenant_isolation={"status": "PASS", "runtime_checks_executed": False, "findings": []}), None)
    assert b.verification["Authentication"] == "NOT VERIFIED" and b.verification_subareas["tenant_isolation"] == "NOT VERIFIED"
    b = load_all(None, report(tmp_path, findings=[], tenant_isolation={"status": "PASS", "findings": []}), None)
    assert b.verification_subareas["tenant_isolation"] == "PASS"


def test_refused_report_stays_not_verified(tmp_path):
    p = report(tmp_path)
    data = json.loads(p.read_text())
    data["safety"] = {"allowed": False, "reason": "production"}
    p.write_text(json.dumps(data))
    b = load_all(None, p, None)
    assert set(b.verification.values()) == {"NOT VERIFIED"} and set(b.verification_subareas.values()) == {"NOT VERIFIED"}


def test_secrets_redacted_and_credentials_ignored(tmp_path):
    leaky = finding("RT-SESSION-002", "session", evidence="Cookie: sid=FAKE-COOKIE-VALUE-7788; Authorization: Bearer FAKE-BEARER-7788xx",
                    endpoint="GET http://127.0.0.1:3000/api/me?session=FAKE-QUERY-SESSION-7788",
                    title="password=FAKE-PASSWORD-7788", credentials={"password": "FAKE-CRED-FIELD-7788"},
                    token="FAKE-TOKEN-FIELD-7788")
    out = tmp_path / "o.sarif"
    p = report(tmp_path, findings=IMPORTED + [leaky])
    assert cli.main(["sarif", "--phase3", str(p), "--sarif", str(out)]) == 0
    text = out.read_text(encoding="utf-8")
    for secret in ("FAKE-COOKIE-VALUE-7788", "FAKE-BEARER-7788xx", "FAKE-QUERY-SESSION-7788", "FAKE-PASSWORD-7788",
                   "FAKE-CRED-FIELD-7788", "FAKE-TOKEN-FIELD-7788"):
        assert secret not in text, secret
    assert "RT-SESSION-002" in text


def test_old_reports_unchanged(tmp_path):
    old = load_all(None, FIX / "phase3-report.json", None)
    assert old.verification_subareas == {} and old.imported_verification is None
    assert "verificationSubareas" not in build(old)["runs"][0]["properties"]
    assert "importedVerification" not in build(old)["runs"][0]["properties"]


def test_cli_gate_prints_statuses(tmp_path, capsys):
    p = report(tmp_path)
    assert cli.main(["gate", "--phase3", str(p)]) == 1   # imported HIGH findings are blocking under the release policy
    out = capsys.readouterr().out
    assert "Authorization: FAIL" in out and "RT-IDOR-001" in out
