"""security-ci v1.3 acceptance: INCOMPLETE semantics, native-style report shape, leakage, v1.2 regression.

Hand-written Phase 3 report JSON only; no network, no application fixture, no credentials. Tests of behaviour that
security-ci already has pass today; tests of the v1.3 native additions (design section 21) are strict xfails.
"""

from __future__ import annotations

import copy
import json
from pathlib import Path

import pytest

from security_ci import cli
from security_ci.gate import evaluate, render
from security_ci.inputs import InputError, load_all
from security_ci.sarif import build

pending = pytest.mark.xfail(strict=True, reason="v1.3 implementation pending")

FIX = Path(__file__).parent / "fixtures"
SECRETS = ("FAKE-V13-SCI-BEARER-4b1d9e", "FAKE-V13-SCI-COOKIE-77c0aa", "FAKE-V13-SCI-QUERY-0e5f31",
           "FAKE-V13-SCI-PASSWORD-a9b8", "FAKE-V13-SCI-TOKENFIELD-19")


def area(status: str, source: str = "native", executed: bool = True, requests: int = 2, findings=()) -> dict:
    return {"area": "x", "status": status, "reason": "hand-written", "source": source, "namespace": "RT-X-*",
            "runtime_checks_executed": executed, "credentials_read": False, "requests_count": requests,
            "request_budget": 4, "actors": ["user_a", "user_b"], "findings": list(findings), "limitations": ["declared only"],
            "checks": [{"check": "I2", "actors": ["user_a"], "method": "GET", "path": "/objects/object-b",
                        "expected": "denied", "status_class": "4xx", "classification": "denied", "marker_present": False}]}


def finding(fid: str, category: str, severity: str = "HIGH", origin: str = "native-verification", **kw) -> dict:
    f = {"id": fid, "category": category, "severity": severity, "confidence": "HIGH", "title": f"Native {category} result",
         "endpoint": "GET /objects/object-b", "expected": "denied", "actual": "allowed", "evidence": "declared marker returned",
         "impact": "i", "recommendation": "r", "validation": "v", "status": "OPEN",
         "blocking": severity in ("CRITICAL", "HIGH"), "source": origin}
    f.update(kw)
    return f


def native_report(tmp_path: Path, *, native_status: str = "EXECUTED", findings=(), subareas=None, auth=None,
                  import_block=None, safety_allowed=True) -> Path:
    data = json.loads((FIX / "phase3-report.json").read_text())
    data["findings"].extend(copy.deepcopy(list(findings)))
    data["safety"] = {"allowed": safety_allowed, "reason": "local target"}
    data["auth_areas"] = auth or {"authentication": area("PASS", requests=9), "session": area("PASS", requests=1)}
    subs = subareas or {"authorization": area("PASS"), "idor_bola": area("PASS", requests=4),
                        "tenant_isolation": area("PASS", source="imported", requests=4)}
    sources = {k: v.get("source", "none") for k, v in subs.items()}
    data["authorization"] = {"area": "Authorization", "status": "PASS", "reason": "hand-written", "scope": [],
                             "runtime_checks_executed": True, "credentials_read": False, "requests_count": 10,
                             "findings": [], "subareas": subs,
                             "verification_source": sources["authorization"] if len(set(sources.values())) == 1 else "mixed",
                             "verification_subarea_source": sources}
    data["native_verification"] = {"status": native_status, "mode": "local-app", "target_allowed": True,
                                   "requests_count": 15, "request_budget": 20, "credentials_read": False,
                                   "areas": ["authentication", "session", "authorization", "idor_bola"]}
    if import_block is not None:
        data["verification_import"] = import_block
    p = tmp_path / "runtime-security-report.json"
    p.write_text(json.dumps(data))
    return p


def results(doc) -> dict:
    return {r["properties"]["findingId"]: r for run in doc["runs"] for r in run["results"]}


BASE_IDS = [f.id for f in load_all(None, FIX / "phase3-report.json", None).findings]
INCOMPLETE_IMPORT = {"status": "INCOMPLETE", "reason": "imported result rejected", "schema_version": "1.0",
                     "requests_count": 0, "request_budget": 20, "credentials_read": False}


# ------------------------------------------------------------------------------------ INCOMPLETE semantics (existing)

def test_incomplete_fails_gate_by_default(tmp_path, capsys):
    p = native_report(tmp_path, import_block=INCOMPLETE_IMPORT)
    b = load_all(None, p, None)
    r = evaluate(b, "release")
    assert not r.passed and r.exit_code == 1 and "phase3 imported verification" in r.incomplete
    assert cli.main(["gate", "--phase3", str(p)]) == 1
    assert "Result: FAIL" in capsys.readouterr().out


def test_allow_incomplete_is_only_an_opt_out(tmp_path, capsys):
    p = native_report(tmp_path, import_block=INCOMPLETE_IMPORT)
    b = load_all(None, p, None)
    r = evaluate(b, "release", allow_incomplete=True)
    assert r.passed and r.incomplete == ["phase3 imported verification"]       # still reported as incomplete
    assert b.imported_verification["status"] == "INCOMPLETE"                     # status not converted
    assert build(b)["runs"][0]["properties"]["importedVerification"]["status"] == "INCOMPLETE"
    assert cli.main(["gate", "--phase3", str(p), "--allow-incomplete"]) == 0
    assert "Incomplete: phase3 imported verification" in capsys.readouterr().out


def test_allow_incomplete_never_hides_violations(tmp_path):
    p = native_report(tmp_path, import_block=INCOMPLETE_IMPORT, findings=[finding("RT-IDOR-001", "idor")])
    r = evaluate(load_all(None, p, None), "release", allow_incomplete=True)
    assert not r.passed and any(v.startswith("RT-IDOR-001") for v in r.violations)


@pytest.mark.parametrize("status", ["INCOMPLETE"])
def test_incomplete_area_status_never_becomes_pass(tmp_path, status):
    p = native_report(tmp_path, auth={"authentication": area(status), "session": area("PASS")},
                      subareas={"authorization": area(status), "idor_bola": area("PASS"), "tenant_isolation": area("PASS")})
    b = load_all(None, p, None)
    for allow in (False, True):
        r = evaluate(b, "release", allow_incomplete=allow)
        assert r.verification["Authentication"] == "INCOMPLETE"
    assert b.verification_subareas["authorization"] == "INCOMPLETE"
    assert "Authentication: INCOMPLETE" in render(evaluate(b, "release", allow_incomplete=True))


# ------------------------------------------------------------------------------------ INCOMPLETE semantics (pending)

def test_native_incomplete_fails_gate_by_default(tmp_path):
    b = load_all(None, native_report(tmp_path, native_status="INCOMPLETE"), None)
    assert not evaluate(b, "release").passed
    assert any("native" in x for x in b.incomplete)
    assert evaluate(b, "release", allow_incomplete=True).passed


def test_native_verification_carried_in_sarif(tmp_path):
    doc = build(load_all(None, native_report(tmp_path, native_status="EXECUTED"), None))
    assert doc["runs"][0]["properties"]["nativeVerification"] == {"status": "EXECUTED", "requestsCount": 15}


# ------------------------------------------------------------------------------------ reporting shape (existing)

def test_native_shaped_statuses_and_findings_preserved(tmp_path):
    p = native_report(tmp_path, findings=[finding("RT-AUTH-001", "authentication", "MEDIUM"), finding("RT-IDOR-001", "idor")],
                      subareas={"authorization": area("PASS"), "idor_bola": area("FAIL", requests=4, findings=["RT-IDOR-001"]),
                                "tenant_isolation": area("PASS", source="imported")})
    b = load_all(None, p, None)
    assert b.verification == {"Authentication": "PASS", "Session": "PASS", "Authorization": "PASS"}
    assert b.verification_subareas == {"authorization": "PASS", "idor_bola": "FAIL", "tenant_isolation": "PASS"}
    res = results(build(b))
    assert res["RT-IDOR-001"]["ruleId"].startswith("RT-IDOR/") and res["RT-IDOR-001"]["level"] == "error"
    assert res["RT-AUTH-001"]["level"] == "warning"                   # severity mapping unchanged
    assert [f.id for f in b.findings if f.id in BASE_IDS] == BASE_IDS


def test_unbacked_native_pass_is_not_verified(tmp_path):
    p = native_report(tmp_path, auth={"authentication": area("PASS", executed=False), "session": area("EXECUTED", executed=False)},
                      subareas={"authorization": area("PASS", executed=False), "idor_bola": area("PASS"),
                                "tenant_isolation": area("FAIL", executed=False)})
    b = load_all(None, p, None)
    assert b.verification["Authentication"] == "NOT VERIFIED" and b.verification["Session"] == "NOT VERIFIED"
    assert b.verification_subareas["authorization"] == "NOT VERIFIED" and b.verification_subareas["tenant_isolation"] == "NOT VERIFIED"


def test_refused_target_forces_not_verified(tmp_path):
    b = load_all(None, native_report(tmp_path, safety_allowed=False), None)
    assert set(b.verification.values()) == {"NOT VERIFIED"} and set(b.verification_subareas.values()) == {"NOT VERIFIED"}


def test_not_verified_creates_no_result(tmp_path):
    nv = area("NOT VERIFIED", executed=False, requests=0)
    p = native_report(tmp_path, native_status="NOT VERIFIED", auth={"authentication": nv, "session": nv},
                      subareas={"authorization": nv, "idor_bola": nv, "tenant_isolation": nv})
    b = load_all(None, p, None)
    assert [f.id for f in b.findings] == BASE_IDS and evaluate(b, "release").passed


# ------------------------------------------------------------------------------------ reporting shape (pending)

def test_native_origin_in_sarif(tmp_path):
    b = load_all(None, native_report(tmp_path, findings=[finding("RT-IDOR-001", "idor")]), None)
    assert results(build(b))["RT-IDOR-001"]["properties"]["origin"] == "native-verification"


def test_sources_carried_in_sarif(tmp_path):
    props = build(load_all(None, native_report(tmp_path), None))["runs"][0]["properties"]
    assert props["verificationSource"]["authorization"] == "mixed"
    assert props["verificationSubareaSource"] == {"authorization": "native", "idor_bola": "native", "tenant_isolation": "imported"}


def test_mixed_rejected_as_individual_source(tmp_path):
    p = native_report(tmp_path, subareas={"authorization": area("PASS", source="mixed"), "idor_bola": area("PASS"),
                                          "tenant_isolation": area("PASS")})
    b = load_all(None, p, None)
    assert b.verification_subareas["authorization"] == "INCOMPLETE"


# ------------------------------------------------------------------------------------ leakage (existing)

def test_planted_secrets_absent_from_sarif_and_gate_output(tmp_path, capsys):
    b1, b2, q, pw, tk = SECRETS
    leaky = finding("RT-SESSION-001", "session", "MEDIUM",
                    evidence=f"Cookie: sid={b2}; Authorization: Bearer {b1}",
                    endpoint=f"GET http://127.0.0.1:3000/account?session={q}", title=f"password={pw}",
                    actual=f"token={tk}", credentials={"password": pw}, token=tk)
    auth = {"authentication": area("PASS"), "session": dict(area("FAIL", findings=["RT-SESSION-001"]),
                                                          evidence=[{"check": f"S2 Bearer {b1}"}], secret=pw)}
    p = native_report(tmp_path, findings=[leaky], auth=auth)
    out = tmp_path / "o.sarif"
    assert cli.main(["sarif", "--phase3", str(p), "--sarif", str(out)]) == 0
    cli.main(["gate", "--phase3", str(p), "--allow-incomplete"])
    text = out.read_text(encoding="utf-8") + capsys.readouterr().out
    for s in SECRETS:
        assert s not in text, s
    assert "RT-SESSION-001" in text


# ------------------------------------------------------------------------------------ v1.2 regression

def test_v12_imported_report_unchanged(tmp_path):
    """Adding native-shaped metadata to an imported-only report changes nothing security-ci computes."""
    data = json.loads((FIX / "phase3-report.json").read_text())
    imported = {"area": "x", "status": "PASS", "source": "imported", "runtime_checks_executed": True, "requests_count": 4,
                "findings": [], "credentials_read": False}
    data["auth_areas"] = {"authentication": dict(imported), "session": dict(imported)}
    data["authorization"] = {"area": "Authorization", "status": "PASS", "source": "imported", "runtime_checks_executed": True,
                             "requests_count": 12, "credentials_read": False, "findings": [],
                             "subareas": {k: dict(imported) for k in ("authorization", "idor_bola", "tenant_isolation")}}
    data["verification_import"] = {"status": "EXECUTED", "requests_count": 20, "request_budget": 20}
    plain = tmp_path / "plain.json"
    plain.write_text(json.dumps(data))
    tagged_data = copy.deepcopy(data)
    tagged_data["native_verification"] = {"status": "NOT CONFIGURED", "requests_count": 0}
    tagged_data["authorization"]["verification_source"] = "mixed"
    tagged_data["authorization"]["verification_subarea_source"] = {"authorization": "imported", "idor_bola": "imported",
                                                                   "tenant_isolation": "none"}
    tagged = tmp_path / "tagged.json"
    tagged.write_text(json.dumps(tagged_data))
    a, b = load_all(None, plain, None), load_all(None, tagged, None)
    assert a.verification == b.verification == {"Authentication": "PASS", "Session": "PASS", "Authorization": "PASS"}
    assert a.verification_subareas == b.verification_subareas
    assert a.imported_verification == b.imported_verification == {"status": "EXECUTED", "requestsCount": 20}
    assert [f.id for f in a.findings] == [f.id for f in b.findings] == BASE_IDS
    assert evaluate(a, "release").passed == evaluate(b, "release").passed


def test_v12_fixture_report_still_loads_without_new_fields():
    b = load_all(None, FIX / "phase3-report.json", None)
    assert b.verification_subareas == {} and b.imported_verification is None
    props = build(b)["runs"][0]["properties"]
    assert "importedVerification" not in props and "verificationSubareas" not in props


def test_malformed_reports_keep_existing_errors(tmp_path):
    p = tmp_path / "bad.json"
    p.write_text(json.dumps({"schema_version": "1.0", "tool": {"name": "something-else"}}))
    with pytest.raises(InputError):
        load_all(None, p, None)
    p.write_text("{not json")
    with pytest.raises(InputError):
        load_all(None, p, None)
    assert cli.main(["gate", "--phase3", str(p)]) == 3
