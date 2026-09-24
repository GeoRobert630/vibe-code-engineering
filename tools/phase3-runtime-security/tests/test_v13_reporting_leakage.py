"""v1.3 acceptance: reporting shape and credential leakage (design sections 15, 18-20). No network.

Hand-written verification results go through the existing import, JSON, Markdown and reader paths. Fake
credential-shaped values are planted in every free-text field that the schema accepts; none may appear in output.
The existing redaction mechanisms (``utils.redaction`` and ``verification.redaction``) are used, not a parallel one.
"""

from __future__ import annotations

import importlib.util
import json
from pathlib import Path

import pytest

from runtime_security.config import parse
from runtime_security.reporting import json_report, markdown_report
from runtime_security.runner import RunReport, load_verification

FIX = Path(__file__).parent / "fixtures" / "verification"
BASE = "http://127.0.0.1:3000"
READER_PATH = Path(__file__).resolve().parents[3] / "skills/06-security/17-security-audit/scripts/read_phase3_report.py"
SECRETS = {
    "bearer": "FAKE-V13-BEARER-7f3a9c2e1b",
    "cookie": "FAKE-V13-COOKIE-44aa19be2c",
    "setcookie": "FAKE-V13-SETCOOKIE-903bd1",
    "query": "FAKE-V13-QUERY-SESSION-5d2e",
    "password": "FAKE-V13-PASSWORD-e81f0a",
    "apikey": "FAKE-V13-APIKEY-2c4d6e8f",
    "refresh": "FAKE-V13-REFRESH-b7c9d1",
    "basic": "RkFLRS1WMTMtQkFTSUMtY3JlZGVudGlhbA",
}


def reader():
    spec = importlib.util.spec_from_file_location("read_phase3_report", READER_PATH)
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


def leaky_results() -> dict:
    s = SECRETS
    finding = {"id": "RT-IDOR-001", "severity": "HIGH", "confidence": "HIGH", "title": "Cross-actor object readable",
               "endpoint": f"GET /objects/object-b?session={s['query']}", "expected": "denied",
               "actual": f"allowed; Authorization: Bearer {s['bearer']}",
               "evidence": f"Cookie: sid={s['cookie']} | Set-Cookie: sid={s['setcookie']}; HttpOnly",
               "impact": f"password={s['password']}", "recommendation": f"api_key={s['apikey']}",
               "validation": f"Basic {s['basic']}", "status": "OPEN", "notes": [f"refresh_token={s['refresh']}"]}
    return {
        "schema_version": "1.0", "kind": "vibe-code-engineering/verification-results",
        "producer": {"name": "hand-written-v13-shape", "version": "0.0.0"},
        "target": {"base_url": BASE},
        "areas": {
            "session": {"status": "EXECUTED", "runtime_checks_executed": True, "requests_count": 1,
                        "evidence": [{"check": f"S2 continuity token {s['bearer']}", "expected": "allowed", "observed": "allowed",
                                      "endpoint": f"GET /account?access_token={s['query']}", "fingerprint": "0a1b2c3d4e5f"}],
                        "limitations": [f"sessionid={s['cookie']}"]},
            "idor_bola": {"status": "FAIL", "runtime_checks_executed": True, "requests_count": 4, "findings": [finding],
                          "evidence": [{"check": "I2 other actor object", "expected": "denied", "observed": "allowed"}]},
            "tenant_isolation": {"status": "PASS", "runtime_checks_executed": True, "requests_count": 4,
                                 "evidence": [{"check": "T2 cross-tenant", "expected": "denied", "observed": "denied"}]},
        },
    }


@pytest.fixture()
def written(tmp_path):
    p = tmp_path / "results.json"
    p.write_text(json.dumps(leaky_results()), encoding="utf-8")
    cfg = parse({"target": {"base_url": BASE, "environment": "local", "production": False},
                 "verification_results": {"path": str(p)}})
    r = RunReport(cfg=cfg, safety_reason="local target", refused=False)
    load_verification(cfg, r)
    out = tmp_path / "out"
    json_report.write(r, out)
    markdown_report.write(r, out)
    return r, out


def _assert_clean(text: str) -> None:
    for name, value in SECRETS.items():
        assert value not in text, name


def test_shape_preserved(written):
    r, out = written
    data = json.loads((out / "runtime-security-report.json").read_text(encoding="utf-8"))
    subs = data["authorization"]["subareas"]
    assert data["auth_areas"]["session"]["status"] == "EXECUTED" and data["auth_areas"]["session"]["source"] == "imported"
    assert (subs["idor_bola"]["status"], subs["tenant_isolation"]["status"]) == ("FAIL", "PASS")
    assert subs["idor_bola"]["findings"] == ["RT-IDOR-001"] and data["authorization"]["status"] == "FAIL"
    ev = data["auth_areas"]["session"]["evidence"][0]
    assert set(ev) == {"check", "expected", "observed", "endpoint", "fingerprint"} and ev["fingerprint"] == "0a1b2c3d4e5f"
    assert data["verification_import"]["redactions"] >= 8 and data["verification_import"]["credentials_read"] is False


def test_no_secret_in_json_or_markdown(written):
    _, out = written
    for f in out.iterdir():
        _assert_clean(f.read_text(encoding="utf-8"))


def test_no_secret_in_exposed_evidence_fields(written):
    _, out = written
    data = json.loads((out / "runtime-security-report.json").read_text(encoding="utf-8"))
    exposed = [data["auth_areas"]["session"]["evidence"], data["auth_areas"]["session"]["limitations"],
               data["authorization"]["subareas"]["idor_bola"]["evidence"], data["findings"]]
    _assert_clean(json.dumps(exposed))


def test_reader_summary_of_generated_report_is_clean(written):
    _, out = written
    r = reader()
    s = r.build_summary(r.load(out))
    _assert_clean(r.render(s) + json.dumps(s))
    assert s["idor_bola"]["status"] == "FAIL" and s["session"]["status"] == "EXECUTED"


@pytest.mark.xfail(strict=True, reason="implementation gap: read_phase3_report.py prints finding text without its own "
                                        "redaction; the v1.3 design (section 18) requires every consumer to redact again")
def test_reader_redacts_hand_written_reports_independently():
    """Design section 18: every consumer redacts again. The reader currently prints finding text as stored."""
    r = reader()
    data = json.loads(json.dumps(_hand_written_phase3_report()))
    _assert_clean(r.render(r.build_summary(data)))


def _hand_written_phase3_report() -> dict:
    s = SECRETS
    return {"schema_version": "1.0", "tool": {"name": "phase3-runtime-security", "version": "x"},
            "target": {"base_url": BASE}, "environment": {"name": "local", "production": False},
            "safety": {"allowed": True, "reason": "local"}, "checks": [], "summary": {"result": "FAIL", "findings_by_severity": {}},
            "exit_code": 2, "limitations": [],
            "findings": [{"id": "RT-IDOR-001", "category": "idor", "severity": "HIGH", "confidence": "HIGH", "title": "t",
                          "endpoint": f"GET /objects/b?token={s['query']}", "expected": "e", "actual": f"Bearer {s['bearer']}",
                          "evidence": f"Cookie: sid={s['cookie']}", "impact": "i", "recommendation": "r", "validation": "v",
                          "status": "OPEN", "blocking": True}]}
