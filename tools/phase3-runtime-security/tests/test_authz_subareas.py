"""Authorization sub-areas and reserved RT-IDOR / RT-TENANT namespaces (reporting groundwork only).

No requests, no credentials, no generated findings: every sub-area is NOT VERIFIED.
"""

from __future__ import annotations

import importlib.util
import json
import re
import socket
from pathlib import Path

import pytest
from conftest import full_report

from runtime_security.authz.status import SUBAREAS, authz_area_status, authz_subareas
from runtime_security.config import parse
from runtime_security.models import FINDING_ID_RE, ID_PREFIX, Confidence, Finding, Severity
from runtime_security.reporting import json_report, markdown_report
from runtime_security.runner import RunReport, run_all

READER_PATH = Path(__file__).resolve().parents[3] / "skills/06-security/17-security-audit/scripts/read_phase3_report.py"
SUBAREA_KEYS = ["authorization", "idor_bola", "tenant_isolation"]


def reader():
    spec = importlib.util.spec_from_file_location("read_phase3_report", READER_PATH)
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


def base_report(**kw) -> RunReport:
    cfg = parse({"target": {"base_url": "http://127.0.0.1:3000", "environment": "local", "production": False}})
    return RunReport(cfg=cfg, safety_reason="local target", refused=False, **kw)


def finding(category: str, fid: str) -> Finding:
    return Finding(category=category, severity=Severity.HIGH, confidence=Confidence.HIGH, title="imported result",
                   endpoint="GET /api/items/<redacted>", expected="denied", actual="allowed", evidence="imported fixture",
                   impact="i", recommendation="r", validation="v", id=fid)


def write(tmp_path: Path, data: dict) -> Path:
    (tmp_path / "runtime-security-report.json").write_text(json.dumps(data), encoding="utf-8")
    return tmp_path


def assert_not_verified_block(block: dict) -> None:
    assert block["status"] == "NOT VERIFIED"
    assert block["runtime_checks_executed"] is False and block["credentials_read"] is False
    assert block["findings"] == []


# --- report model -------------------------------------------------------------------------------------------------

def test_all_three_subareas_not_verified():
    a = authz_area_status([], refused=False)
    assert list(a["subareas"]) == SUBAREA_KEYS
    for block in a["subareas"].values():
        assert_not_verified_block(block)
    assert {b["namespace"] for b in a["subareas"].values()} == {"RT-AUTHZ-*", "RT-IDOR-*", "RT-TENANT-*"}
    # top-level Phase 3C fields unchanged
    assert a["status"] == "NOT VERIFIED" and a["runtime_checks_executed"] is False and a["credentials_read"] is False
    assert a["scope"] == ["authorization", "IDOR/BOLA", "tenant isolation"] and a["findings"] == []


def test_refused_subareas_not_verified():
    subs = authz_subareas([], refused=True)
    for block in subs.values():
        assert_not_verified_block(block)
        assert block["reason"].startswith("Safety gate refused")


def test_subareas_never_pass_or_fail_even_with_reserved_findings():
    fs = [finding("authorization", "RT-AUTHZ-001"), finding("idor", "RT-IDOR-001"), finding("tenant_isolation", "RT-TENANT-001")]
    subs = authz_subareas(fs, refused=False)
    assert {k: b["status"] for k, b in subs.items()} == dict.fromkeys(SUBAREA_KEYS, "NOT VERIFIED")
    assert subs["idor_bola"]["findings"] == ["RT-IDOR-001"] and subs["tenant_isolation"]["findings"] == ["RT-TENANT-001"]
    # top-level FAIL semantics unchanged: only RT-AUTHZ-* can make the area FAIL
    assert authz_area_status(fs, refused=False)["findings"] == ["RT-AUTHZ-001"]
    assert authz_area_status(fs[1:], refused=False)["status"] == "NOT VERIFIED"


def test_new_report_json_contains_subareas_and_no_synthetic_findings(unsafe_app):
    report = full_report(unsafe_app.url)
    data = json_report.build(report)
    subs = data["authorization"]["subareas"]
    assert list(subs) == SUBAREA_KEYS
    for block in subs.values():
        assert_not_verified_block(block)
    assert not any(re.match(r"RT-(AUTHZ|IDOR|TENANT)-", f["id"]) for f in data["findings"])
    assert not any(f["category"] in ("authorization", "idor", "tenant_isolation") for f in data["findings"])
    json.dumps(data)


def test_markdown_subarea_table(safe_app):
    md = markdown_report.render(full_report(safe_app.url))
    section = md.split("## Authorization\n", 1)[1].split("## Authorization Findings", 1)[0]
    for label, namespace in (("Authorization", "RT-AUTHZ-*"), ("IDOR/BOLA", "RT-IDOR-*"), ("Tenant isolation", "RT-TENANT-*")):
        assert f"| {label} | NOT VERIFIED | `{namespace}` | no | no |" in section
    assert md.split("## Authorization Findings", 1)[1].lstrip().startswith("None.")


# --- finding prefixes ---------------------------------------------------------------------------------------------

@pytest.mark.parametrize("fid", ["RT-IDOR-001", "RT-TENANT-001", "RT-IDOR-999", "RT-TENANT-042"])
def test_idor_tenant_ids_accepted(fid):
    assert re.fullmatch(FINDING_ID_RE, fid)
    assert re.fullmatch(reader().FINDING_ID, fid)


@pytest.mark.parametrize("fid", ["RT-IDOR-1", "RT-TENANT-0001", "RT-IDORX-001", "RT-TENANTS-001", "RT-BOLA-001",
                                 "RT-idor-001", "IDOR-001", "RT-IDOR-001x", "RT--001"])
def test_invalid_prefixes_rejected(fid):
    assert not re.fullmatch(FINDING_ID_RE, fid)
    assert not reader().FINDING_ID.match(fid)


def test_prefixes_reserved_but_no_check_generates_them():
    assert ID_PREFIX["idor"] == "IDOR" and ID_PREFIX["tenant_isolation"] == "TENANT"
    cfg = parse({"target": {"base_url": "http://127.0.0.1:9", "environment": "local", "production": True}})
    report = run_all(cfg)   # refused before any request
    assert report.requests_sent == 0 and report.findings == []


def test_imported_ids_kept_out_of_phase3a_findings_section():
    fs = [finding("idor", "RT-IDOR-001"), finding("tenant_isolation", "RT-TENANT-001")]
    md = markdown_report.render(base_report(findings=fs))
    phase3a_part = md.split("## Findings", 1)[1].split("## Authentication", 1)[0]
    authz_part = md.split("## Authorization Findings", 1)[1]
    assert "RT-IDOR-001" not in phase3a_part and "RT-TENANT-001" not in phase3a_part
    assert "RT-IDOR-001" in authz_part and "RT-TENANT-001" in authz_part


# --- reader -------------------------------------------------------------------------------------------------------

def test_reader_old_report_without_subareas(tmp_path, safe_app):
    r = reader()
    data = json_report.build(full_report(safe_app.url))
    data["authorization"].pop("subareas")
    s = r.build_summary(r.load(write(tmp_path, data)))
    assert len(s["areas"]) == 9 and {a["area"]: a for a in s["areas"]}["Authorization"]["status"] == "NOT VERIFIED"
    assert [a["key"] for a in s["authorization_subareas"]] == SUBAREA_KEYS
    for a in s["authorization_subareas"]:
        assert a["status"] == "NOT VERIFIED" and a["reported"] is False and a["findings"] == []
        assert a["runtime_checks_executed"] is False and a["credentials_read"] is False


def test_reader_report_without_authorization_block(tmp_path, safe_app):
    r = reader()
    data = json_report.build(full_report(safe_app.url))
    data.pop("authorization")
    s = r.build_summary(r.load(write(tmp_path, data)))
    assert [a["status"] for a in s["authorization_subareas"]] == ["NOT VERIFIED"] * 3
    assert "AUTHORIZATION SUB-AREAS:" in r.render(s)


def test_reader_new_report_exposes_subareas(tmp_path, safe_app):
    r = reader()
    json_report.write(full_report(safe_app.url), tmp_path)
    s = r.build_summary(r.load(tmp_path))
    assert len(s["areas"]) == 9
    subs = {a["key"]: a for a in s["authorization_subareas"]}
    assert list(subs) == SUBAREA_KEYS and all(a["reported"] and a["status"] == "NOT VERIFIED" for a in subs.values())
    text = r.render(s)
    for label in ("Authorization", "IDOR/BOLA", "Tenant isolation"):
        assert f"- {label}: NOT VERIFIED (runtime checks executed: no; credentials read: no;" in text


def test_reader_missing_single_subarea_defaults_not_verified(tmp_path, safe_app):
    r = reader()
    data = json_report.build(full_report(safe_app.url))
    del data["authorization"]["subareas"]["idor_bola"]
    data["authorization"]["subareas"]["tenant_isolation"] = "garbage"
    subs = {a["key"]: a for a in r.build_summary(r.load(write(tmp_path, data)))["authorization_subareas"]}
    assert subs["idor_bola"]["status"] == "NOT VERIFIED" and subs["idor_bola"]["reported"] is False
    assert subs["tenant_isolation"]["status"] == "NOT VERIFIED" and subs["tenant_isolation"]["reported"] is False
    assert subs["authorization"]["reported"] is True


def test_reader_does_not_accept_unbacked_pass_or_fail(tmp_path, safe_app):
    r = reader()
    data = json_report.build(full_report(safe_app.url))
    data["authorization"]["subareas"]["idor_bola"]["status"] = "PASS"          # claims PASS without executed checks
    data["authorization"]["subareas"]["tenant_isolation"]["status"] = "BOGUS"
    subs = {a["key"]: a for a in r.build_summary(r.load(write(tmp_path, data)))["authorization_subareas"]}
    assert subs["idor_bola"]["status"] == "NOT VERIFIED" and subs["tenant_isolation"]["status"] == "NOT VERIFIED"


def test_reader_no_synthetic_findings(tmp_path, safe_app):
    r = reader()
    json_report.write(full_report(safe_app.url), tmp_path)
    data = r.load(tmp_path)
    s = r.build_summary(data)
    assert s["findings"] == data["findings"]
    assert all(a["findings"] == [] for a in s["authorization_subareas"])
    assert "RT-IDOR" not in r.render(s) and "RT-TENANT" not in r.render(s)


def test_reader_accepts_idor_tenant_ids_and_rejects_malformed(tmp_path):
    r = reader()
    fs = [finding("idor", "RT-IDOR-001"), finding("tenant_isolation", "RT-TENANT-001")]
    write(tmp_path, json_report.build(base_report(findings=fs)))
    assert r.main([str(tmp_path)]) == 0
    s = r.build_summary(r.load(tmp_path))
    subs = {a["key"]: a for a in s["authorization_subareas"]}
    assert subs["idor_bola"]["findings"] == ["RT-IDOR-001"] and subs["tenant_isolation"]["findings"] == ["RT-TENANT-001"]
    assert subs["idor_bola"]["status"] == "NOT VERIFIED"
    for bad in ("RT-IDOR-01", "RT-TENANTX-001"):
        fs[0].id = bad
        write(tmp_path, json_report.build(base_report(findings=fs)))
        assert r.main([str(tmp_path)]) == 3


# --- no requests / no credentials ---------------------------------------------------------------------------------

def test_subarea_reporting_makes_no_requests_and_has_no_credentials(monkeypatch, tmp_path):
    monkeypatch.setattr(socket.socket, "connect", lambda *a, **k: (_ for _ in ()).throw(AssertionError("no network")))
    report = base_report()
    report.zap = __import__("runtime_security.zap.detect", fromlist=["ZapStatus"]).ZapStatus(False)
    json_report.write(report, tmp_path)
    markdown_report.write(report, tmp_path)
    assert report.requests_sent == 0
    blob = "".join(p.read_text(encoding="utf-8") for p in tmp_path.iterdir())
    subs = json.loads((tmp_path / "runtime-security-report.json").read_text(encoding="utf-8"))["authorization"]["subareas"]
    allowed_keys = {"area", "status", "reason", "namespace", "runtime_checks_executed", "credentials_read", "findings"}
    assert all(set(b) == allowed_keys for b in subs.values())
    for word in ("password", "passwd", "secret", "token", "bearer", "api_key", "apikey", "cookie_value"):
        assert word not in json.dumps(subs).lower()
    assert "fake-password" not in blob


def test_subarea_definitions_are_static():
    assert list(SUBAREAS) == SUBAREA_KEYS
