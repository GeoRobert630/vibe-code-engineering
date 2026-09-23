"""Phase 3C authorization coverage status (reporting only): no requests, no credentials, no findings generated."""

from __future__ import annotations

import importlib.util
import json
import os
import socket
from pathlib import Path

import pytest
from conftest import full_report, make_cfg
from mock_app import MockServer

from runtime_security.authz.status import REASON, STATUSES, authz_area_status
from runtime_security.config import parse
from runtime_security.models import FINDING_ID_RE, Confidence, Finding, Severity
from runtime_security.reporting import json_report, markdown_report
from runtime_security.runner import RunReport, run_all

READER_PATH = Path(__file__).resolve().parents[3] / "skills/06-security/17-security-audit/scripts/read_phase3_report.py"


def reader():
    spec = importlib.util.spec_from_file_location("read_phase3_report", READER_PATH)
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


def base_report(**kw) -> RunReport:
    cfg = parse({"target": {"base_url": "http://127.0.0.1:3000", "environment": "local", "production": False}})
    return RunReport(cfg=cfg, safety_reason="local target", refused=False, **kw)


def test_statuses_and_default_not_verified():
    assert STATUSES == ("PASS", "FAIL", "NOT CONFIGURED", "NOT VERIFIED", "INCOMPLETE")
    a = authz_area_status([], refused=False)
    assert a["status"] == "NOT VERIFIED" and a["reason"] == REASON
    assert a["runtime_checks_executed"] is False and a["credentials_read"] is False and a["findings"] == []
    assert a["scope"] == ["authorization", "IDOR/BOLA", "tenant isolation"]
    assert "Layer 2 source-code security review" in REASON and "not a security verdict" in REASON


def test_authorization_in_json_and_no_authz_findings(unsafe_app):
    report = full_report(unsafe_app.url)
    data = json_report.build(report)
    assert data["authorization"]["status"] == "NOT VERIFIED"
    assert not any(f["id"].startswith("RT-AUTHZ-") for f in data["findings"])
    assert data["auth_areas"]["authentication"]["status"] == "NOT VERIFIED"
    assert data["auth_areas"]["session"]["status"] == "NOT VERIFIED"
    json.dumps(data)


def test_authorization_in_markdown_separate_from_auth(safe_app):
    md = markdown_report.render(full_report(safe_app.url))
    section = md.split("## Authorization\n", 1)[1].split("## Authorization Findings", 1)[0]
    assert "Status: **NOT VERIFIED**" in section and "Reason:" in section
    assert "not executed by this Phase 3 runtime implementation" in section and "not a security verdict" in section
    assert "Runtime authorization checks executed: no. Credentials read: no." in section
    assert md.index("## Authentication\n") < md.index("## Session\n") < md.index("## Authorization\n")
    assert md.split("## Authorization Findings", 1)[1].lstrip().startswith("None.")


def test_refused_target_authorization_not_verified():
    cfg = parse({"target": {"base_url": "http://127.0.0.1:9", "environment": "local", "production": True}})
    report = run_all(cfg)
    data = json_report.build(report)
    assert report.refused and report.requests_sent == 0 and report.exit_code == 3
    assert data["authorization"]["status"] == "NOT VERIFIED" and data["authorization"]["reason"].startswith("Safety gate refused")


def test_reserved_namespace_imported_findings():
    f = Finding(category="authorization", severity=Severity.HIGH, confidence=Confidence.HIGH, title="imported",
                endpoint="GET /x", expected="denied", actual="allowed", evidence="imported fixture", impact="i",
                recommendation="r", validation="v", id="RT-AUTHZ-001")
    import re

    assert re.fullmatch(FINDING_ID_RE, "RT-AUTHZ-001") and not re.fullmatch(FINDING_ID_RE, "RT-AUTHZ-1")
    data = json_report.build(base_report(findings=[f]))
    assert data["authorization"]["status"] == "FAIL" and data["authorization"]["findings"] == ["RT-AUTHZ-001"]
    md = markdown_report.render(base_report(findings=[f]))
    findings_part = md.split("## Findings", 1)[1].split("## Authentication", 1)[0]
    assert "RT-AUTHZ-001" not in findings_part and "RT-AUTHZ-001" in md.split("## Authorization Findings", 1)[1]


def test_reader_reads_authorization_area(tmp_path, safe_app):
    r = reader()
    json_report.write(full_report(safe_app.url), tmp_path)
    summary = r.build_summary(r.load(tmp_path))
    areas = {a["area"]: a for a in summary["areas"]}
    assert areas["Authorization"]["status"] == "NOT VERIFIED" and "Layer 2" in areas["Authorization"]["detail"]
    assert areas["Authentication"]["status"] == "NOT VERIFIED" and areas["Session"]["status"] == "NOT VERIFIED"
    text = r.render(summary)
    assert "- Authorization: NOT VERIFIED" in text and "- Authentication: NOT VERIFIED" in text


def test_reader_backward_compatible_without_authorization(tmp_path, safe_app):
    r = reader()
    data = json_report.build(full_report(safe_app.url))
    data.pop("authorization")
    (tmp_path / "runtime-security-report.json").write_text(json.dumps(data))
    areas = {a["area"]: a for a in r.build_summary(r.load(tmp_path))["areas"]}
    assert areas["Authorization"]["status"] == "NOT VERIFIED" and "not reported" in areas["Authorization"]["detail"]


def test_reader_accepts_authz_ids_rejects_malformed(tmp_path):
    r = reader()
    f = Finding(category="authorization", severity=Severity.MEDIUM, confidence=Confidence.MEDIUM, title="t", endpoint="GET /x",
                expected="e", actual="a", evidence="ev", impact="i", recommendation="r", validation="v", id="RT-AUTHZ-001")
    (tmp_path / "runtime-security-report.json").write_text(json.dumps(json_report.build(base_report(findings=[f]))))
    assert r.main([str(tmp_path)]) == 0
    f.id = "RT-AUTHZ-01"
    (tmp_path / "runtime-security-report.json").write_text(json.dumps(json_report.build(base_report(findings=[f]))))
    assert r.main([str(tmp_path)]) == 3


def test_reporting_makes_no_requests_and_reads_no_credentials(monkeypatch, tmp_path):
    monkeypatch.setattr(socket.socket, "connect", lambda *a, **k: (_ for _ in ()).throw(AssertionError("no network")))

    class Guard(dict):
        def _c(self, k):
            if any(x in str(k).upper() for x in ("PASSWORD", "TOKEN", "TEST_USER", "ACTOR")):
                raise AssertionError(f"credential variable {k} accessed")

        def __getitem__(self, k):
            self._c(k)
            return super().__getitem__(k)

        def get(self, k, d=None):
            self._c(k)
            return super().get(k, d)

        def __contains__(self, k):
            self._c(k)
            return super().__contains__(k)

    g = Guard(os.environ)
    g.update({"TEST_USER_PASSWORD": "fake-password-only-for-tests"})
    monkeypatch.setattr(os, "environ", g)
    with pytest.raises(AssertionError):
        os.environ["TEST_USER_PASSWORD"]  # control
    report = base_report()
    report.zap = __import__("runtime_security.zap.detect", fromlist=["ZapStatus"]).ZapStatus(False)
    json_report.write(report, tmp_path)
    markdown_report.write(report, tmp_path)
    blob = "".join(p.read_text(encoding="utf-8") for p in tmp_path.iterdir())
    assert "fake-password-only-for-tests" not in blob and '"status": "NOT VERIFIED"' in blob


def test_request_count_unchanged_by_authorization_status(unsafe_app):
    a = run_all(make_cfg(unsafe_app.url))
    before = a.requests_sent
    json_report.build(a)
    markdown_report.render(a)
    assert a.requests_sent == before and a.exit_code == 2
    with MockServer("safe") as s:
        assert full_report(s.url).exit_code == 0
