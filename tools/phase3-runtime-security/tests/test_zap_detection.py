"""OWASP ZAP detection and reporting (read-only). ZAP is never run; tests do not need ZAP installed."""

from __future__ import annotations

import importlib.util
import json
import os
import socket
import subprocess
from pathlib import Path

import pytest
from conftest import make_cfg

from runtime_security.config import parse
from runtime_security.reporting import json_report, markdown_report
from runtime_security.runner import RunReport, run_all
from runtime_security.zap import detect
from runtime_security.zap.detect import REASON_AVAILABLE_NOT_RUN, REASON_UNAVAILABLE, ZapStatus, detect_zap, normalize, parse_version

READER_PATH = Path(__file__).resolve().parents[3] / "skills/06-security/17-security-audit/scripts/read_phase3_report.py"


def load_reader():
    spec = importlib.util.spec_from_file_location("read_phase3_report", READER_PATH)
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


@pytest.fixture()
def no_zap(monkeypatch):
    monkeypatch.setattr(detect.shutil, "which", lambda name: None)
    monkeypatch.setattr(detect, "_install_candidates", lambda: [])


@pytest.fixture()
def fake_zap(tmp_path, monkeypatch):
    home = tmp_path / "Zed Attack Proxy"
    home.mkdir()
    launcher = home / ("zap.bat" if os.name == "nt" else "zap.sh")
    launcher.write_text("echo this fake launcher must never be executed\nexit 99\n")
    (home / "zap-2.16.1.jar").write_bytes(b"")
    monkeypatch.setattr(detect.shutil, "which", lambda name: str(launcher) if name == launcher.name else None)
    monkeypatch.setattr(detect, "_install_candidates", lambda: [])
    return launcher


def report_for(cfg, zap: ZapStatus | None = None) -> RunReport:
    r = RunReport(cfg=cfg, safety_reason="local target", refused=False)
    if zap is not None:
        r.zap = zap
    return r


# 1. unavailable
def test_zap_unavailable(no_zap):
    z = detect_zap()
    assert z == ZapStatus(False) and z.authentication_testing == "not available" and z.reason == REASON_UNAVAILABLE


# 2. available via mocked executable on PATH, and via install location
def test_zap_available_on_path(fake_zap):
    z = detect_zap()
    assert z.available and z.source == "path" and z.location == str(fake_zap) and z.version == "2.16.1"
    assert z.authentication_testing == "available" and z.reason == REASON_AVAILABLE_NOT_RUN


def test_zap_available_in_install_location(tmp_path, monkeypatch):
    monkeypatch.setattr(detect.shutil, "which", lambda name: None)
    launcher = tmp_path / "zap.sh"
    launcher.write_text("exit 99\n")
    monkeypatch.setattr(detect, "_install_candidates", lambda: [tmp_path / "missing" / "zap.sh", launcher])
    z = detect_zap()
    assert z.available and z.source == "install-location" and z.version is None


# 3. version parsing
def test_version_parsing(tmp_path):
    assert parse_version(tmp_path) is None
    (tmp_path / "zap-2.15.0.jar").write_bytes(b"")
    (tmp_path / "zap-extra.jar").write_bytes(b"")
    assert parse_version(tmp_path) == "2.15.0"
    (tmp_path / "zap-2.16.0.jar").write_bytes(b"")
    assert parse_version(tmp_path) is None  # ambiguous: two versions
    assert parse_version(tmp_path / "does-not-exist") is None


# 4. malformed detection results
@pytest.mark.parametrize("raw", [None, "yes", [], {}, {"available": "true"}, {"available": True},
                                 {"available": True, "location": "bad\npath"}, {"available": 1, "location": "/x"}])
def test_malformed_detection_results_are_unavailable(raw):
    assert normalize(raw).available is False


def test_normalize_sanitises_fields():
    z = normalize({"available": True, "location": "/opt/zap/zap.sh", "version": "2.16.0; rm -rf /", "source": "evil"})
    assert z.available and z.version is None and z.source == "unknown"
    z = normalize({"available": False, "version": "2.16.0", "location": "/x", "source": "path"})
    assert z == ZapStatus(False)


# 5. report serialization + 7/8/9 statuses
def test_report_serialization_unavailable():
    report = report_for(parse({"target": {"base_url": "http://127.0.0.1:3000", "environment": "local", "production": False}}), ZapStatus(False))
    data = json_report.build(report)
    assert data["zap"] == {"available": False, "version": None, "source": "unknown", "location": None,
                           "authentication_testing": "not available", "authenticated_testing_executed": False}
    for area in ("authentication", "session"):
        assert data["auth_areas"][area]["status"] == "NOT VERIFIED"
        assert data["auth_areas"][area]["reason"].startswith(REASON_UNAVAILABLE)
    assert data["findings"] == []  # unavailability is a status, never a finding
    md = markdown_report.render(report)
    auth_section = md.split("## Authentication\n", 1)[1].split("## Session", 1)[0]
    assert "OWASP ZAP: Unavailable" in auth_section and "authenticated testing was not executed" in auth_section


def test_available_but_not_run_is_still_not_verified():
    zap = ZapStatus(True, "2.16.1", "path", "/opt/zap/zap.sh")
    report = report_for(parse({"target": {"base_url": "http://127.0.0.1:3000", "environment": "local", "production": False}}), zap)
    data = json_report.build(report)
    assert data["zap"]["available"] is True and data["zap"]["authenticated_testing_executed"] is False and data["zap"]["authentication_testing"] == "available"
    for area in ("authentication", "session"):
        assert data["auth_areas"][area]["status"] == "NOT VERIFIED"
        assert data["auth_areas"][area]["reason"].startswith(REASON_AVAILABLE_NOT_RUN)
    assert data["findings"] == []
    assert "OWASP ZAP: Available \\(version 2.16.1" in markdown_report.render(report)


def test_refused_target_reason_unchanged():
    cfg = parse({"target": {"base_url": "http://127.0.0.1:9", "environment": "local", "production": True}})
    report = run_all(cfg)
    report.zap = ZapStatus(False)
    data = json_report.build(report)
    assert report.requests_sent == 0 and data["auth_areas"]["authentication"]["reason"].startswith("safety gate refused")


# 6. reader output
@pytest.mark.parametrize("zap,expected", [(ZapStatus(False), "OWASP ZAP: Unavailable; authenticated testing not executed"),
                                          (ZapStatus(True, "2.16.1", "path", "/opt/zap/zap.sh"), "OWASP ZAP: Available (version 2.16.1); authenticated testing not executed")])
def test_reader_output(tmp_path, zap, expected):
    reader = load_reader()
    report = report_for(parse({"target": {"base_url": "http://127.0.0.1:3000", "environment": "local", "production": False}}), zap)
    (tmp_path / "runtime-security-report.json").write_text(json.dumps(json_report.build(report)))
    summary = reader.build_summary(reader.load(tmp_path))
    text = reader.render(summary)
    assert expected in text
    areas = {a["area"]: a for a in summary["areas"]}
    assert areas["Authentication"]["status"] == "NOT VERIFIED" and areas["Session"]["status"] == "NOT VERIFIED"
    assert zap.reason in areas["Authentication"]["detail"]


def test_reader_old_report_without_zap(tmp_path, no_zap):
    reader = load_reader()
    data = json_report.build(report_for(parse({"target": {"base_url": "http://127.0.0.1:3000", "environment": "local", "production": False}})))
    data.pop("zap")
    (tmp_path / "runtime-security-report.json").write_text(json.dumps(data))
    assert "Unavailable (not reported by this runtime report)" in reader.render(reader.build_summary(reader.load(tmp_path)))


# 10/11 + no process started: detection and reporting with guards
def test_detection_and_reporting_start_no_process_no_network_no_credentials(monkeypatch, fake_zap, tmp_path):
    def forbid(*a, **k):
        raise AssertionError("no process may be started")

    for name in ("Popen", "run", "call", "check_call", "check_output"):
        monkeypatch.setattr(subprocess, name, forbid)
    monkeypatch.setattr(os, "system", forbid)
    monkeypatch.setattr(socket.socket, "connect", lambda *a, **k: (_ for _ in ()).throw(AssertionError("no network")))

    class Guard(dict):
        def _c(self, k):
            if "PASSWORD" in str(k).upper() or str(k).upper().startswith(("TEST_USER", "ZAP_TEST")):
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

    guarded = Guard(os.environ)
    guarded.update({"TEST_USER_PASSWORD": "fake-password-only-for-tests", "ZAP_TEST_USER_A_PASSWORD": "fake-password-only-for-tests"})
    monkeypatch.setattr(os, "environ", guarded)
    with pytest.raises(AssertionError):
        os.environ["ZAP_TEST_USER_A_PASSWORD"]  # control: guard fires
    cfg = parse({"target": {"base_url": "http://127.0.0.1:3000", "environment": "local", "production": False},
                 "authentication": {"enabled": False},
                 "credentials": {"username_env": "TEST_USER_EMAIL", "password_env": "TEST_USER_PASSWORD"}})
    report = report_for(cfg)
    out = tmp_path / "out"
    json_report.write(report, out)
    markdown_report.write(report, out)
    assert report.zap.available and report.zap.version == "2.16.1"
    blob = "".join(p.read_text(encoding="utf-8") for p in out.iterdir())
    assert "fake-password-only-for-tests" not in blob


# 12. Phase 3A behaviour unchanged by ZAP detection
def test_phase3a_findings_identical_with_and_without_zap(unsafe_app, no_zap):
    a = run_all(make_cfg(unsafe_app.url))
    a.zap = ZapStatus(False)
    b = run_all(make_cfg(unsafe_app.url))
    b.zap = ZapStatus(True, "2.16.1", "path", "/opt/zap/zap.sh")
    ja, jb = json_report.build(a), json_report.build(b)
    assert [(f["id"], f["title"], f["severity"]) for f in ja["findings"]] == [(f["id"], f["title"], f["severity"]) for f in jb["findings"]]
    assert ja["exit_code"] == jb["exit_code"] == 2 and a.requests_sent == b.requests_sent


def test_this_machine_detection_is_read_only_and_consistent():
    """Real detection on this machine (no mocks): must not raise, must return a valid status."""
    z = detect_zap()
    assert normalize(z) == z
