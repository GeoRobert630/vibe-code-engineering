"""ZAP baseline (passive) integration: command builder, parser, importer, correlation, reports.

Unit tests use fixture files only; no ZAP or Docker is needed or started.
"""

from __future__ import annotations

import importlib.util
import json
import os
import shutil
import subprocess
from pathlib import Path

import pytest
from conftest import make_cfg

from runtime_security import runner
from runtime_security.config import ConfigError, parse
from runtime_security.models import Confidence, Severity, Status
from runtime_security.reporting import json_report, markdown_report
from runtime_security.runner import run_all
from runtime_security.zap import baseline as zb
from runtime_security.zap.importer import import_alerts
from runtime_security.zap.results import ZapReportError, parse_console, parse_report, sanitized_report

FIX = Path(__file__).parent / "fixtures" / "zap"
READER_PATH = Path(__file__).resolve().parents[3] / "skills/06-security/17-security-audit/scripts/read_phase3_report.py"
SECRETS = ["abc123FAKESESSIONVALUE", "FakeLeakedPassw0rd", "FAKEBEARERTOKENVALUE0123456789", "FAKEQUERYTOKEN123"]


def zap_cfg(url: str, **zap):
    data = {"target": {"base_url": url, "environment": "local", "production": False},
            "cors": {"allowed_origins": ["https://app.example.test"]},
            "error_leakage": {"invalid_resource_path": "/api/items/not-a-valid-id", "missing_parameter_path": "/api/search"},
            "limits": {"delay_seconds": 0}, "zap_baseline": {"enabled": True, **zap}}
    return parse(data)


@pytest.fixture()
def fake_baseline(monkeypatch):
    """Replace the Docker run with fixture output copied into the output dir."""
    calls = []

    def fake(base_url, out_dir, image, spider_minutes, timeout_seconds):
        calls.append(base_url)
        out_dir.mkdir(parents=True, exist_ok=True)
        shutil.copy(FIX / "baseline-unsafe.json", out_dir / zb.REPORT_NAME)
        console = (FIX / "console-unsafe.txt").read_text()
        (out_dir / zb.OUTPUT_NAME).write_text(console)
        return zb.BaselineRun(True, True, "ZAP baseline (passive) executed", image, zb.container_target(base_url), 1, False,
                              ["docker", "run", "..."], str(out_dir / zb.REPORT_NAME), str(out_dir / zb.OUTPUT_NAME), console)

    monkeypatch.setattr(runner.zap_baseline_mod, "run_baseline", fake)
    return calls


# ------------------------------------------------------------------ command builder / safety

def test_command_is_baseline_only_single_mount_no_env(tmp_path):
    cmd = zb.build_command("docker", zb.DEFAULT_IMAGE, tmp_path / "zap", "http://host.docker.internal:3000/", 1)
    assert cmd[cmd.index(zb.DEFAULT_IMAGE) + 1] == "zap-baseline.py"
    assert "--pull=never" in cmd and "--rm" in cmd
    assert cmd.count("-v") == 1 and cmd[cmd.index("-v") + 1].endswith(":/zap/wrk:rw")
    assert str((tmp_path / "zap").resolve()) in cmd[cmd.index("-v") + 1]
    assert not any(a in ("-e", "--env", "--env-file") for a in cmd)
    assert "-J" in cmd and cmd[cmd.index("-J") + 1] == "zap-report.json"
    assert not any("full-scan" in a or "api-scan" in a for a in cmd)


@pytest.mark.parametrize("script", ["zap-full-scan.py", "zap-api-scan.py", "zap.sh"])
def test_active_scan_scripts_refused(tmp_path, script):
    with pytest.raises(zb.BaselineNotAllowed):
        zb.build_command("docker", zb.DEFAULT_IMAGE, tmp_path, "http://host.docker.internal:3000/", 1, script=script)


@pytest.mark.parametrize("target", ["ftp://x/", "http://user:pw@host/", "http://host/?token=x", "notaurl"])
def test_bad_zap_targets_refused(tmp_path, target):
    with pytest.raises(zb.BaselineNotAllowed):
        zb.build_command("docker", zb.DEFAULT_IMAGE, tmp_path, target, 1)


def test_container_target_maps_loopback_only():
    assert zb.container_target("http://127.0.0.1:3000") == "http://host.docker.internal:3000/"
    assert zb.container_target("http://localhost:8080/app") == "http://host.docker.internal:8080/app"
    assert zb.container_target("https://staging.example.test") == "https://staging.example.test/"


@pytest.mark.parametrize("bad", [{"enabled": "yes"}, {"image": "evil/zap"}, {"spider_minutes": 99}, {"timeout_seconds": 5}, {"mode": "full"}])
def test_invalid_zap_config_rejected(bad):
    data = {"target": {"base_url": "http://127.0.0.1:3000", "environment": "local", "production": False}, "zap_baseline": {"enabled": True, **bad}}
    with pytest.raises(ConfigError):
        parse(data)


def test_production_refused_before_zap(monkeypatch, tmp_path):
    called = []
    monkeypatch.setattr(runner.zap_baseline_mod, "run_baseline", lambda *a, **k: called.append(a))
    cfg = parse({"target": {"base_url": "http://127.0.0.1:9", "environment": "local", "production": True}, "zap_baseline": {"enabled": True}})
    report = run_all(cfg, zap_output_dir=tmp_path / "zap")
    assert report.refused and called == [] and report.requests_sent == 0
    assert report.zap_baseline["executed"] is False and "refused" in report.zap_baseline["reason"]
    assert not (tmp_path / "zap").exists()


def test_zap_unavailable_when_docker_missing(monkeypatch, tmp_path, safe_app):
    monkeypatch.setattr(zb.shutil, "which", lambda name: None)
    report = run_all(zap_cfg(safe_app.url), zap_output_dir=tmp_path / "zap")
    assert report.zap_baseline["available"] is False and report.zap_baseline["executed"] is False
    assert "docker is not installed" in report.zap_baseline["reason"]
    assert not report.zap_failed and report.exit_code == 0  # unavailability is not a failure or finding
    assert not any(f.category == "zap" for f in report.findings)


def test_zap_unavailable_when_image_missing_never_pulls(monkeypatch, tmp_path):
    seen = []

    def fake_run(cmd, **kw):
        seen.append(cmd)
        return subprocess.CompletedProcess(cmd, 1, "", "No such image")

    monkeypatch.setattr(zb.shutil, "which", lambda name: "/usr/bin/docker")
    monkeypatch.setattr(zb.subprocess, "run", fake_run)
    monkeypatch.setattr(zb.subprocess, "Popen", lambda *a, **k: (_ for _ in ()).throw(AssertionError("must not run ZAP")))
    run = zb.run_baseline("http://127.0.0.1:3000", tmp_path / "zap")
    assert not run.available and "never pulled" in run.reason
    assert seen == [["/usr/bin/docker", "image", "inspect", "--format", "{{.Id}}", zb.DEFAULT_IMAGE]]


# ------------------------------------------------------------------ parsing

def test_valid_report_parsing():
    version, alerts = parse_report((FIX / "baseline-unsafe.json").read_text())
    assert version == "2.17.0"
    ids = [a.plugin_id for a in alerts]
    assert set(ids) == {"10021", "10010", "10098", "90022", "99999", "10049", "10202"}
    a = next(x for x in alerts if x.plugin_id == "10021")
    assert (a.name, a.risk, a.confidence, a.cwe, a.count) == ("X-Content-Type-Options Header Missing", "Low", "Medium", "CWE-693", 2)
    assert a.instances[0].param == "x-content-type-options" and a.to_dict()["source"] == "OWASP ZAP"


def test_malformed_json_rejected():
    with pytest.raises(ZapReportError):
        parse_report((FIX / "malformed.json").read_text())
    with pytest.raises(ZapReportError):
        parse_report("[1, 2]")


def test_console_pass_warn_fail_info():
    rules, summary = parse_console((FIX / "console-unsafe.txt").read_text())
    assert summary == {"FAIL": 1, "WARN": 4, "INFO": 1, "PASS": 3}
    assert [r["id"] for r in rules["PASS"]] == ["10003", "10009", "10035"]
    assert {r["id"] for r in rules["WARN"]} == {"10021", "10010", "99999", "90022"}
    assert [r["id"] for r in rules["FAIL"]] == ["10098"] and [r["id"] for r in rules["INFO"]] == ["10049"]


def test_secret_redaction_in_parse_and_sanitized_file():
    raw = (FIX / "baseline-unsafe.json").read_text()
    _, alerts = parse_report(raw)
    blob = json.dumps([a.to_dict() for a in alerts]) + sanitized_report(raw)
    for s in SECRETS:
        assert s not in blob, s
    cookie = next(a for a in alerts if a.plugin_id == "10010").instances[0]
    assert cookie.evidence == "Set-Cookie: <redacted>" and "token=<redacted>" in cookie.url


# ------------------------------------------------------------------ importer / correlation

def test_import_policy_with_unsafe_phase3a(unsafe_app, fake_baseline, tmp_path):
    report = run_all(zap_cfg(unsafe_app.url), zap_output_dir=tmp_path / "zap")
    assert fake_baseline and report.zap_baseline["executed"]
    zap_findings = [f for f in report.findings if f.category == "zap"]
    # unknown rule (Medium risk, Low confidence) is the only new finding
    assert [f.id for f in zap_findings] == ["RT-ZAP-001"]
    f = zap_findings[0]
    assert (f.severity, f.confidence, f.status, f.source) == (Severity.MEDIUM, Confidence.LOW, Status.OPEN, "OWASP ZAP")
    assert "ZAP alert: 99999" in f.notes
    corr = {c["zap_alert_id"]: c for c in report.correlations}
    assert set(corr) == {"10021", "10010", "10098", "90022"}
    assert all(c["relation"] == "confirms" and c["phase3a_findings"] for c in corr.values())
    assert any(i.startswith("RT-HEADERS-") for i in corr["10021"]["phase3a_findings"])
    assert any(i.startswith("RT-COOKIE-") for i in corr["10010"]["phase3a_findings"])
    alerts = {a["plugin_id"]: a for a in report.zap_baseline["alerts"]}
    assert alerts["10049"]["disposition"].startswith("informational")
    assert "false positive" in alerts["10202"]["disposition"]
    assert alerts["10098"]["baseline_status"] == "FAIL" and alerts["10021"]["baseline_status"] == "WARN"
    # no duplicate blocking finding: Phase 3A ids unchanged, only one RT-ZAP added
    plain = run_all(make_cfg(unsafe_app.url))
    assert [x.id for x in plain.findings] == [x.id for x in report.findings if x.category != "zap"]


def test_import_with_safe_phase3a_creates_low_review_findings(safe_app, fake_baseline, tmp_path):
    report = run_all(zap_cfg(safe_app.url), zap_output_dir=tmp_path / "zap")
    zap = {f.notes[0]: f for f in report.findings if f.category == "zap"}
    assert zap["ZAP alert: 10021"].severity == Severity.LOW and zap["ZAP alert: 10021"].status == Status.REQUIRES_REVIEW
    related = {c["zap_alert_id"] for c in report.correlations if c["relation"] == "related-phase3a-passed"}
    assert "10021" in related
    assert not report.blocking  # nothing here is blocking under release policy


def test_high_risk_mapping_never_critical():
    from runtime_security.zap.results import ZapAlert

    a = ZapAlert("40012", "40012", "Cross Site Scripting (Reflected)", 3, "High", 3, "High", "CWE-79", 1)
    new, _, _ = import_alerts([a], [], set())
    assert new[0].severity == Severity.HIGH and new[0].confidence == Confidence.HIGH


# ------------------------------------------------------------------ reports / reader

def test_report_generation_and_redaction(unsafe_app, fake_baseline, tmp_path):
    out = tmp_path / "out"
    report = run_all(zap_cfg(unsafe_app.url), zap_output_dir=out / "zap")
    json_report.write(report, out)
    markdown_report.write(report, out)
    data = json.loads((out / "runtime-security-report.json").read_text())
    assert data["zap_baseline"]["summary"] == {"FAIL": 1, "WARN": 4, "INFO": 1, "PASS": 3}
    assert data["zap"]["source"] == "docker-image" and data["zap"]["version"] == "2.17.0"
    assert any(f["id"] == "RT-ZAP-001" for f in data["findings"])
    md = (out / "runtime-security-report.md").read_text()
    for heading in ("## ZAP Baseline", "### ZAP FAIL", "### ZAP WARN", "### ZAP INFO", "### Alerts", "### ZAP Findings", "## Correlated Findings"):
        assert heading in md
    assert "do NOT mean the application is secure" in md
    findings_section = md.split("## Findings", 1)[1].split("## Authentication", 1)[0]
    assert "RT-ZAP-001" not in findings_section
    blob = "".join(p.read_text(encoding="utf-8") for p in out.rglob("*") if p.is_file())
    for s in SECRETS:
        assert s not in blob, s


def test_reader_shows_zap_baseline(unsafe_app, fake_baseline, tmp_path):
    spec = importlib.util.spec_from_file_location("read_phase3_report", READER_PATH)
    reader = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(reader)
    out = tmp_path / "out"
    report = run_all(zap_cfg(unsafe_app.url), zap_output_dir=out / "zap")
    json_report.write(report, out)
    text = reader.render(reader.build_summary(reader.load(out)))
    assert "ZAP baseline (passive): executed, exit 1, FAIL 1, WARN 4, INFO 1, PASS 3" in text
    assert "not proof of security" in text and "correlations: 4" in text
    assert "RT-ZAP-001" in text


def test_disabled_zap_leaves_phase3a_report_unchanged(unsafe_app):
    a = run_all(make_cfg(unsafe_app.url))
    assert a.zap_baseline["executed"] is False and a.correlations == []
    assert not any(f.category == "zap" for f in a.findings) and a.exit_code == 2


# ------------------------------------------------------------------ no credentials / no active scan in the real runner path

def test_run_baseline_passes_no_credentials_and_only_baseline(monkeypatch, tmp_path):
    captured = {}

    class FakeProc:
        stdout = None
        returncode = 0

        def __init__(self, cmd, **kw):
            captured["cmd"], captured["env"] = cmd, kw.get("env", {})
            import io
            self.stdout = io.BytesIO(b"PASS: Something [10003]\nFAIL-NEW: 0\tFAIL-INPROG: 0\tWARN-NEW: 0\tWARN-INPROG: 0\tINFO: 0\tIGNORE: 0\tPASS: 1\n")

        def wait(self, timeout=None):
            return 0

        def kill(self):
            pass

    monkeypatch.setenv("TEST_USER_PASSWORD", "fake-password-only-for-tests")
    monkeypatch.setenv("ZAP_TEST_USER_A_PASSWORD", "fake-password-only-for-tests")
    monkeypatch.setenv("GITHUB_TOKEN", "FAKE-gh-token")
    monkeypatch.setattr(zb.shutil, "which", lambda name: "/usr/bin/docker")
    monkeypatch.setattr(zb, "image_available", lambda docker, image: True)
    monkeypatch.setattr(zb.subprocess, "Popen", FakeProc)
    run = zb.run_baseline("http://127.0.0.1:3000", tmp_path / "zap")
    assert run.executed and run.exit_code == 0
    assert "zap-baseline.py" in captured["cmd"] and not any("full-scan" in c for c in captured["cmd"])
    assert not any(k in captured["env"] for k in ("TEST_USER_PASSWORD", "ZAP_TEST_USER_A_PASSWORD", "GITHUB_TOKEN"))
    assert "fake-password-only-for-tests" not in " ".join(captured["cmd"])
