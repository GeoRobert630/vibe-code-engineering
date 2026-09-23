"""SARIF export tests (fixtures only; no scanners run except in test_existing_exit_codes_unchanged)."""

from __future__ import annotations

import json
import os
import subprocess
import sys
from pathlib import Path

import pytest

from security_ci import cli
from security_ci.inputs import InputError, load_all
from security_ci.sarif import LEVEL, SECURITY_SEVERITY, build

FIX = Path(__file__).parent / "fixtures"
REPO = Path(__file__).resolve().parents[3]
SECRETS = ["AKIAFAKEFAKEFAKE0000", "FakeUpstreamPassw0rd", "FAKESESSIONQUERYVALUE", "FAKEBEARERVALUE1234567890"]


def full_bundle():
    return load_all(FIX / "phase2-report.json", FIX / "phase3-report.json", FIX / "ai-findings.json")


def validate_sarif(doc: dict) -> None:
    """Structural checks for the SARIF 2.1.0 subset we emit (required properties and value domains)."""
    assert doc["version"] == "2.1.0" and doc["$schema"].endswith("sarif-2.1.0.json")
    assert isinstance(doc["runs"], list) and doc["runs"]
    for run in doc["runs"]:
        driver = run["tool"]["driver"]
        assert isinstance(driver["name"], str) and driver["name"]
        rule_ids = [r["id"] for r in driver.get("rules", [])]
        assert len(rule_ids) == len(set(rule_ids)), "rule ids must be unique per run"
        for r in driver.get("rules", []):
            assert r["shortDescription"]["text"] and r["defaultConfiguration"]["level"] in ("none", "note", "warning", "error")
            float(r["properties"]["security-severity"])
        assert isinstance(run["results"], list)
        for res in run["results"]:
            assert res["message"]["text"]
            assert res["level"] in ("none", "note", "warning", "error")
            assert res["ruleId"] in rule_ids
            for loc in res.get("locations", []):
                phys = loc.get("physicalLocation")
                if phys:
                    uri = phys["artifactLocation"]["uri"]
                    assert not uri.startswith("/") and ":" not in uri and ".." not in uri.split("/")
                    if "region" in phys:
                        assert phys["region"]["startLine"] >= 1
                        assert phys["region"].get("startColumn", 1) >= 1
            for s in res.get("suppressions", []):
                assert s["kind"] in ("inSource", "external")


def results(doc):
    return {r["properties"]["findingId"]: r for run in doc["runs"] for r in run["results"]}


def test_valid_structure_mixed_sources():
    doc = build(full_bundle())
    validate_sarif(doc)
    assert [r["tool"]["driver"]["name"] for r in doc["runs"]] == ["phase2-security-scanner", "phase3-runtime-security", "ai-code-review"]
    json.dumps(doc)


def test_finding_conversion_and_source_preservation():
    res = results(build(full_bundle()))
    ev = res["P2-aaaaaaaaaaa1"]
    assert ev["ruleId"] == "js-eval" and ev["message"]["text"].startswith("[P2-aaaaaaaaaaa1] Use of eval()")
    assert ev["properties"]["source"] == "phase2-security-scanner" and ev["properties"]["layer"] == "phase2"
    assert res["RT-ZAP-001"]["properties"]["source"] == "OWASP ZAP"
    assert res["RT-HEADERS-001"]["properties"]["source"] == "phase3-runtime-security"
    assert res["AI-01"]["properties"]["source"] == "ai-code-review"


@pytest.mark.parametrize("fid,sev", [("P2-aaaaaaaaaaa1", "CRITICAL"), ("P2-aaaaaaaaaaa2", "HIGH"), ("RT-COOKIE-001", "MEDIUM"),
                                     ("RT-HEADERS-001", "LOW"), ("P2-aaaaaaaaaaa5", "INFORMATIONAL")])
def test_severity_conversion(fid, sev):
    r = results(build(full_bundle()))[fid]
    assert r["properties"]["severity"] == sev and r["level"] == LEVEL[sev] and r["properties"]["security-severity"] == SECURITY_SEVERITY[sev]


def test_zap_low_not_promoted():
    r = results(build(full_bundle()))["RT-ZAP-003"]
    assert r["properties"]["severity"] == "LOW" and r["level"] == "note" and r["properties"]["security-severity"] == "3.0"


def test_file_line_column_handling():
    res = results(build(full_bundle()))
    phys = res["P2-aaaaaaaaaaa1"]["locations"][0]["physicalLocation"]
    assert phys["artifactLocation"] == {"uri": "server.js", "uriBaseId": "%SRCROOT%"} and phys["region"] == {"startLine": 11, "startColumn": 18}
    assert "region" not in res["P2-aaaaaaaaaaa2"]["locations"][0]["physicalLocation"] or res["P2-aaaaaaaaaaa2"]["locations"][0]["physicalLocation"]["region"] == {"startLine": 4}
    assert "locations" not in res["P2-aaaaaaaaaaa4"]          # no file at all
    assert "locations" not in res["P2-aaaaaaaaaaa5"]          # absolute path + line 0 rejected
    rt = res["RT-HEADERS-001"]["locations"][0]
    assert "physicalLocation" not in rt and rt["logicalLocations"][0]["name"] == "GET /"


def test_runtime_anchor_adds_physical_location():
    res = results(build(full_bundle(), runtime_anchor="security/runtime-security.yaml"))
    phys = res["RT-ZAP-001"]["locations"][0]["physicalLocation"]
    assert phys["artifactLocation"]["uri"] == "security/runtime-security.yaml" and phys["region"]["startLine"] == 1


def test_cwe_handling():
    res = results(build(full_bundle()))
    assert res["P2-aaaaaaaaaaa1"]["properties"]["cwe"] == "CWE-95"
    assert "cwe" not in res["P2-aaaaaaaaaaa5"]["properties"]   # "not-a-cwe" dropped
    assert "cwe" not in res["P2-aaaaaaaaaaa4"]["properties"]


def test_zap_alert_id_and_url_preserved():
    r = results(build(full_bundle()))["RT-ZAP-001"]
    assert r["properties"]["zapAlertId"] == "10055" and r["ruleId"] == "zap/10055"
    assert r["properties"]["url"] == "http://host.docker.internal:3510/?session=<redacted>"


def test_correlation_and_cross_source_deduplication():
    bundle = full_bundle()
    doc = build(bundle)
    res = results(doc)
    assert "RT-ZAP-002" not in res            # ZAP 10021 confirms RT-HEADERS-001 -> not emitted twice
    assert "AI-02" not in res                 # AI-02 duplicate_of P2-aaaaaaaaaaa1
    assert res["P2-aaaaaaaaaaa1"]["properties"]["crossReferences"] == ["AI-02"]
    assert res["RT-HEADERS-001"]["properties"]["correlatedZapAlerts"] == ["10021"]
    assert "RT-ZAP-003" in res                 # "related-phase3a-passed" is not a duplicate
    dedup = {d["id"] for run in doc["runs"] for d in run["properties"].get("deduplicated", [])}
    assert dedup == {"RT-ZAP-002", "AI-02"}
    assert res["AI-03"]["properties"]["crossReferences"] == ["RT-COOKIE-001"]


def test_redaction_second_layer():
    blob = json.dumps(build(full_bundle()))
    for s in SECRETS:
        assert s not in blob, s
    assert "<redacted" in blob


def test_baselined_findings_are_suppressed_not_dropped():
    r = results(build(full_bundle()))["P2-aaaaaaaaaaa3"]
    assert r["suppressions"][0]["kind"] == "external" and "BASELINED" in r["suppressions"][0]["justification"]


def test_malformed_and_missing_optional_fields(tmp_path):
    p2 = tmp_path / "p2.json"
    p2.write_text(json.dumps({"schema_version": "1.0", "findings": [
        {"id": "P2-bbbbbbbbbbb1", "severity": "weird", "title": None},
        {"id": "P2-bbbbbbbbbbb2"},
        "not-a-dict",
    ]}))
    doc = build(load_all(p2, None, None))
    validate_sarif(doc)
    res = results(doc)
    assert res["P2-bbbbbbbbbbb1"]["properties"]["severity"] == "INFORMATIONAL" and res["P2-bbbbbbbbbbb2"]["message"]["text"]


@pytest.mark.parametrize("content,name", [("{not json", "p2.json"), ("[1,2]", "p2.json"), (json.dumps({"schema_version": "9"}), "p2.json")])
def test_invalid_inputs_rejected(tmp_path, content, name):
    p = tmp_path / name
    p.write_text(content)
    with pytest.raises(InputError):
        load_all(p, None, None)


def test_invalid_ai_ids_rejected(tmp_path):
    p = tmp_path / "ai.json"
    p.write_text(json.dumps({"findings": [{"id": "P2-xyz", "title": "x"}]}))
    with pytest.raises(InputError):
        load_all(None, None, p)


def test_empty_finding_set(tmp_path):
    p2 = tmp_path / "p2.json"
    p2.write_text(json.dumps({"schema_version": "1.0", "findings": [], "exit_code": 0}))
    doc = build(load_all(p2, None, None))
    validate_sarif(doc)
    assert doc["runs"][0]["results"] == []


def test_verification_status_carried_not_changed():
    doc = build(full_bundle())
    run3 = next(r for r in doc["runs"] if r["tool"]["driver"]["name"] == "phase3-runtime-security")
    assert run3["properties"]["verificationStatus"] == {"Authentication": "NOT VERIFIED", "Session": "NOT VERIFIED"}
    assert "not proof of security" in run3["properties"]["notice"]
    assert "passive only" in run3["properties"]["zapBaseline"]


def test_cli_sarif_command(tmp_path, capsys):
    out = tmp_path / "out" / "security.sarif"
    code = cli.main(["sarif", "--phase2", str(FIX / "phase2-report.json"), "--phase3", str(FIX / "phase3-report.json"),
                     "--ai", str(FIX / "ai-findings.json"), "--sarif", str(out)])
    text = capsys.readouterr().out
    assert code == 0 and out.is_file() and "Authentication: NOT VERIFIED" in text and "2 deduplicated" in text
    validate_sarif(json.loads(out.read_text()))


def test_cli_rejects_absolute_runtime_anchor(tmp_path):
    assert cli.main(["sarif", "--phase2", str(FIX / "phase2-report.json"), "--sarif", str(tmp_path / "x.sarif"), "--runtime-anchor", "/etc/passwd"]) == 3
    assert cli.main(["sarif", "--sarif", str(tmp_path / "x.sarif")]) == 3


def test_existing_exit_codes_unchanged(tmp_path):
    """Run the real Phase 2 and Phase 3 CLIs, then export: their exit codes and reports are untouched."""
    env2 = dict(os.environ, PYTHONPATH=str(REPO / "tools/phase2-security-scanner/src"))
    r2 = subprocess.run([sys.executable, "-m", "phase2.cli", "--project", str(REPO / "tools/phase2-security-scanner/tests/fixtures/vulnerable-node"),
                         "--output", str(tmp_path / "p2"), "--no-external-tools"], capture_output=True, text=True, env=env2, shell=False, timeout=300)
    assert r2.returncode == 2
    before = (tmp_path / "p2" / "security-report.json").read_bytes()
    cfg = tmp_path / "rt.yaml"
    cfg.write_text("target:\n  base_url: http://127.0.0.1:9\n  environment: local\n  production: true\n")
    env3 = dict(os.environ, PYTHONPATH=str(REPO / "tools/phase3-runtime-security/src"))
    r3 = subprocess.run([sys.executable, "-m", "runtime_security.cli", "--config", str(cfg), "--output", str(tmp_path / "p3")],
                        capture_output=True, text=True, env=env3, shell=False, timeout=120)
    assert r3.returncode == 3 and "STOP" in r3.stdout
    code = cli.main(["sarif", "--phase2", str(tmp_path / "p2" / "security-report.json"),
                     "--phase3", str(tmp_path / "p3" / "runtime-security-report.json"), "--sarif", str(tmp_path / "out.sarif")])
    assert code == 0
    assert (tmp_path / "p2" / "security-report.json").read_bytes() == before
    doc = json.loads((tmp_path / "out.sarif").read_text())
    validate_sarif(doc)
    run2 = doc["runs"][0]
    assert run2["properties"]["sourceExitCode"] == 2 and len(run2["results"]) > 10
