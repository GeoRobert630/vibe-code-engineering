"""v1.3 acceptance: the v1.2 imported-results path keeps working unchanged (design section 2). No network.

The existing v1.2 tests (test_verification_import.py, test_verification_status.py, test_authz_subareas.py) are not
modified. These tests pin the v1.2 behaviour explicitly so a v1.3 change that alters it fails here.
"""

from __future__ import annotations

import copy
import importlib.util
import json
from pathlib import Path

import pytest

from runtime_security.config import parse
from runtime_security.models import FINDING_ID_RE
from runtime_security.reporting import json_report
from runtime_security.runner import RunReport, load_verification
from runtime_security.verification import importer
from runtime_security.verification.importer import ImportRejected, validate

FIX = Path(__file__).parent / "fixtures" / "verification"
BASE = "http://127.0.0.1:3000"
READER_PATH = Path(__file__).resolve().parents[3] / "skills/06-security/17-security-audit/scripts/read_phase3_report.py"

# v1.2.0 results for tests/fixtures/verification/valid.json (pinned; changing them is a regression)
V12_AREA_STATUS = {"authentication": "PASS", "session": "EXECUTED", "authorization": "PASS", "idor_bola": "FAIL",
                   "tenant_isolation": "PASS"}


def valid() -> dict:
    return json.loads((FIX / "valid.json").read_text(encoding="utf-8"))


def reader():
    spec = importlib.util.spec_from_file_location("read_phase3_report", READER_PATH)
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


def build(tmp_path: Path, doc: dict) -> dict:
    p = tmp_path / "results.json"
    p.write_text(json.dumps(doc), encoding="utf-8")
    cfg = parse({"target": {"base_url": BASE, "environment": "local", "production": False},
                 "verification_results": {"path": str(p)}})
    r = RunReport(cfg=cfg, safety_reason="local target", refused=False)
    load_verification(cfg, r)
    return json_report.build(r)


def test_v12_fixture_statuses_unchanged():
    r = validate(valid(), BASE)
    assert {k: a.status for k, a in r.areas.items()} == V12_AREA_STATUS
    assert r.requests_count == 17 and [f.id for f in r.findings] == ["RT-IDOR-001"]


def test_v12_report_blocks_unchanged(tmp_path):
    data = build(tmp_path, valid())
    assert data["verification_import"]["status"] == "EXECUTED" and data["verification_import"]["schema_version"] == "1.0"
    assert data["auth_areas"]["authentication"]["status"] == "PASS" and data["authorization"]["status"] == "FAIL"
    assert {k: s["status"] for k, s in data["authorization"]["subareas"].items()} == {
        k: V12_AREA_STATUS[k] for k in ("authorization", "idor_bola", "tenant_isolation")}
    assert data["findings"][0]["source"] == "imported-verification"


@pytest.mark.parametrize("fid", ["RT-AUTH-001", "RT-SESSION-001", "RT-AUTHZ-001", "RT-IDOR-001", "RT-TENANT-001",
                                 "RT-HEADERS-001", "RT-COOKIE-001", "RT-CORS-001", "RT-REDIRECT-001", "RT-TLS-001",
                                 "RT-ERROR-001", "RT-ZAP-001"])
def test_existing_namespaces_still_valid(fid):
    import re

    assert re.fullmatch(FINDING_ID_RE, fid) and reader().FINDING_ID.match(fid)


@pytest.mark.parametrize("where, key, value", [
    ((), "native_verification", {"status": "EXECUTED"}),
    ((), "verification_source", "mixed"),
    (("areas", "session"), "source", "native"),
    (("areas", "session"), "verification_subarea_source", {"authorization": "native"}),
    (("areas", "session"), "checks", []),
    (("areas", "session"), "actors", ["user_a"]),
])
def test_import_schema_still_strict_for_native_shaped_fields(where, key, value):
    """Schema 1.0 is not widened by v1.3: native-only fields in an import file are rejected, as before."""
    d = valid()
    node = d
    for w in where:
        node = node[w]
    node[key] = value
    with pytest.raises(ImportRejected, match="unknown field|credential-shaped field"):
        validate(d, BASE)


def test_old_report_with_native_shaped_metadata_still_reads(tmp_path):
    data = build(tmp_path, valid())
    data["native_verification"] = {"status": "NOT CONFIGURED", "requests_count": 0, "request_budget": 20}
    data["authorization"]["verification_source"] = "imported"
    data["authorization"]["verification_subarea_source"] = {"authorization": "imported", "idor_bola": "imported",
                                                            "tenant_isolation": "imported"}
    (tmp_path / "runtime-security-report.json").write_text(json.dumps(data), encoding="utf-8")
    r = reader()
    s = r.build_summary(r.load(tmp_path))
    assert s["authorization"]["status"] == "FAIL" and s["idor_bola"]["status"] == "FAIL"
    assert s["tenant_isolation"]["status"] == "PASS" and s["requests_count"] == 17 and len(s["areas"]) == 9


def test_mixed_source_metadata_does_not_change_imported_only_flow(tmp_path):
    plain = build(tmp_path, valid())
    tagged = copy.deepcopy(plain)
    tagged["authorization"]["verification_source"] = "mixed"
    tagged["authorization"]["verification_subarea_source"] = {"authorization": "imported", "idor_bola": "imported",
                                                              "tenant_isolation": "none"}
    r = reader()
    a = r.build_summary(plain)
    b = r.build_summary(tagged)
    for key in ("authentication", "session", "authorization", "idor_bola", "tenant_isolation", "requests_count", "areas"):
        assert a[key] == b[key], key


@pytest.mark.parametrize("mutate, match", [
    (lambda d: d.update(schema_version="1.2"), "schema_version"),
    (lambda d: d["areas"]["session"].update(requests_count=21), "request budget"),
    (lambda d: d["areas"]["idor_bola"]["findings"][0].update(id="RT-TENANT-001"), "namespace"),
    (lambda d: d["areas"]["session"].update(token="x"), "credential-shaped"),
])
def test_malformed_imports_keep_v12_behaviour(tmp_path, mutate, match):
    d = valid()
    mutate(d)
    with pytest.raises(ImportRejected, match=match):
        validate(d, BASE)
    data = build(tmp_path, d)
    assert data["verification_import"]["status"] == "INCOMPLETE" and data["findings"] == []


def test_malformed_report_still_rejected_by_reader(tmp_path):
    (tmp_path / "runtime-security-report.json").write_text(json.dumps({"schema_version": "2.0"}), encoding="utf-8")
    with pytest.raises(ValueError):
        reader().load(tmp_path)
    missing = tmp_path / "does-not-exist.json"
    assert importer.load(missing, BASE).status == "INCOMPLETE"
