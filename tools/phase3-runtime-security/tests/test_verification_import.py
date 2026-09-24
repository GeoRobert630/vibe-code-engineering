"""Imported verification results: schema validation, request budget, namespaces, redaction and report integration.

Hand-written JSON fixtures only (tests/fixtures/verification). No request is sent and no credential is handled.
"""

from __future__ import annotations

import copy
import importlib.util
import json
import re
import socket
from pathlib import Path

import pytest
from conftest import full_report, make_cfg

from runtime_security.config import ConfigError, parse
from runtime_security.reporting import json_report, markdown_report
from runtime_security.runner import RunReport, load_verification, run_all
from runtime_security.verification import importer
from runtime_security.verification.importer import ImportRejected, validate

FIX = Path(__file__).parent / "fixtures" / "verification"
BASE = "http://127.0.0.1:3000"
READER_PATH = Path(__file__).resolve().parents[3] / "skills/06-security/17-security-audit/scripts/read_phase3_report.py"
SCHEMA_PATH = Path(__file__).resolve().parents[1] / "schemas/verification-results.schema.json"
FAKE_SECRETS = [f"FAKE-{x}" for x in ("QUERY-SESSION-VALUE-1", "BEARER-VALUE-0001", "COOKIE-VALUE-0002", "SETCOOKIE-VALUE-0003",
                                     "PASSWORD-VALUE-0004", "REFRESH-VALUE-0005", "APIKEY-VALUE-0006", "XAPIKEY-VALUE-0008",
                                     "TOKEN-SCHEME-0009", "ACCESS-TOKEN-0010", "SESSIONID-VALUE-0011", "SESSION-ID-FIELD-0012")]
FAKE_SECRETS.append("RkFLRS1CQVNJQy1WQUxVRS0wMDA3")   # base64 of a fake Basic credential


def valid() -> dict:
    return json.loads((FIX / "valid.json").read_text(encoding="utf-8"))


def reader():
    spec = importlib.util.spec_from_file_location("read_phase3_report", READER_PATH)
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


@pytest.fixture(autouse=True)
def no_network(monkeypatch):
    """Everything here is offline except the explicit mock-app Phase 3A regression tests."""
    monkeypatch.setattr(socket, "create_connection", lambda *a, **k: (_ for _ in ()).throw(AssertionError("no network")))


def cfg_with(path: Path | None, base_url: str = BASE, production: bool = False):
    data = {"target": {"base_url": base_url, "environment": "local", "production": production}}
    if path is not None:
        data["verification_results"] = {"path": str(path)}
    return parse(data)


def imported_report(tmp_path: Path, doc: dict | None = None, fixture: str | None = None) -> RunReport:
    if fixture:
        path = FIX / fixture
    else:
        path = tmp_path / "results.json"
        path.write_text(json.dumps(valid() if doc is None else doc), encoding="utf-8")
    cfg = cfg_with(path)
    report = RunReport(cfg=cfg, safety_reason="local target", refused=False)
    load_verification(cfg, report)
    return report


def rejected(doc: dict, match: str) -> None:
    with pytest.raises(ImportRejected, match=match):
        validate(doc, BASE)


# ------------------------------------------------------------------------------------------------- schema / validation

def test_valid_import():
    r = validate(valid(), BASE)
    assert r.usable and r.status == "EXECUTED" and r.requests_count == 17
    assert {k: a.status for k, a in r.areas.items()} == {
        "authentication": "PASS", "session": "EXECUTED", "authorization": "PASS", "idor_bola": "FAIL", "tenant_isolation": "PASS"}
    assert [f.id for f in r.findings] == ["RT-IDOR-001"] and r.findings[0].category == "idor"
    assert r.areas["session"].limitations == ["Session rotation not supported by the target; not verified."]


def test_missing_file_and_malformed_json_are_incomplete(tmp_path):
    for path in (tmp_path / "missing.json", FIX / "malformed.json"):
        r = importer.load(path, BASE)
        assert r.status == "INCOMPLETE" and not r.usable and r.areas == {}
        assert all(r.area_status(k) == "INCOMPLETE" for k in importer.AREAS)


@pytest.mark.parametrize("mutate, match", [
    (lambda d: d.update(schema_version="2.0"), "schema_version"),
    (lambda d: d.update(kind="other"), "kind"),
    (lambda d: d.pop("producer"), "missing field"),
    (lambda d: d.update(extra=1), "unknown field"),
    (lambda d: d["areas"].update(websocket={}), "unknown area"),
    (lambda d: d.update(areas={}), "non-empty"),
    (lambda d: d["areas"]["session"].update(status="SECURE"), "status must be one of"),
    (lambda d: d["areas"]["session"].update(runtime_checks_executed="yes"), "true or false"),
    (lambda d: d["areas"]["session"].pop("requests_count"), "missing field"),
    (lambda d: d["areas"]["session"]["evidence"][0].update(observed="maybe"), "observed must be one of"),
    (lambda d: d["areas"]["session"]["evidence"][0].update(fingerprint="0A1B2C3D4E5F"), "fingerprint"),
    (lambda d: d["areas"]["session"].update(limitations="text"), "must be a list"),
    (lambda d: d.update(target={"base_url": "http://127.0.0.1:4000"}), "does not match"),
    (lambda d: d.update(target={"base_url": "http://user:pw@127.0.0.1:3000"}), "without credentials"),
    (lambda d: d["areas"]["idor_bola"]["findings"][0].update(severity="SEVERE"), "invalid severity"),
    (lambda d: d["areas"]["idor_bola"]["findings"][0].pop("impact"), "missing field"),
])
def test_malformed_documents_rejected(mutate, match):
    d = valid()
    mutate(d)
    rejected(d, match)


def test_malformed_import_makes_report_incomplete(tmp_path):
    d = valid()
    d["areas"]["session"]["requests_count"] = -1
    report = imported_report(tmp_path, d)
    data = json_report.build(report)
    assert data["verification_import"]["status"] == "INCOMPLETE"
    assert data["auth_areas"]["authentication"]["status"] == "INCOMPLETE"
    assert data["authorization"]["status"] == "INCOMPLETE"
    assert all(s["status"] == "INCOMPLETE" and s["findings"] == [] for s in data["authorization"]["subareas"].values())
    assert data["findings"] == [] and report.exit_code == 3 and report.summary.startswith("INCOMPLETE")


# ------------------------------------------------------------------------------------------------- request budget

@pytest.mark.parametrize("count", [0, 1, 20])
def test_request_count_bounds_accepted(count):
    d = {**valid(), "areas": {"session": {"status": "READY" if count == 0 else "EXECUTED", "runtime_checks_executed": count > 0,
                                          "requests_count": count}}}
    r = validate(d, BASE)
    assert r.requests_count == count
    assert r.areas["session"].status == ("READY" if count == 0 else "EXECUTED")


@pytest.mark.parametrize("count, match", [(21, "exceeds the request budget"), (-1, "must not be negative"),
                                          (1.5, "must be an integer"), ("3", "must be an integer"), (True, "must be an integer"),
                                          (None, "must be an integer")])
def test_request_count_rejected(count, match):
    d = valid()
    d["areas"]["session"]["requests_count"] = count
    rejected(d, match)


def test_total_request_budget_enforced():
    d = valid()
    d["areas"]["session"]["requests_count"] = 6   # 4 + 6 + 2 + 4 + 4 = 20: allowed
    assert validate(d, BASE).requests_count == 20
    d["areas"]["session"]["requests_count"] = 7   # 21
    rejected(d, "total requests_count 21 exceeds")


# ------------------------------------------------------------------------------------------------- namespaces / IDs

@pytest.mark.parametrize("area, fid, category", [
    ("authentication", "RT-AUTH-001", "authentication"), ("session", "RT-SESSION-001", "session"),
    ("authorization", "RT-AUTHZ-001", "authorization"), ("idor_bola", "RT-IDOR-002", "idor"),
    ("tenant_isolation", "RT-TENANT-001", "tenant_isolation"),
])
def test_namespaces_accepted(area, fid, category):
    d = valid()
    f = copy.deepcopy(d["areas"]["idor_bola"]["findings"][0]) | {"id": fid}
    d["areas"][area] = {"status": "FAIL", "runtime_checks_executed": True, "requests_count": 2, "findings": [f]}
    if area != "idor_bola":
        d["areas"]["idor_bola"]["findings"] = []
        d["areas"]["idor_bola"]["status"] = "EXECUTED"
    r = validate(d, BASE)
    assert [x.id for x in r.areas[area].findings] == [fid] and r.areas[area].findings[0].category == category
    assert r.areas[area].status == "FAIL"


@pytest.mark.parametrize("fid, match", [
    ("RT-BOLA-001", "not a valid"), ("RT-IDOR-01", "not a valid"), ("RT-IDOR-0001", "not a valid"), ("RT-idor-001", "not a valid"),
    ("RT-HEADERS-001", "not a valid"), ("RT-ZAP-001", "not a valid"), ("RT-IDOR-001\n", "not a valid"),
    ("RT-TENANT-001", "outside the RT-IDOR-\\* namespace"),
])
def test_invalid_ids_rejected(fid, match):
    d = valid()
    d["areas"]["idor_bola"]["findings"][0]["id"] = fid
    rejected(d, match)


def test_duplicate_ids_rejected():
    d = valid()
    d["areas"]["idor_bola"]["findings"].append(copy.deepcopy(d["areas"]["idor_bola"]["findings"][0]))
    rejected(d, "duplicate finding id")


def test_finding_ids_deterministic_and_preserved(tmp_path):
    d = valid()
    f = d["areas"]["idor_bola"]["findings"][0]
    d["areas"]["idor_bola"]["findings"] = [f | {"id": "RT-IDOR-003"}, f | {"id": "RT-IDOR-001"}]
    first = [x["id"] for x in json_report.build(imported_report(tmp_path, d))["findings"]]
    second = [x["id"] for x in json_report.build(imported_report(tmp_path, d))["findings"]]
    assert first == second == ["RT-IDOR-001", "RT-IDOR-003"]


# ------------------------------------------------------------------------------------------------- ambiguity / PASS rules

def test_imported_pass_requires_runtime_checks_executed():
    d = valid()
    d["areas"]["tenant_isolation"]["runtime_checks_executed"] = False
    assert validate(d, BASE).areas["tenant_isolation"].status == "INCOMPLETE"


@pytest.mark.parametrize("area, change", [
    ("authentication", {"evidence": []}),                                        # PASS without evidence
    ("authorization", {"requests_count": 0}),                                     # PASS with zero requests
    ("idor_bola", {"status": "PASS"}),                                            # PASS contradicted by a finding
    ("tenant_isolation", {"status": "FAIL"}),                                     # FAIL without a finding
    ("session", {"status": "NOT VERIFIED"}),                                      # NOT VERIFIED while executed
])
def test_ambiguous_results_are_incomplete(area, change):
    d = valid()
    d["areas"][area].update(change)
    r = validate(d, BASE)
    assert r.areas[area].status == "INCOMPLETE" and r.areas[area].claimed == d["areas"][area]["status"]


# ------------------------------------------------------------------------------------------------- credentials / redaction

@pytest.mark.parametrize("path, key", [
    ((), "password"), (("producer",), "api_key"), (("areas", "session"), "cookie"), (("areas", "session"), "session_id"),
    (("areas", "session"), "refresh_token"), (("areas", "session"), "Authorization"), (("areas", "session"), "bearer"),
    (("areas", "session"), "credentials"), (("areas", "session"), "X-Api-Key"), (("areas", "session"), "sid"),
])
def test_credential_shaped_fields_rejected(path, key):
    d = valid()
    node = d
    for p in path:
        node = node[p]
    node[key] = "FAKE-VALUE-SHOULD-NOT-APPEAR"
    with pytest.raises(ImportRejected, match="credential-shaped field") as exc:
        validate(d, BASE)
    assert "FAKE-VALUE-SHOULD-NOT-APPEAR" not in str(exc.value)


def test_credential_field_fixture_rejected_without_leaking(tmp_path):
    report = imported_report(tmp_path, fixture="credential-field.json")
    assert report.verification.status == "INCOMPLETE" and "credential-shaped field" in report.verification.reason
    blob = json.dumps(json_report.build(report)) + markdown_report.render(report)
    assert "FAKE-SESSION-ID-FIELD-0012" not in blob


def test_secret_values_redacted_in_json_and_markdown(tmp_path):
    report = imported_report(tmp_path, fixture="secrets-in-values.json")
    assert report.verification.usable and report.verification.redactions >= 8
    json_report.write(report, tmp_path / "out")
    markdown_report.write(report, tmp_path / "out")
    blob = "".join(p.read_text(encoding="utf-8") for p in (tmp_path / "out").iterdir())
    for secret in FAKE_SECRETS:
        assert secret not in blob, secret
    data = json.loads((tmp_path / "out" / "runtime-security-report.json").read_text(encoding="utf-8"))
    f = data["findings"][0]
    assert f["id"] == "RT-SESSION-001" and "<redacted>" in f["evidence"] and "session=<redacted>" in f["endpoint"]
    assert data["auth_areas"]["session"]["status"] == "FAIL"


def test_secret_values_not_in_exceptions():
    d = json.loads((FIX / "secrets-in-values.json").read_text(encoding="utf-8"))
    d["areas"]["session"]["findings"][0]["severity"] = "BAD"
    with pytest.raises(ImportRejected) as exc:
        validate(d, BASE)
    assert not any(s in str(exc.value) for s in FAKE_SECRETS)
    d = json.loads((FIX / "secrets-in-values.json").read_text(encoding="utf-8"))
    d["areas"]["session"]["FAKE-SESSIONID-VALUE-0011-token"] = 1
    with pytest.raises(ImportRejected) as exc:
        validate(d, BASE)
    assert "credential-shaped" in str(exc.value)


def test_no_credential_inputs_in_config_or_cli():
    with pytest.raises(ConfigError, match="unknown keys"):
        parse({"target": {"base_url": BASE, "environment": "local", "production": False},
               "verification_results": {"path": "r.json", "token": "x"}})
    with pytest.raises(ConfigError, match=".json"):
        parse({"target": {"base_url": BASE, "environment": "local", "production": False}, "verification_results": {"path": "r.txt"}})
    import inspect

    from runtime_security import cli
    from runtime_security.verification import importer as imp
    src = inspect.getsource(cli) + inspect.getsource(imp)
    assert "environ" not in src and "getenv" not in src and "--token" not in src and "--password" not in src


# ------------------------------------------------------------------------------------------------- report integration

def test_no_import_keeps_not_verified_and_invents_nothing():
    report = RunReport(cfg=cfg_with(None), safety_reason="local target", refused=False)
    data = json_report.build(report)
    assert data["verification_import"]["status"] == "NOT CONFIGURED" and data["verification_import"]["requests_count"] == 0
    assert data["auth_areas"]["authentication"]["status"] == "NOT VERIFIED" and "source" not in data["auth_areas"]["session"]
    assert data["authorization"]["status"] == "NOT VERIFIED" and data["authorization"]["runtime_checks_executed"] is False
    assert all(s["status"] == "NOT VERIFIED" for s in data["authorization"]["subareas"].values())
    assert data["findings"] == []


def test_report_round_trip_with_valid_import(tmp_path):
    report = imported_report(tmp_path)
    json_report.write(report, tmp_path / "out")
    data = json.loads((tmp_path / "out" / "runtime-security-report.json").read_text(encoding="utf-8"))
    vi = data["verification_import"]
    assert vi["status"] == "EXECUTED" and vi["requests_count"] == 17 and vi["request_budget"] == 20 and vi["credentials_read"] is False
    auth, sess = data["auth_areas"]["authentication"], data["auth_areas"]["session"]
    assert auth["status"] == "PASS" and auth["requests_count"] == 4 and auth["runtime_checks_executed"] is True
    assert auth["limitations"] == ["Single configured login flow only."] and auth["credentials_read"] is False
    assert sess["status"] == "EXECUTED" and sess["evidence"][0]["fingerprint"] == "0a1b2c3d4e5f"
    az = data["authorization"]
    assert az["status"] == "FAIL" and az["requests_count"] == 10 and az["runtime_checks_executed"] is True
    assert az["credentials_read"] is False
    subs = az["subareas"]
    assert {k: s["status"] for k, s in subs.items()} == {"authorization": "PASS", "idor_bola": "FAIL", "tenant_isolation": "PASS"}
    assert subs["idor_bola"]["findings"] == ["RT-IDOR-001"] and subs["idor_bola"]["requests_count"] == 4
    assert [f["id"] for f in data["findings"]] == ["RT-IDOR-001"] and data["findings"][0]["source"] == "imported-verification"
    assert data["requests_sent"] == 0 and report.exit_code == 2   # imported HIGH finding keeps the existing blocking semantics
    # reader round-trip
    r = reader()
    s = r.build_summary(r.load(tmp_path / "out"))
    assert s["authentication"]["status"] == "PASS" and s["session"]["status"] == "EXECUTED"
    assert s["authorization"]["status"] == "FAIL" and s["idor_bola"]["status"] == "FAIL" and s["idor_bola"]["requests_count"] == 4
    assert s["tenant_isolation"]["status"] == "PASS" and s["requests_count"] == 17
    assert s["verification_import"]["status"] == "EXECUTED" and len(s["areas"]) == 9
    assert "IMPORTED VERIFICATION: EXECUTED" in r.render(s)


def test_partial_import_absent_areas_not_verified(tmp_path):
    d = valid()
    d["areas"] = {"tenant_isolation": d["areas"]["tenant_isolation"]}
    data = json_report.build(imported_report(tmp_path, d))
    assert data["auth_areas"]["authentication"]["status"] == "NOT VERIFIED"
    subs = data["authorization"]["subareas"]
    assert subs["tenant_isolation"]["status"] == "PASS" and subs["idor_bola"]["status"] == "NOT VERIFIED"
    assert data["authorization"]["status"] == "EXECUTED"   # partial coverage is never PASS


def test_refused_target_import_not_applied(tmp_path):
    cfg = cfg_with(FIX / "valid.json", production=True)
    report = run_all(cfg)
    data = json_report.build(report)
    assert report.refused and report.requests_sent == 0 and report.verification is None
    assert data["verification_import"]["status"] == "READY"
    assert data["authorization"]["status"] == "NOT VERIFIED" and data["findings"] == []


def test_markdown_output(tmp_path):
    md = markdown_report.render(imported_report(tmp_path))
    auth = md.split("## Authentication\n", 1)[1].split("## Session\n", 1)[0]
    assert "Status: **PASS**" in auth and "Requests count: 4. Findings: 0. Credentials read: no." in auth
    assert "- Single configured login flow only." in auth
    az = md.split("## Authorization\n", 1)[1].split("## Authorization Findings", 1)[0]
    assert "Status: **FAIL**" in az and "Runtime authorization checks executed: yes." in az
    assert "| IDOR/BOLA | FAIL | `RT-IDOR-*` | yes | no | 4 | 1 |" in az
    assert "| Tenant isolation | PASS | `RT-TENANT-*` | yes | no | 4 | 0 |" in az
    assert "### IDOR/BOLA limitations" in az and "Two declared resources only; no enumeration." in az
    assert "Imported verification results: **EXECUTED**" in az and "Requests count: 17 (budget 20)" in az
    assert "RT-IDOR-001" in md.split("## Authorization Findings", 1)[1]


def test_markdown_without_import(safe_app, monkeypatch):
    monkeypatch.undo()   # local mock application
    report = full_report(safe_app.url)
    assert report.exit_code == 0
    md = markdown_report.render(report)
    assert "Imported verification results: **NOT CONFIGURED**" in md
    assert "| IDOR/BOLA | NOT VERIFIED | `RT-IDOR-*` | no | no | 0 | 0 |" in md


def test_relative_path_resolved_against_config(tmp_path):
    (tmp_path / "results.json").write_text("{}", encoding="utf-8")
    cfg_file = tmp_path / "runtime-security.yaml"
    cfg = parse({"target": {"base_url": BASE, "environment": "local", "production": False},
                 "verification_results": {"path": "results.json"}}, str(cfg_file))
    assert Path(cfg.verification_results) == (tmp_path / "results.json").resolve()


# ------------------------------------------------------------------------------------------------- Phase 3A/3B unchanged

def test_phase3a_unchanged_without_import(unsafe_app, monkeypatch):
    monkeypatch.undo()   # the mock application is local; allow loopback connections for this regression test
    a = run_all(make_cfg(unsafe_app.url))
    data = json_report.build(a)
    assert a.exit_code == 2 and a.verification is None
    assert all(re.match(r"RT-(HEADERS|COOKIE|CORS|REDIRECT|TLS|ERROR)-\d{3}$", f["id"]) for f in data["findings"])
    assert set(data["auth_areas"]["authentication"]) == {"area", "status", "reason", "findings"}
    assert data["verification_import"]["status"] == "NOT CONFIGURED"


def test_phase3a_with_import_keeps_3a_results(safe_app, tmp_path, monkeypatch):
    monkeypatch.undo()
    d = valid()
    d["target"]["base_url"] = safe_app.url
    path = tmp_path / "results.json"
    path.write_text(json.dumps(d), encoding="utf-8")
    base = run_all(make_cfg(safe_app.url))
    cfg = make_cfg(safe_app.url)
    cfg.verification_results = str(path)
    with_import = run_all(cfg)
    assert with_import.requests_sent == base.requests_sent          # importing sends no request
    outcomes = lambda rep: [(r.check, r.name, r.outcome) for run in rep.runs for r in run.results]  # noqa: E731
    assert outcomes(with_import) == outcomes(base)
    assert [f.id for f in with_import.findings if not f.id.startswith("RT-IDOR")] == [f.id for f in base.findings]


def test_schema_file_matches_importer():
    schema = json.loads(SCHEMA_PATH.read_text(encoding="utf-8"))
    assert schema["properties"]["schema_version"]["const"] == importer.SCHEMA_VERSION
    assert schema["properties"]["kind"]["const"] == importer.KIND
    assert set(schema["properties"]["areas"]["properties"]) == set(importer.AREAS)
    area = schema["$defs"]["area"]
    assert set(area["properties"]) == importer.AREA_KEYS and set(area["required"]) == importer.AREA_REQUIRED
    assert area["properties"]["requests_count"]["maximum"] == importer.REQUEST_BUDGET
    assert set(schema["$defs"]["finding"]["required"]) == importer.FINDING_REQUIRED
    assert set(schema["$defs"]["evidence"]["properties"]) == importer.EVIDENCE_KEYS
    assert tuple(schema["$defs"]["status"]["enum"]) == __import__("runtime_security.verification.status", fromlist=["x"]).STATUSES
