import json

import pytest
from conftest import FIXTURES

from phase2.baseline import manager
from phase2.models import Confidence, Finding, Severity, Status
from phase2.orchestrator import ScanOptions, deduplicate, run_scan


def mk(title="t", severity=Severity.HIGH, line=1, file="a.py", category="x", scanner="s", source="s:1", key=""):
    return Finding(scanner=scanner, category=category, severity=severity, confidence=Confidence.MEDIUM, title=title,
                   description="d", file=file, line=line, source=[source], dedup_key=key)


def test_ids_are_deterministic():
    a, b = mk(), mk()
    a.compute_ids(), b.compute_ids()
    assert a.id == b.id and a.id.startswith("P2-")
    c = mk(line=2)
    c.compute_ids()
    assert c.id != a.id


def test_deduplication_merges_sources_and_keeps_worst():
    f1 = mk(severity=Severity.MEDIUM, scanner="secrets", source="internal:x", key="secret:aws")
    f2 = mk(severity=Severity.CRITICAL, scanner="secrets", source="gitleaks:aws-access-token", key="secret:aws", title="other title")
    f3 = mk(line=9, key="secret:aws")
    out = deduplicate([f1, f2, f3])
    assert len(out) == 2
    merged = out[0]
    assert merged.severity == Severity.CRITICAL
    assert merged.source == ["gitleaks:aws-access-token", "internal:x"]


def _findings():
    out = [mk(title="high", severity=Severity.HIGH), mk(title="crit", severity=Severity.CRITICAL, line=2), mk(title="med", severity=Severity.MEDIUM, line=3)]
    for f in out:
        f.compute_ids()
    return out


def test_write_and_apply_baseline(tmp_path):
    path = tmp_path / "security-baseline.json"
    written, skipped = manager.write(path, _findings(), [])
    assert (written, skipped) == (2, 1)
    doc = json.loads(path.read_text())
    assert all(e["severity"] != "CRITICAL" for e in doc["findings"])

    fresh = _findings() + [mk(title="new", line=7)]
    for f in fresh:
        f.compute_ids()
    res = manager.apply(fresh, manager.load(path), str(path))
    status = {f.title: f.status for f in fresh}
    assert status == {"high": Status.BASELINED, "crit": Status.OPEN, "med": Status.BASELINED, "new": Status.OPEN}
    assert len(res.matched) == 2


def test_critical_in_baseline_is_refused(tmp_path):
    f = _findings()[1]
    path = tmp_path / "b.json"
    path.write_text(json.dumps({"version": 1, "findings": [{"id": f.id, "fingerprint": f.fingerprint, "severity": "CRITICAL"}]}))
    res = manager.apply([f], manager.load(path))
    assert f.status == Status.OPEN and res.refused_critical == [f.id]


def test_severity_escalation_not_baselined(tmp_path):
    f = _findings()[0]  # HIGH
    path = tmp_path / "b.json"
    path.write_text(json.dumps({"version": 1, "findings": [{"id": f.id, "fingerprint": f.fingerprint, "severity": "LOW"}]}))
    manager.apply([f], manager.load(path))
    assert f.status == Status.OPEN


def test_stale_entries_reported_as_fixed(tmp_path):
    path = tmp_path / "b.json"
    path.write_text(json.dumps({"version": 1, "findings": [{"id": "P2-gone", "fingerprint": "x", "severity": "LOW", "title": "old"}, {"bogus": 1}]}))
    res = manager.apply([], manager.load(path))
    assert res.stale[0]["status"] == "FIXED" and res.invalid_entries == 1


def test_malformed_baseline_rejected(tmp_path):
    path = tmp_path / "b.json"
    path.write_text("[1,2,3]")
    with pytest.raises(manager.BaselineError):
        manager.load(path)
    path.write_text('{"version": 99, "findings": []}')
    with pytest.raises(manager.BaselineError):
        manager.load(path)


def test_baseline_end_to_end_changes_exit_code(tmp_path):
    base = tmp_path / "security-baseline.json"
    first = run_scan(ScanOptions(project=FIXTURES / "vulnerable-python", use_external_tools=False, baseline_path=base, update_baseline=True))
    assert base.exists() and first.exit_code == 2
    second = run_scan(ScanOptions(project=FIXTURES / "vulnerable-python", use_external_tools=False, baseline_path=base))
    assert all(f.severity == Severity.CRITICAL for f in second.findings if f.status in (Status.OPEN, Status.REQUIRES_REVIEW))
    assert second.exit_code == 2  # criticals can never be baselined
    assert second.baseline["matched"] > 0
