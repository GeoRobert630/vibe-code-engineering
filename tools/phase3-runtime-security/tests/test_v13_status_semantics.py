"""v1.3 acceptance: the seven statuses and the Authorization aggregate (design section 16).

The native verifier reuses ``verification/status.resolve`` and ``aggregate``. These tests assert the observable
contract through the existing v1.2 import path (hand-written JSON, no network) and the status functions. Expected
values come from the design text, not from implementation constants.
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from runtime_security.config import parse
from runtime_security.reporting import json_report
from runtime_security.runner import RunReport, load_verification
from runtime_security.verification.status import aggregate, resolve

FIX = Path(__file__).parent / "fixtures" / "verification"
BASE = "http://127.0.0.1:3000"
SEVEN = {"NOT CONFIGURED", "READY", "EXECUTED", "PASS", "FAIL", "INCOMPLETE", "NOT VERIFIED"}

FINDING = {"id": "RT-TENANT-001", "severity": "HIGH", "confidence": "HIGH", "title": "Cross-tenant read allowed",
           "endpoint": "GET /tenants/tenant-b/resource-b", "expected": "denied", "actual": "allowed",
           "evidence": "declared marker returned", "impact": "i", "recommendation": "r", "validation": "v", "status": "OPEN"}
EVIDENCE = [{"check": "T1 own tenant", "expected": "allowed", "observed": "allowed"}]


def area(status, executed=True, requests=2, findings=(), evidence=EVIDENCE):
    return {"status": status, "runtime_checks_executed": executed, "requests_count": requests,
            "findings": list(findings), "evidence": list(evidence)}


def report(tmp_path: Path, areas: dict | None) -> dict:
    data = {"target": {"base_url": BASE, "environment": "local", "production": False}}
    if areas is not None:
        doc = json.loads((FIX / "valid.json").read_text(encoding="utf-8"))
        doc["areas"] = areas
        p = tmp_path / "results.json"
        p.write_text(json.dumps(doc), encoding="utf-8")
        data["verification_results"] = {"path": str(p)}
    cfg = parse(data)
    r = RunReport(cfg=cfg, safety_reason="local target", refused=False)
    load_verification(cfg, r)
    return json_report.build(r)


# ------------------------------------------------------------------------------------ each status is reachable

@pytest.mark.parametrize("areas, expected", [
    (None, "NOT CONFIGURED"),                                                           # no configuration
    ({"session": area("READY", executed=False, requests=0, evidence=())}, "READY"),     # configured, not executed
    ({"session": area("EXECUTED")}, "EXECUTED"),                                        # ran, no verdict
    ({"session": area("PASS")}, "PASS"),                                                # sufficient evidence
    ({"session": area("FAIL", findings=[dict(FINDING, id="RT-SESSION-001")])}, "FAIL"),  # proven by a finding
    ({"session": area("PASS", executed=False)}, "INCOMPLETE"),                          # ambiguous claim
    ({"tenant_isolation": area("PASS")}, "NOT VERIFIED"),                               # area absent from the import
])
def test_every_status_reachable_through_the_report(tmp_path, areas, expected):
    data = report(tmp_path, areas)
    if expected == "NOT CONFIGURED":
        assert data["verification_import"]["status"] == "NOT CONFIGURED"
        assert data["auth_areas"]["session"]["status"] == "NOT VERIFIED"       # v1.2 default block unchanged
    else:
        assert data["auth_areas"]["session"]["status"] == expected
    assert data["auth_areas"]["session"]["status"] in SEVEN


def test_status_vocabulary_closed():
    outputs = {resolve(configured=c, present=p, claimed=s, executed=e, requests_count=n, active_findings=f, evidence_items=v)
               for c in (False, True) for p in (False, True) for s in sorted(SEVEN) + ["BOGUS"]
               for e in (False, True) for n in (0, 1) for f in (0, 1) for v in (0, 1)}
    assert outputs == SEVEN


def test_pass_requires_executed_requests_evidence_and_no_findings():
    base = dict(configured=True, present=True, claimed="PASS")
    assert resolve(**base, executed=True, requests_count=1, active_findings=0, evidence_items=1) == "PASS"
    for change in ({"executed": False}, {"requests_count": 0}, {"active_findings": 1}, {"evidence_items": 0}):
        args = dict(executed=True, requests_count=1, active_findings=0, evidence_items=1) | change
        assert resolve(**base, **args) == "INCOMPLETE"


def test_not_verified_and_not_configured_never_pass():
    for claimed in ("NOT VERIFIED", "NOT CONFIGURED", "READY"):
        for executed in (False, True):
            assert resolve(configured=True, present=True, claimed=claimed, executed=executed, requests_count=5,
                           evidence_items=5) != "PASS"


# ------------------------------------------------------------------------------------ Authorization aggregate

@pytest.mark.parametrize("subareas, expected", [
    ({"authorization": area("PASS"), "idor_bola": area("PASS"), "tenant_isolation": area("PASS")}, "PASS"),
    ({"authorization": area("PASS"), "tenant_isolation": area("PASS")}, "EXECUTED"),          # one sub-area source none
    ({"tenant_isolation": area("PASS")}, "EXECUTED"),                                          # imported + none + none
    ({"authorization": area("PASS"), "idor_bola": area("PASS", executed=False),
      "tenant_isolation": area("PASS")}, "INCOMPLETE"),
    ({"authorization": area("PASS"), "idor_bola": area("PASS"),
      "tenant_isolation": area("FAIL", findings=[FINDING])}, "FAIL"),
    ({"authorization": area("READY", executed=False, requests=0, evidence=())}, "READY"),
])
def test_authorization_aggregate_with_mixed_sources(tmp_path, subareas, expected):
    """Sub-areas absent from the import have no evidence (source none); PASS needs all three PASS."""
    data = report(tmp_path, subareas)
    assert data["authorization"]["status"] == expected
    assert aggregate(s["status"] for s in data["authorization"]["subareas"].values()) == expected


def test_aggregate_never_pass_with_a_gap():
    for gap in ("NOT VERIFIED", "NOT CONFIGURED", "READY", "EXECUTED"):
        for pos in range(3):
            parts = ["PASS"] * 3
            parts[pos] = gap
            assert aggregate(parts) != "PASS"
