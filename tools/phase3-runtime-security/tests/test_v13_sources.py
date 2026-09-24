"""v1.3 acceptance: verification source model (docs/V1.3-AUTH-SESSION-AUTHORIZATION-DESIGN.md sections 2, 16, 19).

Tested through public boundaries only (the existing status functions and the serialized Phase 3 JSON report).
No network, no application fixture, no credentials.

Strict xfails mark implementation gaps in existing code against the v1.3 design; they are not behaviour changes.
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from runtime_security.config import parse
from runtime_security.reporting import json_report
from runtime_security.runner import RunReport, load_verification
from runtime_security.verification import status as vst

FIX = Path(__file__).parent / "fixtures" / "verification"
BASE = "http://127.0.0.1:3000"


# ------------------------------------------------------------------------------------ source vs status independence

@pytest.mark.parametrize("statuses", [
    ("PASS", "PASS", "PASS"), ("PASS", "NOT VERIFIED", "PASS"), ("FAIL", "PASS", "INCOMPLETE"), ("READY", "NOT VERIFIED", "READY"),
])
def test_status_aggregate_takes_no_source_input(statuses):
    """The existing aggregate is a function of statuses only, so a source (including mixed) cannot change it."""
    import inspect

    assert list(inspect.signature(vst.aggregate).parameters) == ["statuses"]
    assert vst.aggregate(statuses) == vst.aggregate(list(reversed(statuses)))


# ------------------------------------------------------------------------------------ report-level source (v1.2 path)

def _imported_report(tmp_path: Path, areas: list[str]) -> dict:
    d = json.loads((FIX / "valid.json").read_text(encoding="utf-8"))
    d["areas"] = {k: v for k, v in d["areas"].items() if k in areas}
    p = tmp_path / "results.json"
    p.write_text(json.dumps(d), encoding="utf-8")
    cfg = parse({"target": {"base_url": BASE, "environment": "local", "production": False},
                 "verification_results": {"path": str(p)}})
    r = RunReport(cfg=cfg, safety_reason="local target", refused=False)
    load_verification(cfg, r)
    return json_report.build(r)


def test_imported_areas_report_source_imported(tmp_path):
    data = _imported_report(tmp_path, ["session", "tenant_isolation"])
    assert data["auth_areas"]["session"]["source"] == "imported"
    assert data["authorization"]["subareas"]["tenant_isolation"]["source"] == "imported"
    assert all(v != "mixed" for s in data["authorization"]["subareas"].values() for k, v in s.items() if k == "source")


def test_no_configuration_reports_no_source(tmp_path):
    cfg = parse({"target": {"base_url": BASE, "environment": "local", "production": False}})
    data = json_report.build(RunReport(cfg=cfg, safety_reason="local target", refused=False))
    assert "source" not in data["auth_areas"]["authentication"] and "source" not in data["auth_areas"]["session"]
    assert all("source" not in s for s in data["authorization"]["subareas"].values())


@pytest.mark.xfail(strict=True, reason="implementation gap: an area absent from a configured import is reported as "
                                        "source=imported; the v1.3 design (section 2) requires source=none")
def test_area_absent_from_import_is_source_none(tmp_path):
    """Design section 2: an area with no evidence from either source is `none`, not `imported`."""
    data = _imported_report(tmp_path, ["tenant_isolation"])
    subs = data["authorization"]["subareas"]
    assert subs["tenant_isolation"]["source"] == "imported"
    for key in ("authorization", "idor_bola"):
        assert subs[key]["status"] == "NOT VERIFIED" and subs[key].get("source", "none") == "none"
    assert data["auth_areas"]["authentication"].get("source", "none") == "none"


@pytest.mark.xfail(strict=True, reason="v1.3 implementation pending: the serialized authorization block must carry "
                                        "verification_source and verification_subarea_source (design sections 2 and 19)")
def test_json_authorization_block_carries_aggregate_source(tmp_path):
    data = _imported_report(tmp_path, ["tenant_isolation"])
    az = data["authorization"]
    assert az["verification_source"] == "mixed"
    assert az["verification_subarea_source"] == {"authorization": "none", "idor_bola": "none", "tenant_isolation": "imported"}
