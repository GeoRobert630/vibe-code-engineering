"""v1.4 acceptance: Verification Results Schema 1.1 & Dual-Version Importer (Design §10).

Locks down:
- Schema 1.0 backward compatibility:
  - schema_version="1.0" continues to validate under max 20 requests
  - schema_version="1.0" rejects csrf area as unknown area
  - schema_version="1.0" rejects > 20 requests
- Schema 1.1 dual-version support:
  - schema_version="1.1" accepted
  - schema_version="1.1" accepts optional csrf area with RT-CSRF-NNN findings
  - schema_version="1.1" allows up to 27 total requests
  - schema_version="1.1" rejects > 27 total requests
  - If csrf area is omitted from Schema 1.1, csrf defaults to NOT VERIFIED (source: "none")
  - If csrf area is present in Schema 1.1, reports source: "imported" and origin: "imported-verification"
"""

from __future__ import annotations

import copy
import json
from pathlib import Path
import sys

_SRC = str(Path(__file__).resolve().parents[1] / "src")
_TESTS = str(Path(__file__).resolve().parent)
if _SRC not in sys.path:
    sys.path.insert(0, _SRC)
if _TESTS not in sys.path:
    sys.path.insert(0, _TESTS)

import pytest
from runtime_security.verification import importer
from runtime_security.verification.importer import ImportRejected, validate

pending_schema11 = lambda f: f

FIX = Path(__file__).parent / "fixtures" / "verification"
BASE = "http://127.0.0.1:3000"


def valid_10_doc() -> dict:
    return json.loads((FIX / "valid.json").read_text(encoding="utf-8"))


# =============================================================================
# 1. Schema 1.0 Backward Compatibility (Passes Today)
# =============================================================================

def test_schema_10_valid_document_continues_to_validate():
    """Existing Schema 1.0 document validates under 20 request limit and 5 areas."""
    doc = valid_10_doc()
    assert doc["schema_version"] == "1.0"
    r = validate(doc, BASE)
    assert r.usable and r.status == "EXECUTED"
    assert r.requests_count <= 20
    # 5 areas present
    assert "authentication" in r.areas
    assert "csrf" not in r.areas


def test_schema_10_rejects_csrf_area():
    """Schema 1.0 documents reject the csrf area as unknown."""
    doc = valid_10_doc()
    doc["areas"]["csrf"] = {
        "status": "PASS",
        "runtime_checks_executed": True,
        "requests_count": 4,
        "findings": [],
        "evidence": [],
    }
    with pytest.raises(ImportRejected, match="unknown area"):
        validate(doc, BASE)


def test_schema_10_rejects_requests_count_over_20():
    """Schema 1.0 documents enforce the 20-request ceiling."""
    doc = valid_10_doc()
    doc["areas"]["authentication"]["requests_count"] = 15
    doc["areas"]["session"]["requests_count"] = 10
    # Total = 25 > 20
    with pytest.raises(ImportRejected, match="budget|requests_count"):
        validate(doc, BASE)


# =============================================================================
# 2. Schema 1.1 Support & CSRF Area
# =============================================================================

@pending_schema11
def test_schema_11_accepts_valid_csrf_area_with_rt_csrf_findings():
    """Schema 1.1 documents accept the optional csrf area with RT-CSRF-* findings."""
    doc = valid_10_doc()
    doc["schema_version"] = "1.1"
    doc["areas"]["csrf"] = {
        "status": "FAIL",
        "runtime_checks_executed": True,
        "requests_count": 4,
        "findings": [
            {
                "id": "RT-CSRF-001",
                "severity": "HIGH",
                "confidence": "HIGH",
                "title": "Vulnerable to CSRF",
                "endpoint": "POST /api/action",
                "expected": "denied",
                "actual": "allowed",
                "evidence": "Observed 200 without token",
                "impact": "State change",
                "recommendation": "Add anti-CSRF token",
                "validation": "Send cross-origin request",
                "status": "OPEN",
            }
        ],
        "evidence": [{"check": "C2", "expected": "denied", "observed": "allowed"}],
        "limitations": ["SameSite not tested in browser"],
    }
    r = validate(doc, BASE)
    assert r.usable
    assert "csrf" in r.areas
    assert r.areas["csrf"].status == "FAIL"
    f = next((f for f in r.findings if f.id == "RT-CSRF-001"), None)
    assert f is not None
    assert f.source == "imported-verification"


@pending_schema11
def test_schema_11_rejects_non_csrf_findings_in_csrf_area():
    """CSRF area in Schema 1.1 only accepts RT-CSRF-NNN finding IDs."""
    doc = valid_10_doc()
    doc["schema_version"] = "1.1"
    doc["areas"]["csrf"] = {
        "status": "FAIL",
        "runtime_checks_executed": True,
        "requests_count": 2,
        "findings": [
            {
                "id": "RT-AUTH-001",  # Wrong namespace for csrf
                "severity": "HIGH",
                "confidence": "HIGH",
                "title": "Auth finding in CSRF area",
                "endpoint": "POST /api/action",
                "expected": "denied",
                "actual": "allowed",
                "evidence": "e",
                "impact": "i",
                "recommendation": "r",
                "validation": "v",
                "status": "OPEN",
            }
        ],
        "evidence": [],
    }
    with pytest.raises(ImportRejected, match="namespace|RT-CSRF"):
        validate(doc, BASE)


@pending_schema11
def test_schema_11_allows_up_to_27_total_requests():
    """Schema 1.1 raises total imported request budget from 20 to 27."""
    doc = valid_10_doc()
    doc["schema_version"] = "1.1"
    for area in ("authorization", "idor_bola", "tenant_isolation"):
        if area in doc.get("areas", {}):
            doc["areas"][area]["requests_count"] = 0
    # Set total to 25 (valid for 1.1, invalid for 1.0)
    doc["areas"]["authentication"]["requests_count"] = 10
    doc["areas"]["session"]["requests_count"] = 8
    doc["areas"]["csrf"] = {
        "status": "PASS",
        "runtime_checks_executed": True,
        "requests_count": 7,
        "findings": [],
        "evidence": [],
    }
    # Total = 10 + 8 + 7 + 0 + 0 + 0 = 25 <= 27
    r = validate(doc, BASE)
    assert r.usable
    assert r.requests_count == 25


@pending_schema11
def test_schema_11_rejects_requests_count_over_27():
    """Schema 1.1 rejects imports exceeding the 27 request hard ceiling."""
    doc = valid_10_doc()
    doc["schema_version"] = "1.1"
    doc["areas"]["authentication"]["requests_count"] = 15
    doc["areas"]["session"]["requests_count"] = 10
    doc["areas"]["csrf"] = {
        "status": "PASS",
        "runtime_checks_executed": True,
        "requests_count": 5,
        "findings": [],
        "evidence": [],
    }
    # Total = 30 > 27
    with pytest.raises(ImportRejected, match="budget|requests_count"):
        validate(doc, BASE)


@pending_schema11
def test_schema_11_omitted_csrf_area_defaults_to_none():
    """When a Schema 1.1 document omits the csrf area, csrf is cleanly absent (source: none)."""
    doc = valid_10_doc()
    doc["schema_version"] = "1.1"
    r = validate(doc, BASE)
    assert r.usable
    assert "csrf" not in r.areas
    assert r.area_status("csrf") == "NOT VERIFIED"
