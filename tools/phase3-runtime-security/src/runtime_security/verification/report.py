"""Report blocks built from imported verification results (safe metadata only)."""

from __future__ import annotations

from typing import Any

from ..models import Finding
from . import status as st
from .importer import AREAS, REQUEST_BUDGET, SCHEMA_VERSION, ImportedVerification

REASON_IMPORTED = "Imported result from a separate test suite (validated; no requests sent and no credentials read by this tool)."
REASON_ABSENT = "Configured imported result does not contain this area; not verified."


def import_block(configured: bool, imported: ImportedVerification | None, refused: bool) -> dict[str, Any]:
    """Top-level ``verification_import`` block: NOT CONFIGURED, READY (configured, not applied), EXECUTED or INCOMPLETE."""
    if not configured:
        return {"status": st.NOT_CONFIGURED, "reason": "no imported verification results configured",
                "schema_version": SCHEMA_VERSION, "requests_count": 0, "request_budget": REQUEST_BUDGET, "credentials_read": False}
    if imported is None:
        reason = "safety gate refused the target; imported results were not applied" if refused else "configured; not loaded"
        return {"status": st.READY, "reason": reason, "schema_version": SCHEMA_VERSION, "requests_count": 0,
                "request_budget": REQUEST_BUDGET, "credentials_read": False}
    return imported.to_dict()


def area_fields(imported: ImportedVerification, key: str, findings: list[Finding]) -> dict[str, Any]:
    """Status and safe metadata for one area of a configured import."""
    _, category, namespace = AREAS[key]
    a = imported.areas.get(key) if imported.usable else None
    if not imported.usable:
        reason = imported.reason
    elif a is None:
        reason = REASON_ABSENT
    else:
        reason = REASON_IMPORTED + (f" Claimed status {a.claimed} was not supported by the evidence."
                                    if a.claimed != a.status else "")
    return {
        "status": imported.area_status(key),
        "reason": reason,
        "source": "imported",
        "namespace": f"RT-{namespace}-*",
        "runtime_checks_executed": bool(a and a.runtime_checks_executed),
        "credentials_read": False,
        "requests_count": a.requests_count if a else 0,
        "findings": [f.id for f in findings if f.category == category],
        "evidence": [dict(e) for e in a.evidence] if a else [],
        "limitations": list(a.limitations) if a else [],
    }
