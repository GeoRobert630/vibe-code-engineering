"""Authorization area status (Phase 3C, status/reporting only).

Statuses: PASS, FAIL, NOT CONFIGURED, NOT VERIFIED, INCOMPLETE.
This version never executes runtime authorization checks, so the status is NOT VERIFIED.
The only way the area becomes FAIL is the presence of ``RT-AUTHZ-*`` findings in the
report (reserved namespace for future imported results; none are generated here).
This is a coverage status, not a security verdict.
"""

from __future__ import annotations

from typing import Any

from ..models import Finding

CATEGORY = "authorization"
STATUSES = ("PASS", "FAIL", "NOT CONFIGURED", "NOT VERIFIED", "INCOMPLETE")
SCOPE = ["authorization", "IDOR/BOLA", "tenant isolation"]
REASON = ("Runtime authorization, IDOR/BOLA and tenant-isolation checks are not executed by this Phase 3 runtime "
          "implementation. These areas remain covered only by the Layer 2 source-code security review. "
          "This is a coverage status, not a security verdict.")
REASON_REFUSED = "Safety gate refused the target; nothing was sent. " + REASON


def authz_area_status(findings: list[Finding], refused: bool) -> dict[str, Any]:
    ids = [f.id for f in findings if f.category == CATEGORY]
    if ids and not refused:
        status, reason = "FAIL", "RT-AUTHZ findings present in this report (imported results)."
    else:
        status, reason = "NOT VERIFIED", REASON_REFUSED if refused else REASON
    return {
        "area": "Authorization",
        "status": status,
        "reason": reason,
        "scope": list(SCOPE),
        "runtime_checks_executed": False,   # no authorization requests are sent by this version
        "credentials_read": False,
        "findings": ids,
    }
