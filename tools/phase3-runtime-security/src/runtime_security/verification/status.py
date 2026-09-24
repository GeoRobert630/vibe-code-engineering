"""Status model for imported Authentication / Session / Authorization verification results.

Pure functions only: no I/O, no network. The rules (see docs/AUTH-SESSION-AUTHORIZATION-DESIGN.md, "Imported Results"):

* no configuration                                   => NOT CONFIGURED
* configured, area absent from the imported result   => NOT VERIFIED (never promoted to PASS)
* configured, import unusable (missing/malformed)    => INCOMPLETE
* area present, checks not executed                  => READY / NOT VERIFIED / NOT CONFIGURED / INCOMPLETE as claimed;
                                                        a claimed PASS / FAIL / EXECUTED without execution is ambiguous => INCOMPLETE
* area executed                                      => PASS, FAIL or EXECUTED only when the evidence supports it:
    - PASS      needs requests_count >= 1, at least one evidence item and no active findings
    - FAIL      needs requests_count >= 1 and at least one active finding (proven unauthorized access)
    - EXECUTED  needs requests_count >= 1; with active findings it becomes FAIL
    - anything else (PASS with findings, FAIL without findings, zero requests, READY/NOT VERIFIED while executed)
      is ambiguous => INCOMPLETE
"""

from __future__ import annotations

from collections.abc import Iterable

NOT_CONFIGURED = "NOT CONFIGURED"
READY = "READY"
EXECUTED = "EXECUTED"
PASS = "PASS"
FAIL = "FAIL"
INCOMPLETE = "INCOMPLETE"
NOT_VERIFIED = "NOT VERIFIED"
STATUSES = (NOT_CONFIGURED, READY, EXECUTED, PASS, FAIL, INCOMPLETE, NOT_VERIFIED)
_NOT_EXECUTED_CLAIMS = {READY: READY, NOT_VERIFIED: NOT_VERIFIED, NOT_CONFIGURED: NOT_CONFIGURED, INCOMPLETE: INCOMPLETE}


def resolve(*, configured: bool, present: bool = False, valid: bool = True, claimed: str | None = None,
            executed: bool = False, requests_count: int = 0, active_findings: int = 0, evidence_items: int = 0) -> str:
    """Effective status of one area from validated, normalized inputs."""
    if not configured:
        return NOT_CONFIGURED
    if not valid:
        return INCOMPLETE
    if not present:
        return NOT_VERIFIED
    if claimed not in STATUSES:
        return INCOMPLETE
    if not executed:
        return _NOT_EXECUTED_CLAIMS.get(claimed, INCOMPLETE)   # PASS/FAIL/EXECUTED without execution: ambiguous
    if requests_count < 1:
        return INCOMPLETE
    if claimed == PASS:
        return PASS if active_findings == 0 and evidence_items >= 1 else INCOMPLETE
    if claimed == FAIL:
        return FAIL if active_findings >= 1 else INCOMPLETE
    if claimed == EXECUTED:
        return FAIL if active_findings >= 1 else EXECUTED
    return INCOMPLETE   # INCOMPLETE claimed, or READY / NOT VERIFIED / NOT CONFIGURED while claiming execution


def aggregate(statuses: Iterable[str]) -> str:
    """Combined status of several sub-areas. PASS only when every sub-area is PASS."""
    s = list(statuses)
    if not s:
        return NOT_VERIFIED
    if FAIL in s:
        return FAIL
    if INCOMPLETE in s:
        return INCOMPLETE
    if all(x == PASS for x in s):
        return PASS
    if any(x in (PASS, EXECUTED) for x in s):
        return EXECUTED   # partial coverage: some sub-areas still NOT VERIFIED / READY
    if READY in s:
        return READY
    if all(x == NOT_CONFIGURED for x in s):
        return NOT_CONFIGURED
    return NOT_VERIFIED
