"""Severity ordering, counting, blocking rules, release status and exit codes.

Exit codes (deterministic, highest-priority rule wins):

    2  at least one blocking finding (see ``is_blocking``)
    3  a scanner crashed or an external tool that was run failed / timed out,
       or the CLI was invoked incorrectly
    1  non-blocking active findings (MEDIUM/LOW, or HIGH with LOW confidence)
    0  no active findings above INFORMATIONAL

Blocking findings take precedence over tool failure so a partially failed run
that still found a Critical/High issue reports the more urgent signal. Both are
non-zero, so CI fails either way.
"""

from __future__ import annotations

from collections.abc import Iterable

from .models import ACTIVE_STATUSES, Confidence, Finding, Severity

SEVERITY_ORDER = [
    Severity.CRITICAL,
    Severity.HIGH,
    Severity.MEDIUM,
    Severity.LOW,
    Severity.INFORMATIONAL,
]
_RANK = {sev: len(SEVERITY_ORDER) - i for i, sev in enumerate(SEVERITY_ORDER)}
_CONF_RANK = {Confidence.HIGH: 3, Confidence.MEDIUM: 2, Confidence.LOW: 1}

EXIT_OK = 0
EXIT_NON_BLOCKING = 1
EXIT_BLOCKING = 2
EXIT_FAILURE = 3

READY = "READY"
READY_WITH_RISKS = "READY WITH DOCUMENTED RISKS"
NOT_READY = "NOT READY"


def rank(severity: Severity) -> int:
    return _RANK[severity]


def conf_rank(confidence: Confidence) -> int:
    return _CONF_RANK[confidence]


def parse_severity(value: str) -> Severity:
    value = value.strip().upper()
    if value in ("INFO", "INFORMATION"):
        value = "INFORMATIONAL"
    return Severity(value)


def downgrade(severity: Severity, steps: int = 1) -> Severity:
    idx = min(SEVERITY_ORDER.index(severity) + steps, len(SEVERITY_ORDER) - 1)
    return SEVERITY_ORDER[idx]


def is_active(finding: Finding) -> bool:
    return finding.status in ACTIVE_STATUSES


def is_blocking(finding: Finding) -> bool:
    """Critical always blocks; High blocks unless the evidence is LOW confidence."""
    if not is_active(finding):
        return False
    if finding.severity == Severity.CRITICAL:
        return True
    return finding.severity == Severity.HIGH and finding.confidence != Confidence.LOW


def count_by_severity(findings: Iterable[Finding], active_only: bool = True) -> dict[str, int]:
    counts = {sev.value: 0 for sev in SEVERITY_ORDER}
    for f in findings:
        if active_only and not is_active(f):
            continue
        counts[f.severity.value] += 1
    return counts


def sort_key(finding: Finding) -> tuple:
    return (-rank(finding.severity), -conf_rank(finding.confidence), finding.file or "", finding.line or 0, finding.id)


def release_status(findings: list[Finding], tool_failure: bool) -> str:
    if tool_failure or any(is_blocking(f) for f in findings):
        return NOT_READY
    residual = [f for f in findings if is_active(f) and f.severity != Severity.INFORMATIONAL]
    baselined = [f for f in findings if f.status.value == "BASELINED"]
    if residual or baselined:
        return READY_WITH_RISKS
    return READY


def exit_code(findings: list[Finding], tool_failure: bool) -> int:
    if any(is_blocking(f) for f in findings):
        return EXIT_BLOCKING
    if tool_failure:
        return EXIT_FAILURE
    if any(is_active(f) and f.severity != Severity.INFORMATIONAL for f in findings):
        return EXIT_NON_BLOCKING
    return EXIT_OK
