"""Performance quality gate (same policies, outcomes and exit codes as the 4A accessibility gate).

Policies: release (default: blocking = any FAIL / HIGH), critical (never triggered: CRITICAL is unused),
high (HIGH), medium (+ WARN / MEDIUM), low (+ diagnostics / LOW).
Outcomes: active finding -> FAIL; informational (needs review) -> never fails; INCOMPLETE / REFUSED -> FAIL unless
--allow-incomplete; NOT CONFIGURED -> PASS with a "performance NOT VERIFIED" note unless --require-configured.
The output always states the host timing reliability. Exit codes: 0 pass, 1 fail, 3 input/usage error.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any

ORDER = ["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFORMATIONAL"]
POLICIES = ("release", "critical", "high", "medium", "low")
EXIT_PASS, EXIT_FAIL, EXIT_ERROR = 0, 1, 3


@dataclass
class GateResult:
    policy: str
    passed: bool
    outcome: str
    violations: list[str] = field(default_factory=list)
    informational: int = 0
    incomplete: list[str] = field(default_factory=list)
    counts: dict[str, int] = field(default_factory=dict)
    notes: list[str] = field(default_factory=list)
    timing_reliability: str | None = None

    @property
    def exit_code(self) -> int:
        return EXIT_PASS if self.passed else EXIT_FAIL


def evaluate(report: dict[str, Any], policy: str = "release", allow_incomplete: bool = False,
             require_configured: bool = False) -> GateResult:
    if policy not in POLICIES:
        raise ValueError(f"unknown policy {policy!r}")
    run = report.get("run", {})
    status = run.get("status")
    findings = report.get("findings", [])
    active = [f for f in findings if f.get("status") == "OPEN"]
    informational = sum(1 for f in findings if f.get("status") != "OPEN")
    counts = {s: sum(1 for f in active if f.get("severity") == s) for s in ("HIGH", "MEDIUM", "LOW")}
    reliability = (report.get("host") or {}).get("timing_reliability")
    notes = []
    if reliability == "LOW":
        notes.append("Host timing reliability LOW: timing FAILs were capped at WARN (deterministic checks unaffected).")
    if any(p.get("capped_by_host") for f in findings for p in f.get("pages", [])):
        notes.append("Capped timing results: " + ", ".join(sorted({f["check_id"] for f in findings
                                                                  if any(p.get("capped_by_host") for p in f.get("pages", []))})))
    if status == "NOT CONFIGURED":
        passed = not require_configured
        return GateResult(policy, passed, "NOT CONFIGURED", counts=counts, timing_reliability=reliability,
                          notes=["Performance NOT VERIFIED: no target configured" + ("" if passed else " (--require-configured)")])
    if policy == "release":
        violating = [f for f in active if f.get("blocking")]
    else:
        limit = ORDER.index(policy.upper())
        violating = [f for f in active if f.get("severity") in ORDER and ORDER.index(f["severity"]) <= limit]
    violations = [f"{f['id']} {f['severity']} {f.get('check_id')} "
                  f"({', '.join(str(p.get('value')) for p in f.get('pages', []))})"
                  for f in sorted(violating, key=lambda x: (ORDER.index(x["severity"]), x["id"]))]
    incomplete = []
    if status in ("INCOMPLETE", "REFUSED"):
        incomplete = [f"run {status}: {run.get('reason', '')}"] + list(run.get("incomplete_reasons", []))
    elif status != "COMPLETE":
        incomplete = [f"unknown run status {status!r}"]
    passed = not violations and (allow_incomplete or not incomplete)
    outcome = "FAIL" if violations else ("INCOMPLETE" if incomplete else "PASS")
    return GateResult(policy, passed, outcome, violations, informational, incomplete, counts, notes, reliability)


def render(r: GateResult) -> str:
    lines = [f"Quality CI gate (performance) - policy: {r.policy}",
             "Active findings: " + ", ".join(f"{k.title()} {v}" for k, v in r.counts.items()),
             f"Informational (needs review): {r.informational}",
             f"Timing reliability: {r.timing_reliability or 'n/a'}"]
    lines += r.notes
    if r.incomplete:
        lines.append("Incomplete: " + "; ".join(r.incomplete))
    if r.violations:
        lines.append(f"Violations ({len(r.violations)}):")
        lines += [f"  - {v}" for v in r.violations[:50]]
    lines.append(f"Outcome: {r.outcome}")
    lines.append("Result: " + ("PASS" if r.passed else "FAIL") + " (lab data; a passing gate is not proof of real-user performance)")
    return "\n".join(lines)
