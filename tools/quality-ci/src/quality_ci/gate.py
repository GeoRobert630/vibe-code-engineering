"""Quality gate over an accessibility report (standalone; security-ci's gate is not used or changed).

Policies (``--fail-on``):
  release  (default) fail on any active finding the report marks ``blocking``
           (axe impact critical/serious, i.e. severity CRITICAL/HIGH).
  critical fail on active CRITICAL findings.
  high     fail on active CRITICAL or HIGH findings.
  medium   also fail on active MEDIUM findings.
  low      also fail on active LOW findings.

The gate distinguishes four outcomes:
  active finding        status OPEN, at or above the policy threshold  -> FAIL
  informational result  needs-review items (INFORMATIONAL)             -> never fail, counted and shown
  scan incomplete       run INCOMPLETE or REFUSED                        -> FAIL unless --allow-incomplete
  not configured        run NOT CONFIGURED                               -> PASS with an explicit
                        "accessibility NOT VERIFIED" notice, FAIL with --require-configured

Exit codes: 0 pass, 1 policy violation, 3 input/usage error.
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
    outcome: str   # PASS | FAIL | INCOMPLETE | NOT CONFIGURED
    violations: list[str] = field(default_factory=list)
    informational: int = 0
    incomplete: list[str] = field(default_factory=list)
    counts: dict[str, int] = field(default_factory=dict)
    notes: list[str] = field(default_factory=list)

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
    counts = {s: sum(1 for f in active if f.get("severity") == s) for s in ORDER[:4]}

    if status == "NOT CONFIGURED":
        passed = not require_configured
        return GateResult(policy, passed, "NOT CONFIGURED", counts=counts,
                          notes=["Accessibility NOT VERIFIED: no target configured"
                                 + ("" if passed else " (--require-configured)")])
    if policy == "release":
        violating = [f for f in active if f.get("blocking")]
    else:
        limit = ORDER.index(policy.upper())
        violating = [f for f in active if f.get("severity") in ORDER and ORDER.index(f["severity"]) <= limit]
    violations = [f"{f['id']} {f['severity']} {f.get('rule_id')} ({f.get('occurrence_count', 0)} occurrence(s))"
                  for f in sorted(violating, key=lambda x: (ORDER.index(x["severity"]), x["id"]))]
    incomplete = []
    if status in ("INCOMPLETE", "REFUSED"):
        incomplete = [f"run {status}: {run.get('reason', '')}"] + list(run.get("incomplete_reasons", []))
    elif status != "COMPLETE":
        incomplete = [f"unknown run status {status!r}"]
    passed = not violations and (allow_incomplete or not incomplete)
    outcome = "FAIL" if violations else ("INCOMPLETE" if incomplete else "PASS")
    return GateResult(policy, passed, outcome, violations, informational, incomplete, counts)


def render(r: GateResult) -> str:
    lines = [f"Quality CI gate (accessibility) - policy: {r.policy}",
             "Active findings: " + ", ".join(f"{k.title()} {v}" for k, v in r.counts.items()),
             f"Informational (needs review): {r.informational}"]
    lines += r.notes
    if r.incomplete:
        lines.append("Incomplete: " + "; ".join(r.incomplete))
    if r.violations:
        lines.append(f"Violations ({len(r.violations)}):")
        lines += [f"  - {v}" for v in r.violations[:50]]
    lines.append(f"Outcome: {r.outcome}")
    lines.append("Result: " + ("PASS" if r.passed else "FAIL") + " (a passing gate is not proof of WCAG compliance)")
    return "\n".join(lines)
