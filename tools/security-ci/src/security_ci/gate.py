"""Explicit CI gate over existing findings. Scanner exit codes are not changed.

Policies (``--fail-on``):
  release  (default) fail on any finding the source report marks ``blocking`` - the project's
           release semantics: active CRITICAL, or active HIGH with MEDIUM/HIGH confidence.
  critical fail on any active CRITICAL finding.
  high     fail on any active CRITICAL or HIGH finding (regardless of confidence).
  medium   also fail on active MEDIUM findings.
  low      also fail on active LOW findings (explicit opt-in; LOW is review-only otherwise).
"Active" means status OPEN or REQUIRES_REVIEW; BASELINED/IGNORED findings never fail the gate.
By default an incomplete scan (scanner/tool failure, safety-gate refusal) also fails the gate;
``--allow-incomplete`` turns that into a warning.

Gate exit codes: 0 pass, 1 policy violation, 3 input/usage error.
The gate never changes verification status: Authentication/Session remain as reported.
"""

from __future__ import annotations

from dataclasses import dataclass, field

from .inputs import Bundle

ORDER = ["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFORMATIONAL"]
POLICIES = ("release", "critical", "high", "medium", "low")
EXIT_PASS, EXIT_FAIL, EXIT_ERROR = 0, 1, 3


@dataclass
class GateResult:
    policy: str
    passed: bool
    violations: list[str] = field(default_factory=list)
    incomplete: list[str] = field(default_factory=list)
    counts: dict[str, int] = field(default_factory=dict)
    verification: dict[str, str] = field(default_factory=dict)

    @property
    def exit_code(self) -> int:
        return EXIT_PASS if self.passed else EXIT_FAIL


def evaluate(bundle: Bundle, policy: str = "release", allow_incomplete: bool = False) -> GateResult:
    if policy not in POLICIES:
        raise ValueError(f"unknown policy {policy!r}")
    active = [f for f in bundle.findings if f.active]
    counts = {s: sum(1 for f in active if f.severity == s) for s in ORDER}
    if policy == "release":
        violating = [f for f in active if f.blocking]
    else:
        limit = ORDER.index(policy.upper())
        violating = [f for f in active if ORDER.index(f.severity) <= limit]
    violations = [f"{f.id} {f.severity} {f.title}" for f in sorted(violating, key=lambda x: (ORDER.index(x.severity), x.id))]
    incomplete = list(bundle.incomplete)
    passed = not violations and (allow_incomplete or not incomplete)
    return GateResult(policy, passed, violations, incomplete, counts, dict(bundle.verification))


def render(result: GateResult) -> str:
    lines = [f"Security CI gate - policy: {result.policy}"]
    lines.append("Active findings: " + ", ".join(f"{k.title()} {v}" for k, v in result.counts.items()))
    for area, status in sorted(result.verification.items()):
        lines.append(f"{area}: {status}")
    if result.incomplete:
        lines.append("Incomplete: " + ", ".join(result.incomplete))
    if result.violations:
        lines.append(f"Violations ({len(result.violations)}):")
        lines += [f"  - {v}" for v in result.violations[:50]]
    lines.append("Result: " + ("PASS" if result.passed else "FAIL") + " (a passing gate is not proof of security)")
    return "\n".join(lines)
