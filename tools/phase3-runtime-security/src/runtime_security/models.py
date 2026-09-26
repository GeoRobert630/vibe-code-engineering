"""Finding and check-result model.

Compatible with Phase 2 reports: same severity/confidence/status vocabulary,
plus runtime-specific fields (endpoint, expected, actual). IDs are RT-<CATEGORY>-NNN.
"""

from __future__ import annotations

from dataclasses import asdict, dataclass, field
from enum import Enum
from typing import Any


class Severity(str, Enum):
    CRITICAL = "CRITICAL"
    HIGH = "HIGH"
    MEDIUM = "MEDIUM"
    LOW = "LOW"
    INFORMATIONAL = "INFORMATIONAL"


class Confidence(str, Enum):
    HIGH = "HIGH"
    MEDIUM = "MEDIUM"
    LOW = "LOW"


class Status(str, Enum):
    OPEN = "OPEN"
    REQUIRES_REVIEW = "REQUIRES_REVIEW"
    PASS = "PASS"
    FAIL = "FAIL"
    INCOMPLETE = "INCOMPLETE"
    NOT_CONFIGURED = "NOT CONFIGURED"
    NOT_VERIFIED = "NOT VERIFIED"


class Outcome(str, Enum):
    PASSED = "PASSED"
    FAILED = "FAILED"
    NOT_VERIFIED = "NOT_VERIFIED"
    NOT_APPLICABLE = "NOT_APPLICABLE"


SEVERITY_ORDER = [Severity.CRITICAL, Severity.HIGH, Severity.MEDIUM, Severity.LOW, Severity.INFORMATIONAL]

# RT-<prefix>-NNN per check category.
ID_PREFIX = {
    "headers": "HEADERS",
    "cookies": "COOKIE",
    "cors": "CORS",
    "redirects": "REDIRECT",
    "tls": "TLS",
    "error_leakage": "ERROR",
    # Phase 3B plumbing (no checks produce these yet)
    "authentication": "AUTH",
    "session": "SESSION",
    # OWASP ZAP baseline (passive) findings
    "zap": "ZAP",
    # Reserved for future imported authorization results (Phase 3C); none are generated.
    "authorization": "AUTHZ",
    # Reserved for future IDOR/BOLA and tenant-isolation results (design only); none are generated.
    "idor": "IDOR",
    "tenant_isolation": "TENANT",
    "csrf": "CSRF",
}
FINDING_ID_RE = r"RT-(HEADERS|COOKIE|CORS|REDIRECT|TLS|ERROR|AUTH|SESSION|ZAP|AUTHZ|IDOR|TENANT|CSRF)-\d{3}"


@dataclass
class Finding:
    category: str
    severity: Severity
    confidence: Confidence
    title: str
    endpoint: str
    expected: str
    actual: str
    evidence: str
    impact: str
    recommendation: str
    validation: str
    status: Status = Status.OPEN
    cwe: str | None = None
    owasp: str | None = None
    notes: list[str] = field(default_factory=list)
    source: str = "phase3-runtime"
    id: str = ""

    def to_dict(self) -> dict[str, Any]:
        data = asdict(self)
        for key in ("severity", "confidence", "status"):
            data[key] = getattr(self, key).value
        return data


@dataclass
class CheckResult:
    """One verified (or unverifiable) assertion; every finding comes from a FAILED result."""

    check: str
    name: str
    endpoint: str
    outcome: Outcome
    detail: str

    def to_dict(self) -> dict[str, Any]:
        return {"check": self.check, "name": self.name, "endpoint": self.endpoint, "outcome": self.outcome.value, "detail": self.detail}


@dataclass
class CheckRun:
    name: str
    results: list[CheckResult] = field(default_factory=list)
    findings: list[Finding] = field(default_factory=list)
    error: str | None = None
    enabled: bool = True

    def add(self, name: str, endpoint: str, outcome: Outcome, detail: str) -> None:
        self.results.append(CheckResult(self.name, name, endpoint, outcome, detail))

    def fail(self, name: str, finding: Finding) -> None:
        self.results.append(CheckResult(self.name, name, finding.endpoint, Outcome.FAILED, finding.title))
        self.findings.append(finding)
