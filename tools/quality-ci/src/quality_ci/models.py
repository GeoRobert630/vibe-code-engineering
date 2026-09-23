"""Data model: page scans (engine output, already reduced) and grouped Q-A11Y findings."""

from __future__ import annotations

import hashlib
import re
from dataclasses import dataclass, field
from typing import Any

NAMESPACE = "Q-A11Y"
FINDING_ID_RE = re.compile(r"^Q-A11Y-[0-9a-f]{10}$")
SEVERITIES = ("CRITICAL", "HIGH", "MEDIUM", "LOW", "INFORMATIONAL")
# axe-core impact -> five-level severity used across the pipeline (impact is kept verbatim as well).
IMPACT_SEVERITY = {"critical": "CRITICAL", "serious": "HIGH", "moderate": "MEDIUM", "minor": "LOW"}
IMPACT_ORDER = ("critical", "serious", "moderate", "minor")
KIND_VIOLATION = "violation"
KIND_REVIEW = "needs-review"
STATUS_OPEN = "OPEN"
STATUS_REVIEW = "NEEDS_REVIEW"

PAGE_OK = "SCANNED"
PAGE_STATUSES = (PAGE_OK, "TIMEOUT", "ERROR", "OVERSIZE", "NAVIGATION BLOCKED", "HTTP ERROR", "NOT SCANNED")

RUN_COMPLETE = "COMPLETE"
RUN_INCOMPLETE = "INCOMPLETE"
RUN_REFUSED = "REFUSED"
RUN_NOT_CONFIGURED = "NOT CONFIGURED"


def finding_id(kind: str, rule_id: str) -> str:
    """Deterministic: depends only on the engine rule and whether it is a violation or a review item."""
    return f"{NAMESPACE}-" + hashlib.sha256(f"axe-core:{kind}:{rule_id}".encode()).hexdigest()[:10]


def max_impact(impacts: list[str | None]) -> str | None:
    present = [i for i in impacts if i in IMPACT_ORDER]
    return min(present, key=IMPACT_ORDER.index) if present else None


@dataclass
class RuleResult:
    """One engine rule result on one page (reduced: no HTML, no failure summaries)."""
    rule_id: str
    impact: str | None
    help: str
    description: str
    help_url: str
    tags: list[str]
    targets: list[str]


@dataclass
class PageScan:
    url: str
    status: str
    reason: str = ""
    http_status: int | None = None
    violations: list[RuleResult] = field(default_factory=list)
    incomplete: list[RuleResult] = field(default_factory=list)
    rules_evaluated: list[str] = field(default_factory=list)
    blocked_requests: dict[str, int] = field(default_factory=dict)
    duration_ms: int = 0

    @property
    def ok(self) -> bool:
        return self.status == PAGE_OK


@dataclass
class PageOccurrence:
    url: str
    occurrences: int
    selectors: list[str]


@dataclass
class Finding:
    id: str
    kind: str
    rule_id: str
    title: str
    description: str
    impact: str | None
    severity: str
    status: str
    blocking: bool
    help: str
    help_url: str
    wcag: list[str]
    tags: list[str]
    pages: list[PageOccurrence]
    source: str
    category: str = "accessibility"

    @property
    def occurrence_count(self) -> int:
        return sum(p.occurrences for p in self.pages)

    @property
    def urls(self) -> list[str]:
        return [p.url for p in self.pages]

    @property
    def selector(self) -> str:
        for p in self.pages:
            if p.selectors:
                return p.selectors[0]
        return ""

    @property
    def active(self) -> bool:
        return self.status == STATUS_OPEN

    def to_dict(self) -> dict[str, Any]:
        return {
            "id": self.id, "kind": self.kind, "rule_id": self.rule_id, "engine_rule": f"axe-core/{self.rule_id}",
            "title": self.title, "description": self.description, "impact": self.impact, "severity": self.severity,
            "status": self.status, "blocking": self.blocking, "category": self.category, "source": self.source,
            "url": self.urls[0] if self.urls else "", "urls": self.urls, "selector": self.selector,
            "occurrence_count": self.occurrence_count,
            "pages": [{"url": p.url, "occurrences": p.occurrences, "selectors": p.selectors} for p in self.pages],
            "help": self.help, "help_url": self.help_url, "wcag": self.wcag, "tags": self.tags,
        }
