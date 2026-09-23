"""Group engine results into Q-A11Y findings.

Deduplication: all nodes that fail the same engine rule are one finding. Occurrences are counted per
page (every failing node), each page keeps up to ``MAX_SELECTORS`` representative selectors, and all
affected page URLs are preserved. Different rules are never merged, and a rule's violations are kept
separate from its needs-review results (different kinds, different IDs).
"""

from __future__ import annotations

from .models import (
    IMPACT_SEVERITY, KIND_REVIEW, KIND_VIOLATION, STATUS_OPEN, STATUS_REVIEW, Finding, PageOccurrence, PageScan,
    RuleResult, finding_id, max_impact,
)
from .redaction import clean, safe_selector, safe_url

MAX_SELECTORS = 5
SEVERITY_ORDER = ("CRITICAL", "HIGH", "MEDIUM", "LOW", "INFORMATIONAL")


def _severity(kind: str, impact: str | None) -> str:
    if kind == KIND_REVIEW:
        return "INFORMATIONAL"   # the engine could not decide; a human must review
    return IMPACT_SEVERITY.get(impact or "", "MEDIUM")


def build_findings(pages: list[PageScan], source: str) -> list[Finding]:
    grouped: dict[tuple[str, str], list[tuple[str, RuleResult]]] = {}
    for page in pages:
        for kind, results in ((KIND_VIOLATION, page.violations), (KIND_REVIEW, page.incomplete)):
            for r in results:
                grouped.setdefault((kind, r.rule_id), []).append((page.url, r))

    findings: list[Finding] = []
    for (kind, rule_id), items in grouped.items():
        first = items[0][1]
        occ: dict[str, PageOccurrence] = {}
        for url, r in items:
            u = safe_url(url)
            po = occ.setdefault(u, PageOccurrence(u, 0, []))
            count = max(len(r.targets), 1)
            po.occurrences += count
            for t in r.targets:
                s = safe_selector(t)
                if s and s not in po.selectors and len(po.selectors) < MAX_SELECTORS:
                    po.selectors.append(s)
        impact = max_impact([r.impact for _, r in items])
        severity = _severity(kind, impact)
        tags = sorted({clean(t, 40) for _, r in items for t in r.tags})
        findings.append(Finding(
            id=finding_id(kind, rule_id), kind=kind, rule_id=clean(rule_id, 80), title=clean(first.help, 200),
            description=clean(first.description, 600), impact=impact, severity=severity,
            status=STATUS_OPEN if kind == KIND_VIOLATION else STATUS_REVIEW,
            blocking=kind == KIND_VIOLATION and severity in ("CRITICAL", "HIGH"),
            help=clean(first.help, 300), help_url=safe_url(first.help_url) if first.help_url else "",
            wcag=[t for t in tags if t.startswith("wcag") and any(c.isdigit() for c in t)], tags=tags,
            pages=list(occ.values()), source=source,
        ))
    findings.sort(key=lambda f: (f.kind != KIND_VIOLATION, SEVERITY_ORDER.index(f.severity), f.rule_id))
    return findings
