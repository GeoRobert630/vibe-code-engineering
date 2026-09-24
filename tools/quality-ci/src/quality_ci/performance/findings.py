"""Q-PERF findings: one finding per check across pages (specification section 6).

ID = "Q-PERF-" + sha256("performance:<check_id>")[:10]. Each page keeps its value, per-run values, status and up
to five contributors (safe URLs). Severity from the worst page result:

    FAIL                                   -> HIGH, OPEN, blocking
    WARN (budget / timing / model; incl. unstable and host-capped) -> MEDIUM, OPEN
    diagnostic > 0                         -> LOW, OPEN
    NOT MEASURED / nondeterministic only   -> INFORMATIONAL, NEEDS_REVIEW
CRITICAL is never used for performance.
"""

from __future__ import annotations

import hashlib
import re
from dataclasses import dataclass, field
from typing import Any

from ..redaction import clean, safe_url
from .aggregate import FAIL, NOT_MEASURED, PASS, WARN

NAMESPACE = "Q-PERF"
FINDING_ID_RE = re.compile(r"^Q-PERF-[0-9a-f]{10}$")
SEVERITY_ORDER = ("CRITICAL", "HIGH", "MEDIUM", "LOW", "INFORMATIONAL")

UNITS = {"timing.cls": "unitless", "budget.request-count": "count", "budget.render-blocking": "count",
         "budget.dom-nodes": "count", "diagnostic.unsized-images": "count", "diagnostic.oversized-images": "count",
         "diagnostic.text-compression": "count"}
TITLES = {
    "timing.fcp": "First Contentful Paint over budget", "timing.lcp": "Largest Contentful Paint over budget",
    "timing.cls": "Cumulative Layout Shift over budget", "timing.tbt": "Total Blocking Time over budget",
    "budget.total-bytes": "Total page weight over budget", "budget.script-bytes": "JavaScript bytes over budget",
    "budget.stylesheet-bytes": "Stylesheet bytes over budget", "budget.image-bytes": "Image bytes over budget",
    "budget.font-bytes": "Font bytes over budget", "budget.document-bytes": "HTML document bytes over budget",
    "budget.request-count": "Too many requests", "budget.render-blocking": "Too many render-blocking resources",
    "budget.dom-nodes": "DOM too large", "model.critical-path": "Modelled critical path over budget",
    "diagnostic.unsized-images": "Images without explicit dimensions",
    "diagnostic.oversized-images": "Images much larger than displayed",
    "diagnostic.text-compression": "Text resources served without compression",
}
HELP = {
    "timing.fcp": "Reduce render-blocking resources and main-thread work before first paint.",
    "timing.lcp": "Make the largest element render earlier: prioritise its resource, avoid blocking scripts and styles.",
    "timing.cls": "Reserve space for images, embeds and late content (width/height or aspect-ratio); avoid inserting content above existing content.",
    "timing.tbt": "Split long main-thread tasks (> 50 ms), defer non-critical JavaScript, yield to the event loop.",
    "budget.render-blocking": "Defer or async scripts, inline critical CSS, avoid CSS @import chains.",
    "budget.dom-nodes": "Render fewer elements: paginate or virtualise long lists.",
    "model.critical-path": "Fewer and smaller render-blocking resources shorten the critical path.",
    "diagnostic.unsized-images": "Add width and height attributes (or CSS aspect-ratio) to images.",
    "diagnostic.oversized-images": "Serve images close to their displayed size (responsive images).",
    "diagnostic.text-compression": "Enable gzip or brotli for text responses.",
}


def finding_id(check_id: str) -> str:
    return f"{NAMESPACE}-" + hashlib.sha256(f"performance:{check_id}".encode()).hexdigest()[:10]


def kind_of(check_id: str) -> str:
    return check_id.split(".", 1)[0]


def unit_of(check_id: str) -> str:
    return UNITS.get(check_id, "bytes" if check_id.startswith("budget.") else "ms")


@dataclass
class PageValue:
    url: str
    value: Any
    runs: list
    status: str
    contributors: list[str]
    unstable: bool = False
    nondeterministic: bool = False
    capped_by_host: bool = False


@dataclass
class Finding:
    id: str
    check_id: str
    kind: str
    title: str
    description: str
    unit: str
    warn: Any
    fail: Any
    severity: str
    status: str
    blocking: bool
    pages: list[PageValue]
    source: str
    help: str
    help_url: str = ""
    category: str = "performance"
    notes: list[str] = field(default_factory=list)

    @property
    def active(self) -> bool:
        return self.status == "OPEN"

    @property
    def urls(self) -> list[str]:
        return [p.url for p in self.pages]

    @property
    def occurrence_count(self) -> int:
        return len(self.pages)

    def to_dict(self) -> dict[str, Any]:
        return {
            "id": self.id, "kind": self.kind, "check_id": self.check_id, "title": self.title,
            "description": self.description, "metric": self.check_id, "unit": self.unit,
            "threshold": {"warn": self.warn, "fail": self.fail}, "severity": self.severity, "status": self.status,
            "blocking": self.blocking, "url": self.urls[0] if self.urls else "", "urls": self.urls,
            "pages": [{"url": p.url, "value": p.value, "runs": p.runs, "status": p.status, "contributors": p.contributors,
                       "unstable": p.unstable, "nondeterministic": p.nondeterministic, "capped_by_host": p.capped_by_host}
                      for p in self.pages],
            "occurrence_count": self.occurrence_count, "help": self.help, "help_url": self.help_url,
            "source": self.source, "category": self.category, "notes": self.notes,
        }


def _severity(kind: str, statuses: set[str], nondeterministic: bool) -> tuple[str, str, bool] | None:
    if FAIL in statuses:
        return "HIGH", "OPEN", True
    if WARN in statuses:
        return ("LOW" if kind == "diagnostic" else "MEDIUM"), "OPEN", False
    if NOT_MEASURED in statuses or nondeterministic:
        return "INFORMATIONAL", "NEEDS_REVIEW", False
    return None


def build_findings(pages: list, cfg) -> list[Finding]:
    from . import TOOL_NAME, __version__

    out: list[Finding] = []
    for check_id in cfg.budgets:
        affected = [(p, p.checks[check_id]) for p in pages if check_id in p.checks]
        statuses = {r.status for _, r in affected}
        nondet = any(r.nondeterministic for _, r in affected)
        sev = _severity(kind_of(check_id), statuses, nondet)
        if sev is None:
            continue
        severity, status, blocking = sev
        relevant = [(p, r) for p, r in affected if r.status not in (PASS,) or r.nondeterministic]
        values = [PageValue(url=safe_url(p.url), value=r.value, runs=r.runs, status=r.status,
                            contributors=[safe_url(c) for c in r.contributors[:5]], unstable=r.unstable,
                            nondeterministic=r.nondeterministic, capped_by_host=r.capped) for p, r in relevant]
        warn, fail = cfg.budgets[check_id]
        notes = []
        if any(v.unstable for v in values):
            notes.append("unstable: coefficient of variation > 0.35 across runs; never FAIL")
        if any(v.capped_by_host for v in values):
            notes.append("timing FAIL capped at WARN: host timing reliability LOW")
        if nondet:
            notes.append("nondeterministic: deterministic value differed across runs; maximum used")
        if check_id in cfg.changed_budgets:
            notes.append("budget changed from the default")
        desc = (f"{check_id} measured {'/'.join(str(v.value) for v in values)} {unit_of(check_id)} "
                f"(warn > {warn}, fail > {fail if fail is not None else 'never'})")
        out.append(Finding(
            id=finding_id(check_id), check_id=check_id, kind=kind_of(check_id), title=TITLES.get(check_id, check_id),
            description=clean(desc, 600), unit=unit_of(check_id), warn=warn, fail=fail, severity=severity, status=status,
            blocking=blocking, pages=values, source=f"{TOOL_NAME} {__version__}", help=HELP.get(check_id, ""), notes=notes,
        ))
    out.sort(key=lambda f: (SEVERITY_ORDER.index(f.severity), f.check_id))
    return out
