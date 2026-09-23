"""Run orchestration: safety gate, page/time budgets, engine, grouping. Deterministic apart from timestamps."""

from __future__ import annotations

import time
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any, Callable

from . import TOOL_NAME, __version__
from .config import Config
from .engine import AxeEngine, EngineUnavailable
from .findings import build_findings
from .models import (
    PAGE_OK, RUN_COMPLETE, RUN_INCOMPLETE, RUN_NOT_CONFIGURED, RUN_REFUSED, Finding, PageScan,
)
from .redaction import clean
from .safety import evaluate as safety_evaluate

EXIT_OK, EXIT_NON_BLOCKING, EXIT_BLOCKING, EXIT_ERROR = 0, 1, 2, 3

LIMITATIONS = [
    "Automated checks only: the engine detects a subset of WCAG success criteria. This scan is not proof of full "
    "WCAG compliance or of complete accessibility; manual testing (keyboard, screen reader, zoom, cognitive) is still required.",
    "Only the explicitly configured pages are scanned, in their initial state after load; no crawling, clicking, "
    "typing, form submission or authenticated pages.",
    "Needs-review results are items the engine could not decide automatically; they are informational and must be "
    "checked by a person.",
    "Colour contrast is evaluated only where the engine can compute it (e.g. not over background images or gradients).",
    "Keyboard and focus checks are limited to what can be detected statically (e.g. tabindex, focusable hidden "
    "content); focus order and keyboard traps are not exercised.",
    "Cross-origin iframes and requests to origins other than the target (and configured asset origins) are not loaded; "
    "content that depends on them is not evaluated.",
    "Accessibility findings are quality findings (Q-A11Y-*); they are not security findings.",
]


@dataclass
class RunReport:
    status: str
    reason: str
    cfg: Config | None
    engine: dict[str, Any]
    pages: list[PageScan] = field(default_factory=list)
    findings: list[Finding] = field(default_factory=list)
    incomplete_reasons: list[str] = field(default_factory=list)
    started_at: str = ""
    finished_at: str = ""
    tool: str = f"{TOOL_NAME} {__version__}"

    @property
    def rules_evaluated(self) -> list[str]:
        return sorted({r for p in self.pages for r in p.rules_evaluated})

    @property
    def active(self) -> list[Finding]:
        return [f for f in self.findings if f.active]

    @property
    def verdict(self) -> str:
        """Accessibility area status: PASS / FAIL / INCOMPLETE / NOT CONFIGURED / NOT VERIFIED."""
        if self.status == RUN_NOT_CONFIGURED:
            return "NOT CONFIGURED"
        if self.status == RUN_REFUSED:
            return "NOT VERIFIED"
        if self.active:
            return "FAIL"
        return "PASS" if self.status == RUN_COMPLETE else "INCOMPLETE"

    @property
    def exit_code(self) -> int:
        if self.status in (RUN_REFUSED, RUN_INCOMPLETE):
            return EXIT_ERROR
        if any(f.blocking for f in self.active):
            return EXIT_BLOCKING
        if self.active:
            return EXIT_NON_BLOCKING
        return EXIT_OK


def _now() -> str:
    return datetime.now(timezone.utc).replace(microsecond=0).isoformat().replace("+00:00", "Z")


def not_configured(reason: str = "no accessibility target configured") -> RunReport:
    now = _now()
    return RunReport(RUN_NOT_CONFIGURED, clean(reason), None, {"name": "axe-core", "executed": False},
                     started_at=now, finished_at=now)


def run(cfg: Config, engine_factory: Callable[[Config], Any] = AxeEngine,
        clock: Callable[[], float] = time.monotonic) -> RunReport:
    started = _now()
    decision = safety_evaluate(cfg)
    report = RunReport(RUN_COMPLETE, decision.reason, cfg, {"name": "axe-core", "executed": False}, started_at=started)
    if not decision.allowed:
        report.status = RUN_REFUSED
        report.reason = f"Safety gate refused the target: {decision.reason}. No browser was started and no request was sent."
        report.pages = [PageScan(url=u, status="NOT SCANNED", reason="refused by the safety gate") for u in cfg.pages]
        report.finished_at = _now()
        return report

    to_scan = cfg.pages[: cfg.max_pages]
    skipped = cfg.pages[cfg.max_pages:]
    deadline = clock() + cfg.total_timeout_seconds
    try:
        engine = engine_factory(cfg)
        with engine as eng:
            report.engine = dict(eng.info, executed=True)
            for url in to_scan:
                remaining = deadline - clock()
                if remaining <= 0:
                    report.pages.append(PageScan(url=url, status="NOT SCANNED",
                                                 reason=f"total_timeout_seconds={cfg.total_timeout_seconds:g} reached"))
                    continue
                report.pages.append(eng.scan(url, min(cfg.page_timeout_seconds, remaining)))
            report.engine = dict(eng.info, executed=True)
    except EngineUnavailable as exc:
        report.engine = {"name": "axe-core", "executed": False, "error": clean(str(exc), 300)}
        report.incomplete_reasons.append(f"engine unavailable: {clean(str(exc), 300)}")
        scanned = {p.url for p in report.pages}
        report.pages += [PageScan(url=u, status="NOT SCANNED", reason="engine unavailable") for u in to_scan if u not in scanned]
    for url in skipped:
        report.pages.append(PageScan(url=url, status="NOT SCANNED", reason=f"limits.max_pages={cfg.max_pages} reached"))
    if skipped:
        report.incomplete_reasons.append(f"page limit reached: {len(skipped)} configured page(s) not scanned")
    for p in report.pages:
        if p.status != PAGE_OK and p.reason and not p.reason.startswith("limits.max_pages") and p.reason != "engine unavailable":
            report.incomplete_reasons.append(f"{p.status}: {clean(p.reason, 200)}")
    source = f"axe-core {report.engine.get('version', '')}".strip()
    report.findings = build_findings([p for p in report.pages if p.ok], source)
    if report.incomplete_reasons or any(not p.ok for p in report.pages):
        report.status = RUN_INCOMPLETE
        report.reason = "one or more configured pages could not be fully analysed"
    else:
        report.reason = f"{decision.reason}; all configured pages analysed"
    report.finished_at = _now()
    return report
