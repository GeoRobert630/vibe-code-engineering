"""Run orchestration: safety gate, host benchmark, warm-up + measured runs per page, aggregation, findings.

Runs are strictly sequential (one browser, one page load at a time) and never retried: a failed run makes the page
INCOMPLETE. Deterministic apart from timestamps and the measured timing values.
"""

from __future__ import annotations

import os
import platform
import time
from collections import Counter
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any, Callable

from ..redaction import clean, safe_selector
from ..safety import evaluate as safety_evaluate    # 4A safety policy, reused unchanged
from . import TOOL_NAME, __version__
from .aggregate import FAIL, NOT_APPLICABLE, CheckResult, aggregate_deterministic, aggregate_timing, page_status
from .config import WARMUP_RUNS, PerfConfig
from .engine import MIN_BENCHMARK, MIN_BENCHMARK_CALIBRATION, EngineUnavailable, PerfEngine, reliability
from .findings import Finding, build_findings
from .measure import RECORDED, TIMING_CHECKS, RunData, deterministic, round_value, timings

EXIT_OK, EXIT_NON_BLOCKING, EXIT_BLOCKING, EXIT_ERROR = 0, 1, 2, 3
RUN_COMPLETE, RUN_INCOMPLETE, RUN_REFUSED, RUN_NOT_CONFIGURED = "COMPLETE", "INCOMPLETE", "REFUSED", "NOT CONFIGURED"


@dataclass
class PageResult:
    url: str
    status: str
    reason: str = ""
    runs: list[dict[str, Any]] = field(default_factory=list)          # per measured run: timing + recorded values
    checks: dict[str, CheckResult] = field(default_factory=dict)
    median: dict[str, Any] = field(default_factory=dict)
    deterministic: dict[str, Any] = field(default_factory=dict)
    lcp_element: str = ""
    blocked: dict[str, int] = field(default_factory=dict)
    duration_ms: int = 0

    @property
    def ok(self) -> bool:
        return self.status == "SCANNED"

    @property
    def verdict(self) -> str:
        return page_status(list(self.checks.values())) if self.ok else self.status


@dataclass
class PerfReport:
    status: str
    reason: str
    cfg: PerfConfig | None
    engine: dict[str, Any]
    host: dict[str, Any] = field(default_factory=dict)
    pages: list[PageResult] = field(default_factory=list)
    findings: list[Finding] = field(default_factory=list)
    incomplete_reasons: list[str] = field(default_factory=list)
    started_at: str = ""
    finished_at: str = ""
    tool: str = f"{TOOL_NAME} {__version__}"

    @property
    def active(self) -> list[Finding]:
        return [f for f in self.findings if f.active]

    @property
    def timing_reliability(self) -> str | None:
        return self.host.get("timing_reliability")

    @property
    def verdict(self) -> str:
        if self.status == RUN_NOT_CONFIGURED:
            return "NOT CONFIGURED"
        if self.status == RUN_REFUSED:
            return "NOT VERIFIED"
        if any(f.blocking for f in self.active):
            return "FAIL"
        if self.status == RUN_INCOMPLETE:
            return "INCOMPLETE"
        return "WARN" if self.active else "PASS"

    @property
    def exit_code(self) -> int:
        if self.status in (RUN_REFUSED, RUN_INCOMPLETE):
            return EXIT_ERROR
        if any(f.blocking for f in self.active):
            return EXIT_BLOCKING
        return EXIT_NON_BLOCKING if self.active else EXIT_OK


def _now() -> str:
    return datetime.now(timezone.utc).replace(microsecond=0).isoformat().replace("+00:00", "Z")


def not_configured(reason: str = "no performance target configured") -> PerfReport:
    now = _now()
    return PerfReport(RUN_NOT_CONFIGURED, clean(reason), None, {"name": "chromium-performance-apis", "executed": False},
                      started_at=now, finished_at=now)


def evaluate_page(page: PageResult, runs: list[RunData], cfg: PerfConfig, reliability_low: bool) -> None:
    """Aggregate the measured runs of one page into check results (specification section 2)."""
    local = cfg.environment == "local"
    det = [deterministic(r, cfg.profile, local) for r in runs]
    tim = [timings(r) for r in runs]
    page.runs = [{k: round_value(k, t[k]) for k in (*TIMING_CHECKS, *RECORDED)} for t in tim]
    for check_id, (warn, fail) in cfg.budgets.items():
        if check_id in TIMING_CHECKS:
            res = aggregate_timing(check_id, [t[check_id] for t in tim], warn, fail, reliability_low)
            res.contributors = []
        else:
            values = [d["values"][check_id] for d in det]
            res = aggregate_deterministic(check_id, values, warn, fail)
            if res.status != NOT_APPLICABLE and values:
                idx = max(range(len(values)), key=lambda i: (values[i] or 0))    # the run with the reported (max) value
                res.contributors = det[idx]["contributors"].get(check_id, [])[:5]
        page.checks[check_id] = res
    page.median = {k: _median([t[k] for t in tim]) for k in RECORDED}
    page.deterministic = {**{k: v for k, v in det[0]["values"].items()}, **det[0]["details"]} if det else {}
    targets = Counter(r.lcp_target for r in runs if r.lcp_target)
    page.lcp_element = safe_selector(targets.most_common(1)[0][0]) if targets else ""


def _median(values: list) -> float | None:
    present = sorted(v for v in values if v is not None)
    if not present:
        return None
    mid = len(present) // 2
    value = present[mid] if len(present) % 2 else (present[mid - 1] + present[mid]) / 2
    return round(value)


def run(cfg: PerfConfig, engine_factory: Callable[[PerfConfig], Any] = PerfEngine,
        clock: Callable[[], float] = time.monotonic) -> PerfReport:
    started = _now()
    decision = safety_evaluate(cfg)
    report = PerfReport(RUN_COMPLETE, decision.reason, cfg, {"name": "chromium-performance-apis", "executed": False},
                        started_at=started)
    report.host = {"benchmark_index": None, "min_benchmark": MIN_BENCHMARK, "calibration": MIN_BENCHMARK_CALIBRATION,
                   "timing_reliability": None, "cpu_count": os.cpu_count(), "os_family": platform.system()}
    if not decision.allowed:
        report.status = RUN_REFUSED
        report.reason = f"Safety gate refused the target: {decision.reason}. No browser was started and no request was sent."
        report.pages = [PageResult(url=u, status="NOT SCANNED", reason="refused by the safety gate") for u in cfg.pages]
        report.finished_at = _now()
        return report

    to_scan, skipped = cfg.pages[: cfg.max_pages], cfg.pages[cfg.max_pages:]
    deadline = clock() + cfg.total_timeout_seconds
    try:
        with engine_factory(cfg) as eng:
            index = eng.benchmark()
            rel = reliability(index)
            report.host.update(benchmark_index=index, timing_reliability=rel)
            for url in to_scan:
                page = PageResult(url=url, status="SCANNED")
                measured: list[RunData] = []
                t0 = clock()
                for i in range(WARMUP_RUNS + cfg.runs):
                    remaining = deadline - clock()
                    if remaining <= 0:
                        page.status, page.reason = "NOT SCANNED", f"total_timeout_seconds={cfg.total_timeout_seconds:g} reached"
                        break
                    out = eng.run(url, min(cfg.page_timeout_seconds, remaining))
                    for k, v in out.blocked.items():
                        page.blocked[k] = page.blocked.get(k, 0) + v
                    if out.status != "SCANNED":      # no retries: a failed run makes the page incomplete
                        page.status, page.reason = out.status, out.reason
                        break
                    if i >= WARMUP_RUNS:
                        measured.append(out.data)
                page.duration_ms = int((clock() - t0) * 1000)
                if page.ok:
                    evaluate_page(page, measured, cfg, rel == "LOW")
                report.pages.append(page)
            report.engine = dict(eng.info, executed=True)
    except EngineUnavailable as exc:
        report.engine = {"name": "chromium-performance-apis", "executed": False, "error": clean(str(exc), 300)}
        report.incomplete_reasons.append(f"engine unavailable: {clean(str(exc), 300)}")
        done = {p.url for p in report.pages}
        report.pages += [PageResult(url=u, status="NOT SCANNED", reason="engine unavailable") for u in to_scan if u not in done]
    for url in skipped:
        report.pages.append(PageResult(url=url, status="NOT SCANNED", reason=f"limits.max_pages={cfg.max_pages} reached"))
    if skipped:
        report.incomplete_reasons.append(f"page limit reached: {len(skipped)} configured page(s) not scanned")
    for p in report.pages:
        if not p.ok and p.reason not in ("engine unavailable",) and not p.reason.startswith("limits.max_pages"):
            report.incomplete_reasons.append(f"{p.status}: {clean(p.reason, 200)}")
    report.incomplete_reasons = list(dict.fromkeys(report.incomplete_reasons))
    report.findings = build_findings([p for p in report.pages if p.ok], cfg)
    if report.incomplete_reasons or any(not p.ok for p in report.pages):
        report.status = RUN_INCOMPLETE
        report.reason = "one or more configured pages could not be fully measured"
    else:
        report.reason = f"{decision.reason}; all configured pages measured"
    report.finished_at = _now()
    return report


__all__ = ["FAIL", "PageResult", "PerfReport", "not_configured", "run"]
