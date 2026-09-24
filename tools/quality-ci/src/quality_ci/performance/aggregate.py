"""Aggregation rules (specification section 2 / 12). Pure functions, no browser.

* value > fail -> FAIL; else value > warn -> WARN; else PASS. Equality passes. Values are rounded first.
* Timing checks: median of the measured runs. FAIL additionally needs a strict majority of runs above ``fail``
  (floor(N/2) + 1: 2 of 3, 3 of 5, 4 of 7); otherwise WARN.
* Coefficient of variation > 0.35 on a WARN/FAIL timing check -> WARN with unstable = true (never FAIL).
* timing_reliability LOW caps timing FAIL at WARN. Deterministic checks are never capped.
* Deterministic checks must be identical across runs; otherwise nondeterministic = true and the maximum is used.
* No value in any run -> NOT MEASURED. text compression on local targets -> NOT APPLICABLE.
"""

from __future__ import annotations

import statistics
from dataclasses import dataclass, field

from .measure import round_value

PASS, WARN, FAIL = "PASS", "WARN", "FAIL"
NOT_MEASURED, NOT_APPLICABLE = "NOT MEASURED", "NOT APPLICABLE"
CV_LIMIT = 0.35


@dataclass
class CheckResult:
    check_id: str
    value: float | int | None
    status: str
    warn: float | None
    fail: float | None
    runs: list[float | int | None] = field(default_factory=list)
    unstable: bool = False
    nondeterministic: bool = False
    capped: bool = False          # timing FAIL capped at WARN by low host reliability
    cv: float | None = None
    contributors: list[str] = field(default_factory=list)

    def to_dict(self) -> dict:
        return {"value": self.value, "status": self.status, "warn": self.warn, "fail": self.fail, "runs": self.runs,
                "unstable": self.unstable, "nondeterministic": self.nondeterministic, "capped_by_host": self.capped,
                "cv": self.cv}


def classify(value, warn, fail) -> str:
    if value is None:
        return NOT_MEASURED
    if fail is not None and value > fail:
        return FAIL
    if warn is not None and value > warn:
        return WARN
    return PASS


def majority(n: int) -> int:
    return n // 2 + 1


def cv(values: list[float]) -> float:
    if len(values) < 2:
        return 0.0
    mean = statistics.fmean(values)
    if mean == 0:
        return 0.0
    return statistics.pstdev(values) / mean


def aggregate_timing(check_id: str, raw_runs: list[float | None], warn, fail, reliability_low: bool) -> CheckResult:
    runs = [round_value(check_id, v) for v in raw_runs]
    present = [v for v in runs if v is not None]
    if not present:
        return CheckResult(check_id, None, NOT_MEASURED, warn, fail, runs)
    med = statistics.median(present)
    med = round_value(check_id, med)
    status = classify(med, warn, fail)
    if status == FAIL and sum(1 for v in present if v > fail) < majority(len(present)):
        status = WARN
    variation = round(cv([float(v) for v in present]), 3)
    unstable = False
    if variation > CV_LIMIT and status in (WARN, FAIL):
        status, unstable = WARN, True
    capped = False
    if reliability_low and status == FAIL:
        status, capped = WARN, True
    return CheckResult(check_id, med, status, warn, fail, runs, unstable=unstable, capped=capped, cv=variation)


def aggregate_deterministic(check_id: str, raw_runs: list[float | int | None], warn, fail) -> CheckResult:
    runs = [round_value(check_id, v) for v in raw_runs]
    present = [v for v in runs if v is not None]
    if not raw_runs or all(v is None for v in raw_runs):
        status = NOT_APPLICABLE if check_id == "diagnostic.text-compression" and raw_runs else NOT_MEASURED
        return CheckResult(check_id, None, status, warn, fail, runs)
    nondeterministic = len(set(present)) > 1
    value = max(present)
    return CheckResult(check_id, value, classify(value, warn, fail), warn, fail, runs, nondeterministic=nondeterministic)


def page_status(results: list[CheckResult]) -> str:
    statuses = {r.status for r in results}
    if FAIL in statuses:
        return FAIL
    if WARN in statuses:
        return WARN
    return PASS
