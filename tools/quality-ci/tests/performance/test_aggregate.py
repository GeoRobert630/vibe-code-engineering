"""Aggregation rules and measurement definitions (no browser)."""

from __future__ import annotations

import pytest

from quality_ci.performance.aggregate import (
    FAIL, NOT_APPLICABLE, NOT_MEASURED, PASS, WARN, aggregate_deterministic, aggregate_timing, classify, cv, majority,
    page_status,
)
from quality_ci.performance.config import PROFILES
from quality_ci.performance.measure import (
    Resource, critical_path_ms, deterministic, render_blocking_depth, round_value, tbt, timings,
)

from .fake_engine import BASE, run_data


@pytest.mark.parametrize("value,expected", [(100, PASS), (200, PASS), (201, WARN), (600, WARN), (601, FAIL), (None, NOT_MEASURED)])
def test_classify_equality_passes(value, expected):
    assert classify(value, 200, 600) == expected


def test_rounding():
    assert round_value("timing.lcp", 2500.4) == 2500 and round_value("timing.lcp", 2500.6) == 2501
    assert round_value("timing.cls", 0.10049) == 0.1 and round_value("timing.cls", 0.1005) in (0.1, 0.101)
    assert classify(round_value("timing.cls", 0.1004), 0.1, 0.25) == PASS         # 0.1004 -> 0.100 == warn -> PASS
    assert round_value("budget.total-bytes", 1_600_000) == 1_600_000


@pytest.mark.parametrize("n,need", [(3, 2), (4, 3), (5, 3), (6, 4), (7, 4)])
def test_majority(n, need):
    assert majority(n) == need


def test_timing_median_and_majority_rule():
    r = aggregate_timing("timing.tbt", [700, 700, 590], 200, 600, False)          # median 700, 2/3 above fail, low CV
    assert (r.value, r.status) == (700, FAIL)
    r = aggregate_timing("timing.tbt", [700, 650, 650], 200, 600, False)
    assert r.status == FAIL
    r = aggregate_timing("timing.lcp", [4100, 3900, 4100, 3900, 4200], 2500, 4000, False)   # median 4100, 3/5 above
    assert (r.value, r.status) == (4100, FAIL)
    r = aggregate_timing("timing.lcp", [4100, 4100, 3900, 3900], 2500, 4000, False)          # median 4000 == fail
    assert (r.value, r.status) == (4000, WARN)


def test_majority_not_met_downgrades_to_warn():
    # median above fail but only 2 of 4 runs above fail (needs 3)
    r = aggregate_timing("timing.lcp", [4200, 4200, 3990, 3990], 2500, 4000, False)
    assert r.value == 4095 and r.status == WARN


def test_unstable_cv_never_fails():
    r = aggregate_timing("timing.tbt", [1300, 100, 1300], 200, 600, False)        # FAIL by majority, CV > 0.35
    assert r.cv > 0.35 and r.status == WARN and r.unstable
    stable = aggregate_timing("timing.tbt", [1300, 1301, 1300], 200, 600, False)
    assert stable.status == FAIL and not stable.unstable and stable.cv < 0.01
    passing = aggregate_timing("timing.tbt", [0, 100, 0], 200, 600, False)          # high CV but PASS: not flagged
    assert passing.status == PASS and not passing.unstable


def test_reliability_low_caps_timing_fail_only():
    r = aggregate_timing("timing.tbt", [1300, 1300, 1300], 200, 600, True)
    assert r.status == WARN and r.capped
    assert aggregate_timing("timing.tbt", [300, 300, 300], 200, 600, True).capped is False
    d = aggregate_deterministic("budget.dom-nodes", [3217, 3217, 3217], 1500, 3000)
    assert d.status == FAIL                                                          # deterministic never capped


def test_deterministic_agreement_and_nondeterministic_max():
    same = aggregate_deterministic("budget.dom-nodes", [1200, 1200, 1200], 1500, 3000)
    assert (same.value, same.status, same.nondeterministic) == (1200, PASS, False)
    diff = aggregate_deterministic("budget.dom-nodes", [1400, 1600, 1400], 1500, 3000)
    assert (diff.value, diff.status, diff.nondeterministic) == (1600, WARN, True)


def test_not_measured_and_not_applicable():
    assert aggregate_timing("timing.lcp", [None, None, None], 2500, 4000, False).status == NOT_MEASURED
    assert aggregate_timing("timing.lcp", [None, 3000, 3000], 2500, 4000, False).value == 3000
    assert aggregate_deterministic("diagnostic.text-compression", [None, None, None], 0, None).status == NOT_APPLICABLE


def test_page_status():
    mk = lambda s: aggregate_deterministic("x", [1], None, None).__class__("x", 1, s, None, None)   # noqa: E731
    assert page_status([mk(PASS), mk(WARN)]) == WARN and page_status([mk(WARN), mk(FAIL)]) == FAIL
    assert page_status([mk(PASS), mk(NOT_APPLICABLE)]) == PASS


def test_cv():
    assert cv([1, 1, 1]) == 0 and cv([0, 0]) == 0 and cv([5]) == 0
    assert round(cv([100, 200, 300]), 3) == 0.408


# ------------------------------------------------------------------ measurement definitions

def test_tbt_after_fcp_including_straddle():
    tasks = [(0, 300), (150, 120), (500, 700), (1300, 40)]
    # fcp=200: task1 ends 300 -> part after FCP 100 -> 50; task2 150..270 straddles -> 70 -> 20; task3 -> 650; task4 < 50 -> 0
    assert tbt(tasks, 200) == 720
    assert tbt(tasks, None) is None and tbt([], 100) == 0


def test_render_blocking_depth_and_model_formula():
    prof = PROFILES["mobile-lab"]
    assert render_blocking_depth(run_data()) == 0
    assert render_blocking_depth(run_data(scripts=["a.js"])) == 1
    assert render_blocking_depth(run_data(styles=["s.css"], imports=[("i1.css", 1), ("i2.css", 2)])) == 3
    # (1 + 3) x 150 ms + (1758 + 400342) bytes x 8 / 1600 kbit/s
    assert round(critical_path_ms(prof, 3, 1758, 400_342)) == 600 + round(402_100 * 8 / 1600)
    assert critical_path_ms(PROFILES["desktop-lab"], 0, 10_000, 0) == 40 + 8


def test_deterministic_accounting_and_contributors():
    res = [Resource(f"{BASE}/p.html", "document", 1758, "text/html", "", True),
           Resource(f"{BASE}/slow.js", "script", 400_033, "text/javascript"),
           Resource(f"{BASE}/slow.css", "stylesheet", 226, "text/css"),
           Resource(f"{BASE}/i1.css", "stylesheet", 58, "text/css"),
           Resource(f"{BASE}/i2.css", "stylesheet", 25, "text/css"),
           Resource(f"{BASE}/img/x.png", "image", 1060, "image/png"),
           Resource(f"{BASE}/f.woff2", "font", 900, "font/woff2")]
    rd = run_data(resources=res, scripts=[f"{BASE}/slow.js"], styles=[f"{BASE}/slow.css"],
                  imports=[(f"{BASE}/i1.css", 1), (f"{BASE}/i2.css", 2)], dom=3217, unsized=[f"{BASE}/img/x.png"])
    d = deterministic(rd, PROFILES["mobile-lab"], local=True)
    v = d["values"]
    assert v["budget.total-bytes"] == sum(r.bytes for r in res) and v["budget.script-bytes"] == 400_033
    assert v["budget.stylesheet-bytes"] == 309 and v["budget.image-bytes"] == 1060 and v["budget.font-bytes"] == 900
    assert v["budget.document-bytes"] == 1758 and v["budget.request-count"] == 7 and v["budget.render-blocking"] == 4
    assert v["budget.dom-nodes"] == 3217 and v["diagnostic.unsized-images"] == 1 and v["diagnostic.text-compression"] is None
    assert d["details"] == {"render_blocking_depth": 3, "document_bytes": 1758, "render_blocking_bytes": 400_342}
    assert v["model.critical-path"] == round(4 * 150 + (1758 + 400_342) * 8 / 1600)
    assert d["contributors"]["budget.script-bytes"] == [f"{BASE}/slow.js"]
    assert d["contributors"]["budget.render-blocking"][0] == f"{BASE}/slow.js"


def test_text_compression_only_for_non_local():
    res = [Resource(f"{BASE}/p.html", "document", 5000, "text/html; charset=utf-8", "", True),
           Resource(f"{BASE}/a.js", "script", 5000, "application/javascript", "gzip"),
           Resource(f"{BASE}/b.css", "stylesheet", 500, "text/css", ""),              # <= 1 KB: ignored
           Resource(f"{BASE}/c.png", "image", 9000, "image/png", "")]                 # not text
    assert deterministic(run_data(resources=res), PROFILES["mobile-lab"], local=False)["values"]["diagnostic.text-compression"] == 1
    assert deterministic(run_data(resources=res), PROFILES["mobile-lab"], local=True)["values"]["diagnostic.text-compression"] is None


def test_timings_recorded():
    t = timings(run_data(fcp=200, lcp=900, cls=0.05, tbt_tasks=[(300, 120), (500, 30)]))
    assert (t["timing.fcp"], t["timing.lcp"], t["timing.cls"], t["timing.tbt"], t["long_tasks"]) == (200, 900, 0.05, 70, 1)
    assert {"ttfb_ms", "dcl_ms", "load_ms"} <= set(t) and "inp" not in " ".join(t)
