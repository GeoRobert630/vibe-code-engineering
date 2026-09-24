"""Q-PERF findings: IDs, grouping, severity table, contributors; runner limits and no-retry behaviour (fake engine)."""

from __future__ import annotations

import hashlib

from quality_ci.performance.engine import RunOutcome
from quality_ci.performance.findings import FINDING_ID_RE, finding_id
from quality_ci.performance.measure import Resource
from quality_ci.performance.runner import EXIT_BLOCKING, EXIT_ERROR, EXIT_NON_BLOCKING, EXIT_OK, run

from .conftest import make_cfg
from .fake_engine import BASE, FakeEngine, factory, ok, run_data

SLOW = ok(run_data(fcp=200, lcp=1880, cls=0.376, tbt_tasks=[(300, 700), (1010, 700)], dom=3217,
                   scripts=[f"{BASE}/slow.js"], styles=[f"{BASE}/slow.css"], imports=[(f"{BASE}/i1.css", 1), (f"{BASE}/i2.css", 2)],
                   unsized=[f"{BASE}/img/shift.png"],
                   resources=[Resource(f"{BASE}/slow.html", "document", 1758, "text/html", "", True),
                              Resource(f"{BASE}/slow.js", "script", 400_033, "text/javascript"),
                              Resource(f"{BASE}/slow.css", "stylesheet", 226, "text/css"),
                              Resource(f"{BASE}/i1.css", "stylesheet", 58, "text/css"),
                              Resource(f"{BASE}/i2.css", "stylesheet", 25, "text/css"),
                              Resource(f"{BASE}/img/shift.png", "image", 1060, "image/png")]))


def by_check(report):
    return {f.check_id: f for f in report.findings}


def test_ids_deterministic_and_namespaced():
    fid = finding_id("timing.tbt")
    assert fid == "Q-PERF-" + hashlib.sha256(b"performance:timing.tbt").hexdigest()[:10] and FINDING_ID_RE.match(fid)
    assert fid == finding_id("timing.tbt") != finding_id("timing.cls") and not fid.startswith("Q-A11Y-")


def test_clean_page_no_findings():
    r = run(make_cfg(), factory())
    assert r.findings == [] and r.verdict == "PASS" and r.exit_code == EXIT_OK and r.status == "COMPLETE"


def test_slow_findings_and_severity_table():
    r = run(make_cfg(pages=["/slow.html"]), factory({"/slow.html": SLOW}))
    f = by_check(r)
    for cid in ("timing.tbt", "timing.cls", "budget.dom-nodes"):
        assert (f[cid].severity, f[cid].status, f[cid].blocking) == ("HIGH", "OPEN", True), cid
    for cid in ("budget.render-blocking", "budget.script-bytes", "model.critical-path"):
        assert (f[cid].severity, f[cid].blocking) == ("MEDIUM", False), cid
    assert (f["diagnostic.unsized-images"].severity, f["diagnostic.unsized-images"].blocking) == ("LOW", False)
    assert f["timing.tbt"].pages[0].value == 1300 and f["timing.tbt"].pages[0].runs == [1300, 1300, 1300]
    assert f["budget.render-blocking"].pages[0].contributors[0] == f"{BASE}/slow.js"
    assert "timing.lcp" not in f and "timing.fcp" not in f
    assert all(x.severity != "CRITICAL" for x in r.findings)
    assert r.verdict == "FAIL" and r.exit_code == EXIT_BLOCKING


def test_slow_host_capped_still_fails_on_dom_nodes():
    r = run(make_cfg(pages=["/slow.html"]), factory({"/slow.html": SLOW}, index=10.0))
    f = by_check(r)
    assert r.host["timing_reliability"] == "LOW"
    assert f["timing.tbt"].severity == "MEDIUM" and f["timing.tbt"].pages[0].capped_by_host
    assert f["timing.cls"].severity == "MEDIUM" and any("capped" in n for n in f["timing.cls"].notes)
    assert f["budget.dom-nodes"].severity == "HIGH" and f["budget.dom-nodes"].blocking
    assert r.verdict == "FAIL" and r.exit_code == EXIT_BLOCKING


def test_warn_only_and_diagnostic_only():
    warn = run(make_cfg(), factory(default=ok(run_data(dom=1600))))
    assert [(f.check_id, f.severity) for f in warn.findings] == [("budget.dom-nodes", "MEDIUM")]
    assert warn.verdict == "WARN" and warn.exit_code == EXIT_NON_BLOCKING
    diag = run(make_cfg(), factory(default=ok(run_data(oversized=[f"{BASE}/big.png"]))))
    assert [(f.check_id, f.severity) for f in diag.findings] == [("diagnostic.oversized-images", "LOW")]


def test_not_measured_and_nondeterministic_are_informational():
    r = run(make_cfg(), factory(default=ok(run_data(lcp=None))))
    f = by_check(r)["timing.lcp"]
    assert (f.severity, f.status, f.blocking) == ("INFORMATIONAL", "NEEDS_REVIEW", False) and r.verdict == "PASS"
    seq = [ok(run_data(dom=1200)), ok(run_data(dom=1200)), ok(run_data(dom=1210)), ok(run_data(dom=1200))]
    nd = by_check(run(make_cfg(), factory({"/page.html": seq})))["budget.dom-nodes"]
    assert nd.severity == "INFORMATIONAL" and nd.pages[0].nondeterministic and nd.pages[0].value == 1210


def test_grouped_across_pages_contributors_capped():
    many = [Resource(f"{BASE}/s{i}.js", "script", 100_000, "text/javascript") for i in range(8)]
    heavy = ok(run_data(resources=[Resource(f"{BASE}/p.html", "document", 1000, "text/html", "", True), *many]))
    r = run(make_cfg(pages=["/a", "/b", "/c"]), factory({"/a": heavy, "/b": heavy}))
    f = by_check(r)["budget.script-bytes"]
    assert f.urls == [f"{BASE}/a", f"{BASE}/b"] and f.occurrence_count == 2 and len(f.pages[0].contributors) == 5
    assert len([x for x in r.findings if x.check_id == "budget.script-bytes"]) == 1


def test_warmup_discarded_and_runs_count():
    warm = ok(run_data(tbt_tasks=[(300, 5000)]))                 # huge warm-up value must not count
    r = run(make_cfg(runs=5), factory({"/page.html": [warm] + [ok(run_data())] * 5}))
    eng = FakeEngine.instances[0]
    assert len(eng.calls) == 6 and r.pages[0].runs[0]["timing.tbt"] == 0 and len(r.pages[0].runs) == 5
    assert r.findings == []


def test_failed_run_no_retry_page_incomplete():
    seq = [ok(run_data()), ok(run_data()), RunOutcome(status="TIMEOUT", reason="page load exceeded page_timeout_seconds")]
    r = run(make_cfg(), factory({"/page.html": seq}))
    assert len(FakeEngine.instances[0].calls) == 3                                     # stopped, not retried
    assert r.pages[0].status == "TIMEOUT" and r.status == "INCOMPLETE" and r.exit_code == EXIT_ERROR
    assert r.verdict == "INCOMPLETE" and r.findings == []


def test_page_count_limit_and_total_timeout():
    r = run(make_cfg(pages=["/1", "/2", "/3"], limits={"max_pages": 2}), factory())
    assert [p.status for p in r.pages] == ["SCANNED", "SCANNED", "NOT SCANNED"] and r.status == "INCOMPLETE"
    t = {"now": 0.0}

    def clock():
        t["now"] += 10
        return t["now"]

    r2 = run(make_cfg(pages=["/1", "/2"], limits={"total_timeout_seconds": 70, "page_timeout_seconds": 30}), factory(), clock=clock)
    calls = FakeEngine.instances[-1].calls
    assert all(ts <= 30 for _, ts in calls) and r2.pages[1].status == "NOT SCANNED" and "total_timeout_seconds=70" in r2.pages[1].reason


def test_engine_unavailable_incomplete():
    from quality_ci.performance.engine import EngineUnavailable

    def broken(cfg):
        raise EngineUnavailable("browser could not be started (missing)")

    r = run(make_cfg(), broken)
    assert r.status == "INCOMPLETE" and r.engine["executed"] is False and r.exit_code == EXIT_ERROR
