"""Deterministic IDs, grouping/deduplication, URL and selector handling, redaction, limits, incomplete scans."""

from __future__ import annotations

import json
import re

from conftest import BASE, FakeEngine, factory, make_cfg, rr

from quality_ci import reporting
from quality_ci.engine import AXE_SHA256, EngineUnavailable, load_axe_source
from quality_ci.findings import MAX_SELECTORS, build_findings
from quality_ci.models import FINDING_ID_RE, PAGE_OK, RUN_COMPLETE, RUN_INCOMPLETE, PageScan, finding_id
from quality_ci.redaction import safe_selector, safe_url
from quality_ci.runner import EXIT_BLOCKING, EXIT_ERROR, EXIT_NON_BLOCKING, EXIT_OK, run


def page(url, violations=(), incomplete=()):
    return PageScan(url=url, status=PAGE_OK, violations=list(violations), incomplete=list(incomplete),
                    rules_evaluated=sorted({r.rule_id for r in [*violations, *incomplete]} | {"document-title"}))


def test_deterministic_ids_and_format():
    a = finding_id("violation", "image-alt")
    assert a == finding_id("violation", "image-alt") and FINDING_ID_RE.match(a)
    assert a != finding_id("violation", "label") and a != finding_id("needs-review", "image-alt")
    assert a == "Q-A11Y-" + __import__("hashlib").sha256(b"axe-core:violation:image-alt").hexdigest()[:10]


def test_duplicate_correlation_same_page_and_across_pages():
    p1 = page(f"{BASE}/a", [rr("image-alt", "critical", ["img.a", "img.b", "img.c"]), rr("label", "critical", ["#n"])])
    p2 = page(f"{BASE}/b", [rr("image-alt", "serious", ["img.z"])])
    findings = build_findings([p1, p2], "axe-core 4.10.3")
    by_rule = {f.rule_id: f for f in findings}
    assert set(by_rule) == {"image-alt", "label"}                       # different rules never merged
    img = by_rule["image-alt"]
    assert img.occurrence_count == 4 and img.urls == [f"{BASE}/a", f"{BASE}/b"]
    assert img.pages[0].occurrences == 3 and img.pages[0].selectors == ["img.a", "img.b", "img.c"]
    assert img.selector == "img.a" and img.impact == "critical" and img.severity == "CRITICAL" and img.blocking
    assert img.source == "axe-core 4.10.3" and img.category == "accessibility"


def test_violation_and_review_kept_separate():
    p = page(f"{BASE}/a", [rr("color-contrast", "serious", ["p"])], [rr("color-contrast", "serious", ["h2"])])
    f = build_findings([p], "axe-core")
    assert [(x.kind, x.status, x.severity, x.blocking) for x in f] == [
        ("violation", "OPEN", "HIGH", True), ("needs-review", "NEEDS_REVIEW", "INFORMATIONAL", False)]
    assert f[0].id != f[1].id


def test_severity_mapping_and_blocking():
    p = page(f"{BASE}/a", [rr("r1", "critical"), rr("r2", "serious"), rr("r3", "moderate"), rr("r4", "minor"), rr("r5", None)])
    got = {f.rule_id: (f.severity, f.blocking) for f in build_findings([p], "axe")}
    assert got == {"r1": ("CRITICAL", True), "r2": ("HIGH", True), "r3": ("MEDIUM", False), "r4": ("LOW", False), "r5": ("MEDIUM", False)}


def test_selector_handling_capped_and_redacted():
    targets = [f"li:nth-child({i})" for i in range(9)] + ['input[value="hunter2-secret"]', "#tok_ghp_abcdefghijklmnopqrstuvwxyz0123456789AB",
                                                          'a[href="/x?session=abc123"]', "iframe >>> #inner"]
    f = build_findings([page(f"{BASE}/a", [rr("list", "serious", targets)])], "axe")[0]
    assert f.occurrence_count == 13 and len(f.pages[0].selectors) == MAX_SELECTORS
    assert safe_selector('input[value="hunter2-secret"]') == 'input[value="<redacted>"]'
    assert "ghp_" not in safe_selector("#tok_ghp_abcdefghijklmnopqrstuvwxyz0123456789AB")
    assert "abc123" not in safe_selector('a[href="/x?session=abc123"]')
    assert safe_selector("iframe >>> #inner") == "iframe >>> #inner"
    assert len(safe_selector("div " * 200)) <= 200


def test_url_handling_query_userinfo_fragment():
    assert safe_url("http://127.0.0.1:8080/p?token=abc&x=1#frag") == "http://127.0.0.1:8080/p?token=<redacted>&x=<redacted>"
    assert safe_url("https://user:pw@example.test/") == "https://example.test/"
    assert safe_url("http://localhost:3000") == "http://localhost:3000/"
    f = build_findings([page(f"{BASE}/p?session=s3cr3t", [rr("label")])], "axe")[0]
    assert f.urls == [f"{BASE}/p?session=<redacted>"] and "s3cr3t" not in json.dumps(f.to_dict())
    assert f.help_url.endswith("?application=<redacted>")


def test_clean_run_bad_run_exit_codes():
    clean_run = run(make_cfg(), factory())
    assert clean_run.status == RUN_COMPLETE and clean_run.verdict == "PASS" and clean_run.exit_code == EXIT_OK
    bad = run(make_cfg(pages=["/bad.html"]), factory({"/bad.html": page("", [rr("image-alt", "critical")])}))
    assert bad.verdict == "FAIL" and bad.exit_code == EXIT_BLOCKING
    minor = run(make_cfg(pages=["/m"]), factory({"/m": page("", [rr("region", "moderate")])}))
    assert minor.verdict == "FAIL" and minor.exit_code == EXIT_NON_BLOCKING
    review = run(make_cfg(pages=["/r"]), factory({"/r": page("", [], [rr("color-contrast")])}))
    assert review.verdict == "PASS" and review.exit_code == EXIT_OK and len(review.findings) == 1


def test_page_count_limit():
    cfg = make_cfg(pages=["/1", "/2", "/3"], limits={"max_pages": 2})
    r = run(cfg, factory())
    eng = FakeEngine.instances[0]
    assert [u for u, _ in eng.calls] == [f"{BASE}/1", f"{BASE}/2"]
    assert r.status == RUN_INCOMPLETE and r.exit_code == EXIT_ERROR and r.verdict == "INCOMPLETE"
    assert r.pages[2].status == "NOT SCANNED" and "max_pages=2" in r.pages[2].reason
    assert any("page limit reached" in x for x in r.incomplete_reasons)


def test_total_timeout_and_page_timeout_budget():
    t = {"now": 0.0}

    def clock():
        t["now"] += 40
        return t["now"]

    cfg = make_cfg(pages=["/1", "/2", "/3"], limits={"total_timeout_seconds": 100, "page_timeout_seconds": 30})
    r = run(cfg, factory(), clock=clock)
    calls = FakeEngine.instances[0].calls
    # deadline 140: page 1 gets the page cap (30), page 2 only the remaining total budget (20), page 3 none
    assert [t for _, t in calls] == [30, 20]
    assert [p.status for p in r.pages] == ["SCANNED", "SCANNED", "NOT SCANNED"]
    assert r.status == RUN_INCOMPLETE and "total_timeout_seconds=100" in r.pages[2].reason


def test_page_timeout_status_makes_run_incomplete():
    slow = PageScan(url="", status="TIMEOUT", reason="page load exceeded page_timeout_seconds")
    r = run(make_cfg(pages=["/good.html", "/slow"]), factory({"/slow": slow}))
    assert r.status == RUN_INCOMPLETE and r.exit_code == EXIT_ERROR
    assert any(x.startswith("TIMEOUT") for x in r.incomplete_reasons)


def test_engine_unavailable_is_incomplete_not_pass():
    def broken(cfg):
        raise EngineUnavailable("browser could not be started (missing)")

    r = run(make_cfg(), broken)
    d = reporting.build(r)
    assert d["run"]["status"] == "INCOMPLETE" and d["run"]["verdict"] == "INCOMPLETE" and d["engine"]["executed"] is False
    assert d["pages_tested"][0]["status"] == "NOT SCANNED" and r.exit_code == EXIT_ERROR


def test_axe_integrity_pinned(tmp_path):
    assert load_axe_source().startswith("/*! axe")
    bad = tmp_path / "axe.min.js"
    bad.write_text("window.axe = {}")
    try:
        load_axe_source(bad)
    except EngineUnavailable as exc:
        assert "integrity" in str(exc) and AXE_SHA256[:12] in str(exc)
    else:
        raise AssertionError("tampered engine accepted")


def test_json_deterministic_apart_from_timestamps():
    pages = {"/bad.html": page("", [rr("label", "critical", ["#b", "#a"]), rr("image-alt", "critical")])}
    a = reporting.build(run(make_cfg(pages=["/bad.html", "/good.html"]), factory(pages)))
    b = reporting.build(run(make_cfg(pages=["/bad.html", "/good.html"]), factory(pages)))
    for d in (a, b):
        d["run"].pop("started_at"), d["run"].pop("finished_at")
    assert json.dumps(a, sort_keys=True) == json.dumps(b, sort_keys=True)
    assert re.match(r"^\d{4}-\d\d-\d\dT\d\d:\d\d:\d\dZ$", reporting.build(run(make_cfg(), factory()))["run"]["started_at"])
