"""Real engine: headless Chromium + web-vitals against the local fixture server (skipped without Playwright/browser)."""

from __future__ import annotations

import json
import os

import pytest

from quality_ci.performance import reporting, sarif
from quality_ci.performance.config import parse
from quality_ci.performance.gate import evaluate
from quality_ci.performance.runner import run

from .perf_server import PerfServer

pytestmark = pytest.mark.browser

SLOW_FAIL = {"timing.tbt", "timing.cls", "budget.dom-nodes"}
SLOW_WARN = {"budget.render-blocking", "budget.script-bytes"}


def _channel() -> str:
    try:
        from playwright.sync_api import sync_playwright
    except ImportError:
        pytest.skip("Playwright not installed (pip install 'quality-ci[browser]')")
    with sync_playwright() as p:
        for channel in ("chromium", "chrome", "msedge"):
            try:
                p.chromium.launch(**({} if channel == "chromium" else {"channel": channel})).close()
                return channel
            except Exception:  # noqa: BLE001
                continue
    pytest.skip("no Chromium-family browser available for Playwright")


@pytest.fixture(scope="module")
def channel():
    return _channel()


@pytest.fixture(scope="module")
def server():
    with PerfServer(slow_seconds=4, big_bytes=300_000) as s:
        yield s


def measure(server, channel, pages, **extra):
    limits = {"page_timeout_seconds": 20, **extra.pop("limits", {})}
    cfg = parse({"target": {"base_url": server.url, "environment": "local", "production": False}, "pages": pages,
                 "browser": {"channel": channel}, "limits": limits, **extra})
    return reporting.build(run(cfg))


def statuses(d):
    return {f["check_id"]: f["pages"][0]["status"] for f in d["findings"]}


def test_good_pass(server, channel):
    d = measure(server, channel, ["/good.html"])
    assert d["run"]["status"] == "COMPLETE" and d["run"]["verdict"] == "PASS" and d["findings"] == []
    p = d["pages_tested"][0]
    assert p["deterministic"]["budget.total-bytes"] == 32_094 and p["deterministic"]["budget.request-count"] == 3
    assert p["deterministic"]["budget.render-blocking"] == 0 and p["deterministic"]["budget.dom-nodes"] == 196
    assert all(p["median"][k] is not None for k in ("timing.fcp", "timing.lcp", "timing.cls", "timing.tbt"))
    assert evaluate(d).passed and d["engine"]["executed"] is True and d["host"]["benchmark_index"]


def test_slow_fail(server, channel):
    d = measure(server, channel, ["/slow.html"])
    st = statuses(d)
    assert d["run"]["verdict"] == "FAIL" and {c for c, s in st.items() if s == "FAIL"} == SLOW_FAIL
    assert SLOW_WARN <= {c for c, s in st.items() if s == "WARN"}
    assert st.get("diagnostic.unsized-images") == "WARN"
    p = d["pages_tested"][0]
    det = p["deterministic"]
    assert (det["budget.dom-nodes"], det["budget.render-blocking"], det["budget.script-bytes"], det["render_blocking_depth"]) == \
        (3217, 4, 400_033, 3)
    assert det["model.critical-path"] == round(4 * 150 + (det["document_bytes"] + det["render_blocking_bytes"]) * 8 / 1600)
    assert p["median"]["timing.tbt"] >= 1200 and p["median"]["timing.cls"] > 0.25
    g = evaluate(d)
    assert not g.passed and g.outcome == "FAIL"
    assert "security-severity" not in json.dumps(sarif.build(d))


def test_fixed_pass_no_shared_findings(server, channel):
    fixed = measure(server, channel, ["/fixed.html"])
    assert fixed["run"]["verdict"] == "PASS" and fixed["findings"] == [] and evaluate(fixed).passed
    det = fixed["pages_tested"][0]["deterministic"]
    assert (det["budget.dom-nodes"], det["budget.render-blocking"], det["budget.script-bytes"]) == (1217, 0, 120_086)


def test_desktop_profile(server, channel):
    d = measure(server, channel, ["/good.html"], profile="desktop-lab")
    assert d["profile"]["name"] == "desktop-lab" and d["run"]["verdict"] == "PASS"


def test_no_destructive_requests_no_form_submission(server, channel):
    before = len(server.rec.requests)
    d = measure(server, channel, ["/autopost.html"])
    new = server.rec.requests[before:]
    assert {m for m, _ in new} == {"GET"} and not any(p.startswith(("/api", "/submit")) for _, p in new)
    assert d["pages_tested"][0]["status"] == "NAVIGATION BLOCKED" and d["run"]["status"] == "INCOMPLETE"


def test_redirect_offsite_timeout_oversize_request_cap(server, channel):
    d = measure(server, channel, ["/redirect.html", "/offsite.html"])
    red, off = d["pages_tested"]
    assert red["status"] == "NAVIGATION BLOCKED" and "redirect" in red["reason"]
    assert off["status"] == "SCANNED" and off["blocked_requests"].get("origin", 0) >= 1
    t = measure(server, channel, ["/slow-load.html"], limits={"page_timeout_seconds": 2})
    assert t["pages_tested"][0]["status"] == "TIMEOUT" and not evaluate(t).passed
    o = measure(server, channel, ["/big.html"], limits={"max_page_bytes": 200_000})
    assert o["pages_tested"][0]["status"] == "OVERSIZE"
    m = measure(server, channel, ["/many.html"], limits={"max_requests": 10})
    assert m["pages_tested"][0]["status"] == "TOO MANY REQUESTS" and m["run"]["status"] == "INCOMPLETE"


def test_oversized_image_diagnostic(server, channel):
    d = measure(server, channel, ["/oversized.html"])
    assert statuses(d).get("diagnostic.oversized-images") == "WARN"


def test_redaction_real(server, channel):
    cfg = parse({"target": {"base_url": server.url, "environment": "local", "production": False},
                 "pages": ["/secret.html?session=abcdef123456"], "browser": {"channel": channel}})
    report = run(cfg)
    d = reporting.build(report)
    text = json.dumps(d) + json.dumps(sarif.build(d)) + reporting.render_markdown(report)
    for s in ("abcdef123456", "ghp_", "sk_live", "Private words", "Secret text"):
        assert s not in text, s
    assert d["pages_tested"][0]["url"].endswith("/secret.html?session=<redacted>")


def test_real_run_reads_no_credentials(server, channel, monkeypatch):
    from .test_reports_sarif_gate import _EnvGuard

    g = _EnvGuard(os.environ)
    g["QA_PASSWORD"] = "fake-password-only-for-tests"
    monkeypatch.setattr(os, "environ", g)
    d = measure(server, channel, ["/good.html"])
    assert d["run"]["verdict"] == "PASS" and "fake-password" not in json.dumps(d)
