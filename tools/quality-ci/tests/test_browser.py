"""Real engine tests: axe-core in headless Chromium against the local fixture server.

Skipped (not failed) when Playwright or a Chromium-family browser is unavailable; the reason is printed with -rs.
"""

from __future__ import annotations

import json
import os

import pytest
from fixture_server import FixtureServer

from quality_ci import reporting, sarif
from quality_ci.config import parse
from quality_ci.gate import evaluate
from quality_ci.runner import run

pytestmark = pytest.mark.browser

BAD_RULES = {"aria-roles", "button-name", "color-contrast", "document-title", "heading-order", "html-has-lang",
             "image-alt", "label", "link-name", "region", "tabindex"}


def _channel() -> str:
    try:
        from playwright.sync_api import sync_playwright
    except ImportError:
        pytest.skip("Playwright not installed (pip install 'quality-ci[browser]')")
    with sync_playwright() as p:
        for channel in ("chromium", "chrome", "msedge"):
            try:
                b = p.chromium.launch(**({} if channel == "chromium" else {"channel": channel}))
                b.close()
                return channel
            except Exception:  # noqa: BLE001
                continue
    pytest.skip("no Chromium-family browser available for Playwright")


@pytest.fixture(scope="module")
def channel():
    return _channel()


@pytest.fixture(scope="module")
def server():
    with FixtureServer(slow_seconds=4, big_bytes=300_000) as s:
        yield s


def scan(server, channel, pages, **limits):
    cfg = parse({"target": {"base_url": server.url, "environment": "local", "production": False}, "pages": pages,
                 "browser": {"channel": channel}, "limits": {"page_timeout_seconds": 15, "max_page_bytes": 200_000, **limits}})
    return reporting.build(run(cfg))


def rules(d):
    return {f["rule_id"] for f in d["findings"] if f["kind"] == "violation"}


def test_good_pass(server, channel):
    d = scan(server, channel, ["/good.html"])
    assert d["run"]["status"] == "COMPLETE" and d["run"]["verdict"] == "PASS" and rules(d) == set()
    assert len(d["rules_evaluated"]) >= 50 and d["engine"]["version"] == "4.10.3" and d["engine"]["executed"] is True
    assert evaluate(d).passed


def test_bad_fail_with_known_violations(server, channel):
    d = scan(server, channel, ["/bad.html"])
    assert d["run"]["verdict"] == "FAIL" and rules(d) == BAD_RULES
    g = evaluate(d)
    assert not g.passed and g.outcome == "FAIL"
    by = {f["rule_id"]: f for f in d["findings"]}
    assert by["image-alt"]["occurrence_count"] == 3 and by["image-alt"]["severity"] == "CRITICAL" and by["image-alt"]["blocking"]
    assert by["label"]["occurrence_count"] == 2 and by["label"]["selector"] == "#name"
    assert by["html-has-lang"]["selector"] == "html" and by["color-contrast"]["occurrence_count"] == 2
    assert all(f["id"].startswith("Q-A11Y-") and f["source"] == "axe-core 4.10.3" for f in d["findings"])
    doc = sarif.build(d)
    assert {r["ruleId"] for r in doc["runs"][0]["results"] if r["kind"] == "fail"} == {f"a11y/{r}" for r in BAD_RULES}


def test_fixed_pass(server, channel):
    d = scan(server, channel, ["/fixed.html"])
    assert d["run"]["verdict"] == "PASS" and rules(d) == set() and evaluate(d).passed


def test_bad_and_fixed_together_deterministic(server, channel):
    a = scan(server, channel, ["/bad.html", "/fixed.html", "/good.html"])
    b = scan(server, channel, ["/bad.html", "/fixed.html", "/good.html"])
    for d in (a, b):
        d["run"].pop("started_at"), d["run"].pop("finished_at")
        for p in d["pages_tested"]:
            p.pop("duration_ms")
    assert json.dumps(a["findings"], sort_keys=True) == json.dumps(b["findings"], sort_keys=True)
    assert a == b
    assert all(set(f["urls"]) == {f"{server.url}/bad.html"} for f in a["findings"] if f["kind"] == "violation")


def test_no_destructive_requests_and_no_form_submission(server, channel):
    before = len(server.rec.requests)
    d = scan(server, channel, ["/autopost.html"])
    new = server.rec.requests[before:]
    assert {m for m, _ in new} == {"GET"} and not any(p.startswith(("/api", "/submit")) for _, p in new)
    page = d["pages_tested"][0]
    assert page["status"] == "NAVIGATION BLOCKED" and d["run"]["status"] == "INCOMPLETE"
    assert page["blocked_requests"].get("method", 0) >= 1 and page["blocked_requests"].get("navigation", 0) == 1


def test_redirect_not_followed_and_offsite_blocked(server, channel):
    d = scan(server, channel, ["/redirect.html", "/offsite.html"])
    red, off = d["pages_tested"]
    assert red["status"] == "NAVIGATION BLOCKED" and "redirect" in red["reason"]
    assert off["status"] == "SCANNED" and off["blocked_requests"] == {"origin": 1}


def test_timeout(server, channel):
    d = scan(server, channel, ["/slow.html"], page_timeout_seconds=1)
    assert d["pages_tested"][0]["status"] == "TIMEOUT" and d["run"]["status"] == "INCOMPLETE" and not evaluate(d).passed


def test_page_size_limit(server, channel):
    d = scan(server, channel, ["/big.html"])
    assert d["pages_tested"][0]["status"] == "OVERSIZE" and d["run"]["status"] == "INCOMPLETE"


def test_page_count_limit_real(server, channel):
    d = scan(server, channel, ["/good.html", "/fixed.html", "/bad.html"], max_pages=2)
    assert [p["status"] for p in d["pages_tested"]] == ["SCANNED", "SCANNED", "NOT SCANNED"]
    assert d["run"]["status"] == "INCOMPLETE" and rules(d) == set()


def test_selector_and_url_redaction_real(server, channel):
    d = scan(server, channel, ["/secret.html?session=abcdef123456"])
    text = json.dumps(d) + json.dumps(sarif.build(d))
    assert "ghp_" not in text and "sk_live" not in text and "abcdef123456" not in text
    assert d["pages_tested"][0]["url"].endswith("/secret.html?session=<redacted>")
    assert "Secret selectors" not in text                          # no page text copied (document title)


def test_real_scan_reads_no_credentials(server, channel, monkeypatch):
    from test_reports_sarif_gate import _EnvGuard

    g = _EnvGuard(os.environ)
    g["QA_PASSWORD"] = "fake-password-only-for-tests"
    monkeypatch.setattr(os, "environ", g)
    d = scan(server, channel, ["/good.html"])
    assert d["run"]["verdict"] == "PASS" and "fake-password" not in json.dumps(d)
