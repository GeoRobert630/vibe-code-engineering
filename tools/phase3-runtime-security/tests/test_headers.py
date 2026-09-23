from conftest import client_for, failed, make_cfg

from runtime_security.checks import headers
from runtime_security.models import Outcome, Severity


def test_safe_headers_pass(safe_app):
    cfg = make_cfg(safe_app.url)
    run = headers.run(client_for(cfg), cfg)
    assert run.findings == []
    passed = {r.name for r in run.results if r.outcome == Outcome.PASSED}
    assert {"X-Content-Type-Options", "Content-Security-Policy", "Framing protection", "Referrer-Policy", "Permissions-Policy"} <= passed
    csp = next(r for r in run.results if r.name == "Content-Security-Policy")
    assert "does not by itself prevent XSS" in csp.detail
    # plain-HTTP target: HSTS is not applicable here, reported as not verified
    hsts = next(r for r in run.results if r.name == "Strict-Transport-Security")
    assert hsts.outcome == Outcome.NOT_VERIFIED


def test_unsafe_headers_detected(unsafe_app):
    cfg = make_cfg(unsafe_app.url)
    run = headers.run(client_for(cfg), cfg)
    assert {"X-Content-Type-Options", "Content-Security-Policy", "Framing protection", "Referrer-Policy", "x-powered-by disclosure", "server disclosure"} <= failed(run)
    framing = next(f for f in run.findings if "clickjacking" in f.title)
    assert framing.severity == Severity.MEDIUM
    csp = next(f for f in run.findings if "Content-Security-Policy" in f.title)
    assert "does not replace output encoding" in csp.impact


def test_json_api_does_not_require_document_headers(safe_app):
    cfg = make_cfg(safe_app.url, headers__paths=["/api/items/1"])
    run = headers.run(client_for(cfg), cfg)
    na = {r.name for r in run.results if r.outcome == Outcome.NOT_APPLICABLE}
    assert {"Content-Security-Policy", "Framing protection"} <= na
