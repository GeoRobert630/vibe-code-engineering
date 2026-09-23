from conftest import client_for, make_cfg
from mock_app import UNSAFE_COOKIE_VALUE

from runtime_security.checks import cookies
from runtime_security.models import Outcome, Severity


def test_secure_cookies_pass(safe_app):
    cfg = make_cfg(safe_app.url)
    run = cookies.run(client_for(cfg), cfg)
    assert run.findings == []
    details = " ".join(r.detail for r in run.results if r.outcome == Outcome.PASSED)
    assert "name=session" in details and "HttpOnly" in details and "SameSite=Lax" in details


def test_insecure_cookies_detected(unsafe_app):
    cfg = make_cfg(unsafe_app.url)
    run = cookies.run(client_for(cfg), cfg)
    titles = {f.title for f in run.findings}
    assert "Cookie without Secure flag (session)" in titles
    assert "Session cookie without HttpOnly (session)" in titles
    assert "Session cookie without explicit SameSite (session)" in titles
    assert "SameSite=None without Secure (tracking)" in titles
    assert next(f for f in run.findings if f.title.startswith("Session cookie without HttpOnly")).severity == Severity.MEDIUM


def test_cookie_values_never_reported(unsafe_app):
    cfg = make_cfg(unsafe_app.url)
    run = cookies.run(client_for(cfg), cfg)
    blob = repr([f.to_dict() for f in run.findings]) + repr([r.to_dict() for r in run.results])
    assert UNSAFE_COOKIE_VALUE not in blob
    assert "value=<redacted" in blob


def test_parse_samesite_none_with_secure_is_acceptable():
    c = cookies.parse_set_cookie("sid=x; Secure; HttpOnly; SameSite=None; Path=/")
    assert c.samesite == "None" and c.secure and c.httponly


def test_no_cookies_is_not_verified(safe_app):
    cfg = make_cfg(safe_app.url, cookies__paths=["/api/items/1"])
    run = cookies.run(client_for(cfg), cfg)
    assert run.results[-1].outcome == Outcome.NOT_VERIFIED


def test_cookie_name_survives_redaction_in_final_report(unsafe_app):
    from conftest import full_report

    report = full_report(unsafe_app.url)
    ev = next(f.evidence for f in report.findings if f.title.startswith("Session cookie without HttpOnly"))
    assert "name=session" in ev and UNSAFE_COOKIE_VALUE not in ev and "value=<redacted" in ev
