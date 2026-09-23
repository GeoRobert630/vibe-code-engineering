import json

from conftest import client_for, full_report, make_cfg
from mock_app import UNSAFE_COOKIE_VALUE, UNSAFE_DB_PASSWORD

from runtime_security.checks import error_leakage
from runtime_security.models import Severity
from runtime_security.reporting import json_report, markdown_report


def test_safe_errors_pass(safe_app):
    cfg = make_cfg(safe_app.url)
    run = error_leakage.run(client_for(cfg), cfg)
    assert run.findings == []
    assert len(run.results) == 5  # nonexistent, missing param, invalid id, malformed JSON, unsupported method


def test_stack_trace_and_db_error_detected(unsafe_app):
    cfg = make_cfg(unsafe_app.url)
    run = error_leakage.run(client_for(cfg), cfg)
    labels = {f.title for f in run.findings}
    assert "Error response leaks python stack trace" in labels
    assert "Error response leaks sql/database error" in labels
    assert "Error response leaks filesystem/source path" in labels
    assert "Error response leaks node.js stack trace" in labels
    secret = next(f for f in run.findings if "secret-like" in f.title)
    assert secret.severity == Severity.HIGH


def test_leaked_secret_redacted_in_reports(unsafe_app):
    report = full_report(unsafe_app.url)
    blob = json.dumps(json_report.build(report)) + markdown_report.render(report)
    assert UNSAFE_DB_PASSWORD not in blob
    assert UNSAFE_COOKIE_VALUE not in blob
    assert "<redacted>" in blob or "&lt;redacted&gt;" in blob


def test_probes_do_not_send_valid_json(safe_app):
    cfg = make_cfg(safe_app.url)
    methods = {p[0] for p in error_leakage._probes(cfg)}
    assert methods <= {"GET", "POST", "PHASE3PROBE"}
    post_body = next(p[2] for p in error_leakage._probes(cfg) if p[0] == "POST")
    try:
        json.loads(post_body)
        raise AssertionError("probe body must be invalid JSON")
    except ValueError:
        pass
