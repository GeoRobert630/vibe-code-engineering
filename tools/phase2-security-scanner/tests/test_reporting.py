import json

from phase2.models import Confidence, Finding, Severity, Status
from phase2.orchestrator import ScanReport
from phase2.reporting import json_report, markdown_report
from phase2.severity import (
    EXIT_BLOCKING, EXIT_FAILURE, EXIT_NON_BLOCKING, EXIT_OK, NOT_READY, READY, READY_WITH_RISKS,
    count_by_severity, exit_code, is_blocking, release_status,
)


def mk(sev, conf=Confidence.HIGH, status=Status.OPEN, **kw):
    f = Finding(scanner="s", category="c", severity=sev, confidence=conf, title=kw.pop("title", f"{sev.value} issue"), description="d", status=status, **kw)
    f.compute_ids()
    return f


def report(findings, failure=False):
    return ScanReport(project={"name": "p", "path": "/p", "files_scanned": 1}, technologies=[], tools=[], scanners=[],
                      findings=findings, baseline=None, limitations=["lim"], configuration={"external_tools": False, "min_report_severity": "INFORMATIONAL"},
                      tool_failure=failure)


def test_severity_counting_only_active():
    fs = [mk(Severity.HIGH), mk(Severity.HIGH, status=Status.BASELINED), mk(Severity.LOW, status=Status.REQUIRES_REVIEW), mk(Severity.MEDIUM, status=Status.IGNORED)]
    c = count_by_severity(fs)
    assert c == {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 0, "LOW": 1, "INFORMATIONAL": 0}
    assert count_by_severity(fs, active_only=False)["HIGH"] == 2


def test_blocking_rules():
    assert is_blocking(mk(Severity.CRITICAL, Confidence.LOW))
    assert is_blocking(mk(Severity.HIGH, Confidence.MEDIUM, Status.REQUIRES_REVIEW))
    assert not is_blocking(mk(Severity.HIGH, Confidence.LOW))
    assert not is_blocking(mk(Severity.CRITICAL, status=Status.BASELINED))
    assert not is_blocking(mk(Severity.MEDIUM))


def test_exit_codes_and_release_status():
    assert exit_code([], False) == EXIT_OK and release_status([], False) == READY
    assert exit_code([mk(Severity.INFORMATIONAL)], False) == EXIT_OK
    assert exit_code([mk(Severity.LOW)], False) == EXIT_NON_BLOCKING
    assert release_status([mk(Severity.LOW)], False) == READY_WITH_RISKS
    assert exit_code([mk(Severity.HIGH)], False) == EXIT_BLOCKING
    assert release_status([mk(Severity.HIGH)], False) == NOT_READY
    assert exit_code([mk(Severity.LOW)], True) == EXIT_FAILURE
    assert exit_code([mk(Severity.CRITICAL)], True) == EXIT_BLOCKING
    assert release_status([], True) == NOT_READY
    assert release_status([mk(Severity.MEDIUM, status=Status.BASELINED)], False) == READY_WITH_RISKS


def test_json_report_structure(vulnerable_node_report):
    data = json_report.build(vulnerable_node_report)
    assert data["schema_version"] == "1.0"
    assert data["release_status"] == "NOT READY" and data["exit_code"] == 2
    required = {"id", "scanner", "category", "severity", "confidence", "title", "description", "project", "file", "line", "column",
                "evidence", "impact", "recommendation", "validation", "cwe", "owasp", "source", "status"}
    for f in data["findings"]:
        assert required <= set(f)
    assert data["summary"]["active_by_severity"]["CRITICAL"] >= 1
    json.dumps(data)  # serialisable


def test_severity_filter_does_not_change_exit(vulnerable_node_report):
    data = json_report.build(vulnerable_node_report, Severity.CRITICAL)
    assert all(f["severity"] == "CRITICAL" for f in data["findings"])
    assert data["summary"]["active_by_severity"]["HIGH"] > 0 and data["exit_code"] == 2


def test_markdown_sections(vulnerable_node_report):
    md = markdown_report.render(vulnerable_node_report)
    for heading in ["# Security Audit Report", "## Project", "## Technologies Detected", "## Scanner Availability", "## Summary",
                    "## Blocking Findings", "## Findings", "## Baseline Findings", "## Limitations", "## Release Status"]:
        assert heading in md
    assert "**NOT READY**" in md


def test_markdown_escapes_untrusted_content():
    f = mk(Severity.LOW, title="t", file="x|y<script>.js", evidence="[click](http://evil) <img src=x onerror=alert(1)> `code`")
    md = markdown_report.render(report([f]))
    assert "<script>" not in md and "<img" not in md and "[click](http" not in md
    assert "&lt;img" in md


def test_empty_report_says_not_proof_of_security():
    md = markdown_report.render(report([]))
    assert "**READY**" in md and "does not mean the application is secure" in md
