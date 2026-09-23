"""Error-leakage correlation: one finding per distinct disclosure, all reproducing probes preserved."""

from __future__ import annotations

import json
import sys
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

import pytest
from conftest import full_report, make_cfg
from mock_app import MockServer

from runtime_security.checks import error_leakage
from runtime_security.models import Severity
from runtime_security.reporting import json_report, markdown_report
from runtime_security.utils.http import Client

SECURITY_CI_SRC = Path(__file__).resolve().parents[2] / "security-ci" / "src"
FAKE_SECRET = "FakeLeakedDbPassw0rd77"

TRACE_A = ('Traceback (most recent call last):\n  File "/home/app/src/server.py", line 42, in handle\n'
           '    cur.execute(query)\npsycopg2.errors.SyntaxError: syntax error at or near "WHERE"\n'
           f"DATABASE_URL=postgres://app:{FAKE_SECRET}@db.internal/appdb\n")
TRACE_B = 'Traceback (most recent call last):\n  File "/home/app/src/api.py", line 9, in parse\njson.decoder.JSONDecodeError: Expecting value\n'
TRACE_A_OTHER_EXC = 'Traceback (most recent call last):\n  File "/home/app/src/server.py", line 42, in handle\nKeyError: \'id\'\n'


class _Server:
    """Local server whose response body per (method, path-prefix) is set by the test."""

    def __init__(self, routes: dict[tuple[str, str], str], default: str = '{"error": "not found"}'):
        self.routes, self.default = routes, default
        outer = self

        class H(BaseHTTPRequestHandler):
            server_version = "app"
            sys_version = ""

            def log_message(self, *a):
                pass

            def _reply(self):
                path = self.path.split("?")[0]
                body = outer.default
                for (method, prefix), text in outer.routes.items():
                    if (method in ("*", self.command)) and path.startswith(prefix):
                        body = text
                        break
                data = body.encode()
                self.send_response(500 if body != outer.default else 404)
                self.send_header("Content-Type", "text/plain")
                self.send_header("Content-Length", str(len(data)))
                self.end_headers()
                self.wfile.write(data)

            def do_GET(self):
                self._reply()

            def do_POST(self):
                self.rfile.read(int(self.headers.get("Content-Length") or 0))
                self._reply()

            def do_PHASE3PROBE(self):
                self._reply()

        self.httpd = ThreadingHTTPServer(("127.0.0.1", 0), H)
        self.url = f"http://127.0.0.1:{self.httpd.server_address[1]}"
        threading.Thread(target=self.httpd.serve_forever, daemon=True).start()

    def close(self):
        self.httpd.shutdown()
        self.httpd.server_close()


@pytest.fixture()
def server():
    servers = []

    def make(routes, default='{"error": "not found"}'):
        s = _Server(routes, default)
        servers.append(s)
        return s

    yield make
    for s in servers:
        s.close()


def run_check(url):
    cfg = make_cfg(url)
    return error_leakage.run(Client(cfg), cfg)


def by_title(run):
    out: dict[str, list] = {}
    for f in run.findings:
        out.setdefault(f.title, []).append(f)
    return out


def test_identical_leak_from_multiple_probes_is_one_finding(server):
    # global error handler: every probe returns the same trace
    s = server({("*", "/"): TRACE_A})
    run = run_check(s.url)
    titles = by_title(run)
    for t in ("Error response leaks python stack trace", "Error response leaks sql/database error",
              "Error response leaks filesystem/source path", "Error response leaks secret-like value"):
        assert len(titles[t]) == 1, t
    trace = titles["Error response leaks python stack trace"][0]
    assert "Reproduced by 5 probe(s)" in trace.notes and trace.evidence.count(" -> 500") == 5
    # every probe kept as its own check result
    assert sum(1 for r in run.results if r.name == "Python stack trace") == 5


def test_severity_not_increased_by_probe_count(server):
    s = server({("*", "/"): TRACE_A})
    titles = by_title(run_check(s.url))
    assert titles["Error response leaks python stack trace"][0].severity == Severity.MEDIUM
    assert titles["Error response leaks secret-like value"][0].severity == Severity.HIGH
    assert titles["Error response leaks filesystem/source path"][0].severity == Severity.LOW


def test_different_error_types_stay_separate(server):
    s = server({("GET", "/api/items/"): TRACE_A, ("POST", "/"): TRACE_B})
    traces = by_title(run_check(s.url))["Error response leaks python stack trace"]
    assert len(traces) == 2
    assert {f.endpoint.split()[0] for f in traces} == {"GET", "POST"}


def test_same_frame_different_exception_stays_separate(server):
    s = server({("GET", "/api/items/"): TRACE_A, ("GET", "/api/search"): TRACE_A_OTHER_EXC})
    traces = by_title(run_check(s.url))["Error response leaks python stack trace"]
    assert len(traces) == 2


def test_different_endpoints_different_information_stay_separate(server):
    s = server({("GET", "/api/items/"): "error at /srv/app/items/handler.py", ("GET", "/api/search"): "error at /srv/app/search/view.py"})
    paths = by_title(run_check(s.url))["Error response leaks filesystem/source path"]
    assert len(paths) == 2 and {f.endpoint for f in paths} == {"GET /api/items/not-a-valid-id", "GET /api/search"}


def test_same_information_from_different_endpoints_merges(server):
    s = server({("GET", "/api/items/"): "error at /srv/app/common/handler.py", ("GET", "/api/search"): "boom /srv/app/common/handler.py"})
    paths = by_title(run_check(s.url))["Error response leaks filesystem/source path"]
    assert len(paths) == 1 and "Reproduced by 2 probe(s)" in paths[0].notes
    assert {n for n in paths[0].notes if n.startswith("Probe:")} == {"Probe: GET /api/search -> status 500",
                                                                     "Probe: GET /api/items/not-a-valid-id -> status 500"}


def test_different_categories_stay_separate(server):
    s = server({("GET", "/api/items/"): TRACE_A})
    titles = by_title(run_check(s.url))
    assert len(titles) == 4  # trace, SQL, path, secret: never merged across categories


def test_deterministic_ids_and_signatures():
    runs = []
    for _ in range(2):
        with MockServer("unsafe") as s:
            runs.append(full_report(s.url))
    a, b = ([(f.id, f.title, f.notes[0]) for f in r.findings if f.category == "error_leakage"] for r in runs)
    assert a == b and len(a) == 8


def test_unsafe_mock_before_after_counts():
    with MockServer("unsafe") as s:
        r = full_report(s.url)
    errs = [f for f in r.findings if f.category == "error_leakage"]
    assert len(errs) == 8  # was 12: the nonexistent-path and invalid-id probes returned the same disclosure
    merged = [f for f in errs if "Reproduced by 2 probe(s)" in f.notes]
    assert len(merged) == 4 and r.exit_code == 2  # exit behaviour unchanged


def test_redaction_in_evidence_notes_and_signature(server, tmp_path):
    s = server({("*", "/"): TRACE_A})
    cfg = make_cfg(s.url)
    run = error_leakage.run(Client(cfg), cfg)
    blob = json.dumps([f.to_dict() for f in run.findings]) + json.dumps([r.to_dict() for r in run.results])
    assert FAKE_SECRET not in blob and "<redacted>" in blob


def test_reports_valid_and_markdown_shows_probes(tmp_path):
    with MockServer("unsafe") as s:
        report = full_report(s.url)
    json_report.write(report, tmp_path)
    markdown_report.write(report, tmp_path)
    data = json.loads((tmp_path / "runtime-security-report.json").read_text(encoding="utf-8"))
    errs = [f for f in data["findings"] if f["category"] == "error_leakage"]
    assert len(errs) == 8 and all("reproduced by" in f["evidence"] for f in errs)
    md = (tmp_path / "runtime-security-report.md").read_text(encoding="utf-8")
    assert md.count("Error response leaks") >= 8 and "Reproduced by 2 probe\\(s\\)" in md
    assert data["summary"]["failed"] == len([r for c in data["checks"] for r in c["results"] if r["outcome"] == "FAILED"])


def test_security_ci_sarif_receives_deduplicated_findings(tmp_path):
    with MockServer("unsafe") as s:
        report = full_report(s.url)
    json_report.write(report, tmp_path)
    sys.path.insert(0, str(SECURITY_CI_SRC))
    try:
        from security_ci.inputs import load_all
        from security_ci.sarif import build
    finally:
        sys.path.remove(str(SECURITY_CI_SRC))
    doc = build(load_all(None, tmp_path / "runtime-security-report.json", None))
    errs = [r for run in doc["runs"] for r in run["results"] if r["properties"]["findingId"].startswith("RT-ERROR-")]
    assert len(errs) == 8
    assert all("reproduced by" in r["message"]["text"] for r in errs)
    assert FAKE_SECRET not in json.dumps(doc) and "FakeLeakedPassw0rd" not in json.dumps(doc)


def test_safe_mock_still_clean():
    with MockServer("safe") as s:
        r = full_report(s.url)
    assert not [f for f in r.findings if f.category == "error_leakage"] and r.exit_code == 0
