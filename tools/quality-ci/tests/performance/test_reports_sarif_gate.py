"""performance-report.json / .md, SARIF 2.1.0, gate, CLI, redaction and no-side-effect checks (fake engine)."""

from __future__ import annotations

import json
import os
from pathlib import Path

import pytest

from quality_ci.performance import reporting, sarif
from quality_ci.performance.cli import main
from quality_ci.performance.gate import evaluate
from quality_ci.performance.measure import Resource
from quality_ci.performance.runner import not_configured, run

from .conftest import make_cfg
from .fake_engine import BASE, factory, ok, run_data
from .perf_server import FAKE_GH
from .test_findings import SLOW


def slow_report(**kw):
    return reporting.build(run(make_cfg(pages=["/slow.html"], **kw), factory({"/slow.html": SLOW})))


def test_json_structure():
    d = slow_report()
    for key in ("schema_version", "tool", "phase", "area", "namespace", "run", "target", "engine", "profile", "host", "budgets",
                "pages_tested", "checks_evaluated", "summary", "findings", "limitations", "notice"):
        assert key in d, key
    assert (d["schema_version"], d["phase"], d["area"], d["namespace"]) == ("1.0", "4B", "Performance", "Q-PERF")
    assert set(d["run"]) == {"status", "verdict", "reason", "incomplete_reasons", "exit_code", "started_at", "finished_at"}
    assert d["profile"] == {"name": "mobile-lab", "viewport": {"width": 412, "height": 823}, "dpr": 1.75, "cpu_throttle": 4.0,
                            "model_rtt_ms": 150, "model_throughput_kbps": 1600, "runs": 3, "warmup_runs": 1,
                            "observation_window_ms": 5000}
    assert set(d["host"]) >= {"benchmark_index", "timing_reliability", "cpu_count", "os_family"}
    assert d["engine"]["web_vitals"]["version"] == "6.2.2"
    p = d["pages_tested"][0]
    assert set(p) >= {"url", "status", "reason", "runs", "median", "deterministic", "checks", "blocked_requests", "duration_ms"}
    assert p["median"]["timing.tbt"] == 1300 and p["deterministic"]["budget.dom-nodes"] == 3217
    f = d["findings"][0]
    for key in ("id", "kind", "check_id", "title", "description", "metric", "unit", "threshold", "severity", "status",
                "blocking", "url", "urls", "pages", "occurrence_count", "help", "help_url", "source", "category"):
        assert key in f, key
    assert d["budgets"]["timing.tbt"] == {"warn": 200, "fail": 600, "default": True}
    assert "not field data" in d["notice"] and any("not Lighthouse TBT" in x for x in d["limitations"])
    json.dumps(d)


def test_changed_budgets_reported():
    d = slow_report(budgets={"budget.dom-nodes": {"warn": 3500, "fail": 4000}})
    assert d["budgets"]["budget.dom-nodes"]["default"] is False
    assert any("budget.dom-nodes" in x for x in d["limitations"] if x.startswith("Budgets changed"))
    assert all(f["check_id"] != "budget.dom-nodes" for f in d["findings"])


def test_markdown_sections():
    md = reporting.render_markdown(run(make_cfg(pages=["/slow.html"]), factory({"/slow.html": SLOW})))
    idx = [md.index(h) for h in ("## Performance\n", "## Findings\n", "## Pages Tested\n", "## Budgets\n", "## Limitations\n")]
    assert idx == sorted(idx)
    assert "Status: **FAIL**" in md and "not proof of real-user performance" in md and "Host timing reliability" in md
    assert "Not run." in reporting.render_markdown(not_configured())


def test_sarif_structure_levels_no_security_severity():
    doc = sarif.build(slow_report(), anchor="docs/perf.md")
    assert doc["version"] == "2.1.0" and len(doc["runs"]) == 1
    r = doc["runs"][0]
    assert r["tool"]["driver"]["name"] == "quality-ci-performance"
    assert r["automationDetails"]["id"] == "vibe-code-engineering/quality/performance/"
    ids = [x["id"] for x in r["tool"]["driver"]["rules"]]
    assert len(ids) == len(set(ids)) and all(i.startswith("perf/") for i in ids)
    by = {x["ruleId"]: x for x in r["results"]}
    assert by["perf/timing.tbt"]["level"] == "error" and by["perf/budget.render-blocking"]["level"] == "warning"
    assert by["perf/diagnostic.unsized-images"]["level"] == "note"
    assert all(x["kind"] == "fail" for x in r["results"])
    assert by["perf/timing.tbt"]["partialFingerprints"]["findingId/v1"].startswith("Q-PERF-")
    assert by["perf/timing.tbt"]["locations"][0]["physicalLocation"]["artifactLocation"]["uri"] == "docs/perf.md"
    assert "security-severity" not in json.dumps(doc)


def test_sarif_review_kind_for_unstable_and_not_measured():
    unstable = [ok(run_data())] + [ok(run_data(tbt_tasks=[(300, v)])) for v in (1350, 150, 1350)]
    d = reporting.build(run(make_cfg(), factory({"/page.html": unstable})))
    res = {x["ruleId"]: x for x in sarif.build(d)["runs"][0]["results"]}
    assert res["perf/timing.tbt"]["kind"] == "review" and res["perf/timing.tbt"]["level"] == "warning"
    nm = reporting.build(run(make_cfg(), factory(default=ok(run_data(lcp=None)))))
    assert sarif.build(nm)["runs"][0]["results"][0]["kind"] == "review"


def test_sarif_deterministic_and_redacted():
    secret = ok(run_data(dom=1600, resources=[Resource(f"{BASE}/p.html?token=abc123secret", "document", 1000, "text/html", "", True)],
                         unsized=[f"{BASE}/img/x.png?session=s3cr3t#frag"], lcp_target="#tok_" + FAKE_GH))
    cfg = dict(pages=["/p.html?token=abc123secret"])
    a = reporting.build(run(make_cfg(**cfg), factory({"/p.html?token=abc123secret": secret})))
    b = reporting.build(run(make_cfg(**cfg), factory({"/p.html?token=abc123secret": secret})))
    sa = json.dumps(sarif.build(a))
    assert sa == json.dumps(sarif.build(b))
    text = sa + json.dumps(a)
    for s in ("abc123secret", "s3cr3t", "#frag", FAKE_GH[:14]):
        assert s not in text, s
    assert "token=<redacted>" in text and a["pages_tested"][0]["lcp_element"].startswith("#")


@pytest.mark.parametrize("policy,passed", [("release", False), ("critical", True), ("high", False), ("medium", False), ("low", False)])
def test_gate_policies_slow(policy, passed):
    assert evaluate(slow_report(), policy).passed is passed


def test_gate_outcomes():
    warn = reporting.build(run(make_cfg(), factory(default=ok(run_data(dom=1600)))))
    assert evaluate(warn, "release").passed and evaluate(warn, "high").passed and not evaluate(warn, "medium").passed
    diag = reporting.build(run(make_cfg(), factory(default=ok(run_data(unsized=["x.png"])))))
    assert evaluate(diag, "medium").passed and not evaluate(diag, "low").passed
    nm = reporting.build(run(make_cfg(), factory(default=ok(run_data(lcp=None)))))
    g = evaluate(nm, "low")
    assert g.passed and g.informational == 1                                           # informational never fails
    from quality_ci.performance.engine import RunOutcome
    inc = reporting.build(run(make_cfg(), factory(default=RunOutcome(status="TIMEOUT", reason="t"))))
    g = evaluate(inc)
    assert not g.passed and g.outcome == "INCOMPLETE" and evaluate(inc, allow_incomplete=True).passed
    nc = reporting.build(not_configured())
    assert evaluate(nc).passed and evaluate(nc).outcome == "NOT CONFIGURED" and "NOT VERIFIED" in evaluate(nc).notes[0]
    assert not evaluate(nc, require_configured=True).passed
    capped = reporting.build(run(make_cfg(pages=["/slow.html"]), factory({"/slow.html": SLOW}, index=10.0)))
    g = evaluate(capped)
    assert g.timing_reliability == "LOW" and any("capped" in n for n in g.notes) and not g.passed      # dom-nodes still FAIL
    with pytest.raises(ValueError):
        evaluate(warn, "bogus")


def test_cli_end_to_end(tmp_path, capsys):
    cfgp = tmp_path / "c.json"
    cfgp.write_text(json.dumps({"target": {"base_url": BASE, "environment": "local", "production": False}, "pages": ["/slow.html"]}))
    out = tmp_path / "out"
    assert main(["perf", "--config", str(cfgp), "--output", str(out), "--sarif", str(out / "p.sarif")],
                engine_factory=factory({"/slow.html": SLOW})) == 2
    assert {p.name for p in out.iterdir()} == {"performance-report.json", "performance-report.md", "p.sarif"}
    assert "not proof of real-user performance" in capsys.readouterr().out
    rep = str(out / "performance-report.json")
    assert main(["gate", "--report", rep]) == 1
    o = capsys.readouterr().out
    assert "Result: FAIL" in o and "Timing reliability: HIGH" in o
    assert main(["gate", "--report", rep, "--fail-on", "critical"]) == 0
    assert main(["sarif", "--report", rep, "--sarif", str(tmp_path / "b.sarif"), "--anchor", "README.md"]) == 0
    assert main(["sarif", "--report", rep, "--sarif", str(tmp_path / "c.sarif"), "--anchor", "../x"]) == 3
    assert main(["perf", "--output", str(tmp_path / "nc")]) == 0
    assert main(["gate", "--report", str(tmp_path / "nc" / "performance-report.json")]) == 0
    assert main(["gate", "--report", str(tmp_path / "nc" / "performance-report.json"), "--require-configured"]) == 1
    (tmp_path / "a11y.json").write_text(json.dumps({"namespace": "Q-A11Y", "run": {}, "findings": []}))
    assert main(["gate", "--report", str(tmp_path / "a11y.json")]) == 3
    (tmp_path / "badid.json").write_text(json.dumps({"namespace": "Q-PERF", "run": {}, "findings": [{"id": "Q-A11Y-0123456789"}]}))
    assert main(["gate", "--report", str(tmp_path / "badid.json")]) == 3
    with pytest.raises(SystemExit) as e:
        main(["gate", "--report", rep, "--fail-on", "bogus"])
    assert e.value.code == 3


class _EnvGuard(dict):
    def _c(self, k):
        if any(x in str(k).upper() for x in ("PASSWORD", "TOKEN", "SECRET", "COOKIE", "AUTH", "API_KEY", "CREDENTIAL")):
            raise AssertionError(f"credential variable {k} accessed")

    def __getitem__(self, k):
        self._c(k)
        return super().__getitem__(k)

    def get(self, k, d=None):
        self._c(k)
        return super().get(k, d)

    def __contains__(self, k):
        self._c(k)
        return super().__contains__(k)


def test_no_credentials_read(tmp_path, monkeypatch):
    g = _EnvGuard(os.environ)
    g["QA_PASSWORD"] = "fake-password-only-for-tests"
    monkeypatch.setattr(os, "environ", g)
    with pytest.raises(AssertionError):
        os.environ["QA_PASSWORD"]
    cfgp = tmp_path / "c.json"
    cfgp.write_text(json.dumps({"target": {"base_url": BASE, "environment": "local", "production": False}, "pages": ["/slow.html"]}))
    main(["perf", "--config", str(cfgp), "--output", str(tmp_path / "o"), "--sarif", str(tmp_path / "o" / "p.sarif")],
         engine_factory=factory({"/slow.html": SLOW}))
    blob = "".join(p.read_text(encoding="utf-8") for p in (tmp_path / "o").iterdir())
    assert "fake-password" not in blob


def test_source_no_env_no_interaction_no_hostnames():
    src = Path(__file__).resolve().parents[2] / "src" / "quality_ci" / "performance"
    text = "\n".join(p.read_text(encoding="utf-8") for p in src.glob("*.py"))
    assert "os.environ" not in text and "getenv" not in text
    assert "gethostname" not in text and "platform.node" not in text and "getuser" not in text
    assert "http_credentials=None" in text and "storage_state=None" in text
    for call in (".fill(", ".click(", ".type(", ".press(", ".check(", ".submit(", ".select_option(", ".mouse.", ".keyboard.",
                 "emulateNetworkConditions", "Network.emulate", "onINP"):
        assert call not in text, call
    assert "setCPUThrottlingRate" in text
