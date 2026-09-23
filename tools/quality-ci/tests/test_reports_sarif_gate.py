"""JSON/Markdown reports, SARIF 2.1.0 structure, quality gate and CLI; no credentials read."""

from __future__ import annotations

import json
import os
from pathlib import Path

import pytest
from conftest import BASE, factory, make_cfg, rr

from quality_ci import reporting, sarif
from quality_ci.cli import main
from quality_ci.gate import evaluate
from quality_ci.models import PAGE_OK, PageScan
from quality_ci.runner import not_configured, run

BAD = {"/bad.html": PageScan(url="", status=PAGE_OK, rules_evaluated=["image-alt", "label", "region", "color-contrast"],
                             violations=[rr("image-alt", "critical", ["img.a", "img.b"]), rr("region", "moderate", ["body > div"])],
                             incomplete=[rr("color-contrast", "serious", ["p.x"])])}


def bad_report():
    return reporting.build(run(make_cfg(pages=["/bad.html", "/good.html"]), factory(BAD)))


def test_json_contains_required_sections():
    d = bad_report()
    for key in ("run", "pages_tested", "rules_evaluated", "findings", "limitations", "engine"):
        assert key in d
    assert d["run"]["status"] == "COMPLETE" and d["run"]["verdict"] == "FAIL" and d["run"]["started_at"] and d["run"]["finished_at"]
    assert d["namespace"] == "Q-A11Y" and d["engine"]["name"] == "axe-core" and d["engine"]["version"] == "4.10.3"
    assert d["rules_evaluated"] == sorted(d["rules_evaluated"]) and "image-alt" in d["rules_evaluated"]
    f = d["findings"][0]
    for key in ("id", "rule_id", "title", "description", "severity", "impact", "url", "selector", "help", "help_url",
                "occurrence_count", "source", "urls", "pages"):
        assert key in f, key
    assert f["source"].startswith("axe-core") and f["engine_rule"] == "axe-core/image-alt"
    assert any("not proof of full WCAG compliance" in x for x in d["limitations"])
    assert "not security findings" in " ".join(d["limitations"])


def test_markdown_sections_and_not_proof(tmp_path):
    md = reporting.render_markdown(run(make_cfg(pages=["/bad.html"]), factory(BAD)))
    idx = [md.index(h) for h in ("## Accessibility\n", "## Findings\n", "## Pages Tested\n", "## Limitations\n")]
    assert idx == sorted(idx)
    assert "Status: **FAIL**" in md and "not proof of full WCAG compliance" in md
    assert "Needs review (informational, not failures)" in md and "`img.a`" in md
    reporting.write_markdown(run(make_cfg(), factory()), tmp_path)
    assert "Status: **PASS**" in (tmp_path / reporting.MD_NAME).read_text()


def test_not_configured_report():
    d = reporting.build(not_configured())
    assert d["run"]["status"] == "NOT CONFIGURED" and d["run"]["verdict"] == "NOT CONFIGURED" and d["findings"] == []
    assert "Not run." in reporting.render_markdown(not_configured())


def test_sarif_structure():
    d = bad_report()
    doc = sarif.build(d, anchor="docs/a11y.md")
    assert doc["version"] == "2.1.0" and doc["$schema"].endswith("sarif-2.1.0.json") and len(doc["runs"]) == 1
    run_ = doc["runs"][0]
    driver = run_["tool"]["driver"]
    assert driver["name"] == "quality-ci-accessibility" and driver["version"] == "4.10.3"
    rule_ids = [r["id"] for r in driver["rules"]]
    assert len(rule_ids) == len(set(rule_ids)) and all(r.startswith("a11y/") for r in rule_ids)
    assert run_["automationDetails"]["id"] == "vibe-code-engineering/quality/accessibility/"
    by_rule = {r["ruleId"]: r for r in run_["results"]}
    assert set(by_rule) <= set(rule_ids)
    assert by_rule["a11y/image-alt"]["level"] == "error" and by_rule["a11y/image-alt"]["kind"] == "fail"
    assert by_rule["a11y/region"]["level"] == "warning"
    assert by_rule["a11y/color-contrast"]["kind"] == "review" and by_rule["a11y/color-contrast"]["level"] == "note"
    r = by_rule["a11y/image-alt"]
    assert r["partialFingerprints"]["findingId/v1"].startswith("Q-A11Y-") and r["properties"]["occurrenceCount"] == 2
    loc = r["locations"][0]
    assert loc["physicalLocation"]["artifactLocation"]["uri"] == "docs/a11y.md" and loc["physicalLocation"]["region"]["startLine"] == 1
    assert loc["logicalLocations"][0]["name"] == f"{BASE}/bad.html" and loc["logicalLocations"][1]["name"] == "img.a"
    text = json.dumps(doc)
    assert "security-severity" not in text                                   # never a security alert
    assert all("accessibility" in rr_["properties"]["tags"] for rr_ in driver["rules"])


def test_sarif_deterministic_and_redacted(tmp_path):
    pages = {"/p": PageScan(url="", status=PAGE_OK, violations=[rr("label", "critical", ['input[value="sk_live_abcdefghijk"]'])])}
    d = reporting.build(run(make_cfg(pages=["/p?token=abc"]), factory({"/p?token=abc": pages["/p"]})))
    a = json.dumps(sarif.build(d))
    d2 = reporting.build(run(make_cfg(pages=["/p?token=abc"]), factory({"/p?token=abc": pages["/p"]})))
    assert a == json.dumps(sarif.build(d2))
    assert "sk_live" not in a and "token=abc" not in a and "token=<redacted>" in a


def test_sarif_empty_report_valid():
    doc = sarif.build(reporting.build(run(make_cfg(), factory())))
    assert doc["runs"][0]["results"] == [] and doc["runs"][0]["properties"]["verdict"] == "PASS"


@pytest.mark.parametrize("policy,passed", [("release", False), ("critical", False), ("high", False), ("medium", False), ("low", False)])
def test_gate_bad_fails_all_policies(policy, passed):
    assert evaluate(bad_report(), policy).passed is passed


def test_gate_distinguishes_outcomes():
    d = reporting.build(run(make_cfg(pages=["/m"]), factory({"/m": PageScan(url="", status=PAGE_OK, violations=[rr("region", "moderate")],
                                                                              incomplete=[rr("color-contrast")])})))
    rel = evaluate(d, "release")
    assert rel.passed and rel.outcome == "PASS" and rel.informational == 1 and rel.counts["MEDIUM"] == 1   # MEDIUM not blocking
    assert not evaluate(d, "medium").passed and evaluate(d, "medium").outcome == "FAIL"
    review_only = reporting.build(run(make_cfg(pages=["/r"]), factory({"/r": PageScan(url="", status=PAGE_OK, incomplete=[rr("x", "critical")])})))
    assert evaluate(review_only, "low").passed                                                              # informational never fails
    inc = reporting.build(run(make_cfg(pages=["/s"]), factory({"/s": PageScan(url="", status="TIMEOUT", reason="t")})))
    g = evaluate(inc)
    assert not g.passed and g.outcome == "INCOMPLETE" and evaluate(inc, allow_incomplete=True).passed
    nc = reporting.build(not_configured())
    assert evaluate(nc).passed and evaluate(nc).outcome == "NOT CONFIGURED" and "NOT VERIFIED" in evaluate(nc).notes[0]
    assert not evaluate(nc, require_configured=True).passed
    refused = reporting.build(run(make_cfg(target={"base_url": BASE, "environment": "local", "production": True}), factory()))
    assert not evaluate(refused).passed and evaluate(refused).outcome == "INCOMPLETE"
    with pytest.raises(ValueError):
        evaluate(d, "bogus")


def test_cli_end_to_end(tmp_path, capsys, monkeypatch):
    cfgp = tmp_path / "c.json"
    cfgp.write_text(json.dumps({"target": {"base_url": BASE, "environment": "local", "production": False}, "pages": ["/bad.html"]}))
    out = tmp_path / "out"
    assert main(["a11y", "--config", str(cfgp), "--output", str(out), "--sarif", str(out / "a.sarif")], engine_factory=factory(BAD)) == 2
    assert (out / "accessibility-report.json").exists() and (out / "accessibility-report.md").exists() and (out / "a.sarif").exists()
    assert "Not proof of full WCAG compliance" in capsys.readouterr().out
    rep = str(out / "accessibility-report.json")
    assert main(["gate", "--report", rep]) == 1
    assert "Result: FAIL" in capsys.readouterr().out
    assert main(["sarif", "--report", rep, "--sarif", str(tmp_path / "b.sarif"), "--anchor", "README.md"]) == 0
    assert main(["sarif", "--report", rep, "--sarif", str(tmp_path / "c.sarif"), "--anchor", "../x"]) == 3
    assert main(["a11y", "--output", str(tmp_path / "nc")]) == 0                                    # not configured
    assert main(["gate", "--report", str(tmp_path / "nc" / "accessibility-report.json")]) == 0
    assert main(["gate", "--report", str(tmp_path / "nc" / "accessibility-report.json"), "--require-configured"]) == 1
    (tmp_path / "junk.json").write_text('{"findings": []}')
    assert main(["gate", "--report", str(tmp_path / "junk.json")]) == 3
    (tmp_path / "badid.json").write_text(json.dumps({"namespace": "Q-A11Y", "run": {}, "findings": [{"id": "RT-HEADERS-001"}]}))
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
    g.update({"QA_PASSWORD": "fake-password-only-for-tests", "API_TOKEN": "fake-token-only-for-tests"})
    monkeypatch.setattr(os, "environ", g)
    with pytest.raises(AssertionError):
        os.environ["QA_PASSWORD"]   # control: the guard works
    cfgp = tmp_path / "c.json"
    cfgp.write_text(json.dumps({"target": {"base_url": BASE, "environment": "local", "production": False}, "pages": ["/bad.html"]}))
    assert main(["a11y", "--config", str(cfgp), "--output", str(tmp_path / "o"), "--sarif", str(tmp_path / "o" / "a.sarif")],
                engine_factory=factory(BAD)) == 2
    blob = "".join(p.read_text(encoding="utf-8") for p in (tmp_path / "o").iterdir())
    assert "fake-password" not in blob and "fake-token" not in blob


def test_source_has_no_environment_or_credential_access():
    src = Path(__file__).resolve().parents[1] / "src" / "quality_ci"
    text = "\n".join(p.read_text(encoding="utf-8") for p in src.glob("*.py"))
    assert "os.environ" not in text and "getenv" not in text
    assert "http_credentials=None" in text and "storage_state=None" in text
    for interaction in (".fill(", ".click(", ".type(", ".press(", ".check(", ".submit(", ".select_option(", ".set_input_files("):
        assert interaction not in text, interaction                       # the page is never interacted with
