"""Performance configuration (profiles, runs, limits, budgets), credential rejection and the reused 4A safety gate."""

from __future__ import annotations

import json

import pytest

from quality_ci.performance.cli import main
from quality_ci.performance.config import (
    DEFAULT_BUDGETS, HARD_MAX_PAGES, PROFILES, ConfigError, load, parse,
)
from quality_ci.performance.runner import EXIT_ERROR, RUN_REFUSED, run

from .conftest import cfg_dict, make_cfg
from .fake_engine import BASE, FakeEngine, factory


def test_profiles_exact_values():
    m, d = PROFILES["mobile-lab"], PROFILES["desktop-lab"]
    assert (m.viewport, m.dpr, m.cpu_throttle, m.model_rtt_ms, m.model_throughput_kbps) == ((412, 823), 1.75, 4.0, 150, 1600)
    assert (d.viewport, d.dpr, d.cpu_throttle, d.model_rtt_ms, d.model_throughput_kbps) == ((1350, 940), 1.0, 1.0, 40, 10_000)
    assert make_cfg().profile is m and make_cfg(profile="desktop-lab").profile is d


def test_default_thresholds_exact():
    assert DEFAULT_BUDGETS["timing.fcp"] == (1800, 3000) and DEFAULT_BUDGETS["timing.lcp"] == (2500, 4000)
    assert DEFAULT_BUDGETS["timing.cls"] == (0.100, 0.250) and DEFAULT_BUDGETS["timing.tbt"] == (200, 600)
    assert DEFAULT_BUDGETS["budget.total-bytes"] == (1_600_000, 4_000_000)
    assert DEFAULT_BUDGETS["budget.script-bytes"] == (350_000, 1_000_000)
    assert DEFAULT_BUDGETS["budget.image-bytes"] == (1_000_000, 2_500_000)
    assert DEFAULT_BUDGETS["budget.request-count"] == (60, 150)
    assert DEFAULT_BUDGETS["budget.render-blocking"] == (2, 6) and DEFAULT_BUDGETS["budget.dom-nodes"] == (1_500, 3_000)
    assert DEFAULT_BUDGETS["model.critical-path"] == (2000, None)
    assert all(DEFAULT_BUDGETS[c] == (0, None) for c in ("diagnostic.unsized-images", "diagnostic.oversized-images",
                                                        "diagnostic.text-compression"))


def test_limits_defaults_and_caps():
    c = make_cfg()
    assert (c.runs, c.max_pages, c.page_timeout_seconds, c.total_timeout_seconds, c.max_page_bytes, c.max_requests,
            c.observation_window_ms) == (3, 10, 30, 600, 5_000_000, 300, 5000)
    for key, bad in (("max_pages", 26), ("page_timeout_seconds", 121), ("total_timeout_seconds", 1801),
                     ("max_page_bytes", 20_000_001), ("max_requests", 501), ("observation_window_ms", 15_001)):
        with pytest.raises(ConfigError, match="hard cap"):
            make_cfg(limits={key: bad})


@pytest.mark.parametrize("runs", [2, 8, "3", True, 3.0])
def test_runs_bounds(runs):
    with pytest.raises(ConfigError, match="runs must be"):
        make_cfg(runs=runs)


@pytest.mark.parametrize("data,msg", [
    ([], "mapping"),
    ({}, "'target' section is required"),
    (cfg_dict(profile="tablet"), "profile must be one of"),
    (cfg_dict(budgets={"timing.inp": {"warn": 1}}), "unknown budget"),
    (cfg_dict(budgets={"timing.lcp": {"warn": 5000, "fail": 3000}}), "warn must be <= fail"),
    (cfg_dict(budgets={"timing.lcp": {"fail": 40_001}}), "hard cap"),
    (cfg_dict(budgets={"model.critical-path": {"fail": 3000}}), "never FAIL"),
    (cfg_dict(budgets={"timing.lcp": {"warn": -1}}), "non-negative"),
    (cfg_dict(budgets={"timing.lcp": 5}), "mapping"),
    (cfg_dict(pages=["http://other.test/"]), "target origin"),
    (cfg_dict(pages=[f"/p{i}" for i in range(HARD_MAX_PAGES + 1)]), "hard cap"),
    (cfg_dict(crawl=True), "unknown configuration key"),
    (cfg_dict(browser={"channel": "firefox"}), "browser.channel"),
])
def test_malformed(data, msg):
    with pytest.raises(ConfigError, match=msg):
        parse(data)


@pytest.mark.parametrize("key", ["headers", "cookies", "auth", "storage_state", "password", "token"])
def test_credential_keys_rejected(key):
    with pytest.raises(ConfigError, match="no credential handling"):
        parse(cfg_dict(**{key: {"x": "y"}}))
    with pytest.raises(ConfigError, match="credentials"):
        parse({"target": {"base_url": "http://u:p@127.0.0.1", "environment": "local", "production": False}, "pages": ["/"]})


def test_budget_override_recorded():
    c = make_cfg(budgets={"timing.lcp": {"warn": 2000, "fail": 3500}, "budget.dom-nodes": {"warn": 1500, "fail": 3000}})
    assert c.budgets["timing.lcp"] == (2000, 3500) and c.changed_budgets == ["timing.lcp"]   # unchanged value not "changed"


def test_load_files(tmp_path):
    (tmp_path / "c.json").write_text(json.dumps(cfg_dict()))
    assert load(tmp_path / "c.json").pages == [f"{BASE}/page.html"]
    (tmp_path / "c.yaml").write_text("target: {base_url: 'http://localhost:3000', environment: local, production: false}\n"
                                     "pages: ['/']\nprofile: desktop-lab\nruns: 5\n")
    c = load(tmp_path / "c.yaml")
    assert c.profile.name == "desktop-lab" and c.runs == 5
    (tmp_path / "bad.yaml").write_text("target: [x\n")
    with pytest.raises(ConfigError, match="invalid YAML"):
        load(tmp_path / "bad.yaml")


def test_cli_malformed_config(tmp_path, capsys):
    (tmp_path / "c.json").write_text(json.dumps({"target": {}}))
    assert main(["perf", "--config", str(tmp_path / "c.json"), "--output", str(tmp_path / "o")]) == EXIT_ERROR
    assert "configuration error" in capsys.readouterr().err and not (tmp_path / "o").exists()


@pytest.mark.parametrize("target,reason", [
    ({"base_url": BASE, "environment": "local", "production": True}, "production targets are refused"),
    ({"base_url": BASE, "environment": "production", "production": False}, "production environment"),
    ({"base_url": "https://prod.example.com", "environment": "staging", "production": False}, "production host"),
    ({"base_url": "https://staging.example.com", "environment": "staging", "production": False}, "authorized_by"),
])
def test_production_and_unsafe_refused_engine_never_started(target, reason):
    r = run(parse({"target": target, "pages": ["/"]}), factory())
    assert r.status == RUN_REFUSED and reason in r.reason and r.verdict == "NOT VERIFIED" and r.exit_code == EXIT_ERROR
    assert FakeEngine.instances == [] and all(p.status == "NOT SCANNED" for p in r.pages)


def test_authorized_remote_staging_allowed():
    c = parse({"target": {"base_url": "https://staging.example.com", "environment": "staging", "production": False,
                          "authorized": True, "authorized_by": "QA lead"}, "pages": ["/"]})
    assert run(c, factory()).status == "COMPLETE"
