"""Malformed configuration, credential rejection, production refusal and safety gate."""

from __future__ import annotations

import json

import pytest
from conftest import BASE, FakeEngine, cfg_dict, factory, make_cfg

from quality_ci.cli import main
from quality_ci.config import HARD_MAX_PAGES, ConfigError, load, parse
from quality_ci.models import RUN_REFUSED
from quality_ci.runner import EXIT_ERROR, run
from quality_ci.safety import evaluate


@pytest.mark.parametrize("data,msg", [
    ([], "mapping"),
    ({}, "'target' section is required"),
    ({"target": {"base_url": "ftp://x", "environment": "local", "production": False}, "pages": ["/"]}, "http(s) URL"),
    ({"target": {"base_url": "http://u:p@127.0.0.1", "environment": "local", "production": False}, "pages": ["/"]}, "credentials"),
    ({"target": {"base_url": BASE, "environment": "local"}, "pages": ["/"]}, "explicitly true or false"),
    ({"target": {"base_url": BASE, "environment": "local", "production": "no"}, "pages": ["/"]}, "explicitly true or false"),
    ({"target": {"base_url": BASE, "environment": "local", "production": False}}, "non-empty list"),
    ({"target": {"base_url": BASE, "environment": "local", "production": False}, "pages": []}, "non-empty list"),
    ({"target": {"base_url": BASE, "environment": "local", "production": False}, "pages": [3]}, "non-empty string"),
    ({"target": {"base_url": BASE, "environment": "local", "production": False}, "pages": ["http://other.test/"]}, "target origin"),
    ({"target": {"base_url": BASE, "environment": "local", "production": False}, "pages": ["/"], "crawl": True}, "unknown configuration key"),
    ({"target": {"base_url": BASE, "environment": "local", "production": False}, "pages": ["/"], "limits": {"max_pages": 0}}, "positive"),
    ({"target": {"base_url": BASE, "environment": "local", "production": False}, "pages": ["/"], "limits": {"max_pages": 99}}, "hard cap"),
    ({"target": {"base_url": BASE, "environment": "local", "production": False}, "pages": ["/"], "limits": {"page_timeout_seconds": 9999}}, "hard cap"),
    ({"target": {"base_url": BASE, "environment": "local", "production": False}, "pages": ["/"], "limits": {"max_page_bytes": "big"}}, "number"),
    ({"target": {"base_url": BASE, "environment": "local", "production": False}, "pages": ["/"], "engine": {"tags": ["bogus"]}}, "engine.tags"),
    ({"target": {"base_url": BASE, "environment": "local", "production": False}, "pages": ["/"], "engine": {"name": "lighthouse"}}, "axe-core"),
    ({"target": {"base_url": BASE, "environment": "local", "production": False}, "pages": ["/"], "browser": {"channel": "firefox"}}, "browser.channel"),
])
def test_malformed_configuration(data, msg):
    with pytest.raises(ConfigError, match=msg.replace("(", r"\(").replace(")", r"\)")):
        parse(data)


def test_page_hard_cap():
    with pytest.raises(ConfigError, match="hard cap"):
        parse(cfg_dict(pages=[f"/p{i}" for i in range(HARD_MAX_PAGES + 1)]))


@pytest.mark.parametrize("section,key", [("", "headers"), ("", "cookies"), ("", "auth"), ("target.", "password"),
                                         ("target.", "token"), ("", "storage_state"), ("browser.", "http_credentials")])
def test_credential_keys_rejected(section, key):
    d = cfg_dict()
    if section == "target.":
        d["target"][key] = "x"
    elif section == "browser.":
        d["browser"] = {key: {"username": "a"}}
    else:
        d[key] = {"x": "y"}
    with pytest.raises(ConfigError, match="no credential handling"):
        parse(d)


def test_pages_normalised_deduplicated_fragment_removed():
    cfg = make_cfg(pages=["/a", "/a#top", f"{BASE}/a", "b?x=1"])
    assert cfg.pages == [f"{BASE}/a", f"{BASE}/b?x=1"]


def test_load_yaml_json_and_invalid(tmp_path):
    (tmp_path / "c.json").write_text(json.dumps(cfg_dict()))
    assert load(tmp_path / "c.json").pages == [f"{BASE}/good.html"]
    (tmp_path / "c.yaml").write_text("target:\n  base_url: http://localhost:3000\n  environment: local\n  production: false\npages: ['/']\n")
    assert load(tmp_path / "c.yaml").host == "localhost"
    (tmp_path / "bad.yaml").write_text("target: [unclosed\n")
    with pytest.raises(ConfigError, match="invalid YAML"):
        load(tmp_path / "bad.yaml")
    (tmp_path / "bad.json").write_text("{")
    with pytest.raises(ConfigError, match="invalid JSON"):
        load(tmp_path / "bad.json")
    with pytest.raises(ConfigError, match="cannot read"):
        load(tmp_path / "missing.yaml")


def test_cli_malformed_config_exit_3(tmp_path, capsys):
    (tmp_path / "c.json").write_text(json.dumps({"target": {}}))
    assert main(["a11y", "--config", str(tmp_path / "c.json"), "--output", str(tmp_path / "o")]) == EXIT_ERROR
    assert "configuration error" in capsys.readouterr().err
    assert not (tmp_path / "o").exists()


@pytest.mark.parametrize("target,reason", [
    ({"base_url": BASE, "environment": "local", "production": True}, "production targets are refused"),
    ({"base_url": BASE, "environment": "production", "production": False}, "production environment"),
    ({"base_url": "https://prod.example.com", "environment": "staging", "production": False}, "production host"),
    ({"base_url": "https://app-live.example.com", "environment": "staging", "production": False}, "production host"),
    ({"base_url": "https://staging.example.com", "environment": "staging", "production": False}, "authorized_by"),
    ({"base_url": "https://staging.example.com", "environment": "local", "production": False}, "not local"),
    ({"base_url": BASE, "environment": "weird", "production": False}, "not one of"),
])
def test_production_and_unsafe_targets_refused(target, reason):
    cfg = parse({"target": target, "pages": ["/"]})
    d = evaluate(cfg)
    assert not d.allowed and reason in d.reason
    report = run(cfg, factory())
    assert report.status == RUN_REFUSED and report.verdict == "NOT VERIFIED" and report.exit_code == EXIT_ERROR
    assert FakeEngine.instances == []            # engine/browser never created, no request sent
    assert all(p.status == "NOT SCANNED" for p in report.pages)


def test_production_asset_origin_refused():
    cfg = make_cfg(assets={"allow_origins": ["https://cdn.prod.example.com"]})
    assert not evaluate(cfg).allowed


def test_allowed_targets():
    assert evaluate(make_cfg()).allowed
    cfg = parse({"target": {"base_url": "https://staging.example.com", "environment": "staging", "production": False,
                            "authorized": True, "authorized_by": "QA lead"}, "pages": ["/"]})
    assert evaluate(cfg).allowed and "authorized by QA lead" in evaluate(cfg).reason
