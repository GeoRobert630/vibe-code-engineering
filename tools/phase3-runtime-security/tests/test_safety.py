import json

import pytest
from conftest import full_report, make_cfg

from runtime_security import cli
from runtime_security.config import ConfigError, parse
from runtime_security.runner import run_all
from runtime_security.utils import safety
from runtime_security.utils.http import BudgetExceeded, Client, RequestNotAllowed


def cfg_dict(**target):
    base = {"base_url": "http://127.0.0.1:3000", "environment": "local", "production": False}
    base.update(target)
    return {"target": base}


def test_production_flag_refused_and_no_requests(safe_app):
    cfg = make_cfg(safe_app.url, target__production=True)
    report = run_all(cfg)
    assert report.refused and report.requests_sent == 0 and report.runs == []
    assert report.exit_code == 3


@pytest.mark.parametrize("env", ["production", "prod", "live"])
def test_production_environment_refused(env):
    d = safety.evaluate(parse(cfg_dict(environment=env)))
    assert not d.allowed


def test_production_looking_host_refused():
    d = safety.evaluate(parse(cfg_dict(base_url="https://api.prod.example.com", environment="staging", authorized=True, authorized_by="sec-lead")))
    assert not d.allowed


def test_remote_staging_requires_explicit_authorization():
    unauth = parse(cfg_dict(base_url="https://staging.example.com", environment="staging"))
    assert not safety.evaluate(unauth).allowed
    auth = parse(cfg_dict(base_url="https://staging.example.com", environment="staging", authorized=True, authorized_by="Jane Doe, ticket SEC-12"))
    assert safety.evaluate(auth).allowed


def test_local_env_with_remote_host_refused():
    assert not safety.evaluate(parse(cfg_dict(base_url="https://example.com", environment="local"))).allowed


def test_production_must_be_explicit():
    with pytest.raises(ConfigError):
        parse({"target": {"base_url": "http://127.0.0.1", "environment": "local"}})


@pytest.mark.parametrize("bad", [
    {"target": {"base_url": "http://user:pw@127.0.0.1", "environment": "local", "production": False}},
    {"target": {"base_url": "ftp://127.0.0.1", "environment": "local", "production": False}},
    {"target": {"base_url": "http://127.0.0.1", "environment": "local", "production": False, "http_url": "http://evil.example/"}},
    {"target": {"base_url": "http://127.0.0.1", "environment": "local", "production": False}, "headers": {"paths": ["https://evil.example/"]}},
    {"target": {"base_url": "http://127.0.0.1", "environment": "local", "production": False}, "unknown": {}},
    {"target": {"base_url": "http://127.0.0.1", "environment": "local", "production": False}, "limits": {"max_requests": 100000}},
])
def test_invalid_configs_rejected(bad):
    with pytest.raises(ConfigError):
        parse(bad)


def test_client_refuses_unsafe_requests():
    cfg = parse(cfg_dict())
    c = Client(cfg)
    for method in ("DELETE", "PUT", "PATCH"):
        with pytest.raises(RequestNotAllowed):
            c.request(method, "/")
    with pytest.raises(RequestNotAllowed):
        c.request("POST", "/", body=b'{"valid": true}')
    with pytest.raises(RequestNotAllowed):
        c.request("GET", "/", base="http://other.example/")
    with pytest.raises(RequestNotAllowed):
        c.request("GET", "//evil.example/x")
    assert c.sent == 0


def test_request_budget_enforced(safe_app):
    cfg = make_cfg(safe_app.url, limits__max_requests=2)
    c = Client(cfg)
    c.request("GET", "/")
    c.request("GET", "/")
    with pytest.raises(BudgetExceeded):
        c.request("GET", "/")
    report = run_all(cfg)
    assert report.exit_code == 3 and any(r.error for r in report.runs)


def test_cli_prints_gate_and_refuses_production(tmp_path, capsys):
    cfg = tmp_path / "rt.yaml"
    cfg.write_text("target:\n  base_url: http://127.0.0.1:9\n  environment: staging\n  production: true\n")
    code = cli.main(["--config", str(cfg), "--output", str(tmp_path / "out")])
    out = capsys.readouterr().out
    assert code == 3
    assert "Target: http://127.0.0.1:9" in out and "Environment: staging" in out and "Production flag: true" in out
    assert "STOP" in out
    data = json.loads((tmp_path / "out" / "runtime-security-report.json").read_text())
    assert data["safety"]["allowed"] is False and data["requests_sent"] == 0


def test_cli_unsafe_app_exit_2_and_safe_app_no_blocking(tmp_path, safe_app, unsafe_app):
    for app, expect_blocking in ((unsafe_app, True), (safe_app, False)):
        cfg = tmp_path / "rt.yaml"
        cfg.write_text(
            f"target:\n  base_url: {app.url}\n  environment: local\n  production: false\n"
            "cors:\n  allowed_origins: ['https://app.example.test']\n"
            "error_leakage:\n  invalid_resource_path: /api/items/not-a-valid-id\n  missing_parameter_path: /api/search\n"
        )
        code = cli.main(["--config", str(cfg), "--output", str(tmp_path / app.url.rsplit(":", 1)[1])])
        if expect_blocking:
            assert code == 2
        else:
            assert code in (0, 1)
            report = full_report(app.url)
            assert report.blocking == []


def test_usage_error_exits_3():
    with pytest.raises(SystemExit) as exc:
        cli.main([])
    assert exc.value.code == 3
