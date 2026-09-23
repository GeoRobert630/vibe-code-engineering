"""Phase 3B plumbing: config, session model, RT-AUTH/RT-SESSION findings, report areas, reader.

No test here performs a login, sends credentials or calls a protected endpoint; the
plumbing does not implement those operations.
"""

from __future__ import annotations

import importlib.util
import inspect
import json
import os
import pickle
import re
from pathlib import Path

import pytest
from conftest import make_cfg

from runtime_security import runner
from runtime_security.auth.models import LoginState, LogoutState, SessionRegistry, SessionState, SessionType
from runtime_security.auth.status import auth_area_status
from runtime_security.config import ConfigError, parse
from runtime_security.models import FINDING_ID_RE, CheckRun, Confidence, Finding, Severity
from runtime_security.reporting import json_report, markdown_report
from runtime_security.runner import RunReport, run_all
from runtime_security.utils.http import Client

READER_PATH = Path(__file__).resolve().parents[3] / "skills/06-security/17-security-audit/scripts/read_phase3_report.py"
FAKE_PASSWORD = "fake-password-only-for-tests"
FAKE_USER = "test@example.invalid"

AUTH_BLOCK = {
    "authentication": {
        "enabled": False,
        "login": {"method": "POST", "path": "/api/auth/login", "content_type": "application/json",
                  "username_field": "email", "password_field": "password"},
        "logout": {"enabled": False, "method": "POST", "path": "/api/auth/logout"},
        "protected_endpoint": {"method": "GET", "path": "/api/me"},
    },
    "credentials": {"username_env": "TEST_USER_EMAIL", "password_env": "TEST_USER_PASSWORD"},
}


def base(**extra):
    data = {"target": {"base_url": "http://127.0.0.1:3000", "environment": "local", "production": False}}
    data.update(json.loads(json.dumps(extra)))
    return data


def load_reader():
    spec = importlib.util.spec_from_file_location("read_phase3_report", READER_PATH)
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


def synthetic(category: str, fid: str) -> Finding:
    return Finding(category=category, severity=Severity.MEDIUM, confidence=Confidence.MEDIUM, title=f"synthetic {category}",
                   endpoint="GET /api/me", expected="denied", actual="synthetic", evidence="synthetic fixture finding",
                   impact="n/a", recommendation="n/a", validation="n/a", id=fid)


# ------------------------------------------------------------------ configuration

def test_authentication_config_parsing():
    cfg = parse(base(**AUTH_BLOCK))
    a = cfg.authentication
    assert a is not None and a.enabled is False
    assert (a.login.method, a.login.path, a.login.content_type, a.login.username_field, a.login.password_field) == (
        "POST", "/api/auth/login", "application/json", "email", "password")


def test_logout_and_protected_endpoint_parsing():
    a = parse(base(**AUTH_BLOCK)).authentication
    assert (a.logout.enabled, a.logout.method, a.logout.path) == (False, "POST", "/api/auth/logout")
    assert (a.protected_endpoint.method, a.protected_endpoint.path) == ("GET", "/api/me")


def test_credentials_are_env_var_names_only():
    a = parse(base(**AUTH_BLOCK)).authentication
    assert (a.credentials.username_env, a.credentials.password_env) == ("TEST_USER_EMAIL", "TEST_USER_PASSWORD")


@pytest.mark.parametrize("name", ["test_user_email", "TEST USER", "1TEST", FAKE_PASSWORD, "", "A" * 65, "TEST-USER"])
def test_invalid_env_var_names_rejected(name):
    data = base(**AUTH_BLOCK)
    data["credentials"]["password_env"] = name
    with pytest.raises(ConfigError):
        parse(data)


@pytest.mark.parametrize("mutate", [
    lambda d: d["credentials"].update({"password": FAKE_PASSWORD}),                       # literal password
    lambda d: d["credentials"].update({"token": "fake-token"}),                           # literal token
    lambda d: d["authentication"]["login"].update({"password": FAKE_PASSWORD}),           # literal in login block
    lambda d: d.update({"users": {"test_user": {"password": FAKE_PASSWORD}}}),            # unknown section
    lambda d: d["authentication"]["login"].update({"method": "GET"}),                     # login must be POST
    lambda d: d["authentication"]["protected_endpoint"].update({"method": "DELETE"}),     # protected endpoint read-only
    lambda d: d["authentication"]["login"].update({"path": "https://evil.example/login"}),  # absolute URL
    lambda d: d["authentication"]["logout"].update({"path": "//evil.example/x"}),
    lambda d: d["authentication"]["login"].update({"content_type": "text/plain"}),
    lambda d: d["authentication"]["login"].update({"username_field": "a b"}),
    lambda d: d["authentication"].update({"enabled": "yes"}),
    lambda d: d["credentials"].update({"password_env": "TEST_USER_EMAIL"}),               # same variable twice
    lambda d: d["authentication"].update({"enabled": True, "protected_endpoint": None}),   # enabled but incomplete
])
def test_invalid_authentication_config_rejected(mutate):
    data = base(**AUTH_BLOCK)
    mutate(data)
    with pytest.raises(ConfigError):
        parse(data)


def test_enabled_logout_requires_method_and_path():
    data = base(**AUTH_BLOCK)
    data["authentication"]["logout"] = {"enabled": True}
    with pytest.raises(ConfigError):
        parse(data)


def test_config_without_auth_is_unchanged():
    assert parse(base()).authentication is None


# ------------------------------------------------------------------ session model

def test_session_model_records_presence_only():
    s = SessionState(actor="test_user")
    assert not s.authenticated and s.session_type == SessionType.NONE and s.login_state == LoginState.NOT_ATTEMPTED
    s.record_login(True)
    s.record_cookie_present(2)
    assert s.authenticated and s.session_type == SessionType.COOKIE and s.cookie_count == 2
    s.record_logout(LogoutState.SUCCEEDED)
    assert not s.authenticated
    b = SessionState(actor="api_user")
    b.record_login(True)
    b.record_bearer_present()
    assert b.authenticated and b.session_type == SessionType.BEARER
    d = b.to_dict()
    assert set(d) == {"actor", "session_type", "authenticated", "login_state", "logout_state", "has_cookie", "cookie_count", "has_bearer_token", "notes"}


def test_session_model_has_no_way_to_store_secret_values():
    fields = set(SessionState.__dataclass_fields__)
    assert not fields & {"cookie", "cookies", "cookie_value", "token", "bearer_token", "password", "authorization"}
    for name in ("record_cookie_present", "record_bearer_present", "record_login", "record_logout"):
        params = set(inspect.signature(getattr(SessionState, name)).parameters) - {"self"}
        assert not params & {"value", "token", "cookie", "password"}, name


def test_session_state_cannot_be_persisted(tmp_path):
    s = SessionState(actor="test_user")
    with pytest.raises(TypeError):
        pickle.dumps(s)
    with pytest.raises(TypeError):
        pickle.dumps(SessionRegistry())
    assert list(tmp_path.iterdir()) == []


def test_registry_gives_independent_sessions():
    reg = SessionRegistry()
    a, b = reg.create("user_a"), reg.create("user_b")
    assert a is not b
    a.record_login(True)
    a.record_cookie_present()
    assert not b.authenticated and b.login_state == LoginState.NOT_ATTEMPTED
    with pytest.raises(ValueError):
        reg.create("user_a")


# ------------------------------------------------------------------ area status and findings

def test_auth_and_session_status_not_verified(safe_app):
    for cfg in (make_cfg(safe_app.url), parse({**base(**AUTH_BLOCK), "target": {"base_url": safe_app.url, "environment": "local", "production": False}})):
        report = run_all(cfg)
        areas = json_report.build(report)["auth_areas"]
        assert areas["authentication"]["status"] == "NOT VERIFIED"
        assert areas["session"]["status"] == "NOT VERIFIED"
        assert "not implemented" in areas["authentication"]["reason"]


def test_refused_target_auth_areas_not_verified():
    cfg = parse({**base(**AUTH_BLOCK), "target": {"base_url": "http://127.0.0.1:9", "environment": "local", "production": True}})
    report = run_all(cfg)
    areas = auth_area_status(cfg, report.findings, report.refused)
    assert report.requests_sent == 0 and all(a["status"] == "NOT VERIFIED" for a in areas.values())


def test_rt_auth_and_session_ids_from_runner(monkeypatch, safe_app):
    def fake_check(client, cfg):
        run = CheckRun("headers")
        run.findings += [synthetic("authentication", ""), synthetic("authentication", ""), synthetic("session", "")]
        return run

    monkeypatch.setitem(runner.CHECKS, "headers", fake_check)
    cfg = make_cfg(safe_app.url)
    ids = sorted(f.id for f in run_all(cfg).findings)
    assert ids == ["RT-AUTH-001", "RT-AUTH-002", "RT-SESSION-001"]
    assert all(re.fullmatch(FINDING_ID_RE, i) for i in ids)


def test_rt_auth_session_serialization_and_markdown_sections():
    cfg = parse(base(**AUTH_BLOCK))
    report = RunReport(cfg=cfg, safety_reason="local target", refused=False,
                       findings=[synthetic("authentication", "RT-AUTH-001"), synthetic("session", "RT-SESSION-001"), synthetic("headers", "RT-HEADERS-001")])
    data = json_report.build(report)
    assert [f["id"] for f in data["findings"]] == ["RT-AUTH-001", "RT-SESSION-001", "RT-HEADERS-001"]
    assert data["auth_areas"]["authentication"] == {"area": "Authentication", "status": "FAIL", "reason": "synthetic/recorded findings present", "findings": ["RT-AUTH-001"]}
    assert data["auth_areas"]["session"]["findings"] == ["RT-SESSION-001"]
    md = markdown_report.render(report)
    for heading in ("## Authentication", "## Session", "## Authentication Findings", "## Session Findings", "## Findings"):
        assert heading in md
    findings_part = md.split("## Findings", 1)[1].split("## Authentication", 1)[0]
    assert "RT-HEADERS-001" in findings_part and "RT-AUTH-001" not in findings_part  # categories kept separate
    assert "RT-AUTH-001" in md.split("## Authentication Findings", 1)[1].split("## Session Findings", 1)[0]
    assert "RT-SESSION-001" in md.split("## Session Findings", 1)[1]


def test_markdown_shows_env_names_not_values(monkeypatch):
    monkeypatch.setenv("TEST_USER_EMAIL", FAKE_USER)
    monkeypatch.setenv("TEST_USER_PASSWORD", FAKE_PASSWORD)
    cfg = parse(base(**AUTH_BLOCK))
    report = RunReport(cfg=cfg, safety_reason="local target", refused=False)
    blob = markdown_report.render(report) + json.dumps(json_report.build(report))
    assert "TEST\\_USER\\_PASSWORD" in blob or "TEST_USER_PASSWORD" in blob
    assert FAKE_PASSWORD not in blob and FAKE_USER not in blob
    assert json_report.build(report)["authentication_config"]["credentials_read"] is False


# ------------------------------------------------------------------ reader

def test_reader_accepts_auth_session_ids_and_areas(tmp_path):
    reader = load_reader()
    cfg = parse(base(**AUTH_BLOCK))
    report = RunReport(cfg=cfg, safety_reason="local target", refused=False,
                       findings=[synthetic("authentication", "RT-AUTH-001"), synthetic("session", "RT-SESSION-002"), synthetic("cors", "RT-CORS-001")])
    path = tmp_path / "runtime-security-report.json"
    path.write_text(json.dumps(json_report.build(report)))
    summary = reader.build_summary(reader.load(tmp_path))
    areas = {a["area"]: a for a in summary["areas"]}
    assert areas["Authentication"]["status"] == "FAIL" and areas["Authentication"]["findings"] == ["RT-AUTH-001"]
    assert areas["Session"]["findings"] == ["RT-SESSION-002"]
    assert areas["CORS"]["findings"] == ["RT-CORS-001"]
    assert len(summary["areas"]) == 9  # 6 Phase 3A + Authentication + Session + Authorization (Phase 3C status)


@pytest.mark.parametrize("bad_id", ["RT-FOO-001", "P2-0123456789ab", "AI-01", "RT-AUTH-1", "RT-auth-001", "RT-AUTH-001x"])
def test_reader_rejects_malformed_ids(tmp_path, bad_id):
    reader = load_reader()
    report = RunReport(cfg=parse(base()), safety_reason="local target", refused=False, findings=[synthetic("authentication", bad_id)])
    path = tmp_path / "runtime-security-report.json"
    path.write_text(json.dumps(json_report.build(report)))
    assert reader.main([str(path)]) == 3


def test_reader_handles_reports_without_auth_areas(tmp_path, safe_app):
    reader = load_reader()
    data = json_report.build(run_all(make_cfg(safe_app.url)))
    data.pop("auth_areas")
    (tmp_path / "runtime-security-report.json").write_text(json.dumps(data))
    areas = {a["area"]: a["status"] for a in reader.build_summary(reader.load(tmp_path))["areas"]}
    assert areas["Authentication"] == "NOT VERIFIED" and areas["Session"] == "NOT VERIFIED"
    assert areas["Security headers"] == "PASS"  # Phase 3A areas still recognised


# ------------------------------------------------------------------ safety: no credentials read, no new requests

class _GuardedEnv(dict):
    GUARDED = {"TEST_USER_EMAIL", "TEST_USER_PASSWORD"}

    def _check(self, key):
        if key in self.GUARDED:
            raise AssertionError(f"credential environment variable {key} was accessed")

    def __getitem__(self, key):
        self._check(key)
        return super().__getitem__(key)

    def get(self, key, default=None):
        self._check(key)
        return super().get(key, default)

    def __contains__(self, key):
        self._check(key)
        return super().__contains__(key)


def test_credentials_never_read(monkeypatch, safe_app, tmp_path):
    guarded = _GuardedEnv(os.environ)
    guarded.update({"TEST_USER_EMAIL": FAKE_USER, "TEST_USER_PASSWORD": FAKE_PASSWORD})
    monkeypatch.setattr(os, "environ", guarded)
    # control: the guard really fires on access
    with pytest.raises(AssertionError):
        os.environ["TEST_USER_PASSWORD"]
    with pytest.raises(AssertionError):
        os.getenv("TEST_USER_EMAIL")
    data = base(**AUTH_BLOCK)
    data["target"]["base_url"] = safe_app.url
    cfg = parse(data)
    report = run_all(cfg)
    json_report.write(report, tmp_path)
    markdown_report.write(report, tmp_path)
    blob = "".join(p.read_text(encoding="utf-8") for p in tmp_path.iterdir())
    assert FAKE_PASSWORD not in blob and FAKE_USER not in blob


def test_zero_new_network_requests(monkeypatch, safe_app):
    sent: list[tuple[str, str]] = []
    original = Client.request

    def recording(self, method, path, *args, **kwargs):
        sent.append((method, path))
        return original(self, method, path, *args, **kwargs)

    monkeypatch.setattr(Client, "request", recording)
    plain = run_all(make_cfg(safe_app.url))
    n_plain, paths_plain = plain.requests_sent, [p for _, p in sent if not p.startswith("/phase3-nonexistent-")]
    sent.clear()
    data = base(**AUTH_BLOCK)
    data["authentication"]["enabled"] = True
    data["authentication"]["logout"]["enabled"] = True
    data["target"]["base_url"] = safe_app.url
    data.update({"cors": {"allowed_origins": ["https://app.example.test"]},
                 "error_leakage": {"invalid_resource_path": "/api/items/not-a-valid-id", "missing_parameter_path": "/api/search"},
                 "limits": {"delay_seconds": 0}})
    with_auth = run_all(parse(data))
    paths_auth = [p for _, p in sent if not p.startswith("/phase3-nonexistent-")]
    assert with_auth.requests_sent == n_plain
    assert paths_auth == paths_plain
    assert not any(p.startswith(("/api/auth", "/api/me")) for _, p in sent)


def test_phase3a_findings_unchanged_by_auth_config(unsafe_app):
    plain = run_all(make_cfg(unsafe_app.url))
    data = base(**AUTH_BLOCK)
    data["target"]["base_url"] = unsafe_app.url
    data.update({"cors": {"allowed_origins": ["https://app.example.test"]},
                 "error_leakage": {"invalid_resource_path": "/api/items/not-a-valid-id", "missing_parameter_path": "/api/search"},
                 "limits": {"delay_seconds": 0}})
    with_auth = run_all(parse(data))
    assert [(f.id, f.title, f.severity) for f in plain.findings] == [(f.id, f.title, f.severity) for f in with_auth.findings]
    assert plain.exit_code == with_auth.exit_code == 2
