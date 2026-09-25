"""Tests for native vertical authorization verification Z1–Z2 (Design §10, §15, §16, §17).

Verifies:
- Z1 privileged authorization positive control (admin GET privileged route)
- Z2 low-privilege authorization denial (user GET privileged route)
- PASS when Z1 is allowed and Z2 is denied
- FAIL with RT-AUTHZ-001 (HIGH/HIGH) when Z2 is allowed (privilege escalation)
- Positive control rule: Z1 failure produces INCOMPLETE with no finding
- Authentication prerequisite: missing A3 authentication produces INCOMPLETE with 0 authz requests
- Missing prerequisites in configuration produces NOT CONFIGURED
- Support for cookie-based and bearer token-based session handling
- Response classifications: allowed, denied, ambiguous, incomplete
- Safe evidence and secret redaction (no credentials, tokens, or bodies leaked)
- Bounded execution (hard maximum 2 requests for authorization)
- Timeout and budget exhaustion produce INCOMPLETE without findings
"""

from __future__ import annotations

import json
import threading
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from typing import Any

import pytest
from runtime_security.config import parse
from runtime_security.models import Confidence, Finding, Severity, Status
from runtime_security.native.auth import build_auth_requests
from runtime_security.native.authz import (
    AUTHZ_NAMESPACE,
    build_authz_requests,
    evaluate_authz_checks,
    make_authz_finding,
)
from runtime_security.native.executor import (
    AREA_HARD_MAXIMUMS,
    AreaExecutionResult,
    NativeExecutionResult,
    NativeExecutor,
    execute_native_plan,
)
from runtime_security.native.identity import IdentityVault, SecretValue
from runtime_security.native.plan import AreaPlan, NativePlan, build_plan
from runtime_security.native.setup_adapter import SETUP_SCHEMA


class _AuthzTestServer:
    """Deterministic local HTTP test server for vertical authorization verification."""

    def __init__(
        self,
        expected_run_id: str = "run-authz-test",
        actors: list[str] | None = None,
        auth_mode: str = "cookie",  # "cookie" | "token"
        scenario: str = "pass",
        # "pass", "z2_allowed" (vuln), "z1_denied", "z1_no_marker",
        # "z2_ambiguous", "a3_fail", "timeout_z1", "timeout_z2"
    ):
        self.requests_log: list[tuple[str, str, dict[str, str], bytes]] = []
        self.expected_run_id = expected_run_id
        self.actors = sorted(actors or ["admin_a", "user_a"])
        self.auth_mode = auth_mode
        self.scenario = scenario
        self.valid_sessions: dict[str, str] = {}  # session_id -> actor
        self._session_counter = 0
        outer = self

        class Handler(BaseHTTPRequestHandler):
            def do_POST(self):
                body = self.rfile.read(int(self.headers.get("Content-Length") or 0))
                outer.requests_log.append(("POST", self.path, dict(self.headers), body))

                # Setup hook endpoint
                if self.path == "/_security/setup-identities":
                    try:
                        data = json.loads(body.decode("utf-8"))
                    except Exception:
                        data = {}
                    req_run_id = data.get("run_id", outer.expected_run_id)
                    self.send_response(200)
                    self.send_header("Content-Type", "application/json")
                    self.end_headers()
                    resp = {
                        "schema": SETUP_SCHEMA,
                        "run_id": req_run_id,
                        "accepted": outer.actors,
                    }
                    self.wfile.write(json.dumps(resp).encode("utf-8"))
                    return

                # Login endpoint
                if self.path == "/api/login":
                    try:
                        data = json.loads(body.decode("utf-8"))
                    except Exception:
                        data = {}
                    username = data.get("email") or data.get("username")
                    password = data.get("password")

                    # Scenario: A3 failure
                    if outer.scenario == "a3_fail":
                        self.send_response(401)
                        self.send_header("Content-Type", "application/json")
                        self.end_headers()
                        self.wfile.write(b'{"error": "positive control failed"}')
                        return

                    # Invalid credentials check (A2)
                    if password and str(password).startswith("invalid_synth_"):
                        self.send_response(401)
                        self.send_header("Content-Type", "application/json")
                        self.end_headers()
                        self.wfile.write(b'{"error": "invalid credentials"}')
                        return

                    # Valid login (A3)
                    session_id = f"sess_{username}_{outer._session_counter}"
                    outer._session_counter += 1
                    outer.valid_sessions[session_id] = username

                    self.send_response(200)
                    if outer.auth_mode == "cookie":
                        self.send_header(
                            "Set-Cookie",
                            f"session_id={session_id}; Path=/; HttpOnly; SameSite=Lax",
                        )
                        self.send_header("Content-Type", "application/json")
                        self.end_headers()
                        self.wfile.write(b'{"status": "ok"}')
                    else:
                        self.send_header("Content-Type", "application/json")
                        self.end_headers()
                        self.wfile.write(json.dumps({"token": session_id}).encode("utf-8"))
                    return

                self.send_response(404)
                self.end_headers()

            def do_GET(self):
                body = self.rfile.read(int(self.headers.get("Content-Length") or 0))
                outer.requests_log.append(("GET", self.path, dict(self.headers), body))

                # Identify active session actor
                actor = None
                if outer.auth_mode == "cookie":
                    cookie_hdr = self.headers.get("Cookie", "")
                    for part in cookie_hdr.split(";"):
                        part = part.strip()
                        if part.startswith("session_id="):
                            sid = part.split("=", 1)[1]
                            actor = outer.valid_sessions.get(sid)
                else:
                    auth_hdr = self.headers.get("Authorization", "")
                    if auth_hdr.startswith("Bearer "):
                        sid = auth_hdr[7:].strip()
                        actor = outer.valid_sessions.get(sid)

                # Protected route for A1 / A4
                if self.path == "/api/profile":
                    if not actor:
                        self.send_response(401)
                        self.send_header("Content-Type", "application/json")
                        self.end_headers()
                        self.wfile.write(b'{"error": "unauthenticated"}')
                        return
                    self.send_response(200)
                    self.send_header("Content-Type", "application/json")
                    self.end_headers()
                    self.wfile.write(f'{{"message": "account:{actor}"}}'.encode("utf-8"))
                    return

                # Privileged route for Z1 / Z2
                if self.path == "/api/admin/report":
                    if outer.scenario == "timeout_z1" and actor == "admin_a":
                        time.sleep(0.3)
                    elif outer.scenario == "timeout_z2" and actor != "admin_a":
                        time.sleep(0.3)

                    if not actor:
                        self.send_response(401)
                        self.send_header("Content-Type", "application/json")
                        self.end_headers()
                        self.wfile.write(b'{"error": "authentication required"}')
                        return

                    # Admin actor access (Z1)
                    if actor == "admin_a":
                        if outer.scenario == "z1_denied":
                            self.send_response(403)
                            self.send_header("Content-Type", "application/json")
                            self.end_headers()
                            self.wfile.write(b'{"error": "forbidden"}')
                            return
                        elif outer.scenario == "z1_no_marker":
                            self.send_response(200)
                            self.send_header("Content-Type", "application/json")
                            self.end_headers()
                            self.wfile.write(b'{"status": "ok but marker missing"}')
                            return
                        else:
                            self.send_response(200)
                            self.send_header("Content-Type", "application/json")
                            self.end_headers()
                            self.wfile.write(b'{"status": "ok", "marker": "privileged_report_marker"}')
                            return

                    # Low-privilege user actor access (Z2)
                    if outer.scenario == "z2_allowed":
                        # VULNERABILITY: User gets access with privileged marker!
                        self.send_response(200)
                        self.send_header("Content-Type", "application/json")
                        self.end_headers()
                        self.wfile.write(b'{"status": "ok", "marker": "privileged_report_marker"}')
                        return
                    elif outer.scenario == "z2_ambiguous":
                        # 200 without marker
                        self.send_response(200)
                        self.send_header("Content-Type", "application/json")
                        self.end_headers()
                        self.wfile.write(b'{"status": "user dashboard"}')
                        return
                    else:
                        # Proper denial (403)
                        self.send_response(403)
                        self.send_header("Content-Type", "application/json")
                        self.end_headers()
                        self.wfile.write(b'{"error": "forbidden: insufficient privileges"}')
                        return

                self.send_response(404)
                self.end_headers()

            def log_message(self, *args):
                pass

        self.httpd = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
        self.port = self.httpd.server_address[1]
        self.url = f"http://127.0.0.1:{self.port}"
        self.thread = threading.Thread(target=self.httpd.serve_forever, daemon=True)
        self.thread.start()

    def close(self):
        self.httpd.shutdown()
        self.httpd.server_close()


def _make_authz_cfg(url: str, mode: str = "fixture"):
    return parse(
        {
            "target": {
                "base_url": url,
                "environment": "local",
                "production": False,
                "authorized": True,
                "authorized_by": "test-suite",
            },
            "authentication": {
                "enabled": True,
                "login": {
                    "method": "POST",
                    "path": "/api/login",
                    "username_field": "email",
                    "password_field": "password",
                },
                "protected_endpoint": {"method": "GET", "path": "/api/profile"},
            },
            "runtime_verification": {
                "mode": mode,
                "allowed_targets": [url],
                "actors": {
                    "admin_a": {"role": "admin", "tenant": "tenant-a"},
                    "user_a": {"role": "user", "tenant": "tenant-a"},
                },
                "routes": {
                    "protected": {"path": "/api/profile", "marker": "account:{label}"},
                    "privileged": {
                        "path": "/api/admin/report",
                        "roles": ["admin"],
                        "marker": "privileged_report_marker",
                    },
                },
                "resources": [],
                "deny_statuses": [401, 403, 404],
            },
        }
    )


# ── 1. Planning Tests ────────────────────────────────────────────────────────


def test_authz_requests_plan():
    cfg = _make_authz_cfg("http://127.0.0.1:8000")
    requests = build_authz_requests(cfg)
    assert len(requests) == 2

    z1 = requests[0]
    assert z1.check_id == "Z1"
    assert z1.area == "authorization"
    assert z1.method == "GET"
    assert z1.path == "/api/admin/report"
    assert z1.actor == "admin_a"
    assert z1.expected == "allowed"
    assert z1.marker == "privileged_report_marker"

    z2 = requests[1]
    assert z2.check_id == "Z2"
    assert z2.area == "authorization"
    assert z2.method == "GET"
    assert z2.path == "/api/admin/report"
    assert z2.actor == "user_a"
    assert z2.expected == "denied"
    assert z2.marker == "privileged_report_marker"

    plan = build_plan(cfg)
    authz_plan = plan.areas["authorization"]
    assert authz_plan.configured is True
    assert authz_plan.requests_count == 2
    assert authz_plan.budget == 2
    assert len(authz_plan.requests) == 2


def test_authz_missing_admin_prerequisite():
    cfg = parse(
        {
            "target": {"base_url": "http://127.0.0.1:8000", "environment": "local", "production": False},
            "runtime_verification": {
                "mode": "fixture",
                "allowed_targets": ["http://127.0.0.1:8000"],
                "actors": {"user_a": {"role": "user"}},
                "routes": {
                    "protected": {"path": "/p", "marker": "m"},
                    "privileged": {"path": "/admin", "marker": "admin"},
                },
            },
        }
    )
    assert build_authz_requests(cfg) == []
    plan = build_plan(cfg)
    assert plan.areas["authorization"].configured is False
    assert "missing" in plan.areas["authorization"].reason


def test_authz_missing_user_prerequisite():
    cfg = parse(
        {
            "target": {"base_url": "http://127.0.0.1:8000", "environment": "local", "production": False},
            "runtime_verification": {
                "mode": "fixture",
                "allowed_targets": ["http://127.0.0.1:8000"],
                "actors": {"admin_a": {"role": "admin"}},
                "routes": {
                    "protected": {"path": "/p", "marker": "m"},
                    "privileged": {"path": "/admin", "marker": "admin"},
                },
            },
        }
    )
    assert build_authz_requests(cfg) == []
    plan = build_plan(cfg)
    assert plan.areas["authorization"].configured is False


def test_authz_missing_privileged_route():
    cfg = parse(
        {
            "target": {"base_url": "http://127.0.0.1:8000", "environment": "local", "production": False},
            "runtime_verification": {
                "mode": "fixture",
                "allowed_targets": ["http://127.0.0.1:8000"],
                "actors": {
                    "admin_a": {"role": "admin"},
                    "user_a": {"role": "user"},
                },
                "routes": {
                    "protected": {"path": "/p", "marker": "m"},
                },
            },
        }
    )
    assert build_authz_requests(cfg) == []
    plan = build_plan(cfg)
    assert plan.areas["authorization"].configured is False


# ── 2. Execution & PASS Scenarios ────────────────────────────────────────────


def test_authz_pass_cookie_auth():
    server = _AuthzTestServer(scenario="pass", auth_mode="cookie")
    try:
        cfg = _make_authz_cfg(server.url)
        plan = build_plan(cfg)
        result = execute_native_plan(cfg, plan)

        authz_res = result.area_results["authorization"]
        assert authz_res.status == "PASS"
        assert authz_res.runtime_checks_executed is True
        assert authz_res.requests_sent == 2
        assert len(authz_res.findings) == 0

        # Verify checks schema (Design §15)
        assert len(authz_res.checks) == 2
        z1, z2 = authz_res.checks[0], authz_res.checks[1]

        assert z1["check"] == "Z1"
        assert z1["area"] == "authorization"
        assert z1["actors"] == ["admin_a"]
        assert z1["method"] == "GET"
        assert z1["path"] == "/api/admin/report"
        assert z1["expected"] == "allowed"
        assert z1["status"] == 200
        assert z1["status_class"] == "2xx"
        assert z1["classification"] == "allowed"
        assert z1["marker_present"] is True

        assert z2["check"] == "Z2"
        assert z2["area"] == "authorization"
        assert z2["actors"] == ["user_a"]
        assert z2["method"] == "GET"
        assert z2["path"] == "/api/admin/report"
        assert z2["expected"] == "denied"
        assert z2["status"] == 403
        assert z2["status_class"] == "4xx"
        assert z2["classification"] == "denied"
        assert z2["marker_present"] is False
    finally:
        server.close()


def test_authz_pass_token_auth():
    server = _AuthzTestServer(scenario="pass", auth_mode="token")
    try:
        cfg = _make_authz_cfg(server.url)
        plan = build_plan(cfg)
        result = execute_native_plan(cfg, plan)

        authz_res = result.area_results["authorization"]
        assert authz_res.status == "PASS"
        assert len(authz_res.findings) == 0
        assert authz_res.requests_sent == 2
    finally:
        server.close()


# ── 3. FAIL Scenarios & RT-AUTHZ-001 ─────────────────────────────────────────


def test_authz_fail_user_allowed_emits_rt_authz_001():
    """Vulnerability test: Low-privilege user allowed access to privileged route."""
    server = _AuthzTestServer(scenario="z2_allowed")
    try:
        cfg = _make_authz_cfg(server.url)
        plan = build_plan(cfg)
        result = execute_native_plan(cfg, plan)

        authz_res = result.area_results["authorization"]
        assert authz_res.status == "FAIL"
        assert authz_res.runtime_checks_executed is True
        assert len(authz_res.findings) == 1

        finding = authz_res.findings[0]
        assert finding.id == "RT-AUTHZ-001"
        assert finding.category == "authorization"
        assert finding.severity == Severity.HIGH
        assert finding.confidence == Confidence.HIGH
        assert finding.status == Status.OPEN
        assert finding.source == "native-verification"
        assert finding.endpoint == "GET /api/admin/report"
        assert finding.expected == "denied"
        assert finding.actual == "allowed"
        assert finding.cwe == "CWE-285"
        assert "user_a" in finding.evidence

        # Check overall execution result reflects FAIL
        assert result.status == "FAIL"
    finally:
        server.close()


# ── 4. Positive Control & Denial Rule ────────────────────────────────────────


def test_authz_positive_control_z1_denied_produces_incomplete():
    """Z1 positive control failed: admin gets 403 on privileged route.

    Must NOT evaluate Z2 denial as PASS, and must NOT fabricate a finding.
    """
    server = _AuthzTestServer(scenario="z1_denied")
    try:
        cfg = _make_authz_cfg(server.url)
        plan = build_plan(cfg)
        result = execute_native_plan(cfg, plan)

        authz_res = result.area_results["authorization"]
        assert authz_res.status == "INCOMPLETE"
        assert "positive control" in authz_res.reason
        assert len(authz_res.findings) == 0

        # Z2 must not have been sent after Z1 positive control failure
        assert authz_res.requests_sent == 1
        assert len(authz_res.checks) == 1
        assert authz_res.checks[0]["check"] == "Z1"
        assert authz_res.checks[0]["classification"] == "denied"
    finally:
        server.close()


def test_authz_positive_control_z1_missing_marker():
    """Z1 admin gets 200 but privileged marker is missing -> ambiguous -> INCOMPLETE."""
    server = _AuthzTestServer(scenario="z1_no_marker")
    try:
        cfg = _make_authz_cfg(server.url)
        plan = build_plan(cfg)
        result = execute_native_plan(cfg, plan)

        authz_res = result.area_results["authorization"]
        assert authz_res.status == "INCOMPLETE"
        assert len(authz_res.findings) == 0
        assert authz_res.requests_sent == 1
        assert authz_res.checks[0]["classification"] == "ambiguous"
    finally:
        server.close()


def test_authz_a3_auth_failure_blocks_authorization():
    """If authentication positive control A3 fails, authorization must not execute."""
    server = _AuthzTestServer(scenario="a3_fail")
    try:
        cfg = _make_authz_cfg(server.url)
        plan = build_plan(cfg)
        result = execute_native_plan(cfg, plan)

        authz_res = result.area_results["authorization"]
        assert authz_res.status == "INCOMPLETE"
        assert "authentication" in authz_res.reason or "A3" in authz_res.reason
        assert authz_res.requests_sent == 0
        assert len(authz_res.findings) == 0
    finally:
        server.close()


def test_authz_z2_ambiguous_does_not_fail_or_pass():
    """Z2 returns 200 without marker (e.g. user dashboard redirect) -> ambiguous."""
    server = _AuthzTestServer(scenario="z2_ambiguous")
    try:
        cfg = _make_authz_cfg(server.url)
        plan = build_plan(cfg)
        result = execute_native_plan(cfg, plan)

        authz_res = result.area_results["authorization"]
        assert authz_res.status == "INCOMPLETE"
        assert len(authz_res.findings) == 0
        assert authz_res.requests_sent == 2
    finally:
        server.close()


# ── 5. Budget, Timeout & Redaction ───────────────────────────────────────────


def test_authz_timeout_z1():
    server = _AuthzTestServer(scenario="timeout_z1")
    try:
        cfg = _make_authz_cfg(server.url)
        plan = build_plan(cfg)
        executor = NativeExecutor(cfg, request_timeout=0.1)
        result = executor.execute_plan(plan)

        authz_res = result.area_results["authorization"]
        assert authz_res.status == "INCOMPLETE"
        assert authz_res.timed_out is True
        assert len(authz_res.findings) == 0
    finally:
        server.close()


def test_authz_timeout_z2():
    server = _AuthzTestServer(scenario="timeout_z2")
    try:
        cfg = _make_authz_cfg(server.url)
        plan = build_plan(cfg)
        executor = NativeExecutor(cfg, request_timeout=0.1)
        result = executor.execute_plan(plan)

        authz_res = result.area_results["authorization"]
        assert authz_res.status == "INCOMPLETE"
        assert authz_res.timed_out is True
        assert len(authz_res.findings) == 0
    finally:
        server.close()


def test_authz_secret_redaction():
    """Verify that credentials and response bodies are never recorded in checks or findings."""
    server = _AuthzTestServer(scenario="z2_allowed")
    try:
        cfg = _make_authz_cfg(server.url)
        plan = build_plan(cfg)
        result = execute_native_plan(cfg, plan)

        authz_res = result.area_results["authorization"]
        data_str = json.dumps(
            {
                "checks": authz_res.checks,
                "findings": [f.to_dict() for f in authz_res.findings],
                "error": authz_res.error,
                "reason": authz_res.reason,
            }
        )

        for sid in server.valid_sessions:
            assert sid not in data_str
        assert "Set-Cookie" not in data_str
        assert "Authorization" not in data_str
    finally:
        server.close()
