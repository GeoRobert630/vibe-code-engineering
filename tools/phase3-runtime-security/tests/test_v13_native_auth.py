"""Tests for native authentication verification (Design §8, §15, §16, §17).

Verifies:
- deterministic A1-A6 request construction and execution
- full A1-A6 PASS scenario (cookie and token auth)
- PASS with logout vs EXECUTED without logout
- A1 unauthenticated allowed -> RT-AUTH-001 finding
- A2 invalid credentials accepted -> RT-AUTH-002 finding
- A3 positive control failure -> INCOMPLETE, zero findings
- A4 marker missing -> ambiguous INCOMPLETE
- A4 authenticated access denied -> positive control failure INCOMPLETE
- A5 logout failure -> INCOMPLETE
- A6 session reuse succeeds -> RT-AUTH-003 finding
- MFA/CAPTCHA challenge detected -> NOT VERIFIED
- secret redaction in results, checks, repr, findings, and reports
- deterministic request order (A1 -> A2 -> A3 (sorted) -> A4 -> A5 -> A6)
- request budget bounds strictly respected (max 9 for auth)
- timeout stops remaining requests and marks INCOMPLETE
- setup failure prevents all authentication requests
- production or public targets remain refused
- no brute force, password spraying, or account enumeration
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
from runtime_security.native.auth import (
    AUTH_NAMESPACE,
    build_auth_requests,
    compute_fingerprint,
    extract_session,
    is_mfa_challenge,
    make_auth_finding,
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


class _AuthTestServer:
    """Deterministic local HTTP test server for authentication verification."""

    def __init__(
        self,
        expected_run_id: str = "run-auth-test",
        actors: list[str] | None = None,
        auth_mode: str = "cookie",  # "cookie" | "token"
        scenario: str = "pass",     # "pass", "a1_fail", "a2_fail", "a3_fail", "a4_missing_marker",
                                    # "a4_denied", "a5_fail", "a6_fail", "mfa", "timeout_a2"
    ):
        self.requests_log: list[tuple[str, str, dict[str, str], bytes]] = []
        self.expected_run_id = expected_run_id
        self.actors = sorted(actors or ["admin_a", "user_a"])
        self.auth_mode = auth_mode
        self.scenario = scenario
        self.valid_sessions: set[str] = set()
        self.logged_out_sessions: set[str] = set()
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
                    if outer.scenario == "timeout_a2":
                        time.sleep(0.3)

                    # Scenario: MFA challenge
                    if outer.scenario == "mfa":
                        self.send_response(200)
                        self.send_header("Content-Type", "application/json")
                        self.send_header("x-mfa-required", "true")
                        self.end_headers()
                        self.wfile.write(b'{"status": "mfa_required"}')
                        return

                    # Parse body
                    try:
                        data = json.loads(body.decode("utf-8"))
                    except Exception:
                        data = {}
                    username = data.get("email") or data.get("username")
                    password = data.get("password")

                    # Scenario: A2 invalid credentials check
                    is_invalid_attempt = password and "invalid_synth_" in password

                    if is_invalid_attempt:
                        if outer.scenario == "a2_fail":
                            # Target incorrectly accepts invalid credentials and issues session
                            session_id = f"sess_inv_{username}"
                            outer.valid_sessions.add(session_id)
                            self.send_response(200)
                            if outer.auth_mode == "cookie":
                                self.send_header("Set-Cookie", f"session_id={session_id}; Path=/; HttpOnly; SameSite=Lax")
                                self.send_header("Content-Type", "application/json")
                                self.end_headers()
                                self.wfile.write(b'{"status": "ok"}')
                            else:
                                self.send_header("Content-Type", "application/json")
                                self.end_headers()
                                self.wfile.write(json.dumps({"token": session_id}).encode("utf-8"))
                        else:
                            # Proper rejection of invalid credentials
                            self.send_response(401)
                            self.send_header("Content-Type", "application/json")
                            self.end_headers()
                            self.wfile.write(b'{"error": "invalid credentials"}')
                        return

                    # Scenario: A3 positive control check
                    if outer.scenario == "a3_fail":
                        # Target fails to authenticate valid synthetic credentials
                        self.send_response(401)
                        self.send_header("Content-Type", "application/json")
                        self.end_headers()
                        self.wfile.write(b'{"error": "positive control failed"}')
                        return

                    # Normal successful login
                    session_id = f"sess_valid_{username}"
                    outer.valid_sessions.add(session_id)
                    self.send_response(200)
                    if outer.auth_mode == "cookie":
                        self.send_header("Set-Cookie", f"session_id={session_id}; Path=/; HttpOnly; SameSite=Lax")
                        self.send_header("Content-Type", "application/json")
                        self.end_headers()
                        self.wfile.write(b'{"status": "ok"}')
                    else:
                        self.send_header("Content-Type", "application/json")
                        self.end_headers()
                        self.wfile.write(json.dumps({"token": session_id}).encode("utf-8"))
                    return

                # Logout endpoint
                if self.path == "/api/logout":
                    if outer.scenario == "a5_fail":
                        self.send_response(500)
                        self.end_headers()
                        self.wfile.write(b'{"error": "logout crashed"}')
                        return

                    # Invalidate session
                    sess = self._get_session()
                    if sess:
                        outer.logged_out_sessions.add(sess)
                        if outer.scenario != "a6_fail":
                            outer.valid_sessions.discard(sess)

                    self.send_response(200)
                    self.send_header("Content-Type", "application/json")
                    if outer.auth_mode == "cookie":
                        self.send_header("Set-Cookie", "session_id=; Max-Age=0; Path=/")
                    self.end_headers()
                    self.wfile.write(b'{"status": "logged_out"}')
                    return

                self.send_response(404)
                self.end_headers()

            def do_GET(self):
                body = self.rfile.read(int(self.headers.get("Content-Length") or 0))
                outer.requests_log.append(("GET", self.path, dict(self.headers), body))

                # Protected endpoint: /api/profile
                if self.path == "/api/profile":
                    sess = self._get_session()

                    # Unauthenticated access (A1)
                    if not sess:
                        if outer.scenario == "a1_fail":
                            # Target incorrectly allows anonymous access
                            self.send_response(200)
                            self.send_header("Content-Type", "application/json")
                            self.end_headers()
                            self.wfile.write(b'{"data": "profile", "marker": "protected:user_a"}')
                            return
                        else:
                            self.send_response(401)
                            self.send_header("Content-Type", "application/json")
                            self.end_headers()
                            self.wfile.write(b'{"error": "authentication required"}')
                            return

                    # Authenticated access
                    # Scenario: A4 denied
                    if outer.scenario == "a4_denied":
                        self.send_response(403)
                        self.send_header("Content-Type", "application/json")
                        self.end_headers()
                        self.wfile.write(b'{"error": "access denied"}')
                        return

                    # Scenario: A4 missing marker
                    if outer.scenario == "a4_missing_marker":
                        self.send_response(200)
                        self.send_header("Content-Type", "application/json")
                        self.end_headers()
                        self.wfile.write(b'{"data": "profile", "user": "user_a"}')  # Marker absent!
                        return

                    # Scenario: A6 reuse after logout
                    if sess in outer.logged_out_sessions:
                        if outer.scenario == "a6_fail":
                            # Session still accepted after logout!
                            self.send_response(200)
                            self.send_header("Content-Type", "application/json")
                            self.end_headers()
                            self.wfile.write(b'{"data": "profile", "marker": "protected:user_a"}')
                            return
                        else:
                            self.send_response(401)
                            self.send_header("Content-Type", "application/json")
                            self.end_headers()
                            self.wfile.write(b'{"error": "session expired/logged out"}')
                            return

                    if sess in outer.valid_sessions:
                        actor = "admin_a" if "admin_a" in sess else "user_a"
                        self.send_response(200)
                        self.send_header("Content-Type", "application/json")
                        self.end_headers()
                        self.wfile.write(f'{{"data": "profile", "marker": "protected:{actor}"}}'.encode("utf-8"))
                        return

                    self.send_response(401)
                    self.end_headers()
                    return

                self.send_response(404)
                self.end_headers()

            def _get_session(self) -> str | None:
                cookie_hdr = self.headers.get("Cookie") or ""
                for part in cookie_hdr.split(";"):
                    p = part.strip()
                    if p.startswith("session_id="):
                        val = p.split("=", 1)[1].strip()
                        if val:
                            return val

                auth_hdr = self.headers.get("Authorization") or ""
                if auth_hdr.startswith("Bearer "):
                    return auth_hdr[7:].strip()
                return None

            def log_message(self, *args):
                pass

        self.httpd = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
        self.port = self.httpd.server_address[1]
        self.url = f"http://127.0.0.1:{self.port}"
        self.thread = threading.Thread(target=self.httpd.serve_forever, daemon=True)
        self.thread.start()

    def close(self):
        self.httpd.shutdown()


def _make_auth_cfg(base_url: str, with_logout: bool = True) -> Any:
    raw: dict[str, Any] = {
        "target": {
            "base_url": base_url,
            "environment": "local",
            "production": False,
            "authorized": True,
            "authorized_by": "sec-team",
        },
        "authentication": {
            "enabled": True,
            "login": {
                "path": "/api/login",
                "method": "POST",
                "username_field": "email",
                "password_field": "password",
            },
            "protected_endpoint": {
                "path": "/api/profile",
                "method": "GET",
            },
        },
        "runtime_verification": {
            "mode": "local-app",
            "allowed_targets": [base_url],
            "identity_setup": {
                "adapter": "http-local",
                "path": "/_security/setup-identities",
            },
            "actors": {
                "admin_a": {"role": "admin", "tenant": "alpha"},
                "user_a": {"role": "user", "tenant": "alpha"},
            },
            "routes": {
                "protected": {
                    "path": "/api/profile",
                    "marker": "protected:{label}",
                }
            },
        },
    }
    if with_logout:
        raw["authentication"]["logout"] = {
            "path": "/api/logout",
            "method": "POST",
            "enabled": True,
        }
    return parse(raw)


def test_auth_full_a1_to_a6_pass_cookie():
    """Verify clean PASS for full A1-A6 authentication checks with cookies."""
    server = _AuthTestServer(scenario="pass", auth_mode="cookie")
    try:
        cfg = _make_auth_cfg(server.url, with_logout=True)
        plan = build_plan(cfg)
        auth_plan = plan.areas["authentication"]
        assert auth_plan.configured is True
        assert auth_plan.requests_count == 7  # A1 + A2 + A3 (admin_a) + A3 (user_a) + A4 + A5 + A6 = 7

        result = execute_native_plan(cfg, plan)
        assert result.status == "PASS"
        auth_res = result.get_area_result("authentication")
        assert auth_res is not None
        assert auth_res.status == "PASS"
        assert auth_res.runtime_checks_executed is True
        assert len(auth_res.findings) == 0
        assert len(auth_res.checks) == auth_plan.requests_count

        # Check evidence records
        check_ids = [c["check"] for c in auth_res.checks]
        assert check_ids == ["A1", "A2", "A3", "A3", "A4", "A5", "A6"]
        classifications = [c["classification"] for c in auth_res.checks]
        assert classifications == [
            "denied",   # A1
            "denied",   # A2
            "allowed",  # A3 admin_a
            "allowed",  # A3 user_a
            "allowed",  # A4
            "allowed",  # A5
            "denied",   # A6
        ]

        # Check report format compatibility
        report_dict = auth_res.to_report_dict(actors=["admin_a", "user_a"])
        assert report_dict["status"] == "PASS"
        assert report_dict["source"] == "native"
        assert report_dict["namespace"] == "RT-AUTH-*"
        assert report_dict["runtime_checks_executed"] is True
        assert report_dict["requests_count"] == auth_plan.requests_count
        assert report_dict["findings"] == []
    finally:
        server.close()


def test_auth_full_a1_to_a6_pass_token():
    """Verify clean PASS for full A1-A6 authentication checks with bearer tokens in JSON."""
    server = _AuthTestServer(scenario="pass", auth_mode="token")
    try:
        cfg = _make_auth_cfg(server.url, with_logout=True)
        plan = build_plan(cfg)
        result = execute_native_plan(cfg, plan)

        assert result.status == "PASS"
        auth_res = result.get_area_result("authentication")
        assert auth_res.status == "PASS"
        assert len(auth_res.findings) == 0
    finally:
        server.close()


def test_auth_without_logout_declared_is_executed_not_pass():
    """When logout is not declared in config, successful auth status must be EXECUTED, not PASS."""
    server = _AuthTestServer(scenario="pass")
    try:
        cfg = _make_auth_cfg(server.url, with_logout=False)
        plan = build_plan(cfg)
        auth_plan = plan.areas["authentication"]
        # No A5 or A6
        assert not any(r.check_id in ("A5", "A6") for r in auth_plan.requests)

        result = execute_native_plan(cfg, plan)
        assert result.status == "EXECUTED"
        auth_res = result.get_area_result("authentication")
        assert auth_res.status == "EXECUTED"
        assert "logout not declared" in auth_res.reason
        assert len(auth_res.findings) == 0
    finally:
        server.close()


def test_auth_a1_unauthenticated_allowed_finding_rt_auth_001():
    """Target allows unauthenticated access to protected route -> RT-AUTH-001 finding."""
    server = _AuthTestServer(scenario="a1_fail")
    try:
        cfg = _make_auth_cfg(server.url, with_logout=True)
        plan = build_plan(cfg)
        result = execute_native_plan(cfg, plan)

        assert result.status == "FAIL"
        auth_res = result.get_area_result("authentication")
        assert auth_res.status == "FAIL"
        assert len(auth_res.findings) == 1
        finding = auth_res.findings[0]
        assert finding.id == "RT-AUTH-001"
        assert finding.severity == Severity.HIGH
        assert finding.confidence == Confidence.HIGH
        assert finding.source == "native-verification"
        assert "Unauthenticated access allowed" in finding.title
    finally:
        server.close()


def test_auth_a2_invalid_credentials_accepted_finding_rt_auth_002():
    """Target accepts invalid synthetic credentials and issues session -> RT-AUTH-002 finding."""
    server = _AuthTestServer(scenario="a2_fail")
    try:
        cfg = _make_auth_cfg(server.url, with_logout=True)
        plan = build_plan(cfg)
        result = execute_native_plan(cfg, plan)

        assert result.status == "FAIL"
        auth_res = result.get_area_result("authentication")
        assert auth_res.status == "FAIL"
        assert any(f.id == "RT-AUTH-002" for f in auth_res.findings)
        finding = [f for f in auth_res.findings if f.id == "RT-AUTH-002"][0]
        assert finding.severity == Severity.HIGH
        assert finding.confidence == Confidence.HIGH
        assert finding.source == "native-verification"
        assert "invalid" in finding.title.lower()
    finally:
        server.close()


def test_auth_a3_positive_control_failure_incomplete_zero_findings():
    """Target rejects valid synthetic credentials -> positive control failed -> INCOMPLETE, 0 findings."""
    server = _AuthTestServer(scenario="a3_fail")
    try:
        cfg = _make_auth_cfg(server.url, with_logout=True)
        plan = build_plan(cfg)
        result = execute_native_plan(cfg, plan)

        assert result.status == "INCOMPLETE"
        auth_res = result.get_area_result("authentication")
        assert auth_res.status == "INCOMPLETE"
        assert "positive control failed" in auth_res.reason
        assert len(auth_res.findings) == 0  # CRITICAL: positive control failure MUST NOT emit findings
    finally:
        server.close()


def test_auth_a4_marker_missing_ambiguous_incomplete():
    """Target returns 200 OK on authenticated route but protected marker is missing -> ambiguous INCOMPLETE."""
    server = _AuthTestServer(scenario="a4_missing_marker")
    try:
        cfg = _make_auth_cfg(server.url, with_logout=True)
        plan = build_plan(cfg)
        result = execute_native_plan(cfg, plan)

        assert result.status == "INCOMPLETE"
        auth_res = result.get_area_result("authentication")
        assert auth_res.status == "INCOMPLETE"
        assert "marker absent" in auth_res.reason
        assert len(auth_res.findings) == 0
    finally:
        server.close()


def test_auth_a4_authenticated_denied_incomplete():
    """Target denies authenticated access with valid session -> positive control failure -> INCOMPLETE."""
    server = _AuthTestServer(scenario="a4_denied")
    try:
        cfg = _make_auth_cfg(server.url, with_logout=True)
        plan = build_plan(cfg)
        result = execute_native_plan(cfg, plan)

        assert result.status == "INCOMPLETE"
        auth_res = result.get_area_result("authentication")
        assert auth_res.status == "INCOMPLETE"
        assert "positive control failed" in auth_res.reason
        assert len(auth_res.findings) == 0
    finally:
        server.close()


def test_auth_a5_logout_failure_incomplete():
    """Target fails logout operation with 500 error -> INCOMPLETE."""
    server = _AuthTestServer(scenario="a5_fail")
    try:
        cfg = _make_auth_cfg(server.url, with_logout=True)
        plan = build_plan(cfg)
        result = execute_native_plan(cfg, plan)

        assert result.status == "INCOMPLETE"
        auth_res = result.get_area_result("authentication")
        assert auth_res.status == "INCOMPLETE"
        assert "logout request failed" in auth_res.reason
        assert len(auth_res.findings) == 0
    finally:
        server.close()


def test_auth_a6_session_reuse_succeeds_finding_rt_auth_003():
    """Target allows access with pre-logout session after logout -> RT-AUTH-003 finding."""
    server = _AuthTestServer(scenario="a6_fail")
    try:
        cfg = _make_auth_cfg(server.url, with_logout=True)
        plan = build_plan(cfg)
        result = execute_native_plan(cfg, plan)

        assert result.status == "FAIL"
        auth_res = result.get_area_result("authentication")
        assert auth_res.status == "FAIL"
        assert any(f.id == "RT-AUTH-003" for f in auth_res.findings)
        finding = [f for f in auth_res.findings if f.id == "RT-AUTH-003"][0]
        assert finding.severity == Severity.HIGH
        assert finding.confidence == Confidence.HIGH
        assert finding.source == "native-verification"
        assert "after logout" in finding.title.lower()
    finally:
        server.close()


def test_auth_mfa_challenge_not_verified():
    """Target indicates MFA or CAPTCHA challenge -> NOT VERIFIED status."""
    server = _AuthTestServer(scenario="mfa")
    try:
        cfg = _make_auth_cfg(server.url, with_logout=True)
        plan = build_plan(cfg)
        result = execute_native_plan(cfg, plan)

        assert result.status == "EXECUTED"
        auth_res = result.get_area_result("authentication")
        assert auth_res.status == "NOT VERIFIED"
        assert "MFA/CAPTCHA" in auth_res.reason
        assert len(auth_res.findings) == 0
    finally:
        server.close()


def test_auth_secret_redaction_and_protection():
    """Verify secrets are never present in result repr, checks, findings, or reports."""
    server = _AuthTestServer(scenario="pass")
    try:
        vault = IdentityVault("run-sec-test", ["admin_a", "user_a"])
        cfg = _make_auth_cfg(server.url, with_logout=True)
        plan = build_plan(cfg)
        executor = NativeExecutor(cfg, vault=vault)
        result = executor.execute_plan(plan)

        admin_secret = vault.get_actor_secret("admin_a").reveal_for_request()
        user_secret = vault.get_actor_secret("user_a").reveal_for_request()

        # Check result repr
        res_repr = repr(result)
        assert admin_secret not in res_repr
        assert user_secret not in res_repr

        # Check area results and checks
        auth_res = result.get_area_result("authentication")
        assert admin_secret not in repr(auth_res)
        assert user_secret not in repr(auth_res)

        for c in auth_res.checks:
            assert admin_secret not in str(c)
            assert user_secret not in str(c)

        # Check report serialization
        report_data = json.dumps(auth_res.to_report_dict(actors=["admin_a", "user_a"]))
        assert admin_secret not in report_data
        assert user_secret not in report_data
    finally:
        server.close()


def test_auth_deterministic_request_order_and_bounds():
    """Verify request sequence order and budget enforcement."""
    server = _AuthTestServer(scenario="pass")
    try:
        cfg = _make_auth_cfg(server.url, with_logout=True)
        plan = build_plan(cfg)
        result = execute_native_plan(cfg, plan)

        # Server logs:
        # [0] = setup
        # [1] = A1 (GET /api/profile)
        # [2] = A2 (POST /api/login)
        # [3] = A3 (POST /api/login, admin_a)
        # [4] = A3 (POST /api/login, user_a) - alphabetical actor order
        # [5] = A4 (GET /api/profile, user_a)
        # [6] = A5 (POST /api/logout, user_a)
        # [7] = A6 (GET /api/profile, user_a)
        # [8] = S2 (GET /api/profile, admin_a) - session continuity with active session
        log = server.requests_log
        assert len(log) == 9  # 1 setup + 7 auth + 1 session verification request

        assert log[0][0] == "POST" and log[0][1] == "/_security/setup-identities"
        assert log[1][0] == "GET" and log[1][1] == "/api/profile"
        assert log[2][0] == "POST" and log[2][1] == "/api/login"
        assert log[3][0] == "POST" and log[3][1] == "/api/login"
        assert log[4][0] == "POST" and log[4][1] == "/api/login"
        assert log[5][0] == "GET" and log[5][1] == "/api/profile"
        assert log[6][0] == "POST" and log[6][1] == "/api/logout"
        assert log[7][0] == "GET" and log[7][1] == "/api/profile"
        assert log[8][0] == "GET" and log[8][1] == "/api/profile"

        # Check actors sent in order
        admin_body = json.loads(log[3][3].decode("utf-8"))
        user_body = json.loads(log[4][3].decode("utf-8"))
        assert admin_body["email"] == "admin_a"
        assert user_body["email"] == "user_a"

        # S2 sends session continuity request with active session (admin_a)
        assert "session_id=sess_valid_admin_a" in log[8][2].get("Cookie", "")

        # Budget bounded: auth + session requests within hard maximums
        assert len(log) - 1 <= AREA_HARD_MAXIMUMS["authentication"] + AREA_HARD_MAXIMUMS["session"]
    finally:
        server.close()


def test_auth_timeout_stops_remaining_requests():
    """Per-request timeout on A2 stops remaining requests and marks INCOMPLETE."""
    server = _AuthTestServer(scenario="timeout_a2")
    try:
        cfg = _make_auth_cfg(server.url, with_logout=True)
        plan = build_plan(cfg)
        executor = NativeExecutor(cfg, request_timeout=0.05)
        result = executor.execute_plan(plan)

        assert result.status == "INCOMPLETE"
        assert result.timed_out is True
        auth_res = result.get_area_result("authentication")
        assert auth_res.status == "INCOMPLETE"
        assert auth_res.timed_out is True
        # Requests after A2 (A3, A4, A5, A6) must not be sent
        paths_sent = [item[1] for item in server.requests_log]
        assert "/api/logout" not in paths_sent
    finally:
        server.close()


def test_auth_setup_failure_prevents_auth_requests():
    """Setup hook failure prevents any authentication requests from being sent."""
    server = _AuthTestServer(scenario="pass")
    server.mode = "fail_setup"

    # Patch handler to fail setup
    class FailSetupServer(_AuthTestServer):
        pass

    class Handler(BaseHTTPRequestHandler):
        def do_POST(self):
            if self.path == "/_security/setup-identities":
                self.send_response(500)
                self.end_headers()
                self.wfile.write(b'{"error": "setup crashed"}')
                return
            self.send_response(200)
            self.end_headers()

        def log_message(self, *args):
            pass

    httpd = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
    port = httpd.server_address[1]
    url = f"http://127.0.0.1:{port}"
    th = threading.Thread(target=httpd.serve_forever, daemon=True)
    th.start()
    try:
        cfg = _make_auth_cfg(url, with_logout=True)
        plan = build_plan(cfg)
        result = execute_native_plan(cfg, plan)

        assert result.status == "INCOMPLETE"
        assert result.setup_result is not None
        assert result.setup_result.succeeded is False
        auth_res = result.get_area_result("authentication")
        assert auth_res.status == "INCOMPLETE"
        assert auth_res.requests_sent == 0
    finally:
        httpd.shutdown()


def test_auth_production_target_refused_zero_requests():
    """Production target is refused by safety gate with zero requests sent."""
    cfg = parse({
        "target": {
            "base_url": "https://api.example.com",
            "environment": "production",
            "production": True,
        },
        "runtime_verification": {
            "mode": "fixture",
            "allowed_targets": ["https://api.example.com"],
        },
    })
    plan = NativePlan()
    result = execute_native_plan(cfg, plan)
    assert result.status == "INCOMPLETE"
    assert result.refused is True
    assert result.requests_sent == 0


def test_auth_no_brute_force_or_spraying_single_invalid_attempt():
    """Ensure verification sends exactly 1 invalid attempt, never sprays or enumerates."""
    server = _AuthTestServer(scenario="pass")
    try:
        cfg = _make_auth_cfg(server.url, with_logout=True)
        plan = build_plan(cfg)
        execute_native_plan(cfg, plan)

        # Count invalid login attempts
        invalid_attempts = 0
        for method, path, _, body in server.requests_log:
            if method == "POST" and path == "/api/login":
                try:
                    data = json.loads(body.decode("utf-8"))
                    if "invalid_synth_" in str(data.get("password", "")):
                        invalid_attempts += 1
                except Exception:
                    pass

        assert invalid_attempts == 1, f"Expected exactly 1 invalid attempt, got {invalid_attempts}"
    finally:
        server.close()
