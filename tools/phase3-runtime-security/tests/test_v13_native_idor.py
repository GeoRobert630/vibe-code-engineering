"""Tests for native horizontal IDOR / BOLA verification I1–I4 (Design §11, §15, §16, §17).

Verifies:
- I1: user_a own object positive control (expected allowed)
- I2: user_a cross-actor access to user_b object (expected denied)
- I3: user_b own object positive control (expected allowed)
- I4: user_b cross-actor access to user_a object (expected denied)
- PASS when I1/I3 are allowed and I2/I4 are denied
- FAIL with RT-IDOR-001 (HIGH/HIGH) when cross-actor access is allowed
- Positive-control gating: I1 or I3 failure prevents false-positive IDOR findings
- Ambiguous responses (e.g. 200 without marker, another resource's marker) resolve to INCOMPLETE
- Authentication prerequisite: missing A3 authentication blocks IDOR execution
- Strict actor and session separation (user_a session for I1/I2, user_b session for I3/I4)
- Support for cookie-based and bearer token-based session handling
- Timeout handling and request budget enforcement (hard maximum 4 requests)
- Secret redaction and safe evidence (no credentials, tokens, or response bodies)
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
from runtime_security.native.idor import (
    IDOR_NAMESPACE,
    build_idor_requests,
    evaluate_idor_checks,
    make_idor_finding,
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


class _IdorTestServer:
    """Deterministic local HTTP test server for IDOR / BOLA verification."""

    def __init__(
        self,
        expected_run_id: str = "run-idor-test",
        actors: list[str] | None = None,
        auth_mode: str = "cookie",  # "cookie" | "token"
        scenario: str = "pass",
    ):
        self.requests_log: list[tuple[str, str, dict[str, str], bytes]] = []
        self.expected_run_id = expected_run_id
        self.actors = sorted(actors or ["user_a", "user_b"])
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
                        self.wfile.write(b'{"error": "login failed"}')
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

                # Object-a resource (owned by user_a)
                if self.path == "/objects/object-a":
                    if outer.scenario == "timeout_i1" and actor == "user_a":
                        time.sleep(0.3)
                    elif outer.scenario in ("timeout_i4", "case_a_timeout_i4") and actor == "user_b":
                        time.sleep(0.3)

                    if not actor:
                        self.send_response(401)
                        self.send_header("Content-Type", "application/json")
                        self.end_headers()
                        self.wfile.write(b'{"error": "authentication required"}')
                        return

                    # Access by owner (user_a, I1)
                    if actor == "user_a":
                        if outer.scenario == "i1_denied":
                            self.send_response(403)
                            self.send_header("Content-Type", "application/json")
                            self.end_headers()
                            self.wfile.write(b'{"error": "forbidden"}')
                            return
                        elif outer.scenario == "i1_no_marker":
                            self.send_response(200)
                            self.send_header("Content-Type", "application/json")
                            self.end_headers()
                            self.wfile.write(b'{"status": "ok but marker missing"}')
                            return
                        else:
                            self.send_response(200)
                            self.send_header("Content-Type", "application/json")
                            self.end_headers()
                            self.wfile.write(b'{"data": "object-a", "owner": "owner:user_a"}')
                            return

                    # Access by other actor (user_b, I4)
                    if actor == "user_b":
                        if outer.scenario == "case_a_500_i4":
                            self.send_response(500)
                            self.send_header("Content-Type", "application/json")
                            self.end_headers()
                            self.wfile.write(b'{"error": "server error"}')
                            return
                        elif outer.scenario == "i4_allowed":
                            # VULNERABILITY: user_b reads user_a's object!
                            self.send_response(200)
                            self.send_header("Content-Type", "application/json")
                            self.end_headers()
                            self.wfile.write(b'{"data": "object-a", "owner": "owner:user_a"}')
                            return
                        elif outer.scenario == "i4_ambiguous":
                            self.send_response(200)
                            self.send_header("Content-Type", "application/json")
                            self.end_headers()
                            self.wfile.write(b'{"status": "generic ok without marker"}')
                            return
                        else:
                            # Proper denial (403)
                            self.send_response(403)
                            self.send_header("Content-Type", "application/json")
                            self.end_headers()
                            self.wfile.write(b'{"error": "forbidden: not owner"}')
                            return

                # Object-b resource (owned by user_b)
                if self.path == "/objects/object-b":
                    if outer.scenario == "timeout_i2" and actor == "user_a":
                        time.sleep(0.3)
                    elif outer.scenario == "timeout_i3" and actor == "user_b":
                        time.sleep(0.3)

                    if not actor:
                        self.send_response(401)
                        self.send_header("Content-Type", "application/json")
                        self.end_headers()
                        self.wfile.write(b'{"error": "authentication required"}')
                        return

                    # Access by other actor (user_a, I2)
                    if actor == "user_a":
                        if outer.scenario in ("i2_allowed", "i3_denied_with_i2_vuln", "case_a_timeout_i4", "case_a_500_i4"):
                            # VULNERABILITY: user_a reads user_b's object!
                            self.send_response(200)
                            self.send_header("Content-Type", "application/json")
                            self.end_headers()
                            self.wfile.write(b'{"data": "object-b", "owner": "owner:user_b"}')
                            return
                        elif outer.scenario == "i2_ambiguous":
                            self.send_response(200)
                            self.send_header("Content-Type", "application/json")
                            self.end_headers()
                            self.wfile.write(b'{"status": "generic ok without marker"}')
                            return
                        elif outer.scenario == "other_marker_returned":
                            # Returns user_a's marker instead of object-b marker
                            self.send_response(200)
                            self.send_header("Content-Type", "application/json")
                            self.end_headers()
                            self.wfile.write(b'{"data": "object-b", "owner": "owner:user_a"}')
                            return
                        else:
                            # Proper denial (403)
                            self.send_response(403)
                            self.send_header("Content-Type", "application/json")
                            self.end_headers()
                            self.wfile.write(b'{"error": "forbidden: not owner"}')
                            return

                    # Access by owner (user_b, I3)
                    if actor == "user_b":
                        if outer.scenario in ("i3_denied", "i3_denied_with_i2_vuln"):
                            self.send_response(403)
                            self.send_header("Content-Type", "application/json")
                            self.end_headers()
                            self.wfile.write(b'{"error": "forbidden"}')
                            return
                        elif outer.scenario == "i3_no_marker":
                            self.send_response(200)
                            self.send_header("Content-Type", "application/json")
                            self.end_headers()
                            self.wfile.write(b'{"status": "ok but marker missing"}')
                            return
                        else:
                            self.send_response(200)
                            self.send_header("Content-Type", "application/json")
                            self.end_headers()
                            self.wfile.write(b'{"data": "object-b", "owner": "owner:user_b"}')
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


def _make_idor_cfg(url: str, mode: str = "fixture"):
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
                    "user_a": {"role": "user", "tenant": "tenant-a"},
                    "user_b": {"role": "user", "tenant": "tenant-a"},
                },
                "routes": {
                    "protected": {"path": "/api/profile", "marker": "account:{label}"},
                },
                "resources": [
                    {
                        "id": "object-a",
                        "path": "/objects/object-a",
                        "owner": "user_a",
                        "marker": "owner:user_a",
                    },
                    {
                        "id": "object-b",
                        "path": "/objects/object-b",
                        "owner": "user_b",
                        "marker": "owner:user_b",
                    },
                ],
                "deny_statuses": [401, 403, 404],
            },
        }
    )


# ── 1. Planning Tests ────────────────────────────────────────────────────────


def test_idor_requests_plan():
    cfg = _make_idor_cfg("http://127.0.0.1:8000")
    requests = build_idor_requests(cfg)
    assert len(requests) == 4

    i1, i2, i3, i4 = requests
    assert i1.check_id == "I1"
    assert i1.area == "idor_bola"
    assert i1.method == "GET"
    assert i1.path == "/objects/object-a"
    assert i1.actor == "user_a"
    assert i1.expected == "allowed"
    assert i1.marker == "owner:user_a"

    assert i2.check_id == "I2"
    assert i2.area == "idor_bola"
    assert i2.method == "GET"
    assert i2.path == "/objects/object-b"
    assert i2.actor == "user_a"
    assert i2.expected == "denied"
    assert i2.marker == "owner:user_b"

    assert i3.check_id == "I3"
    assert i3.area == "idor_bola"
    assert i3.method == "GET"
    assert i3.path == "/objects/object-b"
    assert i3.actor == "user_b"
    assert i3.expected == "allowed"
    assert i3.marker == "owner:user_b"

    assert i4.check_id == "I4"
    assert i4.area == "idor_bola"
    assert i4.method == "GET"
    assert i4.path == "/objects/object-a"
    assert i4.actor == "user_b"
    assert i4.expected == "denied"
    assert i4.marker == "owner:user_a"

    plan = build_plan(cfg)
    idor_plan = plan.areas["idor_bola"]
    assert idor_plan.configured is True
    assert idor_plan.requests_count == 4
    assert idor_plan.budget == 4


def test_idor_not_configured_when_less_than_two_users_with_objects():
    cfg = parse(
        {
            "target": {
                "base_url": "http://127.0.0.1:8000",
                "environment": "local",
                "production": False,
                "authorized": True,
                "authorized_by": "test-suite",
            },
            "runtime_verification": {
                "mode": "fixture",
                "allowed_targets": ["http://127.0.0.1:8000"],
                "actors": {
                    "user_a": {"role": "user", "tenant": "tenant-a"},
                },
                "resources": [
                    {
                        "id": "object-a",
                        "path": "/objects/object-a",
                        "owner": "user_a",
                        "marker": "owner:user_a",
                    }
                ],
            },
        }
    )
    requests = build_idor_requests(cfg)
    assert len(requests) == 0

    plan = build_plan(cfg)
    assert plan.areas["idor_bola"].configured is False
    assert plan.areas["idor_bola"].requests_count == 0


# ── 2. Positive Controls and Denial (PASS) ───────────────────────────────────


def test_idor_full_pass_cookie_auth():
    """I1 and I3 positive controls allowed, I2 and I4 denied -> PASS."""
    srv = _IdorTestServer(scenario="pass", auth_mode="cookie")
    try:
        cfg = _make_idor_cfg(srv.url)
        plan = build_plan(cfg)
        result = execute_native_plan(cfg, plan)

        idor_res = result.area_results["idor_bola"]
        assert idor_res.status == "PASS"
        assert idor_res.runtime_checks_executed is True
        assert idor_res.requests_sent == 4
        assert len(idor_res.findings) == 0
        assert len(idor_res.checks) == 4

        c_by_id = {c["check"]: c for c in idor_res.checks}
        assert c_by_id["I1"]["classification"] == "allowed"
        assert c_by_id["I1"]["actors"] == ["user_a"]
        assert c_by_id["I2"]["classification"] == "denied"
        assert c_by_id["I2"]["actors"] == ["user_a"]
        assert c_by_id["I3"]["classification"] == "allowed"
        assert c_by_id["I3"]["actors"] == ["user_b"]
        assert c_by_id["I4"]["classification"] == "denied"
        assert c_by_id["I4"]["actors"] == ["user_b"]
    finally:
        srv.close()


def test_idor_full_pass_token_auth():
    """Token-based (Bearer) session authentication works for IDOR verification."""
    srv = _IdorTestServer(scenario="pass", auth_mode="token")
    try:
        cfg = _make_idor_cfg(srv.url)
        plan = build_plan(cfg)
        result = execute_native_plan(cfg, plan)

        idor_res = result.area_results["idor_bola"]
        assert idor_res.status == "PASS"
        assert idor_res.requests_sent == 4
        assert len(idor_res.findings) == 0
    finally:
        srv.close()


# ── 3. Cross-Actor Allowed Violations (FAIL -> RT-IDOR-001) ─────────────────


def test_idor_violation_i2_allowed():
    """When user_a accesses user_b's object (I2 allowed), emit RT-IDOR-001."""
    srv = _IdorTestServer(scenario="i2_allowed")
    try:
        cfg = _make_idor_cfg(srv.url)
        plan = build_plan(cfg)
        result = execute_native_plan(cfg, plan)

        idor_res = result.area_results["idor_bola"]
        assert idor_res.status == "FAIL"
        assert idor_res.runtime_checks_executed is True
        assert idor_res.requests_sent == 4
        assert len(idor_res.findings) == 1

        f = idor_res.findings[0]
        assert f.id == "RT-IDOR-001"
        assert f.category == "idor"
        assert f.severity == Severity.HIGH
        assert f.confidence == Confidence.HIGH
        assert f.endpoint == "GET /objects/object-b"
        assert f.expected == "denied"
        assert f.actual == "allowed"
        assert f.cwe == "CWE-639"
        assert f.owasp == "A01:2021-Broken Access Control"
        assert f.source == "native-verification"
        assert f.status == Status.OPEN
    finally:
        srv.close()


def test_idor_violation_i4_allowed():
    """When user_b accesses user_a's object (I4 allowed), emit RT-IDOR-001."""
    srv = _IdorTestServer(scenario="i4_allowed")
    try:
        cfg = _make_idor_cfg(srv.url)
        plan = build_plan(cfg)
        result = execute_native_plan(cfg, plan)

        idor_res = result.area_results["idor_bola"]
        assert idor_res.status == "FAIL"
        assert len(idor_res.findings) == 1

        f = idor_res.findings[0]
        assert f.id == "RT-IDOR-001"
        assert f.endpoint == "GET /objects/object-a"
        assert f.actual == "allowed"
    finally:
        srv.close()


# ── 4. Positive-Control Gating (Prevents Fabricated Findings) ────────────────


def test_idor_positive_control_i1_failure_prevents_finding():
    """If user_a own-object positive control (I1) fails, stop immediately with INCOMPLETE and NO findings."""
    srv = _IdorTestServer(scenario="i1_denied")
    try:
        cfg = _make_idor_cfg(srv.url)
        plan = build_plan(cfg)
        result = execute_native_plan(cfg, plan)

        idor_res = result.area_results["idor_bola"]
        assert idor_res.status == "INCOMPLETE"
        assert len(idor_res.findings) == 0
        assert idor_res.requests_sent == 1
        assert "positive control I1 failed" in idor_res.error
    finally:
        srv.close()


def test_idor_positive_control_i3_failure_suppresses_i2_violation():
    """If user_a accessed object-b (I2) but user_b cannot access object-b (I3), suppress the finding and mark INCOMPLETE."""
    srv = _IdorTestServer(scenario="i3_denied_with_i2_vuln")
    try:
        cfg = _make_idor_cfg(srv.url)
        plan = build_plan(cfg)
        result = execute_native_plan(cfg, plan)

        idor_res = result.area_results["idor_bola"]
        assert idor_res.status == "INCOMPLETE"
        # CRITICAL SECURITY RULE: No finding emitted without both positive controls passing
        assert len(idor_res.findings) == 0
        assert idor_res.requests_sent == 3
        assert "positive control I3 failed" in idor_res.error
    finally:
        srv.close()


# ── 5. Ambiguous Response Handling ──────────────────────────────────────────


def test_idor_ambiguous_response_i2():
    """200 without object marker on cross-actor check I2 resolves to INCOMPLETE without finding."""
    srv = _IdorTestServer(scenario="i2_ambiguous")
    try:
        cfg = _make_idor_cfg(srv.url)
        plan = build_plan(cfg)
        result = execute_native_plan(cfg, plan)

        idor_res = result.area_results["idor_bola"]
        assert idor_res.status == "INCOMPLETE"
        assert len(idor_res.findings) == 0
        assert "ambiguous" in idor_res.reason
    finally:
        srv.close()


def test_idor_ambiguous_when_other_marker_returned():
    """Returning another resource's marker classifies as ambiguous and resolves to INCOMPLETE."""
    srv = _IdorTestServer(scenario="other_marker_returned")
    try:
        cfg = _make_idor_cfg(srv.url)
        plan = build_plan(cfg)
        result = execute_native_plan(cfg, plan)

        idor_res = result.area_results["idor_bola"]
        assert idor_res.status == "INCOMPLETE"
        assert len(idor_res.findings) == 0
    finally:
        srv.close()


# ── 6. Authentication Prerequisite ──────────────────────────────────────────


def test_idor_blocked_when_authentication_fails():
    """If authentication positive controls (A3) fail, IDOR verification is blocked and marked INCOMPLETE."""
    srv = _IdorTestServer(scenario="a3_fail")
    try:
        cfg = _make_idor_cfg(srv.url)
        plan = build_plan(cfg)
        result = execute_native_plan(cfg, plan)

        idor_res = result.area_results["idor_bola"]
        assert idor_res.status == "INCOMPLETE"
        assert idor_res.requests_sent == 0
        assert "authentication positive control" in idor_res.error
    finally:
        srv.close()


# ── 7. Actor and Session Separation ─────────────────────────────────────────


def test_idor_actor_session_isolation():
    """Verify I1/I2 use user_a session and I3/I4 use user_b session."""
    srv = _IdorTestServer(scenario="pass")
    try:
        cfg = _make_idor_cfg(srv.url)
        plan = build_plan(cfg)
        execute_native_plan(cfg, plan)

        # Inspect requests sent to /objects/
        object_reqs = [
            (method, path, headers)
            for (method, path, headers, _) in srv.requests_log
            if path.startswith("/objects/")
        ]
        assert len(object_reqs) == 4

        # Extract session IDs sent
        sent_sessions = []
        for _, _, headers in object_reqs:
            cookie = headers.get("Cookie", "")
            sid = cookie.split("=")[1].split(";")[0]
            sent_sessions.append(sid)

        # I1 (user_a) and I2 (user_a) must share user_a's session
        assert sent_sessions[0] == sent_sessions[1]
        assert srv.valid_sessions[sent_sessions[0]] == "user_a"

        # I3 (user_b) and I4 (user_b) must share user_b's session
        assert sent_sessions[2] == sent_sessions[3]
        assert srv.valid_sessions[sent_sessions[2]] == "user_b"

        # user_a and user_b sessions must be distinct
        assert sent_sessions[0] != sent_sessions[2]
    finally:
        srv.close()


# ── 8. Timeout Handling ──────────────────────────────────────────────────────


def test_idor_request_timeout_i1():
    """Timeout on I1 produces INCOMPLETE with timed_out set."""
    srv = _IdorTestServer(scenario="timeout_i1")
    try:
        cfg = _make_idor_cfg(srv.url)
        plan = build_plan(cfg)
        result = execute_native_plan(cfg, plan, request_timeout=0.1)

        idor_res = result.area_results["idor_bola"]
        assert idor_res.status == "INCOMPLETE"
        assert idor_res.timed_out is True
        assert len(idor_res.findings) == 0
    finally:
        srv.close()


def test_idor_request_timeout_i2():
    """Timeout on I2 produces INCOMPLETE with timed_out set."""
    srv = _IdorTestServer(scenario="timeout_i2")
    try:
        cfg = _make_idor_cfg(srv.url)
        plan = build_plan(cfg)
        result = execute_native_plan(cfg, plan, request_timeout=0.1)

        idor_res = result.area_results["idor_bola"]
        assert idor_res.status == "INCOMPLETE"
        assert idor_res.timed_out is True
        assert len(idor_res.findings) == 0
    finally:
        srv.close()


# ── 9. Request Budget Enforcement ───────────────────────────────────────────


def test_idor_request_budget_enforcement():
    """Total client budget exhaustion halts execution and marks area INCOMPLETE."""
    srv = _IdorTestServer(scenario="pass")
    try:
        cfg = _make_idor_cfg(srv.url)
        plan = build_plan(cfg)
        # Authentication takes setup(0 in fixture) + A1(1) + A2(1) + A3(2) + A4(1) = 5 requests
        # If client max_budget is 6, IDOR runs 1 request (I1) and then budget is exhausted
        executor = NativeExecutor(cfg=cfg)
        assert executor.client is not None
        executor.client.max_budget = 6
        result = executor.execute_plan(plan)

        idor_res = result.area_results["idor_bola"]
        assert idor_res.status == "INCOMPLETE"
        assert idor_res.budget_exceeded is True
        assert len(idor_res.findings) == 0
    finally:
        srv.close()


# ── 10. Secret and Redaction Safety ──────────────────────────────────────────


def test_idor_secret_redaction_safety():
    """Verify no tokens, credentials, or raw response bodies leak into evidence or findings."""
    srv = _IdorTestServer(scenario="i2_allowed")
    try:
        cfg = _make_idor_cfg(srv.url)
        plan = build_plan(cfg)
        result = execute_native_plan(cfg, plan)

        idor_res = result.area_results["idor_bola"]
        assert idor_res.status == "FAIL"
        finding = idor_res.findings[0]

        # Finding must not contain session IDs, credentials, or full response bodies
        finding_dump = str(vars(finding))
        assert "sess_" not in finding_dump
        assert "password" not in finding_dump
        assert "synth_" not in finding_dump

        # Check records must also be safe
        for chk in idor_res.checks:
            chk_dump = json.dumps(chk)
            assert "sess_" not in chk_dump
    finally:
        srv.close()


# ── 11. evaluate_idor_checks Pure Unit Tests ─────────────────────────────────


def test_evaluate_idor_checks_pass():
    checks = [
        {"check": "I1", "classification": "allowed"},
        {"check": "I2", "classification": "denied"},
        {"check": "I3", "classification": "allowed"},
        {"check": "I4", "classification": "denied"},
    ]
    _, findings, status, _ = evaluate_idor_checks(checks)
    assert status == "PASS"
    assert len(findings) == 0


def test_evaluate_idor_checks_fail_i2():
    checks = [
        {"check": "I1", "classification": "allowed"},
        {"check": "I2", "classification": "allowed", "status": 200, "path": "/objects/b"},
        {"check": "I3", "classification": "allowed"},
        {"check": "I4", "classification": "denied"},
    ]
    _, findings, status, _ = evaluate_idor_checks(checks, res_b_path="/objects/b")
    assert status == "FAIL"
    assert len(findings) == 1
    assert findings[0].id == "RT-IDOR-001"
    assert findings[0].endpoint == "GET /objects/b"


def test_evaluate_idor_checks_positive_control_failure():
    # If I3 fails, do not emit finding even if I2 was allowed
    checks = [
        {"check": "I1", "classification": "allowed"},
        {"check": "I2", "classification": "allowed"},
        {"check": "I3", "classification": "denied"},
        {"check": "I4", "classification": "denied"},
    ]
    _, findings, status, _ = evaluate_idor_checks(checks)
    assert status == "INCOMPLETE"
    assert len(findings) == 0


def test_evaluate_idor_checks_ambiguous():
    checks = [
        {"check": "I1", "classification": "allowed"},
        {"check": "I2", "classification": "ambiguous"},
        {"check": "I3", "classification": "allowed"},
        {"check": "I4", "classification": "denied"},
    ]
    _, findings, status, _ = evaluate_idor_checks(checks)
    assert status == "INCOMPLETE"
    assert len(findings) == 0


# ── 12. Case A & Case B Regression Tests ────────────────────────────────────


def test_case_a_idor_violation_retained_when_i4_times_out():
    """Case A: I1 allowed, I2 allowed (IDOR), I3 allowed, I4 timeout.

    The verified I2 vulnerability must NOT be erased or suppressed when I4 times out.
    RT-IDOR-001 remains emitted and area status matches v1.3 design (FAIL).
    """
    srv = _IdorTestServer(scenario="case_a_timeout_i4")
    try:
        cfg = _make_idor_cfg(srv.url)
        plan = build_plan(cfg)
        result = execute_native_plan(cfg, plan, request_timeout=0.1)

        idor_res = result.area_results["idor_bola"]
        assert idor_res.status == "FAIL"
        assert len(idor_res.findings) == 1
        f = idor_res.findings[0]
        assert f.id == "RT-IDOR-001"
        assert f.endpoint == "GET /objects/object-b"
        assert f.expected == "denied"
        assert f.actual == "allowed"
        assert idor_res.timed_out is True
        assert len(idor_res.checks) == 4
        c4 = next(c for c in idor_res.checks if c["check"] == "I4")
        assert c4["classification"] == "incomplete"
    finally:
        srv.close()


def test_case_a_idor_violation_retained_when_i4_returns_500():
    """Case A variant: I1 allowed, I2 allowed (IDOR), I3 allowed, I4 returns 500 (incomplete)."""
    srv = _IdorTestServer(scenario="case_a_500_i4")
    try:
        cfg = _make_idor_cfg(srv.url)
        plan = build_plan(cfg)
        result = execute_native_plan(cfg, plan)

        idor_res = result.area_results["idor_bola"]
        assert idor_res.status == "FAIL"
        assert len(idor_res.findings) == 1
        assert idor_res.findings[0].id == "RT-IDOR-001"
        assert idor_res.findings[0].endpoint == "GET /objects/object-b"
    finally:
        srv.close()


def test_evaluate_idor_checks_case_a_incomplete_i4():
    """Case A pure unit test: I1 allowed, I2 allowed, I3 allowed, I4 incomplete -> FAIL with RT-IDOR-001."""
    checks = [
        {"check": "I1", "classification": "allowed"},
        {"check": "I2", "classification": "allowed", "status": 200, "path": "/objects/object-b"},
        {"check": "I3", "classification": "allowed"},
        {"check": "I4", "classification": "incomplete"},
    ]
    _, findings, status, _ = evaluate_idor_checks(checks, res_b_path="/objects/object-b")
    assert status == "FAIL"
    assert len(findings) == 1
    assert findings[0].id == "RT-IDOR-001"
    assert findings[0].endpoint == "GET /objects/object-b"


def test_evaluate_idor_checks_case_a_missing_i4():
    """Case A pure unit test: I1 allowed, I2 allowed, I3 allowed, I4 not executed (None) -> FAIL with RT-IDOR-001."""
    checks = [
        {"check": "I1", "classification": "allowed"},
        {"check": "I2", "classification": "allowed", "status": 200, "path": "/objects/object-b"},
        {"check": "I3", "classification": "allowed"},
    ]
    _, findings, status, _ = evaluate_idor_checks(checks, res_b_path="/objects/object-b")
    assert status == "FAIL"
    assert len(findings) == 1
    assert findings[0].id == "RT-IDOR-001"
    assert findings[0].endpoint == "GET /objects/object-b"


def test_evaluate_idor_checks_case_b():
    """Case B pure unit test: I1 allowed, I2 denied, I3 allowed, I4 allowed -> FAIL with RT-IDOR-001 on I4."""
    checks = [
        {"check": "I1", "classification": "allowed"},
        {"check": "I2", "classification": "denied"},
        {"check": "I3", "classification": "allowed"},
        {"check": "I4", "classification": "allowed", "status": 200, "path": "/objects/object-a"},
    ]
    _, findings, status, _ = evaluate_idor_checks(checks, res_a_path="/objects/object-a")
    assert status == "FAIL"
    assert len(findings) == 1
    assert findings[0].id == "RT-IDOR-001"
    assert findings[0].endpoint == "GET /objects/object-a"


def test_evaluate_idor_checks_i1_failure_suppresses_all():
    """I1 failure suppresses all IDOR findings even if cross-actor access occurred."""
    checks = [
        {"check": "I1", "classification": "denied"},
        {"check": "I2", "classification": "allowed", "status": 200},
        {"check": "I3", "classification": "allowed"},
        {"check": "I4", "classification": "allowed", "status": 200},
    ]
    _, findings, status, _ = evaluate_idor_checks(checks)
    assert status == "INCOMPLETE"
    assert len(findings) == 0


def test_case_c_i3_failure_suppresses_i2():
    """Case C: I1=allowed, I2=allowed, I3=denied, I4=allowed -> INCOMPLETE, 0 findings."""
    checks = [
        {"check": "I1", "classification": "allowed"},
        {"check": "I2", "classification": "allowed", "status": 200},
        {"check": "I3", "classification": "denied"},
        {"check": "I4", "classification": "allowed", "status": 200},
    ]
    _, findings, status, _ = evaluate_idor_checks(checks)
    assert status == "INCOMPLETE"
    assert len(findings) == 0


def test_case_d_i1_failure_gating():
    """Case D: I1=denied, I2=allowed, I3=allowed, I4=allowed -> INCOMPLETE, 0 findings."""
    checks = [
        {"check": "I1", "classification": "denied"},
        {"check": "I2", "classification": "allowed", "status": 200},
        {"check": "I3", "classification": "allowed"},
        {"check": "I4", "classification": "allowed", "status": 200},
    ]
    _, findings, status, _ = evaluate_idor_checks(checks)
    assert status == "INCOMPLETE"
    assert len(findings) == 0


def test_case_e_ambiguous_i2_yields_incomplete():
    """Case E: I1=allowed, I2=ambiguous, I3=allowed, I4=denied -> INCOMPLETE, 0 findings."""
    checks = [
        {"check": "I1", "classification": "allowed"},
        {"check": "I2", "classification": "ambiguous"},
        {"check": "I3", "classification": "allowed"},
        {"check": "I4", "classification": "denied"},
    ]
    _, findings, status, _ = evaluate_idor_checks(checks)
    assert status == "INCOMPLETE"
    assert len(findings) == 0


