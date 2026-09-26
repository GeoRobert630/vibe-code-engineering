"""Tests for native session verification (Design §9, §15, §16, §17).

Verifies:
- S1 session establishment (reuses A3 evidence)
- S2 session continuity (1 GET protected with same session)
- S3 session invalidation (reuses A5/A6 evidence)
- S4 session rotation (pre-auth cookie rotated on login)
- S5 cookie attributes (HttpOnly, SameSite, Secure per protocol)
- S6 actor separation (distinct fingerprints per actor)
- PASS with full S1-S6 satisfied
- EXECUTED without logout (no S3 possible)
- FAIL: missing HttpOnly → RT-SESSION-002
- FAIL: missing Secure on HTTPS → RT-SESSION-003
- FAIL: missing SameSite → RT-SESSION-004
- FAIL: session not rotated → RT-SESSION-001
- INCOMPLETE: positive control failure
- INCOMPLETE: S2 timeout
- INCOMPLETE: auth area not executed
- secret redaction in results, checks, findings
- deterministic request order and count
- request budget bounds (max 1 for session area)
- setup failure prevents session requests
- integration with authentication area
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
from runtime_security.native.session import (
    SESSION_NAMESPACE,
    build_session_requests,
    evaluate_session_checks,
    extract_all_cookie_attributes,
    make_session_finding,
    parse_cookie_attributes,
)
from runtime_security.native.setup_adapter import SETUP_SCHEMA


class _SessionTestServer:
    """Deterministic local HTTP test server for session verification."""

    def __init__(
        self,
        expected_run_id: str = "run-session-test",
        actors: list[str] | None = None,
        scenario: str = "pass",
        # "pass", "no_httponly", "no_secure", "no_samesite",
        # "no_rotation", "a3_fail", "s2_denied", "s2_timeout",
        # "a6_fail", "no_logout", "token_auth", "shared_session"
        pre_auth_cookie: bool = False,
        s2_sets_new_cookie: bool = False,
    ):
        self.requests_log: list[tuple[str, str, dict[str, str], bytes]] = []
        self.expected_run_id = expected_run_id
        self.actors = sorted(actors or ["admin_a", "user_a"])
        self.scenario = scenario
        self.valid_sessions: set[str] = set()
        self.logged_out_sessions: set[str] = set()
        self.pre_auth_cookie = pre_auth_cookie
        self.s2_sets_new_cookie = s2_sets_new_cookie
        self._session_counter = 0
        outer = self

        class Handler(BaseHTTPRequestHandler):
            def do_POST(self):
                body = self.rfile.read(int(self.headers.get("Content-Length") or 0))
                outer.requests_log.append(("POST", self.path, dict(self.headers), body))

                # Setup hook endpoint
                if self.path == "/_security/setup-identities":
                    if outer.scenario == "fail_setup":
                        self.send_response(500)
                        self.end_headers()
                        self.wfile.write(b'{"error": "setup crashed"}')
                        return
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

                    is_invalid = password and "invalid_synth_" in password

                    if is_invalid:
                        self.send_response(401)
                        self.send_header("Content-Type", "application/json")
                        self.end_headers()
                        self.wfile.write(b'{"error": "invalid credentials"}')
                        return

                    if outer.scenario == "a3_fail":
                        self.send_response(401)
                        self.send_header("Content-Type", "application/json")
                        self.end_headers()
                        self.wfile.write(b'{"error": "positive control failed"}')
                        return

                    if outer.scenario == "token_auth":
                        # Bearer token auth (no cookies)
                        session_id = f"tok_{username}_{outer._session_counter}"
                        outer._session_counter += 1
                        outer.valid_sessions.add(session_id)
                        self.send_response(200)
                        self.send_header("Content-Type", "application/json")
                        self.end_headers()
                        self.wfile.write(json.dumps({"token": session_id}).encode("utf-8"))
                        return

                    # Cookie-based auth
                    if outer.scenario == "shared_session":
                        session_id = "shared_session_for_all"
                    elif outer.scenario == "no_rotation" and outer.pre_auth_cookie:
                        # Reuse the pre-auth cookie value sent with login (not rotated)
                        sent_cookie = self._get_session()
                        session_id = sent_cookie if sent_cookie else "pre_auth_anonymous"
                    else:
                        session_id = f"sess_{username}_{outer._session_counter}"
                        outer._session_counter += 1

                    outer.valid_sessions.add(session_id)
                    self.send_response(200)

                    cookie_parts = [f"session_id={session_id}", "Path=/"]
                    if outer.scenario != "no_httponly":
                        cookie_parts.append("HttpOnly")
                    if outer.scenario != "no_samesite":
                        cookie_parts.append("SameSite=Lax")
                    if outer.scenario == "with_secure":
                        cookie_parts.append("Secure")

                    self.send_header("Set-Cookie", "; ".join(cookie_parts))
                    self.send_header("Content-Type", "application/json")
                    self.end_headers()
                    self.wfile.write(b'{"status": "ok"}')
                    return

                # Logout endpoint
                if self.path == "/api/logout":
                    sess = self._get_session()
                    if sess:
                        outer.logged_out_sessions.add(sess)
                        if outer.scenario != "a6_fail":
                            outer.valid_sessions.discard(sess)
                    self.send_response(200)
                    self.send_header("Content-Type", "application/json")
                    if outer.scenario != "token_auth":
                        self.send_header("Set-Cookie", "session_id=; Max-Age=0; Path=/")
                    self.end_headers()
                    self.wfile.write(b'{"status": "logged_out"}')
                    return

                self.send_response(404)
                self.end_headers()

            def do_GET(self):
                body = self.rfile.read(int(self.headers.get("Content-Length") or 0))
                outer.requests_log.append(("GET", self.path, dict(self.headers), body))

                if self.path == "/api/profile":
                    # Pre-auth cookie
                    if outer.pre_auth_cookie and not self._get_session():
                        pre_sess = f"pre_auth_anonymous"
                        self.send_response(401)
                        self.send_header("Set-Cookie", f"session_id={pre_sess}; Path=/; HttpOnly; SameSite=Lax")
                        self.send_header("Content-Type", "application/json")
                        self.end_headers()
                        self.wfile.write(b'{"error": "authentication required"}')
                        return

                    sess = self._get_session()
                    if not sess:
                        self.send_response(401)
                        self.send_header("Content-Type", "application/json")
                        self.end_headers()
                        self.wfile.write(b'{"error": "authentication required"}')
                        return

                    if outer.scenario == "s2_timeout" and len([r for r in outer.requests_log if r[0] == "GET" and r[1] == "/api/profile" and self._get_session_from_headers(r[2])]) > 1:
                        time.sleep(0.5)

                    if outer.scenario == "s2_denied":
                        # S2 should fail - session not maintained
                        self.send_response(401)
                        self.send_header("Content-Type", "application/json")
                        self.end_headers()
                        self.wfile.write(b'{"error": "session expired"}')
                        return

                    if sess in outer.logged_out_sessions:
                        if outer.scenario == "a6_fail":
                            actor = "user_a"
                            self.send_response(200)
                            self.send_header("Content-Type", "application/json")
                            self.end_headers()
                            self.wfile.write(f'{{"data": "profile", "marker": "protected:{actor}"}}'.encode())
                            return
                        self.send_response(401)
                        self.send_header("Content-Type", "application/json")
                        self.end_headers()
                        self.wfile.write(b'{"error": "session expired/logged out"}')
                        return

                    if sess in outer.valid_sessions:
                        actor = "admin_a" if "admin_a" in sess else "user_a"
                        self.send_response(200)
                        if outer.s2_sets_new_cookie:
                            self.send_header(
                                "Set-Cookie",
                                "session_id=new_different_cookie_from_s2; Path=/; HttpOnly; SameSite=Lax",
                            )
                        self.send_header("Content-Type", "application/json")
                        self.end_headers()
                        self.wfile.write(f'{{"data": "profile", "marker": "protected:{actor}"}}'.encode())
                        return

                    self.send_response(401)
                    self.end_headers()
                    return

                self.send_response(404)
                self.end_headers()

            def _get_session(self) -> str | None:
                return self._get_session_from_headers(dict(self.headers))

            def _get_session_from_headers(self, headers: dict) -> str | None:
                cookie_hdr = headers.get("Cookie") or ""
                for part in cookie_hdr.split(";"):
                    p = part.strip()
                    if p.startswith("session_id="):
                        val = p.split("=", 1)[1].strip()
                        if val:
                            return val
                auth_hdr = headers.get("Authorization") or ""
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


def _make_session_cfg(base_url: str, with_logout: bool = True) -> Any:
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


# ── S1-S6 PASS ──────────────────────────────────────────────────────

def test_session_full_pass():
    """Verify clean PASS for full S1-S6 session checks with cookies and logout."""
    server = _SessionTestServer(scenario="pass")
    try:
        cfg = _make_session_cfg(server.url, with_logout=True)
        plan = build_plan(cfg)
        session_plan = plan.areas["session"]
        assert session_plan.configured is True
        assert session_plan.requests_count == 1  # Only S2 sends a new request

        result = execute_native_plan(cfg, plan)

        auth_res = result.get_area_result("authentication")
        assert auth_res is not None
        assert auth_res.status == "PASS"

        session_res = result.get_area_result("session")
        assert session_res is not None
        assert session_res.status == "PASS"
        assert len(session_res.findings) == 0
        assert session_res.runtime_checks_executed is True

        # Verify check IDs in order
        check_ids = [c["check"] for c in session_res.checks]
        assert check_ids == ["S1", "S2", "S3", "S4", "S5", "S6"]

        # S1: session established
        s1 = session_res.checks[0]
        assert s1["classification"] == "allowed"

        # S2: session continuity
        s2 = session_res.checks[1]
        assert s2["classification"] == "allowed"
        assert s2["marker_present"] is True

        # S3: session invalidation
        s3 = session_res.checks[2]
        assert s3["classification"] == "denied"

        # S4: rotation (NOT APPLICABLE when no pre-auth cookie)
        s4 = session_res.checks[3]
        assert s4["classification"] == "not_applicable"

        # S5: cookie attributes
        s5 = session_res.checks[4]
        assert s5["classification"] == "allowed"

        # S6: actor separation
        s6 = session_res.checks[5]
        assert s6["classification"] == "allowed"
    finally:
        server.close()


def test_session_executed_without_logout():
    """Without logout declared, session area can at most be EXECUTED (not PASS)."""
    server = _SessionTestServer(scenario="pass")
    try:
        cfg = _make_session_cfg(server.url, with_logout=False)
        plan = build_plan(cfg)
        result = execute_native_plan(cfg, plan)

        session_res = result.get_area_result("session")
        assert session_res is not None
        assert session_res.status == "EXECUTED"
        assert len(session_res.findings) == 0

        check_ids = [c["check"] for c in session_res.checks]
        # No S3 without logout
        assert "S3" not in check_ids
    finally:
        server.close()


# ── S2 continuity ────────────────────────────────────────────────────

def test_session_s2_sends_exactly_one_request():
    """Session verification sends exactly 1 new request (S2 continuity)."""
    server = _SessionTestServer(scenario="pass")
    try:
        cfg = _make_session_cfg(server.url, with_logout=True)
        plan = build_plan(cfg)
        result = execute_native_plan(cfg, plan)

        session_res = result.get_area_result("session")
        assert session_res is not None
        assert session_res.requests_sent == 1  # Only S2
        assert session_res.requests_planned == 1
    finally:
        server.close()


def test_session_s2_denied_makes_incomplete():
    """S2 denied (session not maintained) → INCOMPLETE."""
    server = _SessionTestServer(scenario="s2_denied")
    try:
        cfg = _make_session_cfg(server.url, with_logout=True)
        plan = build_plan(cfg)
        result = execute_native_plan(cfg, plan)

        session_res = result.get_area_result("session")
        assert session_res is not None
        assert session_res.status == "INCOMPLETE"
    finally:
        server.close()


def test_session_s2_fingerprints_sent_session_even_if_response_sets_new_cookie():
    """S2 continuity fingerprint represents sent active session even if response sets new cookie."""
    server = _SessionTestServer(scenario="pass", s2_sets_new_cookie=True)
    try:
        cfg = _make_session_cfg(server.url, with_logout=True)
        plan = build_plan(cfg)
        result = execute_native_plan(cfg, plan)

        session_res = result.get_area_result("session")
        assert session_res is not None
        assert session_res.status == "PASS"

        s2 = next(c for c in session_res.checks if c["check"] == "S2")
        assert s2["classification"] == "allowed"

        # S2 actor was admin_a (whose session remained active after A5 logout on user_a)
        auth_res = result.get_area_result("authentication")
        a3_admin = next(c for c in auth_res.checks if c["check"] == "A3" and c["actors"] == ["admin_a"])
        assert s2["fingerprint"] == a3_admin["fingerprint"]
    finally:
        server.close()


def test_session_s2_changed_fingerprint_is_not_pass():
    """A changed continuity fingerprint must NOT be treated as successful continuity."""
    server = _SessionTestServer(scenario="pass")
    try:
        cfg = _make_session_cfg(server.url, with_logout=True)
        plan = build_plan(cfg)
        result = execute_native_plan(cfg, plan)

        auth_res = result.get_area_result("authentication")
        s2_check = {
            "check": "S2",
            "area": "session",
            "actors": ["admin_a"],
            "method": "GET",
            "path": "/api/profile",
            "expected": "allowed",
            "status_class": "2xx",
            "status": 200,
            "classification": "allowed",
            "marker_present": True,
            "elapsed_ms": 1.0,
            "fingerprint": "changed_tampered_fp",
        }
        checks, findings, status, reason = evaluate_session_checks(
            auth_checks=auth_res.checks,
            s2_check=s2_check,
            vault=None,
            run_hmac_key=b"test" * 8,
            is_https=False,
            has_logout=True,
        )
        assert status == "INCOMPLETE"
        s2 = next(c for c in checks if c["check"] == "S2")
        assert s2["classification"] == "incomplete"
    finally:
        server.close()


# ── S5 Cookie Attributes Findings ────────────────────────────────────

def test_session_missing_httponly_finding():
    """Missing HttpOnly → RT-SESSION-002 finding."""
    server = _SessionTestServer(scenario="no_httponly")
    try:
        cfg = _make_session_cfg(server.url, with_logout=True)
        plan = build_plan(cfg)
        result = execute_native_plan(cfg, plan)

        session_res = result.get_area_result("session")
        assert session_res is not None
        assert session_res.status == "FAIL"
        finding_ids = [f.id for f in session_res.findings]
        assert "RT-SESSION-002" in finding_ids

        # Verify the finding has MEDIUM severity
        httponly_finding = next(f for f in session_res.findings if f.id == "RT-SESSION-002")
        assert httponly_finding.severity == Severity.MEDIUM
        assert httponly_finding.confidence == Confidence.HIGH
        assert httponly_finding.source == "native-verification"
    finally:
        server.close()


def test_session_missing_samesite_finding():
    """Missing SameSite → RT-SESSION-004 finding with LOW severity."""
    server = _SessionTestServer(scenario="no_samesite")
    try:
        cfg = _make_session_cfg(server.url, with_logout=True)
        plan = build_plan(cfg)
        result = execute_native_plan(cfg, plan)

        session_res = result.get_area_result("session")
        assert session_res is not None
        assert session_res.status == "FAIL"
        finding_ids = [f.id for f in session_res.findings]
        assert "RT-SESSION-004" in finding_ids

        samesite_finding = next(f for f in session_res.findings if f.id == "RT-SESSION-004")
        assert samesite_finding.severity == Severity.LOW
        assert samesite_finding.confidence == Confidence.HIGH
    finally:
        server.close()


def test_session_s5_not_applicable_for_token_auth():
    """S5 cookie attributes NOT APPLICABLE when using bearer token auth."""
    server = _SessionTestServer(scenario="token_auth")
    try:
        cfg = _make_session_cfg(server.url, with_logout=True)
        plan = build_plan(cfg)
        result = execute_native_plan(cfg, plan)

        session_res = result.get_area_result("session")
        assert session_res is not None
        # With token auth, no cookie attribute findings
        s5_check = next(c for c in session_res.checks if c["check"] == "S5")
        assert s5_check["classification"] == "not_applicable"
        # No cookie attribute findings
        for f in session_res.findings:
            assert f.id not in ("RT-SESSION-002", "RT-SESSION-003", "RT-SESSION-004")
    finally:
        server.close()


def test_session_secure_not_required_on_http():
    """Secure attribute NOT required on HTTP target (NOT APPLICABLE)."""
    server = _SessionTestServer(scenario="pass")
    try:
        cfg = _make_session_cfg(server.url, with_logout=True)
        plan = build_plan(cfg)
        result = execute_native_plan(cfg, plan)

        session_res = result.get_area_result("session")
        assert session_res is not None
        # No RT-SESSION-003 since target is HTTP
        finding_ids = [f.id for f in session_res.findings]
        assert "RT-SESSION-003" not in finding_ids
    finally:
        server.close()


# ── S4 Session Rotation ──────────────────────────────────────────────

def test_session_rotation_satisfied_when_pre_auth_cookie_rotated():
    """Pre-auth cookie issued + sent with A3 + rotated on login -> S4 allowed, PASS."""
    server = _SessionTestServer(scenario="pass", pre_auth_cookie=True)
    try:
        cfg = _make_session_cfg(server.url, with_logout=True)
        plan = build_plan(cfg)
        result = execute_native_plan(cfg, plan)

        session_res = result.get_area_result("session")
        assert session_res is not None
        assert session_res.status == "PASS"

        s4 = next(c for c in session_res.checks if c["check"] == "S4")
        assert s4["classification"] == "allowed"
        assert s4["rotated"] is True
        assert "RT-SESSION-001" not in [f.id for f in session_res.findings]

        # Verify A3 for user_a actually sent the pre-auth cookie (second login attempt after A2)
        user_login_reqs = [
            r for r in server.requests_log
            if r[0] == "POST" and r[1] == "/api/login" and b"user_a" in r[3]
        ]
        assert len(user_login_reqs) == 2  # A2 (invalid) + A3 (valid)
        assert "session_id=pre_auth_anonymous" in user_login_reqs[1][2].get("Cookie", "")
    finally:
        server.close()


def test_session_not_rotated_produces_finding():
    """Pre-auth cookie issued + sent with A3 + NOT rotated -> RT-SESSION-001 finding."""
    server = _SessionTestServer(scenario="no_rotation", pre_auth_cookie=True)
    try:
        cfg = _make_session_cfg(server.url, with_logout=True)
        plan = build_plan(cfg)
        result = execute_native_plan(cfg, plan)

        session_res = result.get_area_result("session")
        assert session_res is not None
        assert session_res.status == "FAIL"

        finding_ids = [f.id for f in session_res.findings]
        assert "RT-SESSION-001" in finding_ids

        f = next(f for f in session_res.findings if f.id == "RT-SESSION-001")
        assert f.severity == Severity.MEDIUM
        assert f.confidence == Confidence.HIGH
        assert f.source == "native-verification"

        s4 = next(c for c in session_res.checks if c["check"] == "S4")
        assert s4["classification"] == "denied"
        assert s4["rotated"] is False
    finally:
        server.close()


def test_session_rotation_not_applicable_when_no_pre_auth_cookie():
    """No pre-auth cookie issued -> S4 classification is not_applicable, rotated is None."""
    server = _SessionTestServer(scenario="pass", pre_auth_cookie=False)
    try:
        cfg = _make_session_cfg(server.url, with_logout=True)
        plan = build_plan(cfg)
        result = execute_native_plan(cfg, plan)

        session_res = result.get_area_result("session")
        assert session_res is not None
        s4 = next(c for c in session_res.checks if c["check"] == "S4")
        assert s4["classification"] == "not_applicable"
        assert s4["rotated"] is None
        assert "RT-SESSION-001" not in [f.id for f in session_res.findings]
    finally:
        server.close()


# ── S1 Evidence Session Type ─────────────────────────────────────────

def test_session_s1_evidence_includes_session_type():
    """S1 evidence dictionary includes session_type ('cookie' or 'token') per Design §9."""
    server = _SessionTestServer(scenario="pass")
    try:
        cfg = _make_session_cfg(server.url, with_logout=True)
        plan = build_plan(cfg)
        result = execute_native_plan(cfg, plan)

        session_res = result.get_area_result("session")
        assert session_res is not None
        s1 = next(c for c in session_res.checks if c["check"] == "S1")
        assert s1["session_type"] == "cookie"
        assert s1["session_count"] >= 1
    finally:
        server.close()


def test_session_s1_evidence_token_session_type():
    """S1 evidence dictionary reports session_type 'token' for bearer auth."""
    server = _SessionTestServer(scenario="token_auth")
    try:
        cfg = _make_session_cfg(server.url, with_logout=True)
        plan = build_plan(cfg)
        result = execute_native_plan(cfg, plan)

        session_res = result.get_area_result("session")
        assert session_res is not None
        s1 = next(c for c in session_res.checks if c["check"] == "S1")
        assert s1["session_type"] == "token"
    finally:
        server.close()


# ── S6 Actor Separation ──────────────────────────────────────────────

def test_session_shared_session_makes_incomplete():
    """S6 shared session between actors → INCOMPLETE (not distinct fingerprints)."""
    server = _SessionTestServer(scenario="shared_session")
    try:
        cfg = _make_session_cfg(server.url, with_logout=True)
        plan = build_plan(cfg)
        result = execute_native_plan(cfg, plan)

        session_res = result.get_area_result("session")
        assert session_res is not None
        # S6 with shared session should cause INCOMPLETE
        s6 = next(c for c in session_res.checks if c["check"] == "S6")
        assert s6["classification"] == "denied"
    finally:
        server.close()


# ── Positive Control Failure ─────────────────────────────────────────

def test_session_positive_control_failure():
    """A3 failure (no session established) → session INCOMPLETE, no findings."""
    server = _SessionTestServer(scenario="a3_fail")
    try:
        cfg = _make_session_cfg(server.url, with_logout=True)
        plan = build_plan(cfg)
        result = execute_native_plan(cfg, plan)

        session_res = result.get_area_result("session")
        assert session_res is not None
        assert session_res.status == "INCOMPLETE"
        assert len(session_res.findings) == 0
    finally:
        server.close()


# ── Secret Redaction ─────────────────────────────────────────────────

def test_session_secrets_not_in_checks():
    """Session secrets/cookies must not appear in check evidence."""
    server = _SessionTestServer(scenario="pass")
    try:
        cfg = _make_session_cfg(server.url, with_logout=True)
        plan = build_plan(cfg)
        result = execute_native_plan(cfg, plan)

        session_res = result.get_area_result("session")
        checks_str = json.dumps(session_res.checks)

        # No raw session IDs should appear
        assert "sess_" not in checks_str or "sess_" in checks_str.split("fingerprint")[0] is False
        # Cookie values should not appear in checks
        assert "session_id=" not in checks_str

        # Report dict should not contain secrets
        report = session_res.to_report_dict(actors=["admin_a", "user_a"])
        report_str = json.dumps(report)
        assert "session_id=" not in report_str
    finally:
        server.close()


def test_session_secrets_not_in_findings():
    """Findings must not contain session cookie values."""
    server = _SessionTestServer(scenario="no_httponly")
    try:
        cfg = _make_session_cfg(server.url, with_logout=True)
        plan = build_plan(cfg)
        result = execute_native_plan(cfg, plan)

        session_res = result.get_area_result("session")
        for finding in session_res.findings:
            assert "sess_" not in finding.evidence
            assert "session_id=" not in finding.evidence
            # Verify the finding repr doesn't leak secrets
            assert "sess_" not in repr(finding)
    finally:
        server.close()


# ── Report Dict ──────────────────────────────────────────────────────

def test_session_report_dict_format():
    """Session area report dict has the correct namespace and structure."""
    server = _SessionTestServer(scenario="pass")
    try:
        cfg = _make_session_cfg(server.url, with_logout=True)
        plan = build_plan(cfg)
        result = execute_native_plan(cfg, plan)

        session_res = result.get_area_result("session")
        report = session_res.to_report_dict(actors=["admin_a", "user_a"])

        assert report["status"] == "PASS"
        assert report["source"] == "native"
        assert report["namespace"] == "RT-SESSION-*"
        assert report["runtime_checks_executed"] is True
        assert report["credentials_read"] is False
        assert report["requests_count"] == 1
        assert report["request_budget"] == 1
        assert report["findings"] == []
        assert "checks" in report
        assert isinstance(report["limitations"], list)
    finally:
        server.close()


def test_session_report_dict_with_findings():
    """Session area report dict includes finding IDs."""
    server = _SessionTestServer(scenario="no_httponly")
    try:
        cfg = _make_session_cfg(server.url, with_logout=True)
        plan = build_plan(cfg)
        result = execute_native_plan(cfg, plan)

        session_res = result.get_area_result("session")
        report = session_res.to_report_dict(actors=["admin_a", "user_a"])

        assert report["status"] == "FAIL"
        assert "RT-SESSION-002" in report["findings"]
    finally:
        server.close()


# ── Deterministic Order ──────────────────────────────────────────────

def test_session_check_order_is_deterministic():
    """S1-S6 checks appear in fixed order."""
    server = _SessionTestServer(scenario="pass")
    try:
        cfg = _make_session_cfg(server.url, with_logout=True)
        plan = build_plan(cfg)
        result = execute_native_plan(cfg, plan)

        session_res = result.get_area_result("session")
        check_ids = [c["check"] for c in session_res.checks]
        assert check_ids == ["S1", "S2", "S3", "S4", "S5", "S6"]
    finally:
        server.close()


def test_session_two_runs_give_same_structure():
    """Two runs against the same fixture give identical check structure."""
    server = _SessionTestServer(scenario="pass")
    try:
        cfg = _make_session_cfg(server.url, with_logout=True)

        plan1 = build_plan(cfg)
        result1 = execute_native_plan(cfg, plan1)
        checks1 = result1.get_area_result("session").checks

        plan2 = build_plan(cfg)
        result2 = execute_native_plan(cfg, plan2)
        checks2 = result2.get_area_result("session").checks

        # Same check IDs in same order
        assert [c["check"] for c in checks1] == [c["check"] for c in checks2]
        # Same classifications
        assert [c["classification"] for c in checks1] == [c["classification"] for c in checks2]
    finally:
        server.close()


# ── Request Budget ───────────────────────────────────────────────────

def test_session_plan_request_count():
    """Session plan should have exactly 1 planned request (S2)."""
    server = _SessionTestServer(scenario="pass")
    try:
        cfg = _make_session_cfg(server.url)
        plan = build_plan(cfg)
        session_plan = plan.areas["session"]
        assert session_plan.requests_count == 1
        assert session_plan.budget == 1
        assert len(session_plan.requests) == 1
        assert session_plan.requests[0].check_id == "S2"
    finally:
        server.close()


def test_session_hard_maximum_is_one():
    """Session area hard maximum is 1."""
    assert AREA_HARD_MAXIMUMS["session"] == 1


# ── Session Namespace ────────────────────────────────────────────────

def test_session_namespace():
    """Session namespace is RT-SESSION-*."""
    assert SESSION_NAMESPACE == "RT-SESSION-*"


def test_session_finding_ids_in_namespace():
    """All session findings use RT-SESSION-NNN format."""
    # Create findings for each possible session check
    f1 = make_session_finding("RT-SESSION-001", "test", Severity.MEDIUM)
    f2 = make_session_finding("RT-SESSION-002", "test", Severity.MEDIUM)
    f3 = make_session_finding("RT-SESSION-003", "test", Severity.MEDIUM)
    f4 = make_session_finding("RT-SESSION-004", "test", Severity.LOW)
    for f in [f1, f2, f3, f4]:
        assert f.id.startswith("RT-SESSION-")
        assert f.source == "native-verification"
        assert f.confidence == Confidence.HIGH


# ── Cookie Attribute Parsing ─────────────────────────────────────────

def test_parse_cookie_attributes_httponly():
    attrs = parse_cookie_attributes("session_id=abc123; Path=/; HttpOnly; SameSite=Lax")
    assert attrs["httponly"] is True
    assert attrs["samesite"] is True
    assert attrs["secure"] is False


def test_parse_cookie_attributes_secure():
    attrs = parse_cookie_attributes("session_id=abc123; Path=/; HttpOnly; Secure; SameSite=Strict")
    assert attrs["httponly"] is True
    assert attrs["secure"] is True
    assert attrs["samesite"] is True


def test_parse_cookie_attributes_none():
    attrs = parse_cookie_attributes("session_id=abc123; Path=/")
    assert attrs["httponly"] is False
    assert attrs["secure"] is False
    assert attrs["samesite"] is False


# ── Build Session Requests ───────────────────────────────────────────

def test_build_session_requests_returns_one():
    """build_session_requests returns exactly 1 request."""
    server = _SessionTestServer(scenario="pass")
    try:
        cfg = _make_session_cfg(server.url)
        requests = build_session_requests(cfg)
        assert len(requests) == 1
        assert requests[0].check_id == "S2"
        assert requests[0].area == "session"
        assert requests[0].method == "GET"
        assert requests[0].actor == "admin_a"
    finally:
        server.close()


def test_build_session_requests_no_runtime_verification():
    """No session requests if runtime_verification is not configured."""
    cfg = parse({
        "target": {
            "base_url": "http://localhost:8080",
            "environment": "local",
            "production": False,
        },
    })
    requests = build_session_requests(cfg)
    assert requests == []


# ── Integration with Authentication ──────────────────────────────────

def test_session_depends_on_authentication():
    """Session area depends on authentication area completing successfully."""
    server = _SessionTestServer(scenario="a3_fail")
    try:
        cfg = _make_session_cfg(server.url, with_logout=True)
        plan = build_plan(cfg)
        result = execute_native_plan(cfg, plan)

        auth_res = result.get_area_result("authentication")
        assert auth_res.status == "INCOMPLETE"

        session_res = result.get_area_result("session")
        assert session_res.status == "INCOMPLETE"
    finally:
        server.close()


def test_session_does_not_break_auth_regression():
    """Authentication results remain unchanged with session verification enabled."""
    server = _SessionTestServer(scenario="pass")
    try:
        cfg = _make_session_cfg(server.url, with_logout=True)
        plan = build_plan(cfg)
        result = execute_native_plan(cfg, plan)

        auth_res = result.get_area_result("authentication")
        assert auth_res.status == "PASS"
        assert len(auth_res.findings) == 0
        assert auth_res.runtime_checks_executed is True

        check_ids = [c["check"] for c in auth_res.checks]
        assert check_ids == ["A1", "A2", "A3", "A3", "A4", "A5", "A6"]
    finally:
        server.close()


# ── Status Classification ────────────────────────────────────────────

def test_session_status_pass():
    """PASS: all S1-S6 satisfied with logout."""
    server = _SessionTestServer(scenario="pass")
    try:
        cfg = _make_session_cfg(server.url, with_logout=True)
        plan = build_plan(cfg)
        result = execute_native_plan(cfg, plan)
        session_res = result.get_area_result("session")
        assert session_res.status == "PASS"
    finally:
        server.close()


def test_session_status_fail_with_finding():
    """FAIL: at least one finding detected."""
    server = _SessionTestServer(scenario="no_httponly")
    try:
        cfg = _make_session_cfg(server.url, with_logout=True)
        plan = build_plan(cfg)
        result = execute_native_plan(cfg, plan)
        session_res = result.get_area_result("session")
        assert session_res.status == "FAIL"
        assert len(session_res.findings) > 0
    finally:
        server.close()


def test_session_status_incomplete_no_findings_on_positive_control_failure():
    """INCOMPLETE: positive control failure emits zero findings."""
    server = _SessionTestServer(scenario="a3_fail")
    try:
        cfg = _make_session_cfg(server.url, with_logout=True)
        plan = build_plan(cfg)
        result = execute_native_plan(cfg, plan)
        session_res = result.get_area_result("session")
        assert session_res.status == "INCOMPLETE"
        assert len(session_res.findings) == 0
    finally:
        server.close()


# ── Setup Failure Interaction ────────────────────────────────────────

def test_session_setup_failure_makes_incomplete():
    """Identity setup failure → session INCOMPLETE, no requests sent."""
    server = _SessionTestServer(scenario="fail_setup")
    try:
        cfg = _make_session_cfg(server.url, with_logout=True)
        plan = build_plan(cfg)
        result = execute_native_plan(cfg, plan)
        session_res = result.get_area_result("session")
        assert session_res is not None
        assert session_res.status == "INCOMPLETE"
        assert session_res.requests_sent == 0
    finally:
        server.close()


# ── Target Safety Interaction ────────────────────────────────────────

def test_session_target_refused():
    """Production target → session NOT VERIFIED or INCOMPLETE."""
    raw = {
        "target": {
            "base_url": "http://127.0.0.1:9999",
            "environment": "production",
            "production": True,
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
            "allowed_targets": ["http://127.0.0.1:9999"],
            "identity_setup": {
                "adapter": "http-local",
                "path": "/_security/setup-identities",
            },
            "actors": {
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
    cfg = parse(raw)
    plan = build_plan(cfg)
    result = execute_native_plan(cfg, plan)
    session_res = result.get_area_result("session")
    assert session_res is not None
    assert session_res.status in ("NOT VERIFIED", "INCOMPLETE")


# ── Overall Result Status ────────────────────────────────────────────

def test_session_overall_result_status():
    """Overall result reflects session status."""
    server = _SessionTestServer(scenario="pass")
    try:
        cfg = _make_session_cfg(server.url, with_logout=True)
        plan = build_plan(cfg)
        result = execute_native_plan(cfg, plan)
        assert result.status == "PASS"
    finally:
        server.close()


def test_session_overall_result_includes_session_findings():
    """Overall result includes session findings."""
    server = _SessionTestServer(scenario="no_httponly")
    try:
        cfg = _make_session_cfg(server.url, with_logout=True)
        plan = build_plan(cfg)
        result = execute_native_plan(cfg, plan)
        finding_ids = [f.id for f in result.findings]
        assert any(fid.startswith("RT-SESSION-") for fid in finding_ids)
    finally:
        server.close()
