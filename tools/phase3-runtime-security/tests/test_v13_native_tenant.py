"""Tests for native tenant isolation verification T1–T4 (Design §12, §15, §16, §17).

Verifies:
- T1: tenant-a actor own-tenant positive control (expected allowed)
- T2: tenant-a actor cross-tenant access to tenant-b resource (expected denied)
- T3: tenant-b actor own-tenant positive control (expected allowed)
- T4: tenant-b actor cross-tenant access to tenant-a resource (expected denied)
- PASS when T1/T3 are allowed and T2/T4 are denied
- FAIL with RT-TENANT-001 (HIGH/HIGH) when cross-tenant access is allowed
- Positive-control gating: T1 or T3 failure prevents false-positive tenant findings
- Ambiguous responses (e.g. 200 without marker, another tenant's marker) resolve to INCOMPLETE
- Authentication prerequisite: missing A3 authentication blocks tenant verification
- Strict actor and session separation (actor_a session for T1/T2, actor_b session for T3/T4)
- Support for cookie-based and bearer token-based session handling
- Timeout handling and request budget enforcement (hard maximum 4 requests)
- Secret redaction and safe evidence (no credentials, tokens, or response bodies)
- Exact semantics from runtime_verification.tenant_resources configuration structure
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
from runtime_security.native.tenant import (
    TENANT_NAMESPACE,
    build_tenant_requests,
    evaluate_tenant_checks,
    make_tenant_finding,
)


class _TenantTestServer:
    """Deterministic local HTTP test server for tenant isolation verification.

    Manages two tenants (tenant-a and tenant-b), each with a declared resource.
    Resources are path-based and protected by session authentication.

    Scenario strings control cross-tenant access behavior:
    - "pass"              : both T2 and T4 properly denied
    - "t2_allowed"        : tenant-a actor gets tenant-b resource (T2 violation)
    - "t4_allowed"        : tenant-b actor gets tenant-a resource (T4 violation)
    - "t1_denied"         : T1 positive control returns 403 (not 200 with marker)
    - "t1_no_marker"      : T1 returns 200 but without the marker (ambiguous)
    - "t3_denied"         : T3 positive control returns 403
    - "t3_no_marker"      : T3 returns 200 but without the marker (ambiguous)
    - "t3_denied_with_t2_vuln" : T2 allowed (violation observed) but T3 denied (suppress finding)
    - "t2_ambiguous"      : T2 returns 200 without marker
    - "t4_ambiguous"      : T4 returns 200 without marker
    - "other_marker_returned"  : T2 returns another tenant's marker (ambiguous)
    - "a3_fail"           : A3 login returns 401 (authentication prerequisite fails)
    - "timeout_t1"        : T1 request is slow (forces timeout on short timeout)
    - "timeout_t2"        : T2 request is slow
    - "timeout_t3"        : T3 request is slow
    - "timeout_t4"        : T4 request is slow
    - "case_a_timeout_t4" : T2 allowed (violation), T3 ok, T4 times out (finding must persist)
    - "case_a_500_t4"     : T2 allowed (violation), T3 ok, T4 returns 500 (finding must persist)
    """

    def __init__(
        self,
        expected_run_id: str = "run-tenant-test",
        actors: list[str] | None = None,
        auth_mode: str = "cookie",  # "cookie" | "token"
        scenario: str = "pass",
    ):
        self.requests_log: list[tuple[str, str, dict[str, str], bytes]] = []
        self.expected_run_id = expected_run_id
        self.actors = sorted(actors or ["user_c", "user_d"])
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

                # tenant-a resource (resource-a, owned by tenant-a)
                if self.path == "/tenants/tenant-a/resource-a":
                    if outer.scenario == "timeout_t1" and actor == "user_c":
                        time.sleep(0.3)
                    elif outer.scenario in ("timeout_t4", "case_a_timeout_t4") and actor == "user_d":
                        time.sleep(0.3)

                    if not actor:
                        self.send_response(401)
                        self.send_header("Content-Type", "application/json")
                        self.end_headers()
                        self.wfile.write(b'{"error": "authentication required"}')
                        return

                    # Access by tenant-a actor (user_c, T1 positive control)
                    if actor == "user_c":
                        if outer.scenario == "t1_denied":
                            self.send_response(403)
                            self.send_header("Content-Type", "application/json")
                            self.end_headers()
                            self.wfile.write(b'{"error": "forbidden"}')
                            return
                        elif outer.scenario == "t1_no_marker":
                            self.send_response(200)
                            self.send_header("Content-Type", "application/json")
                            self.end_headers()
                            self.wfile.write(b'{"status": "ok but marker missing"}')
                            return
                        else:
                            # Proper own-tenant access: return marker
                            self.send_response(200)
                            self.send_header("Content-Type", "application/json")
                            self.end_headers()
                            self.wfile.write(
                                b'{"data": "resource-a", "tenant_marker": "tenant:tenant-a"}'
                            )
                            return

                    # Access by tenant-b actor (user_d, T4 cross-tenant check)
                    if actor == "user_d":
                        if outer.scenario == "case_a_500_t4":
                            self.send_response(500)
                            self.send_header("Content-Type", "application/json")
                            self.end_headers()
                            self.wfile.write(b'{"error": "server error"}')
                            return
                        elif outer.scenario == "t4_allowed":
                            # VULNERABILITY: tenant-b actor reads tenant-a resource!
                            self.send_response(200)
                            self.send_header("Content-Type", "application/json")
                            self.end_headers()
                            self.wfile.write(
                                b'{"data": "resource-a", "tenant_marker": "tenant:tenant-a"}'
                            )
                            return
                        elif outer.scenario == "t4_ambiguous":
                            self.send_response(200)
                            self.send_header("Content-Type", "application/json")
                            self.end_headers()
                            self.wfile.write(b'{"status": "generic ok without marker"}')
                            return
                        else:
                            # Proper cross-tenant denial
                            self.send_response(403)
                            self.send_header("Content-Type", "application/json")
                            self.end_headers()
                            self.wfile.write(b'{"error": "forbidden: wrong tenant"}')
                            return

                # tenant-b resource (resource-b, owned by tenant-b)
                if self.path == "/tenants/tenant-b/resource-b":
                    if outer.scenario == "timeout_t2" and actor == "user_c":
                        time.sleep(0.3)
                    elif outer.scenario == "timeout_t3" and actor == "user_d":
                        time.sleep(0.3)

                    if not actor:
                        self.send_response(401)
                        self.send_header("Content-Type", "application/json")
                        self.end_headers()
                        self.wfile.write(b'{"error": "authentication required"}')
                        return

                    # Access by tenant-a actor (user_c, T2 cross-tenant check)
                    if actor == "user_c":
                        if outer.scenario in ("t2_allowed", "t3_denied_with_t2_vuln", "case_a_timeout_t4", "case_a_500_t4"):
                            # VULNERABILITY: tenant-a actor reads tenant-b resource!
                            self.send_response(200)
                            self.send_header("Content-Type", "application/json")
                            self.end_headers()
                            self.wfile.write(
                                b'{"data": "resource-b", "tenant_marker": "tenant:tenant-b"}'
                            )
                            return
                        elif outer.scenario == "t2_ambiguous":
                            self.send_response(200)
                            self.send_header("Content-Type", "application/json")
                            self.end_headers()
                            self.wfile.write(b'{"status": "generic ok without marker"}')
                            return
                        elif outer.scenario == "other_marker_returned":
                            # Returns tenant-a's marker instead of tenant-b's marker
                            self.send_response(200)
                            self.send_header("Content-Type", "application/json")
                            self.end_headers()
                            self.wfile.write(
                                b'{"data": "resource-b", "tenant_marker": "tenant:tenant-a"}'
                            )
                            return
                        else:
                            # Proper cross-tenant denial
                            self.send_response(403)
                            self.send_header("Content-Type", "application/json")
                            self.end_headers()
                            self.wfile.write(b'{"error": "forbidden: wrong tenant"}')
                            return

                    # Access by tenant-b actor (user_d, T3 positive control)
                    if actor == "user_d":
                        if outer.scenario in ("t3_denied", "t3_denied_with_t2_vuln"):
                            self.send_response(403)
                            self.send_header("Content-Type", "application/json")
                            self.end_headers()
                            self.wfile.write(b'{"error": "forbidden"}')
                            return
                        elif outer.scenario == "t3_no_marker":
                            self.send_response(200)
                            self.send_header("Content-Type", "application/json")
                            self.end_headers()
                            self.wfile.write(b'{"status": "ok but marker missing"}')
                            return
                        else:
                            # Proper own-tenant access: return marker
                            self.send_response(200)
                            self.send_header("Content-Type", "application/json")
                            self.end_headers()
                            self.wfile.write(
                                b'{"data": "resource-b", "tenant_marker": "tenant:tenant-b"}'
                            )
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


def _make_tenant_cfg(url: str, mode: str = "fixture"):
    """Reference tenant configuration per design §6 and §12.

    Uses the exact tenant/resource pairs declared in runtime_verification:
    - tenant-a: actor user_c, resource resource-a at /tenants/tenant-a/resource-a, marker tenant:tenant-a
    - tenant-b: actor user_d, resource resource-b at /tenants/tenant-b/resource-b, marker tenant:tenant-b
    """
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
                    "user_c": {"role": "user", "tenant": "tenant-a"},
                    "user_d": {"role": "user", "tenant": "tenant-b"},
                },
                "routes": {
                    "protected": {"path": "/api/profile", "marker": "account:{label}"},
                },
                "resources": [
                    {
                        "id": "resource-a",
                        "path": "/tenants/tenant-a/resource-a",
                        "tenant": "tenant-a",
                        "marker": "tenant:tenant-a",
                    },
                    {
                        "id": "resource-b",
                        "path": "/tenants/tenant-b/resource-b",
                        "tenant": "tenant-b",
                        "marker": "tenant:tenant-b",
                    },
                ],
                "deny_statuses": [401, 403, 404],
            },
        }
    )


# ── 1. Tenant Request Planning Tests ─────────────────────────────────────────


def test_tenant_requests_plan():
    """Plan builds exactly T1-T4 with correct actors, paths, and markers."""
    cfg = _make_tenant_cfg("http://127.0.0.1:8000")
    requests = build_tenant_requests(cfg)
    assert len(requests) == 4

    t1, t2, t3, t4 = requests

    assert t1.check_id == "T1"
    assert t1.area == "tenant_isolation"
    assert t1.method == "GET"
    assert t1.path == "/tenants/tenant-a/resource-a"
    assert t1.actor == "user_c"
    assert t1.expected == "allowed"
    assert t1.marker == "tenant:tenant-a"

    assert t2.check_id == "T2"
    assert t2.area == "tenant_isolation"
    assert t2.method == "GET"
    assert t2.path == "/tenants/tenant-b/resource-b"
    assert t2.actor == "user_c"
    assert t2.expected == "denied"
    assert t2.marker == "tenant:tenant-b"

    assert t3.check_id == "T3"
    assert t3.area == "tenant_isolation"
    assert t3.method == "GET"
    assert t3.path == "/tenants/tenant-b/resource-b"
    assert t3.actor == "user_d"
    assert t3.expected == "allowed"
    assert t3.marker == "tenant:tenant-b"

    assert t4.check_id == "T4"
    assert t4.area == "tenant_isolation"
    assert t4.method == "GET"
    assert t4.path == "/tenants/tenant-a/resource-a"
    assert t4.actor == "user_d"
    assert t4.expected == "denied"
    assert t4.marker == "tenant:tenant-a"

    plan = build_plan(cfg)
    tenant_plan = plan.areas["tenant_isolation"]
    assert tenant_plan.configured is True
    assert tenant_plan.requests_count == 4
    assert tenant_plan.budget == 4
    assert AREA_HARD_MAXIMUMS["tenant_isolation"] == 4


# ── 2. NOT CONFIGURED: Missing Prerequisites ─────────────────────────────────


def test_tenant_not_configured_when_single_tenant():
    """Single-tenant config -> tenant_isolation NOT CONFIGURED."""
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
                    "user_c": {"role": "user", "tenant": "tenant-a"},
                },
                "resources": [
                    {
                        "id": "resource-a",
                        "path": "/tenants/tenant-a/resource-a",
                        "tenant": "tenant-a",
                        "marker": "tenant:tenant-a",
                    }
                ],
            },
        }
    )
    requests = build_tenant_requests(cfg)
    assert len(requests) == 0

    plan = build_plan(cfg)
    assert plan.areas["tenant_isolation"].configured is False
    assert plan.areas["tenant_isolation"].requests_count == 0


def test_tenant_not_configured_when_no_tenant_resources():
    """Two tenant actors but no tenant resources -> NOT CONFIGURED."""
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
                    "user_c": {"role": "user", "tenant": "tenant-a"},
                    "user_d": {"role": "user", "tenant": "tenant-b"},
                },
                "resources": [
                    {
                        "id": "object-a",
                        "path": "/objects/object-a",
                        "owner": "user_c",
                        "marker": "owner:user_c",
                    }
                ],
            },
        }
    )
    requests = build_tenant_requests(cfg)
    assert len(requests) == 0

    plan = build_plan(cfg)
    assert plan.areas["tenant_isolation"].configured is False


# ── 3. T1/T3 Positive-Control Pass ──────────────────────────────────────────


def test_tenant_full_pass_cookie_auth():
    """T1 and T3 positive controls allowed, T2 and T4 denied -> PASS."""
    srv = _TenantTestServer(scenario="pass", auth_mode="cookie")
    try:
        cfg = _make_tenant_cfg(srv.url)
        plan = build_plan(cfg)
        result = execute_native_plan(cfg, plan)

        tenant_res = result.area_results["tenant_isolation"]
        assert tenant_res.status == "PASS"
        assert tenant_res.runtime_checks_executed is True
        assert tenant_res.requests_sent == 4
        assert len(tenant_res.findings) == 0
        assert len(tenant_res.checks) == 4

        c_by_id = {c["check"]: c for c in tenant_res.checks}
        assert c_by_id["T1"]["classification"] == "allowed"
        assert c_by_id["T1"]["actors"] == ["user_c"]
        assert c_by_id["T2"]["classification"] == "denied"
        assert c_by_id["T2"]["actors"] == ["user_c"]
        assert c_by_id["T3"]["classification"] == "allowed"
        assert c_by_id["T3"]["actors"] == ["user_d"]
        assert c_by_id["T4"]["classification"] == "denied"
        assert c_by_id["T4"]["actors"] == ["user_d"]
    finally:
        srv.close()


def test_tenant_full_pass_token_auth():
    """Bearer token authentication works for tenant isolation verification."""
    srv = _TenantTestServer(scenario="pass", auth_mode="token")
    try:
        cfg = _make_tenant_cfg(srv.url)
        plan = build_plan(cfg)
        result = execute_native_plan(cfg, plan)

        tenant_res = result.area_results["tenant_isolation"]
        assert tenant_res.status == "PASS"
        assert tenant_res.requests_sent == 4
        assert len(tenant_res.findings) == 0
    finally:
        srv.close()


# ── 4. Cross-Tenant Denials (T2/T4 Proper -> PASS) ──────────────────────────


def test_tenant_t2_denial_and_t4_denial_pass():
    """When T2 and T4 are both properly denied, result is PASS with no findings."""
    srv = _TenantTestServer(scenario="pass")
    try:
        cfg = _make_tenant_cfg(srv.url)
        plan = build_plan(cfg)
        result = execute_native_plan(cfg, plan)

        tenant_res = result.area_results["tenant_isolation"]
        assert tenant_res.status == "PASS"
        assert len(tenant_res.findings) == 0
    finally:
        srv.close()


# ── 5. Cross-Tenant Allowed Violations (T2 FAIL -> RT-TENANT-001) ────────────


def test_tenant_violation_t2_allowed():
    """When tenant-a actor accesses tenant-b resource (T2 allowed), emit RT-TENANT-001."""
    srv = _TenantTestServer(scenario="t2_allowed")
    try:
        cfg = _make_tenant_cfg(srv.url)
        plan = build_plan(cfg)
        result = execute_native_plan(cfg, plan)

        tenant_res = result.area_results["tenant_isolation"]
        assert tenant_res.status == "FAIL"
        assert tenant_res.runtime_checks_executed is True
        assert tenant_res.requests_sent == 4
        assert len(tenant_res.findings) == 1

        f = tenant_res.findings[0]
        assert f.id == "RT-TENANT-001"
        assert f.category == "tenant_isolation"
        assert f.severity == Severity.HIGH
        assert f.confidence == Confidence.HIGH
        assert f.endpoint == "GET /tenants/tenant-b/resource-b"
        assert f.expected == "denied"
        assert f.actual == "allowed"
        assert f.cwe == "CWE-639"
        assert f.owasp == "A01:2021-Broken Access Control"
        assert f.source == "native-verification"
        assert f.status == Status.OPEN
    finally:
        srv.close()


# ── 6. Cross-Tenant Allowed (T4 FAIL -> RT-TENANT-001) ───────────────────────


def test_tenant_violation_t4_allowed():
    """When tenant-b actor accesses tenant-a resource (T4 allowed), emit RT-TENANT-001."""
    srv = _TenantTestServer(scenario="t4_allowed")
    try:
        cfg = _make_tenant_cfg(srv.url)
        plan = build_plan(cfg)
        result = execute_native_plan(cfg, plan)

        tenant_res = result.area_results["tenant_isolation"]
        assert tenant_res.status == "FAIL"
        assert len(tenant_res.findings) == 1

        f = tenant_res.findings[0]
        assert f.id == "RT-TENANT-001"
        assert f.endpoint == "GET /tenants/tenant-a/resource-a"
        assert f.actual == "allowed"
    finally:
        srv.close()


# ── 7. T1 Failure Suppresses All Findings ────────────────────────────────────


def test_tenant_positive_control_t1_failure_stops_early():
    """If tenant-a own-tenant positive control (T1) fails, stop immediately with INCOMPLETE and NO findings."""
    srv = _TenantTestServer(scenario="t1_denied")
    try:
        cfg = _make_tenant_cfg(srv.url)
        plan = build_plan(cfg)
        result = execute_native_plan(cfg, plan)

        tenant_res = result.area_results["tenant_isolation"]
        assert tenant_res.status == "INCOMPLETE"
        assert len(tenant_res.findings) == 0
        # Only T1 was executed before early stop
        assert tenant_res.requests_sent == 1
        assert "positive control T1 failed" in tenant_res.error
    finally:
        srv.close()


# ── 8. T3 Failure Suppresses Earlier T2 Violation ───────────────────────────


def test_tenant_positive_control_t3_failure_suppresses_t2_violation():
    """If tenant-a accessed tenant-b resource (T2 violation) but T3 fails, suppress the finding."""
    srv = _TenantTestServer(scenario="t3_denied_with_t2_vuln")
    try:
        cfg = _make_tenant_cfg(srv.url)
        plan = build_plan(cfg)
        result = execute_native_plan(cfg, plan)

        tenant_res = result.area_results["tenant_isolation"]
        assert tenant_res.status == "INCOMPLETE"
        # CRITICAL SECURITY RULE: No finding emitted without both positive controls passing
        assert len(tenant_res.findings) == 0
        assert tenant_res.requests_sent == 3
        assert "positive control T3 failed" in tenant_res.error
    finally:
        srv.close()


# ── 9. Ambiguous Response -> INCOMPLETE ──────────────────────────────────────


def test_tenant_ambiguous_response_t2():
    """200 without resource marker on cross-tenant check T2 resolves to INCOMPLETE without finding."""
    srv = _TenantTestServer(scenario="t2_ambiguous")
    try:
        cfg = _make_tenant_cfg(srv.url)
        plan = build_plan(cfg)
        result = execute_native_plan(cfg, plan)

        tenant_res = result.area_results["tenant_isolation"]
        assert tenant_res.status == "INCOMPLETE"
        assert len(tenant_res.findings) == 0
        assert "ambiguous" in tenant_res.reason
    finally:
        srv.close()


def test_tenant_ambiguous_when_other_marker_returned():
    """Returning another tenant's marker classifies as ambiguous and resolves to INCOMPLETE."""
    srv = _TenantTestServer(scenario="other_marker_returned")
    try:
        cfg = _make_tenant_cfg(srv.url)
        plan = build_plan(cfg)
        result = execute_native_plan(cfg, plan)

        tenant_res = result.area_results["tenant_isolation"]
        assert tenant_res.status == "INCOMPLETE"
        assert len(tenant_res.findings) == 0
    finally:
        srv.close()


# ── 10. Timeout Handling ─────────────────────────────────────────────────────


def test_tenant_request_timeout_t1():
    """Timeout on T1 produces INCOMPLETE with timed_out set."""
    srv = _TenantTestServer(scenario="timeout_t1")
    try:
        cfg = _make_tenant_cfg(srv.url)
        plan = build_plan(cfg)
        result = execute_native_plan(cfg, plan, request_timeout=0.1)

        tenant_res = result.area_results["tenant_isolation"]
        assert tenant_res.status == "INCOMPLETE"
        assert tenant_res.timed_out is True
        assert len(tenant_res.findings) == 0
    finally:
        srv.close()


def test_tenant_request_timeout_t2():
    """Timeout on T2 produces INCOMPLETE with timed_out set."""
    srv = _TenantTestServer(scenario="timeout_t2")
    try:
        cfg = _make_tenant_cfg(srv.url)
        plan = build_plan(cfg)
        result = execute_native_plan(cfg, plan, request_timeout=0.1)

        tenant_res = result.area_results["tenant_isolation"]
        assert tenant_res.status == "INCOMPLETE"
        assert tenant_res.timed_out is True
        assert len(tenant_res.findings) == 0
    finally:
        srv.close()


# ── 11. Request Budget Enforcement ───────────────────────────────────────────


def test_tenant_request_budget_enforcement():
    """Total client budget exhaustion halts execution and marks area INCOMPLETE."""
    srv = _TenantTestServer(scenario="pass")
    try:
        cfg = _make_tenant_cfg(srv.url)
        plan = build_plan(cfg)
        # Authentication takes: A1(1) + A2(1) + A3(2) + A4(1) = 5 requests in fixture mode
        # If client max_budget is 6, tenant runs T1 (1) and then budget is exhausted
        executor = NativeExecutor(cfg=cfg)
        assert executor.client is not None
        executor.client.max_budget = 6
        result = executor.execute_plan(plan)

        tenant_res = result.area_results["tenant_isolation"]
        assert tenant_res.status == "INCOMPLETE"
        assert tenant_res.budget_exceeded is True
        assert len(tenant_res.findings) == 0
    finally:
        srv.close()


# ── 12. Actor/Session Isolation ──────────────────────────────────────────────


def test_tenant_actor_session_isolation():
    """Verify T1/T2 use actor_a (user_c) session and T3/T4 use actor_b (user_d) session."""
    srv = _TenantTestServer(scenario="pass")
    try:
        cfg = _make_tenant_cfg(srv.url)
        plan = build_plan(cfg)
        execute_native_plan(cfg, plan)

        # Inspect requests sent to /tenants/
        tenant_reqs = [
            (method, path, headers)
            for (method, path, headers, _) in srv.requests_log
            if path.startswith("/tenants/")
        ]
        assert len(tenant_reqs) == 4

        # Extract session IDs sent
        sent_sessions = []
        for _, _, headers in tenant_reqs:
            cookie = headers.get("Cookie", "")
            sid = cookie.split("=")[1].split(";")[0]
            sent_sessions.append(sid)

        # T1 (user_c) and T2 (user_c) must share user_c's session
        assert sent_sessions[0] == sent_sessions[1]
        assert srv.valid_sessions[sent_sessions[0]] == "user_c"

        # T3 (user_d) and T4 (user_d) must share user_d's session
        assert sent_sessions[2] == sent_sessions[3]
        assert srv.valid_sessions[sent_sessions[2]] == "user_d"

        # user_c and user_d sessions must be distinct
        assert sent_sessions[0] != sent_sessions[2]
    finally:
        srv.close()


# ── 13. Cookie Authentication ────────────────────────────────────────────────


def test_tenant_cookie_auth_session_attachment():
    """Cookie-based session is correctly attached to T1-T4 requests."""
    srv = _TenantTestServer(scenario="pass", auth_mode="cookie")
    try:
        cfg = _make_tenant_cfg(srv.url)
        plan = build_plan(cfg)
        result = execute_native_plan(cfg, plan)

        tenant_res = result.area_results["tenant_isolation"]
        assert tenant_res.status == "PASS"

        # All 4 tenant requests must carry a Cookie header
        tenant_reqs = [
            (method, path, headers)
            for (method, path, headers, _) in srv.requests_log
            if path.startswith("/tenants/")
        ]
        for _, _, headers in tenant_reqs:
            assert "Cookie" in headers
    finally:
        srv.close()


# ── 14. Bearer Token Authentication ─────────────────────────────────────────


def test_tenant_bearer_token_auth():
    """Bearer token authentication is correctly attached to T1-T4 requests."""
    srv = _TenantTestServer(scenario="pass", auth_mode="token")
    try:
        cfg = _make_tenant_cfg(srv.url)
        plan = build_plan(cfg)
        result = execute_native_plan(cfg, plan)

        tenant_res = result.area_results["tenant_isolation"]
        assert tenant_res.status == "PASS"

        # All 4 tenant requests must carry an Authorization header
        tenant_reqs = [
            (method, path, headers)
            for (method, path, headers, _) in srv.requests_log
            if path.startswith("/tenants/")
        ]
        for _, _, headers in tenant_reqs:
            assert "Authorization" in headers
    finally:
        srv.close()


# ── 15. Secret/Redaction Safety ──────────────────────────────────────────────


def test_tenant_secret_redaction_safety():
    """Verify no tokens, credentials, or raw response bodies leak into evidence or findings."""
    srv = _TenantTestServer(scenario="t2_allowed")
    try:
        cfg = _make_tenant_cfg(srv.url)
        plan = build_plan(cfg)
        result = execute_native_plan(cfg, plan)

        tenant_res = result.area_results["tenant_isolation"]
        assert tenant_res.status == "FAIL"
        finding = tenant_res.findings[0]

        # Finding must not contain session IDs, credentials, or full response bodies
        finding_dump = str(vars(finding))
        assert "sess_" not in finding_dump
        assert "password" not in finding_dump
        assert "synth_" not in finding_dump

        # Check records must also be safe
        for chk in tenant_res.checks:
            chk_dump = json.dumps(chk)
            assert "sess_" not in chk_dump
    finally:
        srv.close()


# ── 16. Case A: T2 Finding Retained When T4 Is Incomplete ────────────────────


def test_case_a_tenant_violation_retained_when_t4_times_out():
    """Case A: T1 allowed, T2 allowed (violation), T3 allowed, T4 timeout.

    The verified T2 cross-tenant violation must NOT be erased when T4 times out.
    RT-TENANT-001 remains emitted and area status is FAIL.
    Analogous to IDOR Case A (design semantics preserved).
    """
    srv = _TenantTestServer(scenario="case_a_timeout_t4")
    try:
        cfg = _make_tenant_cfg(srv.url)
        plan = build_plan(cfg)
        result = execute_native_plan(cfg, plan, request_timeout=0.1)

        tenant_res = result.area_results["tenant_isolation"]
        assert tenant_res.status == "FAIL"
        assert len(tenant_res.findings) == 1
        f = tenant_res.findings[0]
        assert f.id == "RT-TENANT-001"
        assert f.endpoint == "GET /tenants/tenant-b/resource-b"
        assert f.expected == "denied"
        assert f.actual == "allowed"
        assert tenant_res.timed_out is True
        assert len(tenant_res.checks) == 4
        c4 = next(c for c in tenant_res.checks if c["check"] == "T4")
        assert c4["classification"] == "incomplete"
    finally:
        srv.close()


def test_case_a_tenant_violation_retained_when_t4_returns_500():
    """Case A variant: T1 allowed, T2 allowed (violation), T3 allowed, T4 returns 500."""
    srv = _TenantTestServer(scenario="case_a_500_t4")
    try:
        cfg = _make_tenant_cfg(srv.url)
        plan = build_plan(cfg)
        result = execute_native_plan(cfg, plan)

        tenant_res = result.area_results["tenant_isolation"]
        assert tenant_res.status == "FAIL"
        assert len(tenant_res.findings) == 1
        assert tenant_res.findings[0].id == "RT-TENANT-001"
        assert tenant_res.findings[0].endpoint == "GET /tenants/tenant-b/resource-b"
    finally:
        srv.close()


# ── 17. Reverse Case: T2 Denied, T4 Allowed ──────────────────────────────────


def test_evaluate_tenant_checks_case_b_t4_allowed():
    """Reverse case: T1 allowed, T2 denied, T3 allowed, T4 allowed -> RT-TENANT-001 (T4)."""
    checks = [
        {"check": "T1", "classification": "allowed"},
        {"check": "T2", "classification": "denied"},
        {"check": "T3", "classification": "allowed"},
        {"check": "T4", "classification": "allowed", "status": 200, "path": "/tenants/tenant-a/resource-a"},
    ]
    _, findings, status, _ = evaluate_tenant_checks(checks, res_a_path="/tenants/tenant-a/resource-a")
    assert status == "FAIL"
    assert len(findings) == 1
    assert findings[0].id == "RT-TENANT-001"
    assert findings[0].endpoint == "GET /tenants/tenant-a/resource-a"


# ── 18. T3 Failure After Earlier T2 Allowed -> Suppression ───────────────────


def test_evaluate_tenant_checks_t3_failure_suppresses_t2():
    """Case C: T1=allowed, T2=allowed, T3=denied -> INCOMPLETE, 0 findings (T2 suppressed)."""
    checks = [
        {"check": "T1", "classification": "allowed"},
        {"check": "T2", "classification": "allowed", "status": 200},
        {"check": "T3", "classification": "denied"},
    ]
    _, findings, status, reason = evaluate_tenant_checks(checks)
    assert status == "INCOMPLETE"
    assert len(findings) == 0
    assert "T3" in reason


# ── evaluate_tenant_checks Pure Unit Tests ───────────────────────────────────


def test_evaluate_tenant_checks_pass():
    checks = [
        {"check": "T1", "classification": "allowed"},
        {"check": "T2", "classification": "denied"},
        {"check": "T3", "classification": "allowed"},
        {"check": "T4", "classification": "denied"},
    ]
    _, findings, status, _ = evaluate_tenant_checks(checks)
    assert status == "PASS"
    assert len(findings) == 0


def test_evaluate_tenant_checks_fail_t2():
    checks = [
        {"check": "T1", "classification": "allowed"},
        {"check": "T2", "classification": "allowed", "status": 200, "path": "/tenants/tenant-b/resource-b"},
        {"check": "T3", "classification": "allowed"},
        {"check": "T4", "classification": "denied"},
    ]
    _, findings, status, _ = evaluate_tenant_checks(checks, res_b_path="/tenants/tenant-b/resource-b")
    assert status == "FAIL"
    assert len(findings) == 1
    assert findings[0].id == "RT-TENANT-001"
    assert findings[0].endpoint == "GET /tenants/tenant-b/resource-b"


def test_evaluate_tenant_checks_t1_failure_suppresses_all():
    """T1 failure suppresses all tenant findings even if cross-tenant access occurred."""
    checks = [
        {"check": "T1", "classification": "denied"},
        {"check": "T2", "classification": "allowed", "status": 200},
        {"check": "T3", "classification": "allowed"},
        {"check": "T4", "classification": "allowed", "status": 200},
    ]
    _, findings, status, _ = evaluate_tenant_checks(checks)
    assert status == "INCOMPLETE"
    assert len(findings) == 0


def test_evaluate_tenant_checks_positive_control_failure():
    """If T3 fails, do not emit finding even if T2 was allowed."""
    checks = [
        {"check": "T1", "classification": "allowed"},
        {"check": "T2", "classification": "allowed"},
        {"check": "T3", "classification": "denied"},
        {"check": "T4", "classification": "denied"},
    ]
    _, findings, status, _ = evaluate_tenant_checks(checks)
    assert status == "INCOMPLETE"
    assert len(findings) == 0


def test_evaluate_tenant_checks_ambiguous():
    checks = [
        {"check": "T1", "classification": "allowed"},
        {"check": "T2", "classification": "ambiguous"},
        {"check": "T3", "classification": "allowed"},
        {"check": "T4", "classification": "denied"},
    ]
    _, findings, status, _ = evaluate_tenant_checks(checks)
    assert status == "INCOMPLETE"
    assert len(findings) == 0


def test_evaluate_tenant_checks_case_a_incomplete_t4():
    """Case A pure unit test: T1 allowed, T2 allowed, T3 allowed, T4 incomplete -> FAIL with RT-TENANT-001."""
    checks = [
        {"check": "T1", "classification": "allowed"},
        {"check": "T2", "classification": "allowed", "status": 200, "path": "/tenants/tenant-b/resource-b"},
        {"check": "T3", "classification": "allowed"},
        {"check": "T4", "classification": "incomplete"},
    ]
    _, findings, status, _ = evaluate_tenant_checks(checks, res_b_path="/tenants/tenant-b/resource-b")
    assert status == "FAIL"
    assert len(findings) == 1
    assert findings[0].id == "RT-TENANT-001"
    assert findings[0].endpoint == "GET /tenants/tenant-b/resource-b"


def test_evaluate_tenant_checks_case_a_missing_t4():
    """Case A pure unit test: T1 allowed, T2 allowed, T3 allowed, T4 not executed -> FAIL with RT-TENANT-001."""
    checks = [
        {"check": "T1", "classification": "allowed"},
        {"check": "T2", "classification": "allowed", "status": 200, "path": "/tenants/tenant-b/resource-b"},
        {"check": "T3", "classification": "allowed"},
    ]
    _, findings, status, _ = evaluate_tenant_checks(checks, res_b_path="/tenants/tenant-b/resource-b")
    assert status == "FAIL"
    assert len(findings) == 1
    assert findings[0].id == "RT-TENANT-001"
    assert findings[0].endpoint == "GET /tenants/tenant-b/resource-b"


def test_evaluate_tenant_checks_ambiguous_t2_yields_incomplete():
    """T1=allowed, T2=ambiguous, T3=allowed, T4=denied -> INCOMPLETE, 0 findings."""
    checks = [
        {"check": "T1", "classification": "allowed"},
        {"check": "T2", "classification": "ambiguous"},
        {"check": "T3", "classification": "allowed"},
        {"check": "T4", "classification": "denied"},
    ]
    _, findings, status, _ = evaluate_tenant_checks(checks)
    assert status == "INCOMPLETE"
    assert len(findings) == 0


# ── Authentication Prerequisite ──────────────────────────────────────────────


def test_tenant_blocked_when_authentication_fails():
    """If authentication positive controls (A3) fail, tenant verification is blocked."""
    srv = _TenantTestServer(scenario="a3_fail")
    try:
        cfg = _make_tenant_cfg(srv.url)
        plan = build_plan(cfg)
        result = execute_native_plan(cfg, plan)

        tenant_res = result.area_results["tenant_isolation"]
        assert tenant_res.status == "INCOMPLETE"
        assert tenant_res.requests_sent == 0
        assert "authentication positive control" in tenant_res.error
    finally:
        srv.close()


# ── make_tenant_finding Unit Tests ────────────────────────────────────────────


def test_make_tenant_finding_t2():
    """make_tenant_finding produces correct RT-TENANT-001 metadata for T2."""
    f = make_tenant_finding(
        check_id="T2",
        path="/tenants/tenant-b/resource-b",
        status=200,
        actor="user_c",
        target_tenant="tenant-b",
    )
    assert f.id == "RT-TENANT-001"
    assert f.category == "tenant_isolation"
    assert f.severity == Severity.HIGH
    assert f.confidence == Confidence.HIGH
    assert f.endpoint == "GET /tenants/tenant-b/resource-b"
    assert f.expected == "denied"
    assert f.actual == "allowed"
    assert f.cwe == "CWE-639"
    assert f.owasp == "A01:2021-Broken Access Control"
    assert f.source == "native-verification"
    assert f.status == Status.OPEN


def test_make_tenant_finding_t4():
    """make_tenant_finding produces correct RT-TENANT-001 metadata for T4."""
    f = make_tenant_finding(
        check_id="T4",
        path="/tenants/tenant-a/resource-a",
        status=200,
        actor="user_d",
        target_tenant="tenant-a",
    )
    assert f.id == "RT-TENANT-001"
    assert f.endpoint == "GET /tenants/tenant-a/resource-a"
    assert f.severity == Severity.HIGH
    assert f.confidence == Confidence.HIGH


def test_make_tenant_finding_invalid_check_id():
    """make_tenant_finding raises ValueError for invalid check IDs."""
    with pytest.raises(ValueError, match="Unknown tenant check ID"):
        make_tenant_finding(check_id="T1", path="/tenants/tenant-a/resource-a", status=200)


# ── Namespace Validation ──────────────────────────────────────────────────────


def test_tenant_namespace_value():
    """TENANT_NAMESPACE constant is correct."""
    assert TENANT_NAMESPACE == "RT-TENANT-*"


def test_tenant_finding_source_is_native_verification():
    """Finding source must always be 'native-verification', never 'imported'."""
    f = make_tenant_finding(
        check_id="T2",
        path="/tenants/tenant-b/resource-b",
        status=200,
    )
    assert f.source == "native-verification"


# ── Explicit Semantic Review Cases A–E & 4-Actor Reference Tests ─────────────


def test_review_case_a_full_execution():
    """CASE A: T1=allowed, T2=allowed, T3=allowed, T4=incomplete/timeout.

    Expected:
    - T2 proves cross-tenant violation after both positive controls.
    - RT-TENANT-001 MUST remain emitted.
    - T4 being incomplete does not erase T2 finding.
    - Result reflects finding (status FAIL).
    """
    srv = _TenantTestServer(scenario="case_a_timeout_t4")
    try:
        cfg = _make_tenant_cfg(srv.url)
        plan = build_plan(cfg)
        result = execute_native_plan(cfg, plan)

        tenant_res = result.area_results["tenant_isolation"]
        assert tenant_res.status == "FAIL"
        assert len(tenant_res.findings) == 1
        assert tenant_res.findings[0].id == "RT-TENANT-001"
        assert tenant_res.findings[0].endpoint == "GET /tenants/tenant-b/resource-b"
        assert result.status == "FAIL"
    finally:
        srv.close()


def test_review_case_b_full_execution():
    """CASE B: T1=allowed, T2=denied, T3=allowed, T4=allowed.

    Expected:
    - RT-TENANT-001 from T4.
    """
    srv = _TenantTestServer(scenario="t4_allowed")
    try:
        cfg = _make_tenant_cfg(srv.url)
        plan = build_plan(cfg)
        result = execute_native_plan(cfg, plan)

        tenant_res = result.area_results["tenant_isolation"]
        assert tenant_res.status == "FAIL"
        assert len(tenant_res.findings) == 1
        assert tenant_res.findings[0].id == "RT-TENANT-001"
        assert tenant_res.findings[0].endpoint == "GET /tenants/tenant-a/resource-a"
        assert result.status == "FAIL"
    finally:
        srv.close()


def test_review_case_c_full_execution():
    """CASE C: T1=allowed, T2=allowed, T3=denied, T4=allowed.

    Expected:
    - No tenant finding (T3 failure suppresses T2 finding).
    - Status INCOMPLETE.
    - Early stop: T4 is not executed.
    """
    srv = _TenantTestServer(scenario="t3_denied_with_t2_vuln")
    try:
        cfg = _make_tenant_cfg(srv.url)
        plan = build_plan(cfg)
        result = execute_native_plan(cfg, plan)

        tenant_res = result.area_results["tenant_isolation"]
        assert tenant_res.status == "INCOMPLETE"
        assert len(tenant_res.findings) == 0
        assert tenant_res.requests_sent == 3  # T1, T2, T3 executed; T4 stopped
    finally:
        srv.close()


def test_review_case_d_full_execution():
    """CASE D: T1=denied, T2=allowed, T3=allowed, T4=allowed.

    Expected:
    - No finding.
    - Early-stop behavior: only T1 executed.
    - Status INCOMPLETE.
    """
    srv = _TenantTestServer(scenario="t1_denied")
    try:
        cfg = _make_tenant_cfg(srv.url)
        plan = build_plan(cfg)
        result = execute_native_plan(cfg, plan)

        tenant_res = result.area_results["tenant_isolation"]
        assert tenant_res.status == "INCOMPLETE"
        assert len(tenant_res.findings) == 0
        assert tenant_res.requests_sent == 1  # only T1 executed
    finally:
        srv.close()


def test_review_case_e_full_execution():
    """CASE E: T1=allowed, T2=ambiguous, T3=allowed, T4=denied.

    Expected:
    - Status INCOMPLETE (not PASS).
    - No finding.
    """
    srv = _TenantTestServer(scenario="t2_ambiguous")
    try:
        cfg = _make_tenant_cfg(srv.url)
        plan = build_plan(cfg)
        result = execute_native_plan(cfg, plan)

        tenant_res = result.area_results["tenant_isolation"]
        assert tenant_res.status == "INCOMPLETE"
        assert len(tenant_res.findings) == 0
        assert tenant_res.status != "PASS"
    finally:
        srv.close()


def test_canonical_4_actor_design_config_actor_selection():
    """Design §6 reference config: user_a, user_b, admin_a (tenant-a), user_c (tenant-b).

    Verifies:
    - user_a is selected for tenant-a (role user preferred).
    - user_c is selected for tenant-b.
    - admin_a is NEVER substituted as tenant-a actor.
    """
    data = {
        "target": {"base_url": "http://127.0.0.1:3000", "environment": "local", "production": False},
        "runtime_verification": {
            "mode": "fixture",
            "allowed_targets": ["http://127.0.0.1:3000"],
            "actors": {
                "user_a": {"role": "user", "tenant": "tenant-a"},
                "user_b": {"role": "user", "tenant": "tenant-a"},
                "admin_a": {"role": "admin", "tenant": "tenant-a"},
                "user_c": {"role": "user", "tenant": "tenant-b"},
            },
            "routes": {},
            "resources": [
                {
                    "id": "resource-a",
                    "path": "/tenants/tenant-a/resource-a",
                    "tenant": "tenant-a",
                    "marker": "tenant:tenant-a",
                },
                {
                    "id": "resource-b",
                    "path": "/tenants/tenant-b/resource-b",
                    "tenant": "tenant-b",
                    "marker": "tenant:tenant-b",
                },
            ],
            "deny_statuses": [401, 403, 404],
        },
    }
    cfg = parse(data)
    reqs = build_tenant_requests(cfg)
    assert len(reqs) == 4

    t1, t2, t3, t4 = reqs
    # T1/T2 use user_a (tenant-a) - admin_a is NOT substituted!
    assert t1.actor == "user_a"
    assert t1.path == "/tenants/tenant-a/resource-a"
    assert t2.actor == "user_a"
    assert t2.path == "/tenants/tenant-b/resource-b"

    # T3/T4 use user_c (tenant-b)
    assert t3.actor == "user_c"
    assert t3.path == "/tenants/tenant-b/resource-b"
    assert t4.actor == "user_c"
    assert t4.path == "/tenants/tenant-a/resource-a"

