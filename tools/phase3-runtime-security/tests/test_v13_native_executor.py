"""Tests for the bounded native execution layer (v1.3).

Verifies:
- successful bounded execution
- request count tracking
- over-budget rejection
- per-request timeout produces INCOMPLETE, no retry
- per-area timeout (60s bound, stops remaining area requests, marks INCOMPLETE)
- total timeout (180s bound, stops remaining areas, marks INCOMPLETE)
- stopping remaining area requests after timeout or failure
- deterministic ordering of requests and results
- response size bounds (256 KB truncation)
- request size bounds and forbidden methods
- target eligibility enforced before connection
- no DNS re-resolution after validated resolution
- secret and error redaction in results and representations
- identity setup failure aborts all verification areas

All tests use local loopback servers or fakes only. No public network.
"""

from __future__ import annotations

import socket
import threading
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from unittest.mock import patch

import pytest
from runtime_security.config import parse
from runtime_security.native.eligibility import evaluate_native
from runtime_security.native.executor import (
    DEFAULT_REQUEST_TIMEOUT,
    FIXTURE_MAX_REQUESTS,
    LOCAL_APP_MAX_REQUESTS,
    MAX_AREA_TIMEOUT,
    MAX_TOTAL_TIMEOUT,
    AreaExecutionResult,
    NativeExecutionResult,
    NativeExecutor,
    PlannedRequest,
    RequestExecutionResult,
    execute_native_plan,
)
from runtime_security.native.identity import IdentityVault, SecretValue
from runtime_security.native.plan import AreaPlan, NativePlan


class _TestServer:
    def __init__(self, handler_cls=None):
        self.requests_log: list[tuple[str, str, dict[str, str], bytes]] = []

        outer = self

        if handler_cls is None:

            class DefaultHandler(BaseHTTPRequestHandler):
                def do_GET(self):
                    body = self.rfile.read(int(self.headers.get("Content-Length") or 0))
                    outer.requests_log.append(("GET", self.path, dict(self.headers), body))
                    if self.path == "/slow":
                        time.sleep(0.3)
                        self.send_response(200)
                        self.end_headers()
                        self.wfile.write(b'{"status": "slow-ok"}')
                    elif self.path == "/big":
                        self.send_response(200)
                        self.end_headers()
                        # Send 300 KB
                        self.wfile.write(b"X" * (300 * 1024))
                    elif self.path == "/marker":
                        self.send_response(200)
                        self.end_headers()
                        self.wfile.write(b'{"message": "account:user_a found"}')
                    elif self.path == "/error500":
                        self.send_response(500)
                        self.end_headers()
                        self.wfile.write(b'{"error": "internal"}')
                    else:
                        self.send_response(200)
                        self.end_headers()
                        self.wfile.write(b'{"status": "ok"}')

                def do_POST(self):
                    body = self.rfile.read(int(self.headers.get("Content-Length") or 0))
                    outer.requests_log.append(("POST", self.path, dict(self.headers), body))
                    if self.path == "/setup_fail":
                        self.send_response(500)
                        self.end_headers()
                        self.wfile.write(b'{"error": "setup failed"}')
                    else:
                        self.send_response(200)
                        self.end_headers()
                        self.wfile.write(b'{"status": "post-ok"}')

                def do_HEAD(self):
                    outer.requests_log.append(("HEAD", self.path, dict(self.headers), b""))
                    self.send_response(200)
                    self.end_headers()

                def log_message(self, *args):
                    pass

            handler_cls = DefaultHandler

        self.httpd = ThreadingHTTPServer(("127.0.0.1", 0), handler_cls)
        self.port = self.httpd.server_address[1]
        self.url = f"http://127.0.0.1:{self.port}"
        self.thread = threading.Thread(target=self.httpd.serve_forever, daemon=True)
        self.thread.start()

    def close(self):
        self.httpd.shutdown()
        self.httpd.server_close()


@pytest.fixture
def local_server():
    server = _TestServer()
    yield server
    server.close()


def _make_cfg(url: str, mode: str = "fixture", environment: str = "local"):
    return parse(
        {
            "target": {
                "base_url": url,
                "environment": environment,
                "production": False,
                "authorized": True,
                "authorized_by": "sec-team",
            },
            "runtime_verification": {
                "mode": mode,
                "allowed_targets": [url],
                "actors": {
                    "user_a": {"role": "user", "tenant": "tenant-a"},
                    "admin_a": {"role": "admin", "tenant": "tenant-a"},
                },
                "routes": {
                    "protected": {"path": "/account", "marker": "account:user_a"},
                    "privileged": {"path": "/admin", "marker": "privileged"},
                },
                "resources": [],
                "deny_statuses": [401, 403, 404],
            },
        }
    )


# ── 1. Successful bounded execution & count tracking ──────────────────────────


def test_successful_bounded_execution(local_server):
    cfg = _make_cfg(local_server.url)
    req1 = PlannedRequest(
        area="authentication",
        check_id="A1",
        method="GET",
        path="/account",
        marker="account:user_a",
    )
    req2 = PlannedRequest(
        area="authentication",
        check_id="A2",
        method="POST",
        path="/login",
        body=b"u=user_a",
    )
    req3 = PlannedRequest(
        area="authorization",
        check_id="Z1",
        method="GET",
        path="/admin",
    )

    plan = NativePlan(
        areas={
            "authentication": AreaPlan(
                configured=True, requests_count=2, budget=9, requests=[req1, req2]
            ),
            "authorization": AreaPlan(
                configured=True, requests_count=1, budget=2, requests=[req3]
            ),
        },
        total_verification_requests=3,
        total_budget=20,
    )

    executor = NativeExecutor(cfg)
    result = executor.execute_plan(plan)

    assert result.status == "EXECUTED"
    assert result.requests_sent == 3
    assert not result.timed_out
    assert not result.refused

    auth_area = result.area("authentication")
    assert auth_area is not None
    assert auth_area.status == "EXECUTED"
    assert auth_area.requests_sent == 2
    assert len(auth_area.request_results) == 2

    authz_area = result.area("authorization")
    assert authz_area is not None
    assert authz_area.status == "EXECUTED"
    assert authz_area.requests_sent == 1

    assert len(result.all_request_results) == 3
    assert len(local_server.requests_log) == 3


def test_request_count_tracking(local_server):
    cfg = _make_cfg(local_server.url)
    reqs = [
        PlannedRequest(area="authentication", check_id=f"A{i}", path=f"/p{i}")
        for i in range(4)
    ]
    plan = NativePlan(
        areas={
            "authentication": AreaPlan(
                configured=True, requests_count=4, budget=9, requests=reqs
            ),
        },
        total_verification_requests=4,
        total_budget=20,
    )

    executor = NativeExecutor(cfg)
    result = executor.execute_plan(plan)

    assert result.requests_sent == 4
    assert result.area("authentication").requests_sent == 4
    assert executor.client.sent == 4


# ── 2. Over-budget rejection before execution ──────────────────────────────────


def test_plan_marked_over_budget_rejected_before_execution(local_server):
    cfg = _make_cfg(local_server.url)
    req = PlannedRequest(area="authentication", check_id="A1", path="/account")
    plan = NativePlan(
        areas={
            "authentication": AreaPlan(
                configured=True, requests_count=1, budget=9, requests=[req]
            )
        },
        total_verification_requests=1,
        is_over_budget=True,
    )

    result = execute_native_plan(cfg, plan)

    assert result.status == "INCOMPLETE"
    assert result.refused is True
    assert "budget" in result.refusal_reason.lower()
    assert result.requests_sent == 0
    assert len(local_server.requests_log) == 0


def test_plan_exceeding_total_budget_rejected_before_execution(local_server):
    cfg = _make_cfg(local_server.url)
    # Verification limit is 20
    plan = NativePlan(
        areas={
            "authentication": AreaPlan(configured=True, requests_count=9, budget=9),
            "session": AreaPlan(configured=True, requests_count=1, budget=1),
            "authorization": AreaPlan(configured=True, requests_count=2, budget=2),
            "idor_bola": AreaPlan(configured=True, requests_count=4, budget=4),
            "tenant_isolation": AreaPlan(configured=True, requests_count=5, budget=4),  # > 4
        },
        total_verification_requests=21,  # > 20
    )

    result = execute_native_plan(cfg, plan)

    assert result.status == "INCOMPLETE"
    assert result.refused is True
    assert result.requests_sent == 0
    assert len(local_server.requests_log) == 0


def test_area_exceeding_hard_maximum_rejected(local_server):
    cfg = _make_cfg(local_server.url)
    # auth hard maximum is 9; session hard maximum is 1
    plan = NativePlan(
        areas={
            "session": AreaPlan(configured=True, requests_count=2, budget=2),  # > 1!
        },
        total_verification_requests=2,
    )

    result = execute_native_plan(cfg, plan)

    assert result.status == "INCOMPLETE"
    assert result.refused is True
    assert "hard maximum" in result.refusal_reason.lower()
    assert result.requests_sent == 0


def test_planner_and_executor_count_mismatch_rejected(local_server):
    cfg = _make_cfg(local_server.url)
    req1 = PlannedRequest(area="authentication", check_id="A1", path="/account")
    # requests_count claims 2, but only 1 request provided
    plan = NativePlan(
        areas={
            "authentication": AreaPlan(
                configured=True, requests_count=2, budget=9, requests=[req1]
            ),
        },
        total_verification_requests=2,
    )

    result = execute_native_plan(cfg, plan)

    assert result.status == "INCOMPLETE"
    assert result.refused is True
    assert "count" in result.refusal_reason.lower()
    assert result.requests_sent == 0


# ── 3. Timeouts: per-request, per-area, total run, no retry ────────────────────


def test_per_request_timeout_produces_incomplete_no_retry(local_server):
    cfg = _make_cfg(local_server.url)
    req = PlannedRequest(area="authentication", check_id="A1", path="/slow")
    plan = NativePlan(
        areas={
            "authentication": AreaPlan(
                configured=True, requests_count=1, budget=9, requests=[req]
            ),
        },
        total_verification_requests=1,
    )

    # Use short request_timeout of 0.1s against a 0.3s server endpoint
    executor = NativeExecutor(cfg, request_timeout=0.1)
    result = executor.execute_plan(plan)

    assert result.status == "INCOMPLETE"
    assert result.timed_out is True
    auth_area = result.area("authentication")
    assert auth_area.status == "INCOMPLETE"
    assert auth_area.timed_out is True
    assert len(auth_area.request_results) == 1
    assert auth_area.request_results[0].timed_out is True
    assert auth_area.request_results[0].status == "INCOMPLETE"
    # No retry: server received exactly 1 request
    assert len(local_server.requests_log) == 1


def test_stopping_remaining_area_requests_after_timeout(local_server):
    cfg = _make_cfg(local_server.url)
    req1 = PlannedRequest(area="authentication", check_id="A1", path="/fast1")
    req2 = PlannedRequest(area="authentication", check_id="A2", path="/slow")
    req3 = PlannedRequest(area="authentication", check_id="A3", path="/fast2")

    plan = NativePlan(
        areas={
            "authentication": AreaPlan(
                configured=True, requests_count=3, budget=9, requests=[req1, req2, req3]
            ),
        },
        total_verification_requests=3,
    )

    executor = NativeExecutor(cfg, request_timeout=0.1)
    result = executor.execute_plan(plan)

    assert result.status == "INCOMPLETE"
    auth_area = result.area("authentication")
    assert auth_area.status == "INCOMPLETE"
    assert auth_area.timed_out is True
    # req1 succeeded, req2 timed out, req3 was stopped and not executed!
    assert auth_area.requests_sent == 2
    assert len(auth_area.request_results) == 2
    assert auth_area.request_results[0].status == "EXECUTED"
    assert auth_area.request_results[1].timed_out is True

    # Confirm fast2 was never sent to the server
    paths = [item[1] for item in local_server.requests_log]
    assert paths == ["/fast1", "/slow"]
    assert "/fast2" not in paths


def test_per_area_timeout_stops_remaining_requests(local_server):
    cfg = _make_cfg(local_server.url)
    # 3 requests, area timeout is 0.25s, but each /slow takes 0.3s
    reqs = [
        PlannedRequest(area="authentication", check_id=f"A{i}", path="/slow")
        for i in range(3)
    ]
    plan = NativePlan(
        areas={
            "authentication": AreaPlan(
                configured=True, requests_count=3, budget=9, requests=reqs
            ),
        },
        total_verification_requests=3,
    )

    executor = NativeExecutor(cfg, request_timeout=5.0, area_timeout=0.25)
    result = executor.execute_plan(plan)

    assert result.status == "INCOMPLETE"
    auth_area = result.area("authentication")
    assert auth_area.timed_out is True
    assert auth_area.status == "INCOMPLETE"
    # Stopped after first or second request due to area timeout
    assert auth_area.requests_sent < 3


def test_total_run_timeout_stops_remaining_areas(local_server):
    cfg = _make_cfg(local_server.url)
    req1 = PlannedRequest(area="authentication", check_id="A1", path="/slow")
    req2 = PlannedRequest(area="authorization", check_id="Z1", path="/fast")

    plan = NativePlan(
        areas={
            "authentication": AreaPlan(
                configured=True, requests_count=1, budget=9, requests=[req1]
            ),
            "authorization": AreaPlan(
                configured=True, requests_count=1, budget=2, requests=[req2]
            ),
        },
        total_verification_requests=2,
    )

    # total_timeout is 0.2s; req1 takes 0.3s
    executor = NativeExecutor(cfg, request_timeout=5.0, total_timeout=0.2)
    result = executor.execute_plan(plan)

    assert result.status == "INCOMPLETE"
    assert result.timed_out is True

    authz = result.area("authorization")
    assert authz.status == "INCOMPLETE"
    assert authz.timed_out is True

    # req2 in authorization should never have been sent
    paths = [item[1] for item in local_server.requests_log]
    assert "/fast" not in paths


# ── 4. Deterministic ordering ──────────────────────────────────────────────────


def test_deterministic_execution_ordering(local_server):
    cfg = _make_cfg(local_server.url)
    reqs_auth = [
        PlannedRequest(area="authentication", check_id="A1", path="/a1"),
        PlannedRequest(area="authentication", check_id="A2", path="/a2"),
    ]
    reqs_session = [
        PlannedRequest(area="session", check_id="S2", path="/s2"),
    ]
    reqs_authz = [
        PlannedRequest(area="authorization", check_id="Z1", path="/z1"),
        PlannedRequest(area="authorization", check_id="Z2", path="/z2"),
    ]

    plan = NativePlan(
        areas={
            "session": AreaPlan(
                configured=True, requests_count=1, budget=1, requests=reqs_session
            ),
            "authorization": AreaPlan(
                configured=True, requests_count=2, budget=2, requests=reqs_authz
            ),
            "authentication": AreaPlan(
                configured=True, requests_count=2, budget=9, requests=reqs_auth
            ),
        },
        total_verification_requests=5,
    )

    executor = NativeExecutor(cfg)
    result = executor.execute_plan(plan)

    assert result.status == "EXECUTED"
    # Even though plan.areas was defined in arbitrary dict order, execution order
    # MUST be: authentication -> session -> authorization
    paths = [r.path for r in result.all_request_results]
    assert paths == ["/a1", "/a2", "/s2", "/z1", "/z2"]

    server_paths = [item[1] for item in local_server.requests_log]
    assert server_paths == ["/a1", "/a2", "/s2", "/z1", "/z2"]


# ── 5. Response and request bounds ─────────────────────────────────────────────


def test_response_body_size_bound_truncation(local_server):
    cfg = _make_cfg(local_server.url)
    req = PlannedRequest(area="authentication", check_id="A1", path="/big")
    plan = NativePlan(
        areas={
            "authentication": AreaPlan(
                configured=True, requests_count=1, budget=9, requests=[req]
            ),
        },
        total_verification_requests=1,
    )

    executor = NativeExecutor(cfg)
    result = executor.execute_plan(plan)

    assert result.status == "EXECUTED"
    req_res = result.all_request_results[0]
    assert req_res.response is not None
    assert req_res.response.truncated is True
    # 256 KB max
    assert len(req_res.response.body) == 256 * 1024


def test_forbidden_methods_rejected(local_server):
    cfg = _make_cfg(local_server.url)
    req = PlannedRequest(area="authentication", check_id="A1", method="DELETE", path="/p")
    plan = NativePlan(
        areas={
            "authentication": AreaPlan(
                configured=True, requests_count=1, budget=9, requests=[req]
            ),
        },
        total_verification_requests=1,
    )

    executor = NativeExecutor(cfg)
    result = executor.execute_plan(plan)

    assert result.status == "INCOMPLETE"
    assert result.all_request_results[0].status == "INCOMPLETE"
    assert "not allowed" in result.all_request_results[0].error.lower()
    assert len(local_server.requests_log) == 0


def test_non_relative_path_rejected(local_server):
    cfg = _make_cfg(local_server.url)
    req = PlannedRequest(area="authentication", check_id="A1", path="https://evil.com/p")
    plan = NativePlan(
        areas={
            "authentication": AreaPlan(
                configured=True, requests_count=1, budget=9, requests=[req]
            ),
        },
        total_verification_requests=1,
    )

    executor = NativeExecutor(cfg)
    result = executor.execute_plan(plan)

    assert result.status == "INCOMPLETE"
    assert "relative" in result.all_request_results[0].error.lower()
    assert len(local_server.requests_log) == 0


# ── 6. Target safety & DNS pinning ─────────────────────────────────────────────


def test_target_eligibility_enforced_production_refused():
    cfg = parse(
        {
            "target": {
                "base_url": "http://127.0.0.1:3000",
                "environment": "production",
                "production": True,
            },
            "runtime_verification": {
                "mode": "fixture",
                "allowed_targets": ["http://127.0.0.1:3000"],
            },
        }
    )
    req = PlannedRequest(area="authentication", check_id="A1", path="/account")
    plan = NativePlan(
        areas={
            "authentication": AreaPlan(
                configured=True, requests_count=1, budget=9, requests=[req]
            ),
        },
        total_verification_requests=1,
    )

    result = execute_native_plan(cfg, plan)

    assert result.status == "INCOMPLETE"
    assert result.refused is True
    assert result.requests_sent == 0
    assert "safety gate refused" in result.refusal_reason.lower()


def test_no_dns_reresolution_after_validated_resolution(local_server):
    cfg = _make_cfg(local_server.url)
    # Initial eligibility evaluation does DNS resolution once
    decision = evaluate_native(cfg)
    assert decision.allowed is True
    assert len(decision.resolved_ips) > 0

    req1 = PlannedRequest(area="authentication", check_id="A1", path="/p1")
    req2 = PlannedRequest(area="authentication", check_id="A2", path="/p2")
    plan = NativePlan(
        areas={
            "authentication": AreaPlan(
                configured=True, requests_count=2, budget=9, requests=[req1, req2]
            ),
        },
        total_verification_requests=2,
    )

    executor = NativeExecutor(cfg, eligibility=decision)

    # Patch socket.getaddrinfo to raise if called during execution
    def no_dns(*args, **kwargs):
        raise AssertionError("DNS re-resolution was attempted during native execution!")

    with patch("socket.getaddrinfo", side_effect=no_dns):
        result = executor.execute_plan(plan)

    assert result.status == "EXECUTED"
    assert result.requests_sent == 2
    assert len(local_server.requests_log) == 2


# ── 7. Secret and error redaction ──────────────────────────────────────────────


def test_secrets_redacted_in_recorded_headers_and_representation(local_server):
    cfg = _make_cfg(local_server.url)
    secret_token = SecretValue("super-secret-bearer-token-12345")
    secret_cookie = SecretValue("session_id=ultra-confidential-session-cookie")

    req = PlannedRequest(
        area="authentication",
        check_id="A4",
        path="/account",
        headers={
            "Authorization": f"Bearer {secret_token.reveal_for_request()}",
            "Cookie": secret_cookie.reveal_for_request(),
            "X-Custom-Header": "safe-custom-value",
        },
    )
    plan = NativePlan(
        areas={
            "authentication": AreaPlan(
                configured=True, requests_count=1, budget=9, requests=[req]
            ),
        },
        total_verification_requests=1,
    )

    executor = NativeExecutor(cfg)
    result = executor.execute_plan(plan)

    assert result.status == "EXECUTED"
    req_res = result.all_request_results[0]

    # Server received the real values over the wire
    server_headers = local_server.requests_log[0][2]
    assert server_headers.get("Authorization") == "Bearer super-secret-bearer-token-12345"
    assert (
        server_headers.get("Cookie")
        == "session_id=ultra-confidential-session-cookie"
    )

    # BUT the execution result record has them redacted!
    assert req_res.headers_sent["Authorization"] == "<redacted>"
    assert req_res.headers_sent["Cookie"] == "<redacted>"
    assert req_res.headers_sent["X-Custom-Header"] == "safe-custom-value"

    # Representation check
    res_repr = repr(result)
    req_repr = repr(req_res)
    assert "super-secret-bearer-token" not in res_repr
    assert "ultra-confidential" not in res_repr
    assert "super-secret-bearer-token" not in req_repr
    assert "ultra-confidential" not in req_repr


def test_connection_error_redacted_diagnostic(local_server):
    # Port with no listening server
    cfg = parse(
        {
            "target": {
                "base_url": "http://127.0.0.1:65530",
                "environment": "local",
                "production": False,
                "authorized": True,
                "authorized_by": "sec-team",
            },
            "runtime_verification": {
                "mode": "fixture",
                "allowed_targets": ["http://127.0.0.1:65530"],
                "actors": {"user_a": {"role": "user"}},
                "routes": {"protected": {"path": "/p", "marker": "m"}},
                "resources": [],
                "deny_statuses": [401],
            },
        }
    )
    req = PlannedRequest(area="authentication", check_id="A1", path="/p")
    plan = NativePlan(
        areas={
            "authentication": AreaPlan(
                configured=True, requests_count=1, budget=9, requests=[req]
            ),
        },
        total_verification_requests=1,
    )

    executor = NativeExecutor(cfg)
    result = executor.execute_plan(plan)

    assert result.status == "INCOMPLETE"
    req_res = result.all_request_results[0]
    assert req_res.status == "INCOMPLETE"
    assert "connection error" in req_res.error.lower()


# ── 8. Identity setup aborts all verification on failure ───────────────────────


def test_identity_setup_failure_aborts_all_verification(local_server):
    cfg = _make_cfg(local_server.url, mode="local-app")
    setup_req = PlannedRequest(
        area="identity_setup",
        check_id="setup",
        method="POST",
        path="/setup_fail",
        body=b'{"identities": []}',
    )
    auth_req = PlannedRequest(area="authentication", check_id="A1", path="/account")

    plan = NativePlan(
        identity_setup_count=1,
        setup_requests=[setup_req],
        areas={
            "authentication": AreaPlan(
                configured=True, requests_count=1, budget=9, requests=[auth_req]
            ),
        },
        total_verification_requests=1,
    )

    executor = NativeExecutor(cfg)
    result = executor.execute_plan(plan)

    assert result.status == "INCOMPLETE"
    assert result.area("authentication").status == "INCOMPLETE"
    assert "setup" in result.area("authentication").error.lower()

    # Only 1 request sent (the failed setup request); auth request was NEVER sent
    assert result.requests_sent == 1
    paths = [item[1] for item in local_server.requests_log]
    assert paths == ["/setup_fail"]
    assert "/account" not in paths
