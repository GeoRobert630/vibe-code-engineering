"""Tests for v1.3 synthetic identity setup-hook delivery contract (Design §7.1).

Verifies:
- exactly one setup request
- correct payload schema: 'vibe-identity-setup/1'
- run_id generation and matching
- expires_in_seconds = 180
- exact actor-label matching
- 200 and 201 HTTP status success
- non-200/201 failure
- mismatched run_id failure
- mismatched actor label failure
- extra-field or malformed response rejection
- timeout/failure prevents later verification requests
- fixture mode does not send setup
- remote/production setup is refused
- setup payload/secret leakage protections
- response extra fields are discarded
- deterministic setup behavior
- local-app mode without identity_setup marks all areas not configured
"""

from __future__ import annotations

import json
import threading
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

import pytest
from runtime_security.config import parse
from runtime_security.native.executor import NativeExecutor, PlannedRequest
from runtime_security.native.identity import IdentityVault, SecretValue
from runtime_security.native.plan import AreaPlan, NativePlan, build_plan
from runtime_security.native.setup_adapter import (
    SETUP_EXPIRES_IN_SECONDS,
    SETUP_SCHEMA,
    IdentitySetupResult,
    build_setup_payload,
    build_setup_request,
    validate_setup_response,
)


class _SetupServer:
    def __init__(self, expected_run_id: str, actors: list[str], mode: str = "success_200"):
        self.requests_log: list[tuple[str, str, dict[str, str], bytes]] = []
        self.expected_run_id = expected_run_id
        self.actors = sorted(actors)
        self.mode = mode
        outer = self

        class Handler(BaseHTTPRequestHandler):
            def do_POST(self):
                body = self.rfile.read(int(self.headers.get("Content-Length") or 0))
                outer.requests_log.append(("POST", self.path, dict(self.headers), body))

                if outer.mode == "success_200":
                    self.send_response(200)
                    self.send_header("Content-Type", "application/json")
                    self.end_headers()
                    resp = {
                        "schema": SETUP_SCHEMA,
                        "run_id": outer.expected_run_id,
                        "accepted": outer.actors,
                    }
                    self.wfile.write(json.dumps(resp).encode("utf-8"))

                elif outer.mode == "success_201":
                    self.send_response(201)
                    self.send_header("Content-Type", "application/json")
                    self.end_headers()
                    resp = {
                        "schema": SETUP_SCHEMA,
                        "run_id": outer.expected_run_id,
                        "accepted": outer.actors,
                    }
                    self.wfile.write(json.dumps(resp).encode("utf-8"))

                elif outer.mode == "status_500":
                    self.send_response(500)
                    self.send_header("Content-Type", "application/json")
                    self.end_headers()
                    self.wfile.write(b'{"error": "internal error"}')

                elif outer.mode == "wrong_run_id":
                    self.send_response(200)
                    self.send_header("Content-Type", "application/json")
                    self.end_headers()
                    resp = {
                        "schema": SETUP_SCHEMA,
                        "run_id": "different-run-id-999",
                        "accepted": outer.actors,
                    }
                    self.wfile.write(json.dumps(resp).encode("utf-8"))

                elif outer.mode == "missing_actor":
                    self.send_response(200)
                    self.send_header("Content-Type", "application/json")
                    self.end_headers()
                    resp = {
                        "schema": SETUP_SCHEMA,
                        "run_id": outer.expected_run_id,
                        "accepted": outer.actors[:1],  # Only partial accepted
                    }
                    self.wfile.write(json.dumps(resp).encode("utf-8"))

                elif outer.mode == "extra_actor":
                    self.send_response(200)
                    self.send_header("Content-Type", "application/json")
                    self.end_headers()
                    resp = {
                        "schema": SETUP_SCHEMA,
                        "run_id": outer.expected_run_id,
                        "accepted": outer.actors + ["uninvited_guest"],
                    }
                    self.wfile.write(json.dumps(resp).encode("utf-8"))

                elif outer.mode == "extra_fields":
                    self.send_response(200)
                    self.send_header("Content-Type", "application/json")
                    self.end_headers()
                    resp = {
                        "schema": SETUP_SCHEMA,
                        "run_id": outer.expected_run_id,
                        "accepted": outer.actors,
                        "unauthorized_extra_field": "leak",
                    }
                    self.wfile.write(json.dumps(resp).encode("utf-8"))

                elif outer.mode == "wrong_schema":
                    self.send_response(200)
                    self.send_header("Content-Type", "application/json")
                    self.end_headers()
                    resp = {
                        "schema": "vibe-identity-setup/2",
                        "run_id": outer.expected_run_id,
                        "accepted": outer.actors,
                    }
                    self.wfile.write(json.dumps(resp).encode("utf-8"))

                elif outer.mode == "echo_secrets":
                    self.send_response(200)
                    self.send_header("Content-Type", "application/json")
                    self.end_headers()
                    # Echo raw payload containing secrets
                    self.wfile.write(body)

                elif outer.mode == "timeout":
                    time.sleep(0.4)
                    self.send_response(200)
                    self.end_headers()

                else:
                    self.send_response(400)
                    self.end_headers()

            def do_GET(self):
                body = self.rfile.read(int(self.headers.get("Content-Length") or 0))
                outer.requests_log.append(("GET", self.path, dict(self.headers), body))
                self.send_response(200)
                self.end_headers()
                self.wfile.write(b'{"status": "ok"}')

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


def _make_local_app_cfg(url: str, with_setup: bool = True):
    data = {
        "target": {
            "base_url": url,
            "environment": "local",
            "production": False,
            "authorized": True,
            "authorized_by": "sec-team",
        },
        "runtime_verification": {
            "mode": "local-app",
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
    if with_setup:
        data["runtime_verification"]["identity_setup"] = {
            "adapter": "http-local",
            "path": "/__vibe_test__/identities",
        }
    return parse(data)


# ── 1. Payload Construction & Schema ──────────────────────────────────────────


def test_setup_payload_schema_and_fields():
    vault = IdentityVault("test-run-123", ["user_a", "admin_a"])
    cfg = _make_local_app_cfg("http://127.0.0.1:3000")
    payload = build_setup_payload(vault, cfg.runtime_verification.actors)

    assert payload["schema"] == "vibe-identity-setup/1"
    assert payload["run_id"] == "test-run-123"
    assert payload["expires_in_seconds"] == 180

    identities = payload["identities"]
    assert len(identities) == 2

    # Deterministic sorting by label
    assert identities[0]["label"] == "admin_a"
    assert identities[0]["role"] == "admin"
    assert identities[0]["tenant"] == "tenant-a"
    assert identities[0]["secret"] == vault.get_actor_secret("admin_a").reveal_for_request()

    assert identities[1]["label"] == "user_a"
    assert identities[1]["role"] == "user"
    assert identities[1]["tenant"] == "tenant-a"
    assert identities[1]["secret"] == vault.get_actor_secret("user_a").reveal_for_request()


def test_setup_request_construction():
    vault = IdentityVault("run-abc", ["user_a", "admin_a"])
    cfg = _make_local_app_cfg("http://127.0.0.1:3000")
    req = build_setup_request(cfg, vault)

    assert req.area == "identity_setup"
    assert req.check_id == "setup"
    assert req.method == "POST"
    assert req.path == "/__vibe_test__/identities"
    assert req.headers == {"Content-Type": "application/json"}

    # Body is valid JSON matching payload
    data = json.loads(req.body)
    assert data["schema"] == "vibe-identity-setup/1"
    assert data["run_id"] == "run-abc"
    assert data["expires_in_seconds"] == 180


# ── 2. Success Validation (200 and 201) ────────────────────────────────────────


@pytest.mark.parametrize("status_mode", ["success_200", "success_201"])
def test_setup_hook_success_200_and_201(status_mode):
    actors = ["admin_a", "user_a"]
    vault = IdentityVault("run-ok-1", actors)
    server = _SetupServer("run-ok-1", actors, mode=status_mode)
    try:
        cfg = _make_local_app_cfg(server.url)
        plan = NativePlan(
            identity_setup_count=1,
            areas={
                "authentication": AreaPlan(
                    configured=True,
                    requests_count=1,
                    budget=9,
                    requests=[
                        PlannedRequest(area="authentication", check_id="A1", path="/account")
                    ],
                )
            },
            total_verification_requests=1,
        )

        executor = NativeExecutor(cfg, vault=vault)
        result = executor.execute_plan(plan)

        assert result.status == "EXECUTED"
        assert result.setup_result is not None
        assert result.setup_result.succeeded is True
        assert result.setup_result.adapter == "http-local"
        assert result.setup_result.path == "/__vibe_test__/identities"
        assert result.setup_result.run_id == "run-ok-1"
        assert result.setup_result.accepted == ["admin_a", "user_a"]

        # Exactly 1 setup request, then verification request ran
        assert result.requests_sent == 2
        paths = [item[1] for item in server.requests_log]
        assert paths == ["/__vibe_test__/identities", "/account"]
    finally:
        server.close()


def test_exactly_one_setup_request_sent():
    actors = ["admin_a", "user_a"]
    vault = IdentityVault("run-single-setup", actors)
    server = _SetupServer("run-single-setup", actors, mode="success_200")
    try:
        cfg = _make_local_app_cfg(server.url)
        plan = NativePlan(
            identity_setup_count=1,
            areas={
                "authentication": AreaPlan(
                    configured=True,
                    requests_count=2,
                    budget=9,
                    requests=[
                        PlannedRequest(area="authentication", check_id="A1", path="/a1"),
                        PlannedRequest(area="authentication", check_id="A2", path="/a2"),
                    ],
                ),
                "authorization": AreaPlan(
                    configured=True,
                    requests_count=1,
                    budget=2,
                    requests=[
                        PlannedRequest(area="authorization", check_id="Z1", path="/z1"),
                    ],
                ),
            },
            total_verification_requests=3,
        )

        executor = NativeExecutor(cfg, vault=vault)
        result = executor.execute_plan(plan)

        assert result.status == "EXECUTED"
        assert result.requests_sent == 4  # 1 setup + 3 verification
        setup_calls = [item for item in server.requests_log if item[1] == "/__vibe_test__/identities"]
        assert len(setup_calls) == 1
    finally:
        server.close()


# ── 3. Failure Validation ──────────────────────────────────────────────────────


def test_setup_hook_non_200_201_fails():
    actors = ["admin_a", "user_a"]
    vault = IdentityVault("run-err-500", actors)
    server = _SetupServer("run-err-500", actors, mode="status_500")
    try:
        cfg = _make_local_app_cfg(server.url)
        plan = NativePlan(
            identity_setup_count=1,
            areas={
                "authentication": AreaPlan(
                    configured=True,
                    requests_count=1,
                    budget=9,
                    requests=[
                        PlannedRequest(area="authentication", check_id="A1", path="/account")
                    ],
                )
            },
            total_verification_requests=1,
        )

        executor = NativeExecutor(cfg, vault=vault)
        result = executor.execute_plan(plan)

        assert result.status == "INCOMPLETE"
        assert result.setup_result is not None
        assert result.setup_result.succeeded is False
        assert "500" in result.setup_result.error

        # Verification requests prevented!
        assert result.area("authentication").status == "INCOMPLETE"
        assert result.requests_sent == 1
        paths = [item[1] for item in server.requests_log]
        assert paths == ["/__vibe_test__/identities"]
        assert "/account" not in paths
    finally:
        server.close()


def test_setup_hook_mismatched_run_id_fails():
    actors = ["admin_a", "user_a"]
    vault = IdentityVault("my-expected-run-id", actors)
    server = _SetupServer("my-expected-run-id", actors, mode="wrong_run_id")
    try:
        cfg = _make_local_app_cfg(server.url)
        plan = NativePlan(
            identity_setup_count=1,
            areas={
                "authentication": AreaPlan(
                    configured=True,
                    requests_count=1,
                    budget=9,
                    requests=[
                        PlannedRequest(area="authentication", check_id="A1", path="/account")
                    ],
                )
            },
            total_verification_requests=1,
        )

        executor = NativeExecutor(cfg, vault=vault)
        result = executor.execute_plan(plan)

        assert result.status == "INCOMPLETE"
        assert result.setup_result.succeeded is False
        assert "run_id mismatch" in result.setup_result.error
        assert result.area("authentication").status == "INCOMPLETE"
        assert result.requests_sent == 1
    finally:
        server.close()


def test_setup_hook_mismatched_labels_fails():
    actors = ["admin_a", "user_a"]
    vault = IdentityVault("run-labels-test", actors)

    # Sub-case A: Missing an expected actor
    server_missing = _SetupServer("run-labels-test", actors, mode="missing_actor")
    try:
        cfg = _make_local_app_cfg(server_missing.url)
        plan = NativePlan(
            identity_setup_count=1,
            areas={
                "authentication": AreaPlan(
                    configured=True,
                    requests_count=1,
                    budget=9,
                    requests=[
                        PlannedRequest(area="authentication", check_id="A1", path="/account")
                    ],
                )
            },
            total_verification_requests=1,
        )
        executor = NativeExecutor(cfg, vault=vault)
        result = executor.execute_plan(plan)

        assert result.status == "INCOMPLETE"
        assert result.setup_result.succeeded is False
        assert "accepted labels mismatch" in result.setup_result.error
        assert result.requests_sent == 1
    finally:
        server_missing.close()

    # Sub-case B: Extra uninvited actor
    server_extra = _SetupServer("run-labels-test", actors, mode="extra_actor")
    try:
        cfg = _make_local_app_cfg(server_extra.url)
        plan = NativePlan(
            identity_setup_count=1,
            areas={
                "authentication": AreaPlan(
                    configured=True,
                    requests_count=1,
                    budget=9,
                    requests=[
                        PlannedRequest(area="authentication", check_id="A1", path="/account")
                    ],
                )
            },
            total_verification_requests=1,
        )
        executor = NativeExecutor(cfg, vault=vault)
        result = executor.execute_plan(plan)

        assert result.status == "INCOMPLETE"
        assert result.setup_result.succeeded is False
        assert "accepted labels mismatch" in result.setup_result.error
        assert result.requests_sent == 1
    finally:
        server_extra.close()


def test_setup_hook_extra_fields_in_response_rejected():
    actors = ["admin_a", "user_a"]
    vault = IdentityVault("run-extra-fields", actors)
    server = _SetupServer("run-extra-fields", actors, mode="extra_fields")
    try:
        cfg = _make_local_app_cfg(server.url)
        plan = NativePlan(
            identity_setup_count=1,
            areas={
                "authentication": AreaPlan(
                    configured=True,
                    requests_count=1,
                    budget=9,
                    requests=[
                        PlannedRequest(area="authentication", check_id="A1", path="/account")
                    ],
                )
            },
            total_verification_requests=1,
        )

        executor = NativeExecutor(cfg, vault=vault)
        result = executor.execute_plan(plan)

        assert result.status == "INCOMPLETE"
        assert result.setup_result.succeeded is False
        assert "schema violation" in result.setup_result.error
        assert "unexpected extra keys" in result.setup_result.error
        assert result.requests_sent == 1
    finally:
        server.close()


def test_setup_hook_wrong_schema_rejected():
    actors = ["admin_a", "user_a"]
    vault = IdentityVault("run-wrong-schema", actors)
    server = _SetupServer("run-wrong-schema", actors, mode="wrong_schema")
    try:
        cfg = _make_local_app_cfg(server.url)
        plan = NativePlan(
            identity_setup_count=1,
            areas={
                "authentication": AreaPlan(
                    configured=True,
                    requests_count=1,
                    budget=9,
                    requests=[
                        PlannedRequest(area="authentication", check_id="A1", path="/account")
                    ],
                )
            },
            total_verification_requests=1,
        )

        executor = NativeExecutor(cfg, vault=vault)
        result = executor.execute_plan(plan)

        assert result.status == "INCOMPLETE"
        assert result.setup_result.succeeded is False
        assert "schema mismatch" in result.setup_result.error
        assert result.requests_sent == 1
    finally:
        server.close()


def test_setup_hook_timeout_prevents_later_verification_requests():
    actors = ["admin_a", "user_a"]
    vault = IdentityVault("run-timeout-setup", actors)
    server = _SetupServer("run-timeout-setup", actors, mode="timeout")
    try:
        cfg = _make_local_app_cfg(server.url)
        plan = NativePlan(
            identity_setup_count=1,
            areas={
                "authentication": AreaPlan(
                    configured=True,
                    requests_count=1,
                    budget=9,
                    requests=[
                        PlannedRequest(area="authentication", check_id="A1", path="/account")
                    ],
                )
            },
            total_verification_requests=1,
        )

        # 0.1s request timeout against 0.4s server sleep
        executor = NativeExecutor(cfg, vault=vault, request_timeout=0.1)
        result = executor.execute_plan(plan)

        assert result.status == "INCOMPLETE"
        assert result.timed_out is True
        assert result.setup_result.succeeded is False
        assert "timeout" in result.setup_result.error.lower()

        # Verification requests prevented
        assert result.area("authentication").status == "INCOMPLETE"
        assert result.requests_sent == 1
    finally:
        server.close()


def test_setup_hook_network_failure_prevents_later_verification():
    actors = ["admin_a", "user_a"]
    vault = IdentityVault("run-refused", actors)
    # Target port with no server listening
    cfg = _make_local_app_cfg("http://127.0.0.1:65530")
    plan = NativePlan(
        identity_setup_count=1,
        areas={
            "authentication": AreaPlan(
                configured=True,
                requests_count=1,
                budget=9,
                requests=[
                    PlannedRequest(area="authentication", check_id="A1", path="/account")
                ],
            )
        },
        total_verification_requests=1,
    )

    executor = NativeExecutor(cfg, vault=vault)
    result = executor.execute_plan(plan)

    assert result.status == "INCOMPLETE"
    assert result.setup_result.succeeded is False
    assert "connection error" in result.setup_result.error.lower()
    assert result.area("authentication").status == "INCOMPLETE"


# ── 4. Security & Boundary Rules ───────────────────────────────────────────────


def test_fixture_mode_does_not_send_setup():
    cfg = parse(
        {
            "target": {
                "base_url": "http://127.0.0.1:3000",
                "environment": "local",
                "production": False,
            },
            "runtime_verification": {
                "mode": "fixture",
                "allowed_targets": ["http://127.0.0.1:3000"],
                "actors": {"user_a": {"role": "user"}},
                "routes": {"protected": {"path": "/account", "marker": "m"}},
            },
        }
    )
    plan = build_plan(cfg)
    assert plan.identity_setup_count == 0
    assert len(plan.setup_requests) == 0

    # If setup request is explicitly added to a fixture plan, executor refuses
    plan.setup_requests = [
        PlannedRequest(area="identity_setup", check_id="setup", path="/setup")
    ]
    executor = NativeExecutor(cfg)
    result = executor.execute_plan(plan)

    assert result.status == "INCOMPLETE"
    assert result.refused is True
    assert "fixture mode must not use identity setup hook" in result.refusal_reason


def test_remote_or_production_setup_refused():
    cfg = parse(
        {
            "target": {
                "base_url": "http://127.0.0.1:3000",
                "environment": "production",
                "production": True,
            },
            "runtime_verification": {
                "mode": "local-app",
                "allowed_targets": ["http://127.0.0.1:3000"],
                "identity_setup": {"adapter": "http-local", "path": "/setup"},
            },
        }
    )
    plan = NativePlan(identity_setup_count=1)
    executor = NativeExecutor(cfg)
    result = executor.execute_plan(plan)

    assert result.status == "INCOMPLETE"
    assert result.refused is True
    assert result.requests_sent == 0
    assert "safety gate refused" in result.refusal_reason.lower()


def test_setup_payload_and_secret_leakage_protections():
    actors = ["admin_a", "user_a"]
    vault = IdentityVault("run-leak-audit", actors)
    server = _SetupServer("run-leak-audit", actors, mode="success_200")
    try:
        cfg = _make_local_app_cfg(server.url)
        plan = NativePlan(identity_setup_count=1)
        executor = NativeExecutor(cfg, vault=vault)
        result = executor.execute_plan(plan)

        assert result.status == "EXECUTED"
        setup_res = result.setup_result
        assert setup_res.succeeded is True

        # Check representation for secret leakage
        secret_user = vault.get_actor_secret("user_a").reveal_for_request()
        secret_admin = vault.get_actor_secret("admin_a").reveal_for_request()

        res_repr = repr(result)
        setup_repr = repr(setup_res)

        assert secret_user not in res_repr
        assert secret_admin not in res_repr
        assert secret_user not in setup_repr
        assert secret_admin not in setup_repr

        # Check that response body was discarded
        setup_req_res = result.all_request_results[0]
        assert setup_req_res.response.body == ""
    finally:
        server.close()


def test_server_echoing_secret_is_rejected_as_security_violation():
    actors = ["admin_a", "user_a"]
    vault = IdentityVault("run-echo-secret", actors)
    server = _SetupServer("run-echo-secret", actors, mode="echo_secrets")
    try:
        cfg = _make_local_app_cfg(server.url)
        plan = NativePlan(identity_setup_count=1)
        executor = NativeExecutor(cfg, vault=vault)
        result = executor.execute_plan(plan)

        assert result.status == "INCOMPLETE"
        assert result.setup_result.succeeded is False
        assert "echoes synthetic secret" in result.setup_result.error
    finally:
        server.close()


def test_local_app_without_identity_setup_marks_all_areas_not_configured():
    cfg = _make_local_app_cfg("http://127.0.0.1:3000", with_setup=False)
    plan = build_plan(cfg)

    assert plan.identity_setup_count == 0
    assert len(plan.setup_requests) == 0
    for area_name in ["authentication", "session", "authorization", "idor_bola", "tenant_isolation"]:
        assert not plan.areas[area_name].configured
        assert "missing identity_setup" in plan.areas[area_name].reason
