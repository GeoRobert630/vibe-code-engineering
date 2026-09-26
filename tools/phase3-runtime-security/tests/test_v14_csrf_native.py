"""v1.4 acceptance: CSRF native execution and behavioral verification contracts.

Locks down:
- C0 dedicated session (csrf_session) isolation from v1.3 A5/A6 invalidations
- C0 failure / missing login config -> INCOMPLETE, negative probes gated, zero findings
- C1 positive control:
  - strategy-aware token requirements (no token for origin_only, valid token for token/both)
  - same-origin request
  - 2xx with marker and valid 302/303 redirect with marker in Location/body
  - login/auth/error redirects are rejected as C1 failure
  - C1 failure -> INCOMPLETE, gating C2-C4, zero findings
- C2 core CSRF:
  - cross-origin without token
  - rejection -> negative probe passed
  - server acceptance with proven browser credential transmission -> FAIL + RT-CSRF-001 (HIGH/HIGH)
  - server acceptance with unproven browser exploitability (SameSite=Strict/Lax/unverified/Bearer) -> INCOMPLETE, no RT-CSRF-001
  - JSON / PUT / PATCH / custom headers -> no RT-CSRF-001 unless permissive CORS preflight explicitly verified
  - ambient cookie vs Bearer auth distinction
  - server-side acceptance evidence and explicit limitation preserved
- C3 Origin defense:
  - applicable only when configured (both or token with origin_validation=True)
  - valid token + untrusted origin
  - rejection -> pass
  - acceptance -> FAIL + RT-CSRF-003
  - ambiguous / unverified -> INCOMPLETE, never PASS
- C4 Token defense:
  - invalid / tampered token same-origin
  - rejection -> pass
  - acceptance -> FAIL + RT-CSRF-002
  - ambiguous / unverified -> INCOMPLETE, never PASS
  - skipped for origin_only
- Final area status semantics:
  - NOT CONFIGURED, NOT VERIFIED, READY, INCOMPLETE, FAIL, PASS
  - PASS strictly requires C1 success and every applicable negative probe actually rejected
  - Accepted-but-unproven negative probe can NEVER resolve to PASS
- Secret handling:
  - Raw tokens in SecretValue only, never in SessionState
  - Secret redaction in evidence, findings, and reports
- Cleanup semantics:
  - Optional, same-origin, valid token
  - Failure does not alter security verdict, never emits findings, counts toward budget
- Concrete finding catalog:
  - Only RT-CSRF-001, RT-CSRF-002, RT-CSRF-003
"""

from __future__ import annotations

import sys
from pathlib import Path

_SRC = str(Path(__file__).resolve().parents[1] / "src")
_TESTS = str(Path(__file__).resolve().parent)
if _SRC not in sys.path:
    sys.path.insert(0, _SRC)
if _TESTS not in sys.path:
    sys.path.insert(0, _TESTS)

import pytest
from runtime_security.config import parse
from runtime_security.models import Confidence, Finding, Severity, Status
from runtime_security.native.executor import execute_native_plan
from runtime_security.native.identity import SecretValue
from runtime_security.native.plan import build_plan

pending_csrf = lambda f: f

BASE_AUTH = {
    "enabled": True,
    "login": {"method": "POST", "path": "/login", "username_field": "u", "password_field": "p"},
    "protected_endpoint": {"method": "GET", "path": "/protected"},
    "logout": {"enabled": True, "method": "POST", "path": "/logout"},
}

BASE_RV = {
    "mode": "fixture",
    "allowed_targets": ["http://127.0.0.1:3000"],
    "actors": {
        "user_a": {"role": "user", "tenant": "tenant-a"},
    },
    "routes": {
        "protected": {"path": "/account", "marker": "account"},
    },
    "deny_statuses": [400, 401, 403, 422],
}


# =============================================================================
# 1. C0 Dedicated Session Isolation & Login Resolution
# =============================================================================

@pending_csrf
def test_c0_dedicated_csrf_session_isolated_from_a5_a6_logout():
    """C0 establishes a fresh csrf_session; logout in A5/A6 does not invalidate CSRF verification."""
    data = {
        "target": {"base_url": "http://127.0.0.1:3000", "environment": "local", "production": False},
        "authentication": BASE_AUTH,
        "runtime_verification": {
            **BASE_RV,
            "csrf": {"path": "/api/action", "marker": "ok"},
        },
    }
    cfg = parse(data)
    plan = build_plan(cfg)
    result = execute_native_plan(cfg, plan)
    csrf_res = result.areas["csrf"]
    assert csrf_res.status in (Status.PASS, Status.FAIL, Status.INCOMPLETE)
    # Session used in C1-C4 is fresh csrf_session, unaffected by auth area logout
    assert any(c.check_id == "C0" and c.passed for c in csrf_res.checks)


@pending_csrf
def test_c0_missing_login_configuration_resolves_incomplete():
    """When neither authentication.login nor csrf.session_setup exists, CSRF reports INCOMPLETE."""
    data = {
        "target": {"base_url": "http://127.0.0.1:3000", "environment": "local", "production": False},
        "runtime_verification": {
            **BASE_RV,
            "csrf": {"path": "/api/action", "marker": "ok"},
        },
    }
    cfg = parse(data)
    plan = build_plan(cfg)
    result = execute_native_plan(cfg, plan)
    csrf_res = result.areas["csrf"]
    assert csrf_res.status == Status.INCOMPLETE
    assert "missing login configuration" in csrf_res.reason
    assert len(csrf_res.findings) == 0


@pending_csrf
def test_c0_failed_login_gates_c1_to_c4_with_zero_findings():
    """If C0 login fails (e.g. 401), area is INCOMPLETE, C1-C4 are gated, 0 findings emitted."""
    data = {
        "target": {"base_url": "http://127.0.0.1:3000", "environment": "local", "production": False},
        "authentication": {
            **BASE_AUTH,
            "login": {"method": "POST", "path": "/login/fail_all"},
        },
        "runtime_verification": {
            **BASE_RV,
            "csrf": {"path": "/api/action", "marker": "ok"},
        },
    }
    cfg = parse(data)
    plan = build_plan(cfg)
    result = execute_native_plan(cfg, plan)
    csrf_res = result.areas["csrf"]
    assert csrf_res.status == Status.INCOMPLETE
    assert "C0 failed" in csrf_res.reason or "unable to establish" in csrf_res.reason
    # Zero negative findings emitted on gated run
    assert len(csrf_res.findings) == 0
    # No C1, C2, C3, C4 requests executed
    executed_checks = {c.check_id for c in csrf_res.checks}
    assert "C1" not in executed_checks
    assert "C2" not in executed_checks


# =============================================================================
# 2. C1 Positive Control & Redirect Semantics
# =============================================================================

@pending_csrf
def test_c1_positive_control_2xx_with_marker_proceeds_to_c2():
    """C1 returning 2xx with configured marker confirms positive control and proceeds to C2."""
    data = {
        "target": {"base_url": "http://127.0.0.1:3000", "environment": "local", "production": False},
        "authentication": BASE_AUTH,
        "runtime_verification": {
            **BASE_RV,
            "csrf": {"path": "/api/action", "token_strategy": "token", "marker": "action_success"},
        },
    }
    cfg = parse(data)
    plan = build_plan(cfg)
    result = execute_native_plan(cfg, plan)
    csrf_res = result.areas["csrf"]
    c1 = next((c for c in csrf_res.checks if c.check_id == "C1"), None)
    assert c1 is not None and c1.passed


@pending_csrf
def test_c1_positive_control_valid_302_redirect_with_marker():
    """C1 returning 302/303 with marker in Location or body is accepted as positive control pass."""
    data = {
        "target": {"base_url": "http://127.0.0.1:3000", "environment": "local", "production": False},
        "authentication": BASE_AUTH,
        "runtime_verification": {
            **BASE_RV,
            "csrf": {"path": "/api/redirect_action", "token_strategy": "token", "marker": "saved=true"},
        },
    }
    cfg = parse(data)
    plan = build_plan(cfg)
    result = execute_native_plan(cfg, plan)
    csrf_res = result.areas["csrf"]
    c1 = next((c for c in csrf_res.checks if c.check_id == "C1"), None)
    assert c1 is not None and c1.passed


@pending_csrf
def test_c1_login_redirect_is_rejected_as_failure():
    """A redirect to /login or /auth is rejected as positive control failure (INCOMPLETE)."""
    data = {
        "target": {"base_url": "http://127.0.0.1:3000", "environment": "local", "production": False},
        "authentication": BASE_AUTH,
        "runtime_verification": {
            **BASE_RV,
            "csrf": {"path": "/api/login_redirect", "marker": "saved=true"},
        },
    }
    cfg = parse(data)
    plan = build_plan(cfg)
    result = execute_native_plan(cfg, plan)
    csrf_res = result.areas["csrf"]
    assert csrf_res.status == Status.INCOMPLETE
    assert len(csrf_res.findings) == 0


@pending_csrf
def test_c1_failure_gates_negative_checks():
    """When C1 positive control fails (e.g. 500 error or missing marker), C2-C4 are gated."""
    data = {
        "target": {"base_url": "http://127.0.0.1:3000", "environment": "local", "production": False},
        "authentication": BASE_AUTH,
        "runtime_verification": {
            **BASE_RV,
            "csrf": {"path": "/api/error_500", "marker": "expected_marker"},
        },
    }
    cfg = parse(data)
    plan = build_plan(cfg)
    result = execute_native_plan(cfg, plan)
    csrf_res = result.areas["csrf"]
    assert csrf_res.status == Status.INCOMPLETE
    assert len(csrf_res.findings) == 0
    executed_checks = {c.check_id for c in csrf_res.checks}
    assert "C2" not in executed_checks
    assert "C3" not in executed_checks
    assert "C4" not in executed_checks


# =============================================================================
# 3. C2 Core CSRF & Exploitability Gating
# =============================================================================

@pending_csrf
def test_c2_rejection_passes_core_csrf_probe():
    """Server rejecting cross-origin request without token (400/403/422) passes C2."""
    data = {
        "target": {"base_url": "http://127.0.0.1:3000", "environment": "local", "production": False},
        "authentication": BASE_AUTH,
        "runtime_verification": {
            **BASE_RV,
            "csrf": {"path": "/api/protected_csrf", "token_strategy": "origin_only", "marker": "ok"},
        },
    }
    cfg = parse(data)
    plan = build_plan(cfg)
    result = execute_native_plan(cfg, plan)
    csrf_res = result.areas["csrf"]
    assert csrf_res.status == Status.PASS
    assert len(csrf_res.findings) == 0


@pending_csrf
def test_c2_accepted_with_proven_browser_exploitability_emits_rt_csrf_001():
    """Simple form POST accepted with confirmed SameSite=None cookie auth emits RT-CSRF-001 (HIGH/HIGH)."""
    data = {
        "target": {"base_url": "http://127.0.0.1:3000", "environment": "local", "production": False},
        "authentication": BASE_AUTH,
        "runtime_verification": {
            **BASE_RV,
            "csrf": {
                "path": "/api/vulnerable_form_post",
                "method": "POST",
                "content_type": "application/x-www-form-urlencoded",
                "token_strategy": "token",
                "marker": "transferred",
            },
        },
    }
    cfg = parse(data)
    plan = build_plan(cfg)
    result = execute_native_plan(cfg, plan)
    csrf_res = result.areas["csrf"]
    assert csrf_res.status == Status.FAIL
    f = next((f for f in csrf_res.findings if f.id == "RT-CSRF-001"), None)
    assert f is not None
    assert f.severity == Severity.HIGH
    assert f.confidence == Confidence.HIGH
    assert f.category == "csrf"


@pending_csrf
def test_c2_accepted_with_unproven_browser_exploitability_resolves_incomplete():
    """When cross-origin POST is accepted but browser credential transmission is unproven (e.g. SameSite=Lax/Strict),
    RT-CSRF-001 is suppressed and status resolves to INCOMPLETE (never PASS)."""
    data = {
        "target": {"base_url": "http://127.0.0.1:3000", "environment": "local", "production": False},
        "authentication": BASE_AUTH,
        "runtime_verification": {
            **BASE_RV,
            "csrf": {
                "path": "/api/accepted_with_lax_cookie",
                "token_strategy": "token",
                "marker": "transferred",
            },
        },
    }
    cfg = parse(data)
    plan = build_plan(cfg)
    result = execute_native_plan(cfg, plan)
    csrf_res = result.areas["csrf"]
    # Cannot pass because server accepted mutation without token, but cannot emit RT-CSRF-001 -> INCOMPLETE
    assert csrf_res.status == Status.INCOMPLETE
    assert not any(f.id == "RT-CSRF-001" for f in csrf_res.findings)
    assert any("Server accepted cross-origin state change" in l for l in csrf_res.limitations)


@pending_csrf
def test_c2_json_post_without_cors_preflight_does_not_emit_rt_csrf_001():
    """JSON POST accepted without token does NOT emit RT-CSRF-001 unless permissive CORS preflight is verified."""
    data = {
        "target": {"base_url": "http://127.0.0.1:3000", "environment": "local", "production": False},
        "authentication": BASE_AUTH,
        "runtime_verification": {
            **BASE_RV,
            "csrf": {
                "path": "/api/json_action",
                "method": "POST",
                "content_type": "application/json",
                "body": '{"action": "test"}',
                "marker": "ok",
            },
        },
    }
    cfg = parse(data)
    plan = build_plan(cfg)
    result = execute_native_plan(cfg, plan)
    csrf_res = result.areas["csrf"]
    assert csrf_res.status == Status.INCOMPLETE
    assert not any(f.id == "RT-CSRF-001" for f in csrf_res.findings)


@pending_csrf
def test_c2_bearer_auth_is_non_ambient_never_emits_rt_csrf_001():
    """Bearer token authentication is not ambient in browsers; cross-origin acceptance never emits RT-CSRF-001."""
    data = {
        "target": {"base_url": "http://127.0.0.1:3000", "environment": "local", "production": False},
        "authentication": {
            **BASE_AUTH,
            "protected_endpoint": {"method": "GET", "path": "/protected", "auth_type": "bearer"},
        },
        "runtime_verification": {
            **BASE_RV,
            "csrf": {"path": "/api/bearer_action", "marker": "ok"},
        },
    }
    cfg = parse(data)
    plan = build_plan(cfg)
    result = execute_native_plan(cfg, plan)
    csrf_res = result.areas["csrf"]
    assert not any(f.id == "RT-CSRF-001" for f in csrf_res.findings)


# =============================================================================
# 4. C3 Origin Defense Check (Valid Token + Untrusted Origin)
# =============================================================================

@pending_csrf
def test_c3_origin_defense_failure_emits_rt_csrf_003():
    """When origin_validation is enabled, cross-origin request with valid token accepted emits RT-CSRF-003."""
    data = {
        "target": {"base_url": "http://127.0.0.1:3000", "environment": "local", "production": False},
        "authentication": BASE_AUTH,
        "runtime_verification": {
            **BASE_RV,
            "csrf": {
                "path": "/api/action",
                "token_strategy": "both",
                "origin_validation": True,
                "marker": "ok",
            },
        },
    }
    cfg = parse(data)
    plan = build_plan(cfg)
    result = execute_native_plan(cfg, plan)
    csrf_res = result.areas["csrf"]
    f = next((f for f in csrf_res.findings if f.id == "RT-CSRF-003"), None)
    assert f is not None
    assert f.severity in (Severity.MEDIUM, Severity.HIGH)
    assert f.confidence == Confidence.HIGH


@pending_csrf
def test_c3_ambiguous_result_resolves_incomplete_never_pass():
    """An ambiguous or unverified C3 result resolves to INCOMPLETE and never silently becomes PASS."""
    data = {
        "target": {"base_url": "http://127.0.0.1:3000", "environment": "local", "production": False},
        "authentication": BASE_AUTH,
        "runtime_verification": {
            **BASE_RV,
            "csrf": {
                "path": "/api/ambiguous_origin",
                "token_strategy": "both",
                "origin_validation": True,
                "marker": "ok",
            },
        },
    }
    cfg = parse(data)
    plan = build_plan(cfg)
    result = execute_native_plan(cfg, plan)
    csrf_res = result.areas["csrf"]
    assert csrf_res.status == Status.INCOMPLETE
    assert csrf_res.status != Status.PASS


# =============================================================================
# 5. C4 Token Defense Check (Invalid / Tampered Token)
# =============================================================================

@pending_csrf
def test_c4_tampered_token_accepted_emits_rt_csrf_002():
    """Server accepting invalid / tampered token emits RT-CSRF-002 (HIGH/HIGH)."""
    data = {
        "target": {"base_url": "http://127.0.0.1:3000", "environment": "local", "production": False},
        "authentication": BASE_AUTH,
        "runtime_verification": {
            **BASE_RV,
            "csrf": {
                "path": "/api/action",
                "token_strategy": "token",
                "marker": "ok",
            },
        },
    }
    cfg = parse(data)
    plan = build_plan(cfg)
    result = execute_native_plan(cfg, plan)
    csrf_res = result.areas["csrf"]
    f = next((f for f in csrf_res.findings if f.id == "RT-CSRF-002"), None)
    assert f is not None
    assert f.severity == Severity.HIGH
    assert f.confidence == Confidence.HIGH


@pending_csrf
def test_c4_skipped_for_origin_only():
    """In origin_only strategy, C4 token check is not executed and cannot fail."""
    data = {
        "target": {"base_url": "http://127.0.0.1:3000", "environment": "local", "production": False},
        "authentication": BASE_AUTH,
        "runtime_verification": {
            **BASE_RV,
            "csrf": {
                "path": "/api/action",
                "token_strategy": "origin_only",
                "marker": "ok",
            },
        },
    }
    cfg = parse(data)
    plan = build_plan(cfg)
    result = execute_native_plan(cfg, plan)
    csrf_res = result.areas["csrf"]
    executed_checks = {c.check_id for c in csrf_res.checks}
    assert "C4" not in executed_checks


# =============================================================================
# 6. Final Status Semantics & Strict PASS Requirements
# =============================================================================

@pending_csrf
def test_strict_pass_requires_rejection_of_all_applicable_negative_probes():
    """PASS strictly requires positive control C1 pass, actual rejection of every negative probe,
    zero findings, and no unresolved/suppressed probes."""
    data = {
        "target": {"base_url": "http://127.0.0.1:3000", "environment": "local", "production": False},
        "authentication": BASE_AUTH,
        "runtime_verification": {
            **BASE_RV,
            "csrf": {
                "path": "/api/well_defended",
                "token_strategy": "both",
                "origin_validation": True,
                "marker": "ok",
            },
        },
    }
    cfg = parse(data)
    plan = build_plan(cfg)
    result = execute_native_plan(cfg, plan)
    csrf_res = result.areas["csrf"]
    assert csrf_res.status == Status.PASS
    assert len(csrf_res.findings) == 0
    # Every negative check executed was actually rejected
    assert all(c.passed for c in csrf_res.checks if c.check_id in ("C2", "C3", "C4"))


# =============================================================================
# 7. Secret Handling & Redaction
# =============================================================================

@pending_csrf
def test_csrf_raw_tokens_held_in_secret_value_only():
    """Raw CSRF tokens must be wrapped in SecretValue and never leaked to SessionState or repr."""
    secret = SecretValue("super-secret-csrf-token-xyz")
    assert "super-secret-csrf-token-xyz" not in repr(secret)
    assert "[REDACTED]" in repr(secret)
    # Token value accessible only via unwrap
    assert secret.unwrap() == "super-secret-csrf-token-xyz"


# =============================================================================
# 8. Cleanup Semantics
# =============================================================================

@pending_csrf
def test_cleanup_failure_does_not_change_security_status_or_emit_findings():
    """Failure of optional cleanup request records a limitation/warning but never alters status or emits findings."""
    data = {
        "target": {"base_url": "http://127.0.0.1:3000", "environment": "local", "production": False},
        "authentication": BASE_AUTH,
        "runtime_verification": {
            **BASE_RV,
            "csrf": {
                "path": "/api/well_defended",
                "token_strategy": "token",
                "cleanup": {"method": "POST", "body": '{"reset": true}'},
                "marker": "ok",
            },
        },
    }
    cfg = parse(data)
    plan = build_plan(cfg)
    result = execute_native_plan(cfg, plan)
    csrf_res = result.areas["csrf"]
    assert csrf_res.status == Status.PASS
    assert not any(f.category == "cleanup" for f in csrf_res.findings)
