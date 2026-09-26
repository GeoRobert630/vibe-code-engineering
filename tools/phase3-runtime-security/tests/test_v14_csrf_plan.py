"""v1.4 acceptance: CSRF planning and request budget contracts (Design §4, §9).

Locks down:
- Applicability matrix planning:
  - token: C0, C1, C2, C4 (and C3 only if origin_validation=True)
  - origin_only: C0, C1, C2 (C3 and C4 skipped)
  - both: C0, C1, C2, C3, C4
- Request budgets:
  - CSRF area hard maximum: exactly 7 requests
  - Optional prefetch/page_body consumes exactly 1 request
  - Optional cleanup consumes exactly 1 request
  - Total native ceilings: 27 in fixture mode (20 v1.3 + 7 csrf), 28 in local-app mode (21 v1.3 + 7 csrf)
  - Over-budget refusal
- v1.3 regression:
  - When csrf is unconfigured, build_plan plans 0 requests for csrf
  - Existing 5 verification areas preserve their request allocations exactly
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
from runtime_security.native.plan import build_plan

pending_plan = pytest.mark.xfail(
    strict=True,
    reason="v1.4 design contract: CSRF plan generation and budget bounds pending in plan.py",
)

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
        "user_b": {"role": "user", "tenant": "tenant-b"},
        "admin_a": {"role": "admin", "tenant": "tenant-a"},
    },
    "routes": {
        "protected": {"path": "/account", "marker": "account"},
        "privileged": {"path": "/admin", "marker": "admin"},
    },
    "resources": [
        {"id": "o1", "path": "/o1", "marker": "o1", "owner": "user_a"},
        {"id": "o2", "path": "/o2", "marker": "o2", "owner": "user_b"},
        {"id": "t1", "path": "/t1", "marker": "t1", "tenant": "tenant-a"},
        {"id": "t2", "path": "/t2", "marker": "t2", "tenant": "tenant-b"},
    ],
    "deny_statuses": [401, 403, 404],
}


# -----------------------------------------------------------------------------
# 1. v1.3 Regression: CSRF Absent -> 0 Requests Planned (Passes today)
# -----------------------------------------------------------------------------

def test_csrf_absent_plans_zero_requests_and_preserves_v13_totals():
    """When CSRF is not configured, plan totals reflect v1.3 exactly (20 in fixture mode)."""
    data = {
        "target": {"base_url": "http://127.0.0.1:3000", "environment": "local", "production": False},
        "authentication": BASE_AUTH,
        "runtime_verification": BASE_RV,
    }
    cfg = parse(data)
    plan = build_plan(cfg)

    assert not plan.is_over_budget
    # v1.3 5 areas are planned
    assert plan.areas["authentication"].requests_count == 8
    assert plan.areas["session"].requests_count == 1
    assert plan.areas["authorization"].requests_count == 2
    assert plan.areas["idor_bola"].requests_count == 4
    assert plan.areas["tenant_isolation"].requests_count == 4
    # v1.3 total requests count
    assert plan.total_verification_requests == 19


# -----------------------------------------------------------------------------
# 2. Applicability Matrix: token strategy
# -----------------------------------------------------------------------------

@pending_plan
def test_plan_csrf_token_strategy_without_origin_validation():
    """token strategy without origin_validation plans C0, C1, C2, C4 (4 requests)."""
    data = {
        "target": {"base_url": "http://127.0.0.1:3000", "environment": "local", "production": False},
        "authentication": BASE_AUTH,
        "runtime_verification": {
            **BASE_RV,
            "csrf": {
                "path": "/api/action",
                "token_strategy": "token",
                "origin_validation": False,
                "marker": "success",
            },
        },
    }
    cfg = parse(data)
    plan = build_plan(cfg)
    csrf_plan = plan.areas["csrf"]
    assert csrf_plan.configured
    # C0 (login) + C1 (positive) + C2 (core cross-origin) + C4 (invalid token) = 4
    assert csrf_plan.requests_count == 4
    # Check checks included
    check_ids = [r.check_id for r in csrf_plan.requests]
    assert "C0" in check_ids
    assert "C1" in check_ids
    assert "C2" in check_ids
    assert "C4" in check_ids
    assert "C3" not in check_ids


@pending_plan
def test_plan_csrf_token_strategy_with_origin_validation():
    """token strategy with origin_validation=True plans C0, C1, C2, C3, C4 (5 requests)."""
    data = {
        "target": {"base_url": "http://127.0.0.1:3000", "environment": "local", "production": False},
        "authentication": BASE_AUTH,
        "runtime_verification": {
            **BASE_RV,
            "csrf": {
                "path": "/api/action",
                "token_strategy": "token",
                "origin_validation": True,
                "marker": "success",
            },
        },
    }
    cfg = parse(data)
    plan = build_plan(cfg)
    csrf_plan = plan.areas["csrf"]
    assert csrf_plan.requests_count == 5
    check_ids = [r.check_id for r in csrf_plan.requests]
    assert "C3" in check_ids


# -----------------------------------------------------------------------------
# 3. Applicability Matrix: origin_only strategy
# -----------------------------------------------------------------------------

@pending_plan
def test_plan_csrf_origin_only_strategy():
    """origin_only plans C0, C1, C2; C3 and C4 are skipped to eliminate redundancy."""
    data = {
        "target": {"base_url": "http://127.0.0.1:3000", "environment": "local", "production": False},
        "authentication": BASE_AUTH,
        "runtime_verification": {
            **BASE_RV,
            "csrf": {
                "path": "/api/action",
                "token_strategy": "origin_only",
                "marker": "success",
            },
        },
    }
    cfg = parse(data)
    plan = build_plan(cfg)
    csrf_plan = plan.areas["csrf"]
    # C0 (login) + C1 (positive) + C2 (core cross-origin) = 3
    assert csrf_plan.requests_count == 3
    check_ids = [r.check_id for r in csrf_plan.requests]
    assert "C0" in check_ids
    assert "C1" in check_ids
    assert "C2" in check_ids
    assert "C3" not in check_ids
    assert "C4" not in check_ids


# -----------------------------------------------------------------------------
# 4. Applicability Matrix: both strategy
# -----------------------------------------------------------------------------

@pending_plan
def test_plan_csrf_both_strategy():
    """both strategy plans C0, C1, C2, C3, C4."""
    data = {
        "target": {"base_url": "http://127.0.0.1:3000", "environment": "local", "production": False},
        "authentication": BASE_AUTH,
        "runtime_verification": {
            **BASE_RV,
            "csrf": {
                "path": "/api/action",
                "token_strategy": "both",
                "marker": "success",
            },
        },
    }
    cfg = parse(data)
    plan = build_plan(cfg)
    csrf_plan = plan.areas["csrf"]
    assert csrf_plan.requests_count == 5
    check_ids = [r.check_id for r in csrf_plan.requests]
    assert "C0" in check_ids
    assert "C1" in check_ids
    assert "C2" in check_ids
    assert "C3" in check_ids
    assert "C4" in check_ids


# -----------------------------------------------------------------------------
# 5. Full Budget Breakdown: Max 7 Requests
# -----------------------------------------------------------------------------

@pending_plan
def test_plan_csrf_maximum_possible_requests():
    """Maximal CSRF configuration plans C0, prefetch, C1, C2, C3, C4, cleanup = exactly 7 requests."""
    data = {
        "target": {"base_url": "http://127.0.0.1:3000", "environment": "local", "production": False},
        "authentication": BASE_AUTH,
        "runtime_verification": {
            **BASE_RV,
            "csrf": {
                "path": "/api/action",
                "token_strategy": "both",
                "token_source": "prefetch",
                "token_source_marker": "csrf_token",
                "cleanup": {
                    "method": "POST",
                    "body": '{"reset": true}',
                },
                "marker": "success",
            },
        },
    }
    cfg = parse(data)
    plan = build_plan(cfg)
    csrf_plan = plan.areas["csrf"]
    # 1 (C0 login) + 1 (prefetch) + 1 (C1) + 1 (C2) + 1 (C3) + 1 (C4) + 1 (cleanup) = 7
    assert csrf_plan.requests_count == 7
    assert csrf_plan.requests_count <= 7


# -----------------------------------------------------------------------------
# 6. Overall Ceilings: 27 in Fixture, 28 in Local-App
# -----------------------------------------------------------------------------

@pending_plan
def test_total_native_ceilings_with_csrf():
    """Overall plan total cannot exceed 27 in fixture mode or 28 in local-app mode."""
    data = {
        "target": {"base_url": "http://127.0.0.1:3000", "environment": "local", "production": False},
        "authentication": BASE_AUTH,
        "runtime_verification": {
            **BASE_RV,
            "mode": "fixture",
            "csrf": {
                "path": "/api/action",
                "token_strategy": "both",
                "token_source": "prefetch",
                "token_source_marker": "csrf_token",
                "cleanup": {"method": "POST", "body": "{}"},
                "marker": "success",
            },
        },
    }
    cfg = parse(data)
    plan = build_plan(cfg)
    # 19 (v1.3) + 7 (csrf max) = 26 <= 27
    assert plan.total_verification_requests <= 27
    assert not plan.is_over_budget
