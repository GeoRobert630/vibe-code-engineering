import pytest
from runtime_security.config import parse
from runtime_security.native.plan import build_plan

def test_plan_all_areas_configured():
    data = {
        "target": {"base_url": "http://127.0.0.1:3000", "environment": "local", "production": False},
        "authentication": {
            "enabled": True,
            "login": {"method": "POST", "path": "/login", "username_field": "u", "password_field": "p"},
            "protected_endpoint": {"method": "GET", "path": "/protected"},
            "logout": {"enabled": True, "method": "POST", "path": "/logout"}
        },
        "runtime_verification": {
            "mode": "fixture",
            "allowed_targets": ["http://127.0.0.1:3000"],
            "actors": {
                "user_a": {"role": "user", "tenant": "tenant-a"},
                "user_b": {"role": "user", "tenant": "tenant-b"},
                "admin_a": {"role": "admin", "tenant": "tenant-a"}
            },
            "routes": {
                "protected": {"path": "/account", "marker": "account"},
                "privileged": {"path": "/admin", "marker": "admin"}
            },
            "resources": [
                {"id": "o1", "path": "/o1", "marker": "o1", "owner": "user_a"},
                {"id": "o2", "path": "/o2", "marker": "o2", "owner": "user_b"},
                {"id": "t1", "path": "/t1", "marker": "t1", "tenant": "tenant-a"},
                {"id": "t2", "path": "/t2", "marker": "t2", "tenant": "tenant-b"}
            ],
            "deny_statuses": [401, 403, 404]
        }
    }
    cfg = parse(data)
    plan = build_plan(cfg)
    
    assert not plan.is_over_budget
    assert plan.areas["authentication"].configured
    # 2 (A1,A2) + 3 (A3x3) + 1 (A4) + 2 (A5,A6) = 8
    assert plan.areas["authentication"].requests_count == 8
    assert plan.areas["session"].configured
    assert plan.areas["authorization"].configured
    assert plan.areas["idor_bola"].configured
    assert plan.areas["tenant_isolation"].configured
    
    assert plan.total_verification_requests == 8 + 1 + 2 + 4 + 4

def test_plan_prerequisites_missing():
    data = {
        "target": {"base_url": "http://127.0.0.1:3000", "environment": "local", "production": False},
        "runtime_verification": {
            "mode": "fixture",
            "allowed_targets": ["http://127.0.0.1:3000"],
            "actors": {
                "user_a": {"role": "user"}
            },
            "routes": {
                "protected": {"path": "/account", "marker": "account"}
            },
            "resources": [],
            "deny_statuses": []
        }
    }
    cfg = parse(data)
    plan = build_plan(cfg)
    
    # Auth and Session should be configured (5 requests: A1, A2, A3x1, A4. No logout=4 reqs. Wait, 4 requests).
    assert plan.areas["authentication"].configured
    assert plan.areas["authentication"].requests_count == 4
    
    # Others should not be configured
    assert not plan.areas["authorization"].configured
    assert not plan.areas["idor_bola"].configured
    assert not plan.areas["tenant_isolation"].configured
