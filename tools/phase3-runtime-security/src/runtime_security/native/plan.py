from dataclasses import dataclass, field
from typing import List, Dict, Set, Any
from ..config import Config
from .identity import SecretValue

@dataclass
class PlannedRequest:
    area: str
    check_id: str
    method: str = "GET"
    path: str = "/"
    headers: Dict[str, Any] = field(default_factory=dict)
    body: bytes | str | None = None
    actor: str | None = None
    expected: str = "allowed"
    marker: str | None = None

@dataclass
class AreaPlan:
    configured: bool
    reason: str = ""
    requests_count: int = 0
    budget: int = 0
    requests: List[PlannedRequest] = field(default_factory=list)

@dataclass
class NativePlan:
    areas: Dict[str, AreaPlan] = field(default_factory=dict)
    identity_setup_count: int = 0
    setup_requests: List[PlannedRequest] = field(default_factory=list)
    total_verification_requests: int = 0
    total_budget: int = 20
    is_over_budget: bool = False

def build_plan(cfg: Config) -> NativePlan:
    plan = NativePlan()
    rv = cfg.runtime_verification
    if not rv:
        # All areas are NOT CONFIGURED if runtime_verification is missing
        for area in ["authentication", "session", "authorization", "idor_bola", "tenant_isolation", "csrf"]:
            plan.areas[area] = AreaPlan(False, "runtime_verification not configured")
        plan.total_budget = 20
        return plan

    # Dynamic total budget: 27 in fixture, 28 in local-app with CSRF; 20 / 21 without CSRF
    has_csrf_config = bool(rv.csrf)
    if has_csrf_config:
        plan.total_budget = 28 if rv.mode == "local-app" else 27
    else:
        plan.total_budget = 21 if rv.mode == "local-app" else 20

    # 1. Identity setup
    if rv.mode == "local-app":
        if not rv.identity_setup:
            for area in ["authentication", "session", "authorization", "idor_bola", "tenant_isolation", "csrf"]:
                plan.areas[area] = AreaPlan(False, "missing identity_setup in local-app mode")
            plan.identity_setup_count = 0
            return plan
        plan.identity_setup_count = 1
    else:
        plan.identity_setup_count = 0

    actors = rv.actors
    users = [k for k, v in actors.items() if v.role == "user"]
    admins = [k for k, v in actors.items() if v.role == "admin"]
    
    # Pre-calculate counts based on actors
    # Auth: A1(1), A2(1), A3(1 per actor), A4(1), A5(1 if logout), A6(1 if logout)
    # But wait, A4, A5, A6 are for a specific user (user_a).
    # The design says 9 total max. A1(1)+A2(1)+A3(4)+A4(1)+A5(1)+A6(1) = 9
    
    # Check prerequisites
    # Authentication & Session
    has_user = len(users) >= 1
    has_protected = "protected" in rv.routes
    
    # Auth logic
    if has_user and has_protected:
        from .auth import build_auth_requests

        auth_requests = build_auth_requests(cfg)
        count = len(auth_requests)
        plan.areas["authentication"] = AreaPlan(
            configured=True,
            reason="",
            requests_count=count,
            budget=9,
            requests=auth_requests,
        )
        # Session S2 is 1 request (S1, S3-S6 reuse Auth requests)
        from .session import build_session_requests
        session_requests = build_session_requests(cfg)
        session_count = len(session_requests)
        plan.areas["session"] = AreaPlan(True, "", session_count, 1, session_requests)
    else:
        reason = "missing user actor or protected route"
        plan.areas["authentication"] = AreaPlan(False, reason)
        plan.areas["session"] = AreaPlan(False, reason)

    # Authorization
    has_admin = len(admins) >= 1
    has_privileged = "privileged" in rv.routes
    if has_user and has_admin and has_privileged:
        from .authz import build_authz_requests

        authz_requests = build_authz_requests(cfg)
        count = len(authz_requests)
        plan.areas["authorization"] = AreaPlan(True, "", count, 2, authz_requests)
    else:
        plan.areas["authorization"] = AreaPlan(False, "missing user, admin, or privileged route")

    # IDOR/BOLA
    # Two user actors that own declared objects
    owners = set(res.owner for res in rv.resources if res.owner)
    users_with_objects = [u for u in users if u in owners]
    if len(users_with_objects) >= 2:
        from .idor import build_idor_requests

        idor_requests = build_idor_requests(cfg)
        count = len(idor_requests)
        plan.areas["idor_bola"] = AreaPlan(True, "", count, 4, idor_requests)
    else:
        plan.areas["idor_bola"] = AreaPlan(False, "missing two user actors with declared objects")

    # Tenant isolation
    # One actor in each of two tenants, each with a declared tenant resource
    tenant_actors: dict[str, list[str]] = {}
    for a, acfg in sorted(actors.items()):
        if acfg.tenant:
            tenant_actors.setdefault(acfg.tenant, []).append(a)

    tenants_with_resources = set(res.tenant for res in rv.resources if res.tenant)
    tenants_ready = [t for t in sorted(tenant_actors) if t in tenants_with_resources and tenant_actors[t]]
    if len(tenants_ready) >= 2:
        from .tenant import build_tenant_requests

        tenant_requests = build_tenant_requests(cfg)
        count = len(tenant_requests)
        plan.areas["tenant_isolation"] = AreaPlan(True, "", count, 4, tenant_requests)
    else:
        plan.areas["tenant_isolation"] = AreaPlan(False, "missing actors/resources in two distinct tenants")

    # CSRF
    if rv.csrf:
        if has_user:
            from .csrf import build_csrf_requests

            csrf_requests = build_csrf_requests(cfg)
            count = len(csrf_requests)
            plan.areas["csrf"] = AreaPlan(True, "", count, 7, csrf_requests)
        else:
            plan.areas["csrf"] = AreaPlan(False, "missing user actor for csrf")
    else:
        plan.areas["csrf"] = AreaPlan(False, "csrf not configured")

    for area, p in plan.areas.items():
        if p.configured:
            plan.total_verification_requests += p.requests_count
            
    if plan.total_verification_requests > plan.total_budget:
        plan.is_over_budget = True

    return plan
