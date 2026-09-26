"""Native Tenant Isolation Verification (Design §12, §15, §16, §17).

Implements bounded, deterministic runtime verification for tenant isolation:
- T1: tenant-a actor accesses tenant-a's declared resource-a (positive control 1, expected allowed)
- T2: tenant-a actor accesses tenant-b's declared resource-b (cross-tenant denial 1, expected denied)
- T3: tenant-b actor accesses tenant-b's declared resource-b (positive control 2, expected allowed)
- T4: tenant-b actor accesses tenant-a's declared resource-a (cross-tenant denial 2, expected denied)

Guarantees:
- Declared resources only (rv.resources with declared tenant). No identifier guessing,
  enumeration, tenant header/parameter manipulation, or derivation.
- Uses authenticated tenant-a actor session for T1/T2 and tenant-b actor session for T3/T4.
- Positive-control rule: Both own-tenant positive controls (T1 and T3) must succeed before
  any cross-tenant finding (RT-TENANT-001) can be emitted.
- If an own-tenant positive control fails or is ambiguous, do NOT infer a cross-tenant vulnerability.
- T1 failure gating: stop immediately; do not execute T2/T3/T4.
- T3 failure gating: suppress any T2 cross-tenant finding already observed; mark INCOMPLETE.
- An actual cross-tenant allowed response emits exactly RT-TENANT-001 with severity HIGH/HIGH.
- Ambiguous, timeout, 5xx, or incomplete responses resolve to INCOMPLETE.
- Response classification matches Design §15 (allowed, denied, ambiguous, incomplete).
  "allowed" requires 2xx AND the resource's declared marker present.
- Safe evidence only: no credentials, raw tokens, tenant secrets, or response bodies stored.
- Request counts bounded to hard maximum of 4 requests.
"""

from __future__ import annotations

from typing import Any

from ..config import Config
from ..models import Confidence, Finding, Severity, Status
from ..utils.redaction import clean
from .plan import PlannedRequest

TENANT_NAMESPACE = "RT-TENANT-*"


def build_tenant_requests(cfg: Config) -> list[PlannedRequest]:
    """Construct deterministic planned requests for native tenant isolation verification (Design §12).

    Selection rules (from design §6, §12):
    - Exactly two tenants, each with at least one declared actor and one declared resource.
    - Actors processed in sorted label order (design §23).
    - First actor in sorted order per tenant is used as the representative actor.
    - resource-a: first resource for tenant-a (sorted by resource id).
    - resource-b: first resource for tenant-b (sorted by resource id).
    """
    rv = cfg.runtime_verification
    if not rv:
        return []

    actors = rv.actors

    # Group actors by tenant (actors with a declared tenant only)
    tenant_actor_map: dict[str, list[str]] = {}
    for label, acfg in sorted(actors.items()):
        if acfg.tenant:
            tenant_actor_map.setdefault(acfg.tenant, []).append(label)

    # Need at least 2 tenants each with at least 1 actor
    tenant_ids_with_actors = [t for t, acts in tenant_actor_map.items() if acts]
    if len(tenant_ids_with_actors) < 2:
        return []

    # Sort tenants deterministically to pick tenant-a / tenant-b in a stable order
    sorted_tenants = sorted(tenant_ids_with_actors)
    tenant_a_id = sorted_tenants[0]
    tenant_b_id = sorted_tenants[1]

    # Pick the first actor (sorted) for each tenant, preferring 'user' role so admin_a is never substituted
    user_acts_a = [l for l in tenant_actor_map[tenant_a_id] if actors[l].role == "user"]
    actor_a = user_acts_a[0] if user_acts_a else tenant_actor_map[tenant_a_id][0]

    user_acts_b = [l for l in tenant_actor_map[tenant_b_id] if actors[l].role == "user"]
    actor_b = user_acts_b[0] if user_acts_b else tenant_actor_map[tenant_b_id][0]

    # Find the declared resource for each tenant (sorted by resource id for determinism)
    res_a = None
    res_b = None
    for res in sorted(rv.resources, key=lambda r: r.id):
        if res.tenant == tenant_a_id and res_a is None:
            res_a = res
        if res.tenant == tenant_b_id and res_b is None:
            res_b = res

    if res_a is None or res_b is None:
        return []

    requests: list[PlannedRequest] = [
        # T1: tenant-a actor positive control on tenant-a's resource
        PlannedRequest(
            area="tenant_isolation",
            check_id="T1",
            method="GET",
            path=res_a.path,
            actor=actor_a,
            expected="allowed",
            marker=res_a.marker,
        ),
        # T2: tenant-a actor cross-tenant access to tenant-b's resource
        PlannedRequest(
            area="tenant_isolation",
            check_id="T2",
            method="GET",
            path=res_b.path,
            actor=actor_a,
            expected="denied",
            marker=res_b.marker,
        ),
        # T3: tenant-b actor positive control on tenant-b's resource
        PlannedRequest(
            area="tenant_isolation",
            check_id="T3",
            method="GET",
            path=res_b.path,
            actor=actor_b,
            expected="allowed",
            marker=res_b.marker,
        ),
        # T4: tenant-b actor cross-tenant access to tenant-a's resource
        PlannedRequest(
            area="tenant_isolation",
            check_id="T4",
            method="GET",
            path=res_a.path,
            actor=actor_b,
            expected="denied",
            marker=res_a.marker,
        ),
    ]

    return requests


def make_tenant_finding(
    check_id: str,
    path: str,
    status: int,
    detail: str = "",
    actor: str = "actor",
    target_tenant: str = "",
) -> Finding:
    """Construct deterministic Finding for a tenant isolation violation (Design §17).

    RT-TENANT-001 metadata (design §17):
    - category: tenant_isolation
    - severity: HIGH
    - confidence: HIGH
    - CWE: CWE-639 (Authorization Bypass Through User-Controlled Key)
    - OWASP: A01:2021-Broken Access Control
    - source: native-verification
    """
    if check_id not in ("T2", "T4"):
        raise ValueError(f"Unknown tenant check ID for finding: {check_id}")

    tenant_info = f" belonging to tenant '{target_tenant}'" if target_tenant else ""
    return Finding(
        id="RT-TENANT-001",
        category="tenant_isolation",
        severity=Severity.HIGH,
        confidence=Confidence.HIGH,
        title="Cross-tenant resource access allowed",
        endpoint=f"GET {path}",
        expected="denied",
        actual="allowed",
        evidence=clean(
            detail
            or (
                f"Resource marker returned with HTTP status {status} to unauthorized actor '{actor}'"
                f" on resource{tenant_info}"
            ),
            300,
        ),
        impact=(
            "Unauthorized actors can access resources and data belonging to other tenants "
            "without authorization, breaking multi-tenant isolation"
        ),
        recommendation=(
            "Enforce tenant-level authorization checks to verify the requesting actor's tenant "
            "matches the resource's tenant before granting access"
        ),
        validation=(
            f"Send GET request to {path} using an actor from a different tenant "
            "and verify access is denied (401/403/404)"
        ),
        status=Status.OPEN,
        cwe="CWE-639",
        owasp="A01:2021-Broken Access Control",
        source="native-verification",
    )


def evaluate_tenant_checks(
    check_records: list[dict[str, Any]],
    actor_a: str = "actor_a",
    actor_b: str = "actor_b",
    res_a_path: str = "",
    res_b_path: str = "",
) -> tuple[list[dict[str, Any]], list[Finding], str, str]:
    """Evaluate T1–T4 tenant isolation checks and determine area status and findings.

    Positive-control gating semantics (design §12, §15, §16, §22):
    - T1 positive control must be "allowed" before anything else is evaluated.
      If T1 fails, stop immediately (INCOMPLETE, no findings).
    - T3 positive control must be "allowed" to validate any cross-tenant finding.
      If T3 fails, suppress any T2 finding already observed (INCOMPLETE, no findings).
    - RT-TENANT-001 is emitted only when:
        T1 == allowed AND T3 == allowed AND (T2 == allowed OR T4 == allowed)
    - "allowed" requires 2xx AND declared marker present (design §15).
    - If cross-tenant evidence is ambiguous, resolve to INCOMPLETE rather than guessing.
    - If T2 already proves a violation and T4 later becomes incomplete, the T2 finding
      is NOT erased (analogous to IDOR design—one proven cross-tenant access is sufficient).

    Returns:
        (checks, findings, status, reason)
    """
    findings: list[Finding] = []
    checks_by_id = {c.get("check"): c for c in check_records}

    t1 = checks_by_id.get("T1")
    t2 = checks_by_id.get("T2")
    t3 = checks_by_id.get("T3")
    t4 = checks_by_id.get("T4")

    # 1. Verify positive control T1 (tenant-a actor on own resource)
    if t1 is None:
        return check_records, findings, "INCOMPLETE", "positive control T1 not executed"
    if t1.get("classification") != "allowed":
        return (
            check_records,
            findings,
            "INCOMPLETE",
            f"own-tenant positive control T1 failed (classification={t1.get('classification')})",
        )

    # 2. Verify positive control T3 (tenant-b actor on own resource)
    if t3 is None:
        return check_records, findings, "INCOMPLETE", "positive control T3 not executed"
    if t3.get("classification") != "allowed":
        # T3 failure: suppress any T2 cross-tenant finding already observed (design §22)
        return (
            check_records,
            findings,
            "INCOMPLETE",
            f"own-tenant positive control T3 failed (classification={t3.get('classification')})",
        )

    # 3. Both positive controls succeeded. Check cross-tenant denials (T2 and T4).
    if t2 is None:
        return check_records, findings, "INCOMPLETE", "cross-tenant check T2 not executed"

    t2_allowed = t2.get("classification") == "allowed"
    t4_allowed = (t4.get("classification") == "allowed") if t4 else False

    if t2_allowed or t4_allowed:
        # Emit RT-TENANT-001 for the first cross-tenant violation found
        if t2_allowed:
            finding = make_tenant_finding(
                check_id="T2",
                path=res_b_path or t2.get("path", "/tenants/tenant-b/resource-b"),
                status=t2.get("status", 200),
                actor=actor_a,
                target_tenant=actor_b,  # the tenant whose resource was accessed
            )
            findings.append(finding)
        elif t4_allowed:
            finding = make_tenant_finding(
                check_id="T4",
                path=res_a_path or (t4.get("path", "/tenants/tenant-a/resource-a") if t4 else "/tenants/tenant-a/resource-a"),
                status=t4.get("status", 200) if t4 else 200,
                actor=actor_b,
                target_tenant=actor_a,  # the tenant whose resource was accessed
            )
            findings.append(finding)

        return (
            check_records,
            findings,
            "FAIL",
            "cross-tenant resource access allowed (tenant isolation violation)",
        )

    if t4 is None:
        return check_records, findings, "INCOMPLETE", "cross-tenant check T4 not executed"

    # 4. If neither was allowed, verify both were denied
    if t2.get("classification") == "denied" and t4.get("classification") == "denied":
        return (
            check_records,
            findings,
            "PASS",
            "own-tenant positive controls allowed and cross-tenant access denied",
        )

    # 5. Otherwise, ambiguous or incomplete classification
    for cid in ("T2", "T4"):
        c = checks_by_id.get(cid)
        if c and c.get("classification") == "ambiguous":
            return check_records, findings, "INCOMPLETE", f"ambiguous response received for check {cid}"
        if c and c.get("classification") == "incomplete":
            return check_records, findings, "INCOMPLETE", f"incomplete response received for check {cid}"

    return check_records, findings, "INCOMPLETE", "unexpected check classifications in tenant isolation verification"
