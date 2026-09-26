"""Native Authorization Verification (Design §10, §15, §16, §17).

Implements bounded, deterministic runtime verification for the vertical Authorization area:
- Z1: privileged authorization positive control (admin actor GET privileged route)
- Z2: low-privilege authorization denial (user actor GET privileged route)

Guarantees:
- Declared privileged route only (rv.routes["privileged"]).
- Uses authenticated admin actor for Z1 and authenticated user actor for Z2.
- Sends exactly the minimum required requests (hard maximum 2).
- Z1 must be allowed (positive control) for Z2 denial to be evaluated.
- If Z2 is allowed (low-privilege actor served privileged route), emits RT-AUTHZ-001
  with severity HIGH and confidence HIGH.
- Does NOT fabricate findings when positive control or authentication prerequisites fail.
- Response classification: allowed, denied, ambiguous, incomplete.
- Evidence records match Design §15 schema.
- Safe evidence only: no credentials, raw tokens, or response bodies stored.
"""

from __future__ import annotations

from typing import Any

from ..config import Config
from ..models import Confidence, Finding, Severity, Status
from ..utils.redaction import clean
from .plan import PlannedRequest

AUTHZ_NAMESPACE = "RT-AUTHZ-*"


def build_authz_requests(cfg: Config) -> list[PlannedRequest]:
    """Construct deterministic planned requests for native authorization verification (Design §10)."""
    rv = cfg.runtime_verification
    if not rv:
        return []

    privileged_route = rv.routes.get("privileged")
    if not privileged_route:
        return []

    actors = rv.actors
    admins = [k for k, v in sorted(actors.items()) if v.role == "admin"]
    users = [k for k, v in sorted(actors.items()) if v.role == "user"]
    if not admins or not users:
        return []

    admin_actor = admins[0]
    user_actor = users[0]

    privileged_path = privileged_route.path
    privileged_marker = privileged_route.marker

    requests: list[PlannedRequest] = [
        # Z1: privileged authorization positive control
        PlannedRequest(
            area="authorization",
            check_id="Z1",
            method="GET",
            path=privileged_path,
            actor=admin_actor,
            expected="allowed",
            marker=privileged_marker,
        ),
        # Z2: low-privilege authorization denial
        PlannedRequest(
            area="authorization",
            check_id="Z2",
            method="GET",
            path=privileged_path,
            actor=user_actor,
            expected="denied",
            marker=privileged_marker,
        ),
    ]

    return requests


def make_authz_finding(
    check_id: str,
    path: str,
    status: int,
    detail: str = "",
    user_actor: str = "user",
) -> Finding:
    """Construct deterministic Finding for an authorization violation (Design §17)."""
    if check_id == "Z2":
        return Finding(
            id="RT-AUTHZ-001",
            category="authorization",
            severity=Severity.HIGH,
            confidence=Confidence.HIGH,
            title="Privileged route accessible to low-privilege actor",
            endpoint=f"GET {path}",
            expected="denied",
            actual="allowed",
            evidence=clean(
                detail
                or f"Privileged marker returned with HTTP status {status} to low-privilege actor '{user_actor}'",
                300,
            ),
            impact="Low-privilege actor can access privileged routes and administrative functions without authorization",
            recommendation="Enforce role-based access control (RBAC) on privileged endpoints",
            validation=f"Send GET request to {path} using a low-privilege user session and verify access is denied (401/403/404)",
            status=Status.OPEN,
            cwe="CWE-285",
            owasp="A01:2021-Broken Access Control",
            source="native-verification",
        )
    raise ValueError(f"Unknown authz check ID for finding: {check_id}")


def evaluate_authz_checks(
    z1_check: dict[str, Any] | None,
    z2_check: dict[str, Any] | None,
    privileged_path: str = "",
    user_actor: str = "user",
) -> tuple[list[dict[str, Any]], list[Finding], str, str]:
    """Evaluate Z1 and Z2 authorization checks and determine area status.

    Returns:
        (checks, findings, status, reason)
    """
    checks: list[dict[str, Any]] = []
    findings: list[Finding] = []

    if z1_check is None:
        return checks, findings, "INCOMPLETE", "positive control Z1 not executed"

    checks.append(z1_check)

    # Z1 must be allowed for positive control to pass
    if z1_check.get("classification") != "allowed":
        return (
            checks,
            findings,
            "INCOMPLETE",
            f"privileged authorization positive control Z1 failed (classification={z1_check.get('classification')})",
        )

    if z2_check is None:
        return checks, findings, "INCOMPLETE", "low-privilege authorization check Z2 not executed"

    checks.append(z2_check)
    z2_classification = z2_check.get("classification")

    if z2_classification == "denied":
        return (
            checks,
            findings,
            "PASS",
            "privileged route allowed for admin and denied for low-privilege user",
        )
    elif z2_classification == "allowed":
        status_code = z2_check.get("status", 200)
        finding = make_authz_finding(
            check_id="Z2",
            path=privileged_path or z2_check.get("path", "/admin"),
            status=status_code,
            user_actor=user_actor,
        )
        findings.append(finding)
        return (
            checks,
            findings,
            "FAIL",
            "low-privilege user allowed access to privileged route",
        )
    elif z2_classification == "ambiguous":
        return (
            checks,
            findings,
            "INCOMPLETE",
            "ambiguous response received for Z2 request (marker absent but status 2xx/3xx/unexpected)",
        )
    else:
        return (
            checks,
            findings,
            "INCOMPLETE",
            f"Z2 check incomplete (classification={z2_classification})",
        )
