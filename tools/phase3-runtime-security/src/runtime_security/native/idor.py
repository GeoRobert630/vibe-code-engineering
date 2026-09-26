"""Native IDOR / BOLA Verification (Design §11, §15, §16, §17).

Implements bounded, deterministic runtime verification for horizontal IDOR / BOLA:
- I1: user_a accesses user_a's declared object-a resource (positive control 1, expected allowed)
- I2: user_a accesses user_b's declared object-b resource (cross-actor denial 1, expected denied)
- I3: user_b accesses user_b's declared object-b resource (positive control 2, expected allowed)
- I4: user_b accesses user_a's declared object-a resource (cross-actor denial 2, expected denied)

Guarantees:
- Declared resources only (rv.resources with declared owner). No identifier guessing, enumeration, or derivation.
- Uses authenticated user_a session for I1/I2 and user_b session for I3/I4.
- Positive-control rule: Both own-object positive controls (I1 and I3) must succeed before
  any cross-actor finding (RT-IDOR-001) can be emitted.
- If an own-object positive control fails or is ambiguous, do NOT infer a cross-actor vulnerability.
- An actual cross-actor allowed response emits exactly RT-IDOR-001 with severity HIGH and confidence HIGH.
- Ambiguous, timeout, 5xx, or incomplete responses resolve to INCOMPLETE.
- Response classification matches Design §15 (allowed, denied, ambiguous, incomplete).
- Safe evidence only: no credentials, raw tokens, or response bodies stored.
- Request counts bounded to hard maximum of 4 requests.
"""

from __future__ import annotations

from typing import Any

from ..config import Config
from ..models import Confidence, Finding, Severity, Status
from ..utils.redaction import clean
from .plan import PlannedRequest

IDOR_NAMESPACE = "RT-IDOR-*"


def build_idor_requests(cfg: Config) -> list[PlannedRequest]:
    """Construct deterministic planned requests for native IDOR/BOLA verification (Design §11)."""
    rv = cfg.runtime_verification
    if not rv:
        return []

    actors = rv.actors
    users = [k for k, v in sorted(actors.items()) if v.role == "user"]
    if len(users) < 2:
        return []

    # Map each user to their first declared owned resource
    user_resources: dict[str, Any] = {}
    for res in rv.resources:
        if res.owner and res.owner in users and res.owner not in user_resources:
            user_resources[res.owner] = res

    eligible_users = [u for u in users if u in user_resources]
    if len(eligible_users) < 2:
        return []

    user_a = eligible_users[0]
    user_b = eligible_users[1]
    res_a = user_resources[user_a]
    res_b = user_resources[user_b]

    requests: list[PlannedRequest] = [
        # I1: user_a own object positive control
        PlannedRequest(
            area="idor_bola",
            check_id="I1",
            method="GET",
            path=res_a.path,
            actor=user_a,
            expected="allowed",
            marker=res_a.marker,
        ),
        # I2: user_a cross-actor access to user_b's object
        PlannedRequest(
            area="idor_bola",
            check_id="I2",
            method="GET",
            path=res_b.path,
            actor=user_a,
            expected="denied",
            marker=res_b.marker,
        ),
        # I3: user_b own object positive control
        PlannedRequest(
            area="idor_bola",
            check_id="I3",
            method="GET",
            path=res_b.path,
            actor=user_b,
            expected="allowed",
            marker=res_b.marker,
        ),
        # I4: user_b cross-actor access to user_a's object
        PlannedRequest(
            area="idor_bola",
            check_id="I4",
            method="GET",
            path=res_a.path,
            actor=user_b,
            expected="denied",
            marker=res_a.marker,
        ),
    ]

    return requests


def make_idor_finding(
    check_id: str,
    path: str,
    status: int,
    detail: str = "",
    actor: str = "user",
    target_owner: str = "",
) -> Finding:
    """Construct deterministic Finding for an IDOR/BOLA violation (Design §17)."""
    if check_id in ("I2", "I4"):
        owner_info = f" owned by '{target_owner}'" if target_owner else ""
        return Finding(
            id="RT-IDOR-001",
            category="idor",
            severity=Severity.HIGH,
            confidence=Confidence.HIGH,
            title="Cross-user object access allowed",
            endpoint=f"GET {path}",
            expected="denied",
            actual="allowed",
            evidence=clean(
                detail
                or f"Resource marker returned with HTTP status {status} to unauthorized actor '{actor}' on resource{owner_info}",
                300,
            ),
            impact="Unauthorized actors can access resources and objects belonging to other users without authorization",
            recommendation="Enforce object-level authorization checks to verify the requesting actor owns the target resource",
            validation=f"Send GET request to {path} using unauthorized actor session and verify access is denied (401/403/404)",
            status=Status.OPEN,
            cwe="CWE-639",
            owasp="A01:2021-Broken Access Control",
            source="native-verification",
        )
    raise ValueError(f"Unknown idor check ID for finding: {check_id}")


def evaluate_idor_checks(
    check_records: list[dict[str, Any]],
    user_a: str = "user_a",
    user_b: str = "user_b",
    res_a_path: str = "",
    res_b_path: str = "",
) -> tuple[list[dict[str, Any]], list[Finding], str, str]:
    """Evaluate I1–I4 IDOR/BOLA checks and determine area status and findings.

    Returns:
        (checks, findings, status, reason)
    """
    findings: list[Finding] = []
    checks_by_id = {c.get("check"): c for c in check_records}

    i1 = checks_by_id.get("I1")
    i2 = checks_by_id.get("I2")
    i3 = checks_by_id.get("I3")
    i4 = checks_by_id.get("I4")

    # 1. Verify positive control I1 (user_a on own object)
    if i1 is None:
        return check_records, findings, "INCOMPLETE", "positive control I1 not executed"
    if i1.get("classification") != "allowed":
        return (
            check_records,
            findings,
            "INCOMPLETE",
            f"own-object positive control I1 failed (classification={i1.get('classification')})",
        )

    # 2. Verify positive control I3 (user_b on own object)
    if i3 is None:
        return check_records, findings, "INCOMPLETE", "positive control I3 not executed"
    if i3.get("classification") != "allowed":
        return (
            check_records,
            findings,
            "INCOMPLETE",
            f"own-object positive control I3 failed (classification={i3.get('classification')})",
        )

    # 3. Both positive controls succeeded. Check cross-actor denials (I2 and I4).
    if i2 is None:
        return check_records, findings, "INCOMPLETE", "cross-actor check I2 not executed"

    i2_allowed = i2.get("classification") == "allowed"
    i4_allowed = (i4.get("classification") == "allowed") if i4 else False

    if i2_allowed or i4_allowed:
        if i2_allowed:
            finding = make_idor_finding(
                check_id="I2",
                path=res_b_path or i2.get("path", "/objects/object-b"),
                status=i2.get("status", 200),
                actor=user_a,
                target_owner=user_b,
            )
            findings.append(finding)
        elif i4_allowed:
            finding = make_idor_finding(
                check_id="I4",
                path=res_a_path or (i4.get("path", "/objects/object-a") if i4 else "/objects/object-a"),
                status=i4.get("status", 200) if i4 else 200,
                actor=user_b,
                target_owner=user_a,
            )
            findings.append(finding)

        return (
            check_records,
            findings,
            "FAIL",
            "cross-user object access allowed (IDOR/BOLA)",
        )

    if i4 is None:
        return check_records, findings, "INCOMPLETE", "cross-actor check I4 not executed"

    # 4. If neither was allowed, verify both were denied
    if i2.get("classification") == "denied" and i4.get("classification") == "denied":
        return (
            check_records,
            findings,
            "PASS",
            "own-object positive controls allowed and cross-actor access denied",
        )

    # 5. Otherwise, ambiguous or incomplete classification
    for cid in ("I2", "I4"):
        c = checks_by_id.get(cid)
        if c and c.get("classification") == "ambiguous":
            return check_records, findings, "INCOMPLETE", f"ambiguous response received for check {cid}"
        if c and c.get("classification") == "incomplete":
            return check_records, findings, "INCOMPLETE", f"incomplete response received for check {cid}"

    return check_records, findings, "INCOMPLETE", "unexpected check classifications in IDOR verification"

