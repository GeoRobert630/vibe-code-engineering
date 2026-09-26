"""Native Session Verification (Design §9, §15, §16, §17).

Implements bounded, deterministic runtime verification for the Session area:
- S1: session establishment — reuses A3 evidence, verifies session issued
- S2: session continuity — 1 GET protected with same session, allowed + fingerprint unchanged
- S3: session invalidation — reuses A5/A6, verifies A6 denied
- S4: session rotation — if pre-auth cookie issued and sent with A3, post-login fingerprint differs
- S5: cookie attributes — HttpOnly, SameSite present; Secure per protocol (HTTPS => required)
- S6: actor separation — every actor's session fingerprint is distinct

Guarantees:
- Exactly 1 new request (S2 continuity). S1, S3-S6 reuse authentication results.
- Response classification: allowed, denied, ambiguous, incomplete.
- Evidence records match Design §15 schema.
- Deterministic findings RT-SESSION-001..004 per Design §17:
  - RT-SESSION-001: session identifier not rotated (S4), MEDIUM/HIGH
  - RT-SESSION-002: missing HttpOnly attribute (S5), MEDIUM/HIGH
  - RT-SESSION-003: missing Secure attribute on HTTPS (S5), MEDIUM/HIGH
  - RT-SESSION-004: missing SameSite attribute (S5), LOW/HIGH
- Positive control failure → INCOMPLETE, no findings.
- Secrets never exposed in findings, evidence, representations, or reports.
"""

from __future__ import annotations

from typing import Any

from ..config import Config
from ..models import Confidence, Finding, Severity, Status
from ..utils.http import Response
from ..utils.redaction import clean
from .identity import IdentityVault
from .plan import PlannedRequest

SESSION_NAMESPACE = "RT-SESSION-*"


def build_session_requests(cfg: Config) -> list[PlannedRequest]:
    """Construct deterministic planned requests for native session verification (Design §9).

    Session verification sends exactly 1 new request (S2 continuity).
    All other checks (S1, S3, S4, S5, S6) reuse authentication results.
    """
    rv = cfg.runtime_verification
    if not rv:
        return []

    actors = rv.actors
    users = [k for k, v in sorted(actors.items()) if v.role == "user"]
    if not users:
        return []
    primary_user = "user_a" if "user_a" in users else users[0]

    has_logout = bool(
        cfg.authentication
        and cfg.authentication.logout
        and cfg.authentication.logout.enabled
    )
    if has_logout:
        # If logout was performed on primary_user in A5, use an actor whose session
        # remains active from A3 to verify session continuity
        other_actors = [k for k in sorted(actors.keys()) if k != primary_user]
        s2_actor = other_actors[0] if other_actors else primary_user
    else:
        s2_actor = primary_user

    protected_route = rv.routes.get("protected")
    if not protected_route:
        return []
    protected_path = protected_route.path
    protected_marker = protected_route.marker.replace("{label}", s2_actor)

    # S2: one GET protected with the same session
    return [
        PlannedRequest(
            area="session",
            check_id="S2",
            method="GET",
            path=protected_path,
            actor=s2_actor,
            expected="allowed",
            marker=protected_marker,
        )
    ]


def parse_cookie_attributes(set_cookie_header: str) -> dict[str, bool]:
    """Parse cookie attributes from a Set-Cookie header value.

    Returns booleans for HttpOnly, Secure, SameSite presence.
    Does NOT extract cookie values — only attribute flags.
    """
    parts = set_cookie_header.split(";")
    attrs = {p.strip().lower() for p in parts[1:]}  # skip the name=value part

    has_httponly = any("httponly" in a for a in attrs)
    has_secure = any(a.strip() == "secure" for a in attrs)
    has_samesite = any("samesite" in a for a in attrs)

    return {
        "httponly": has_httponly,
        "secure": has_secure,
        "samesite": has_samesite,
    }


def extract_all_cookie_attributes(resp: Response) -> dict[str, bool] | None:
    """Extract combined cookie attributes from all Set-Cookie headers.

    Returns None if no Set-Cookie headers are present.
    Returns the union of attributes across all cookies (any cookie having the
    attribute counts as the attribute being present for that response).
    """
    cookies = resp.header_all("set-cookie")
    if not cookies:
        return None

    combined = {"httponly": False, "secure": False, "samesite": False}
    for cookie_header in cookies:
        attrs = parse_cookie_attributes(cookie_header)
        for key in combined:
            if attrs[key]:
                combined[key] = True

    return combined


def make_session_finding(
    finding_id: str,
    title: str,
    severity: Severity,
    detail: str = "",
    path: str = "",
) -> Finding:
    """Construct deterministic Finding for a session violation (Design §17)."""
    return Finding(
        id=finding_id,
        category="session",
        severity=severity,
        confidence=Confidence.HIGH,
        title=title,
        endpoint=path,
        expected="",
        actual="",
        evidence=clean(detail, 300),
        impact="",
        recommendation="",
        validation="",
        status=Status.OPEN,
        source="native-verification",
    )


def evaluate_session_checks(
    auth_checks: list[dict[str, Any]],
    s2_check: dict[str, Any] | None,
    vault: IdentityVault | None,
    run_hmac_key: bytes,
    is_https: bool,
    has_logout: bool,
    pre_auth_fingerprints: dict[str, str | None] | None = None,
) -> tuple[list[dict[str, Any]], list[Finding], str, str]:
    """Evaluate session checks S1–S6 using authentication evidence and S2 result.

    Returns:
        (checks, findings, status, reason)

    Pre-conditions:
    - auth_checks contains evidence records from authentication A1-A6.
    - s2_check is the evidence record from the session S2 continuity request (or None if not executed).
    - vault contains session state from authentication.
    - pre_auth_fingerprints maps actor labels to pre-authentication fingerprints (for S4 rotation).
    """
    checks: list[dict[str, Any]] = []
    findings: list[Finding] = []
    positive_control_failed = False
    incomplete = False

    # Gather A3 checks from authentication evidence
    a3_checks = [c for c in auth_checks if c.get("check") == "A3"]
    a6_checks = [c for c in auth_checks if c.get("check") == "A6"]

    # ── S1: Session Establishment ─────────────────────────────────────
    # Reuses A3: verify a session cookie or bearer token was issued
    s1_status = "incomplete"
    session_type = "none"
    if not a3_checks:
        positive_control_failed = True
        s1_status = "incomplete"
    else:
        # Check that at least the primary user's A3 resulted in a session
        sessions_issued = sum(
            1 for c in a3_checks
            if c.get("classification") == "allowed" and c.get("fingerprint")
        )
        if sessions_issued > 0:
            first_a3 = a3_checks[0]
            if first_a3.get("cookie_attributes") is not None:
                session_type = "cookie"
            else:
                session_type = "token"
            s1_status = "allowed"
        else:
            positive_control_failed = True
            s1_status = "incomplete"

    checks.append({
        "check": "S1",
        "area": "session",
        "actors": [c.get("actors", ["anonymous"])[0] for c in a3_checks] if a3_checks else ["anonymous"],
        "method": "POST",
        "path": a3_checks[0]["path"] if a3_checks else "/login",
        "expected": "session_issued",
        "status_class": a3_checks[0].get("status_class", "2xx") if a3_checks else "",
        "status": a3_checks[0].get("status", 0) if a3_checks else 0,
        "classification": s1_status,
        "marker_present": False,
        "elapsed_ms": 0.0,
        "fingerprint": a3_checks[0].get("fingerprint") if a3_checks else None,
        "session_count": sessions_issued if "sessions_issued" in locals() and sessions_issued > 0 else len(a3_checks),
        "session_type": session_type,
    })

    if positive_control_failed:
        return checks, [], "INCOMPLETE", "positive control failed: no session established in A3"

    # ── S2: Session Continuity ────────────────────────────────────────
    # Uses the dedicated S2 request result
    if s2_check is None:
        incomplete = True
        checks.append({
            "check": "S2",
            "area": "session",
            "actors": ["user_a"],
            "method": "GET",
            "path": "",
            "expected": "allowed",
            "status_class": "",
            "status": 0,
            "classification": "incomplete",
            "marker_present": False,
            "elapsed_ms": 0.0,
            "fingerprint": None,
        })
    else:
        # Compare S2 fingerprint against the corresponding A3 fingerprint
        s2_actor = s2_check.get("actors", [None])[0]
        a3_for_s2 = next(
            (c for c in a3_checks if c.get("actors", [None])[0] == s2_actor),
            None,
        )
        s2_fp = s2_check.get("fingerprint")
        expected_fp = a3_for_s2.get("fingerprint") if a3_for_s2 else None
        fp_unchanged = bool(s2_fp and expected_fp and s2_fp == expected_fp)

        # S2 PASS requires: classification == "allowed" AND fingerprint == A3 fingerprint
        s2_rec = dict(s2_check)
        if s2_rec.get("classification") != "allowed" or not fp_unchanged:
            incomplete = True
            if not fp_unchanged and s2_rec.get("classification") == "allowed":
                # Changed fingerprint must NOT be treated as successful continuity
                s2_rec["classification"] = "incomplete"

        checks.append(s2_rec)

    # ── S3: Session Invalidation ──────────────────────────────────────
    # Reuses A5/A6: verify A6 denied
    if has_logout:
        if a6_checks:
            a6 = a6_checks[0]
            s3_classification = "denied" if a6.get("classification") == "denied" else "incomplete"
            checks.append({
                "check": "S3",
                "area": "session",
                "actors": a6.get("actors", ["user_a"]),
                "method": a6.get("method", "GET"),
                "path": a6.get("path", ""),
                "expected": "denied",
                "status_class": a6.get("status_class", ""),
                "status": a6.get("status", 0),
                "classification": s3_classification,
                "marker_present": a6.get("marker_present", False),
                "elapsed_ms": 0.0,
                "fingerprint": a6.get("fingerprint"),
            })
            if s3_classification != "denied":
                incomplete = True
        else:
            incomplete = True
            checks.append({
                "check": "S3",
                "area": "session",
                "actors": ["user_a"],
                "method": "GET",
                "path": "",
                "expected": "denied",
                "status_class": "",
                "status": 0,
                "classification": "incomplete",
                "marker_present": False,
                "elapsed_ms": 0.0,
                "fingerprint": None,
            })

    # ── S4: Session Rotation ──────────────────────────────────────────
    # If a pre-authentication session cookie was issued (A1 response) and sent with A3,
    # the post-login fingerprint must differ; otherwise NOT APPLICABLE
    s4_applicable = False
    s4_rotated = True  # assume rotated unless proven otherwise
    s4_actors: list[str] = []

    if pre_auth_fingerprints:
        for actor_label, pre_fp in pre_auth_fingerprints.items():
            if pre_fp is not None:
                # Find the A3 check for this actor
                actor_a3 = [
                    c for c in a3_checks
                    if c.get("actors", [None])[0] == actor_label
                ]
                if actor_a3:
                    s4_applicable = True
                    s4_actors.append(actor_label)
                    post_fp = actor_a3[0].get("fingerprint")
                    if post_fp and pre_fp == post_fp:
                        s4_rotated = False
                        break

    if s4_applicable:
        s4_classification = "allowed" if s4_rotated else "denied"
        checks.append({
            "check": "S4",
            "area": "session",
            "actors": s4_actors if s4_actors else list(pre_auth_fingerprints.keys()),
            "method": "POST",
            "path": a3_checks[0]["path"] if a3_checks else "/login",
            "expected": "rotated",
            "status_class": "",
            "status": 0,
            "classification": s4_classification,
            "marker_present": False,
            "elapsed_ms": 0.0,
            "fingerprint": None,
            "rotated": s4_rotated,
        })
        if not s4_rotated:
            findings.append(make_session_finding(
                "RT-SESSION-001",
                "Session identifier not rotated on login",
                Severity.MEDIUM,
                "Pre-authentication session identifier was not changed after successful login",
                a3_checks[0]["path"] if a3_checks else "",
            ))
    else:
        checks.append({
            "check": "S4",
            "area": "session",
            "actors": [],
            "method": "POST",
            "path": a3_checks[0]["path"] if a3_checks else "/login",
            "expected": "rotated",
            "status_class": "",
            "status": 0,
            "classification": "not_applicable",
            "marker_present": False,
            "elapsed_ms": 0.0,
            "fingerprint": None,
            "rotated": None,
        })

    # ── S5: Cookie Attributes ─────────────────────────────────────────
    # Reuses A3: check cookie attributes from A3 responses
    # HttpOnly and SameSite must be present; Secure per protocol rule
    s5_classification = "allowed"
    s5_attrs: dict[str, bool | None] = {
        "httponly": None,
        "secure": None,
        "samesite": None,
    }

    if a3_checks:
        # S5 applies only when session type is cookie-based
        # Check cookie_attributes stored in auth evidence
        first_a3 = a3_checks[0]
        cookie_attrs = first_a3.get("cookie_attributes")

        if cookie_attrs is not None:
            s5_attrs = dict(cookie_attrs)

            if not cookie_attrs.get("httponly", False):
                s5_classification = "denied"
                findings.append(make_session_finding(
                    "RT-SESSION-002",
                    "Session cookie missing HttpOnly attribute",
                    Severity.MEDIUM,
                    "Session cookie does not have the HttpOnly attribute set",
                    first_a3.get("path", ""),
                ))

            if is_https and not cookie_attrs.get("secure", False):
                s5_classification = "denied"
                findings.append(make_session_finding(
                    "RT-SESSION-003",
                    "Session cookie missing Secure attribute on HTTPS",
                    Severity.MEDIUM,
                    "Session cookie does not have the Secure attribute set on an HTTPS target",
                    first_a3.get("path", ""),
                ))

            if not cookie_attrs.get("samesite", False):
                s5_classification = "denied"
                findings.append(make_session_finding(
                    "RT-SESSION-004",
                    "Session cookie missing SameSite attribute",
                    Severity.LOW,
                    "Session cookie does not have the SameSite attribute set",
                    first_a3.get("path", ""),
                ))
        else:
            # Bearer token auth — cookie attributes are NOT APPLICABLE
            s5_classification = "not_applicable"

    checks.append({
        "check": "S5",
        "area": "session",
        "actors": [a3_checks[0].get("actors", ["user_a"])[0]] if a3_checks else [],
        "method": "POST",
        "path": a3_checks[0]["path"] if a3_checks else "/login",
        "expected": "attributes_present",
        "status_class": "",
        "status": 0,
        "classification": s5_classification,
        "marker_present": False,
        "elapsed_ms": 0.0,
        "fingerprint": None,
        "cookie_attributes": s5_attrs,
    })

    # ── S6: Actor Separation ──────────────────────────────────────────
    # Reuses A3: every actor's session fingerprint must be distinct
    actor_fingerprints: dict[str, str | None] = {}
    for c in a3_checks:
        actor = c.get("actors", [None])[0]
        fp = c.get("fingerprint")
        if actor and fp:
            actor_fingerprints[actor] = fp

    distinct_fps = set(actor_fingerprints.values())
    all_distinct = len(distinct_fps) == len(actor_fingerprints)

    if len(actor_fingerprints) < 2:
        # Need at least 2 actors to check separation
        s6_classification = "not_applicable"
    elif all_distinct:
        s6_classification = "allowed"
    else:
        s6_classification = "denied"
        incomplete = True  # actor separation failure is an INCOMPLETE condition

    checks.append({
        "check": "S6",
        "area": "session",
        "actors": list(actor_fingerprints.keys()),
        "method": "POST",
        "path": a3_checks[0]["path"] if a3_checks else "/login",
        "expected": "distinct_fingerprints",
        "status_class": "",
        "status": 0,
        "classification": s6_classification,
        "marker_present": False,
        "elapsed_ms": 0.0,
        "fingerprint": None,
    })

    # ── Final status determination ────────────────────────────────────
    if positive_control_failed:
        return checks, [], "INCOMPLETE", "positive control failed: no session established"

    if findings:
        status = "FAIL"
        reason = f"{len(findings)} session finding(s) detected"
    elif incomplete:
        status = "INCOMPLETE"
        reason = "session verification incomplete"
    else:
        # Check if all required checks passed
        s5_check = next((c for c in checks if c["check"] == "S5"), None)
        s4_check = next((c for c in checks if c["check"] == "S4"), None)

        # S4 satisfied or NOT APPLICABLE
        s4_ok = (
            s4_check is None
            or s4_check.get("classification") in ("allowed", "not_applicable")
        )

        # S5 satisfied or NOT APPLICABLE (bearer token)
        s5_ok = (
            s5_check is None
            or s5_check.get("classification") in ("allowed", "not_applicable")
        )

        if not has_logout:
            # Without logout, S3 cannot be checked; at most EXECUTED
            status = "EXECUTED"
            reason = "session checks executed; logout not declared (at most EXECUTED)"
        elif s4_ok and s5_ok:
            status = "PASS"
            reason = "all session checks passed"
        else:
            status = "INCOMPLETE"
            reason = "session checks incomplete"

    return checks, findings, status, reason
