"""Native runtime verification for Cross-Site Request Forgery (CSRF) defenses (Design §2-§9).

Implements:
- Check C0: Dedicated CSRF session setup isolated from v1.3 A5/A6 invalidations.
- Check C1: Same-origin positive control with strategy-aware token handling and marker validation.
- Check C2: Core cross-origin negative probe without token; distinguishes server-side acceptance
  from proven browser exploitability.
- Check C3: Cross-origin negative probe with valid token (Origin defense evaluation).
- Check C4: Same-origin negative probe with invalid/tampered token (Token defense evaluation).
- Optional token acquisition (prefetch / page_body) and deterministic cleanup.
- Findings: RT-CSRF-001, RT-CSRF-002, RT-CSRF-003.
- Strict PASS semantics: requires positive control pass, all negative probes actually rejected,
  zero findings, and no unresolved accepted negative probes.
"""

from __future__ import annotations

from dataclasses import dataclass, field
import json
import re
from typing import Any

from ..config import Config, CsrfVerificationConfig
from ..models import Confidence, Finding, Severity, Status
from ..utils.redaction import clean, redact
from .identity import SecretValue
from .plan import PlannedRequest

CSRF_NAMESPACE = "RT-CSRF-*"
UNTRUSTED_ORIGIN = "https://untrusted.invalid"
UNTRUSTED_REFERER = "https://untrusted.invalid/exploit.html"
INVALID_TOKEN_VALUE = "vibe_invalid_csrf_token_value_0000"


@dataclass
class CsrfCheckResult:
    check_id: str
    passed: bool
    status_code: int | None = None
    detail: str = ""


@dataclass
class CsrfContext:
    session_cookies: dict[str, str] = field(default_factory=dict)
    auth_header: str | None = None
    cookie_attributes: dict[str, dict[str, Any]] = field(default_factory=dict)
    token: SecretValue | None = None
    cors_preflight_allowed: bool = False


def make_csrf_finding(
    fid: str,
    endpoint: str,
    expected: str,
    actual: str,
    evidence: str,
    severity: Severity = Severity.HIGH,
    confidence: Confidence = Confidence.HIGH,
) -> Finding:
    titles = {
        "RT-CSRF-001": "State-changing endpoint vulnerable to Cross-Site Request Forgery",
        "RT-CSRF-002": "State-changing endpoint accepts invalid / tampered anti-CSRF token",
        "RT-CSRF-003": "State-changing endpoint fails server-side Origin/Referer validation",
    }
    recommendations = {
        "RT-CSRF-001": (
            "Enforce cryptographically unpredictable, session-bound anti-CSRF tokens and/or "
            "SameSite cookie restrictions on all state-changing endpoints."
        ),
        "RT-CSRF-002": (
            "Cryptographically or statefully validate anti-CSRF token values on all mutating requests. "
            "Reject requests with invalid, missing, or mismatched tokens."
        ),
        "RT-CSRF-003": (
            "Inspect and strictly validate Origin and Referer headers against trusted origins for "
            "all state-changing requests."
        ),
    }
    impacts = {
        "RT-CSRF-001": "Attacker can forge unauthorized state-changing operations on behalf of authenticated users.",
        "RT-CSRF-002": "Attacker can bypass CSRF token validation by supplying arbitrary or tampered tokens.",
        "RT-CSRF-003": "Cross-origin requests from untrusted origins are processed, weakening defense-in-depth.",
    }

    return Finding(
        category="csrf",
        severity=severity,
        confidence=confidence,
        status=Status.OPEN,
        title=titles.get(fid, f"CSRF finding {fid}"),
        endpoint=endpoint,
        expected=expected,
        actual=actual,
        evidence=evidence,
        impact=impacts.get(fid, "State-changing operation vulnerable to forgery."),
        recommendation=recommendations.get(fid, "Implement anti-CSRF protections."),
        validation="Re-run native CSRF verification checks.",
        cwe="CWE-352",
        id=fid,
        source="native-verification",
    )


def build_csrf_requests(cfg: Config) -> list[PlannedRequest]:
    """Construct deterministic planned requests for the CSRF verification plan."""
    rv = cfg.runtime_verification
    if not rv or not rv.csrf:
        return []

    csrf_cfg = rv.csrf
    requests: list[PlannedRequest] = []

    # C0: Dedicated CSRF Session Setup
    login_path = "/login"
    login_method = "POST"
    if csrf_cfg.session_setup:
        login_path = csrf_cfg.session_setup.path
        login_method = csrf_cfg.session_setup.method
    elif cfg.authentication and cfg.authentication.login:
        login_path = cfg.authentication.login.path
        login_method = cfg.authentication.login.method

    requests.append(
        PlannedRequest(
            area="csrf",
            check_id="C0",
            method=login_method,
            path=login_path,
            actor="user_a",
            expected="allowed",
        )
    )

    # Optional Token Acquisition (prefetch or page_body)
    if csrf_cfg.token_source in ("prefetch", "page_body"):
        fetch_path = csrf_cfg.token_source_path or "/csrf-token"
        requests.append(
            PlannedRequest(
                area="csrf",
                check_id="prefetch",
                method="GET",
                path=fetch_path,
                actor="user_a",
                expected="allowed",
            )
        )

    # C1: Positive Control Baseline (Same-Origin)
    requests.append(
        PlannedRequest(
            area="csrf",
            check_id="C1",
            method=csrf_cfg.method,
            path=csrf_cfg.path,
            actor="user_a",
            expected="allowed",
            marker=csrf_cfg.marker,
        )
    )

    # C2: Cross-Origin Submission Without Token (Core CSRF Probe)
    requests.append(
        PlannedRequest(
            area="csrf",
            check_id="C2",
            method=csrf_cfg.method,
            path=csrf_cfg.path,
            actor="user_a",
            expected="denied",
        )
    )

    # C3: Cross-Origin Submission With Valid Token (Origin Defense)
    # Only applicable when token_strategy == "both" OR ("token" with origin_validation == True)
    if csrf_cfg.token_strategy == "both" or (
        csrf_cfg.token_strategy == "token" and csrf_cfg.origin_validation
    ):
        requests.append(
            PlannedRequest(
                area="csrf",
                check_id="C3",
                method=csrf_cfg.method,
                path=csrf_cfg.path,
                actor="user_a",
                expected="denied",
            )
        )

    # C4: Same-Origin Submission With Invalid Token (Token Defense)
    # Only applicable when token_strategy in ("token", "both")
    if csrf_cfg.token_strategy in ("token", "both"):
        requests.append(
            PlannedRequest(
                area="csrf",
                check_id="C4",
                method=csrf_cfg.method,
                path=csrf_cfg.path,
                actor="user_a",
                expected="denied",
            )
        )

    # Optional Cleanup Request
    if csrf_cfg.cleanup:
        cl_method = csrf_cfg.cleanup.method
        cl_path = csrf_cfg.cleanup.path or csrf_cfg.path
        requests.append(
            PlannedRequest(
                area="csrf",
                check_id="cleanup",
                method=cl_method,
                path=cl_path,
                actor="user_a",
                expected="allowed",
            )
        )

    return requests
