"""Bounded native execution layer for v1.3 verification plans.

Guarantees:
* Target safety: enforces target eligibility (including Phase 3 safety gate)
  before any connection attempt.
* DNS pinning: connects directly to pre-validated IP address(es); never
  re-resolves hostname during execution.
* Strict request bounds:
  - Hard total request limit (20 in fixture mode, 21 in local-app mode).
  - Hard setup limit (1 in local-app mode, 0 in fixture mode).
  - Hard per-area maximums (auth: 9, session: 1, authz: 2, idor: 4, tenant: 4).
  - Refuses over-budget plans before sending any requests.
  - Enforces count agreement between planner and executor.
* Timeouts:
  - Per-request timeout (default 10s from cfg.timeout, produces INCOMPLETE).
  - Per-area timeout (max 60s, marks area INCOMPLETE, stops remaining area requests).
  - Total run timeout (max 180s, marks run INCOMPLETE, never exceeded).
  - No retries after timeout or error.
* Request & response bounds:
  - Max body size 256 KB (MAX_BODY).
  - Allowed methods: GET, HEAD, POST only.
  - Relative paths only.
  - No redirect following.
* Determinism:
  - Explicit execution order (setup -> auth -> session -> authz -> idor -> tenant).
  - Explicit request results in order.
* Secret protection & redaction:
  - SecretValue revealed only for transmission on the wire.
  - Diagnostics and headers sanitized with safe_header_value / redact / clean.
"""

from __future__ import annotations

import http.client
import ipaddress
import json
import secrets
import socket
import ssl
import time
import urllib.parse
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional
from urllib.parse import urlsplit

from ..config import Config
from ..models import Confidence, Finding, Severity, Status
from ..utils.http import MAX_BODY, BudgetExceeded, RequestNotAllowed, Response
from ..utils.redaction import clean, redact, safe_header_value
from .auth import compute_fingerprint, extract_session, is_mfa_challenge, make_auth_finding
from .eligibility import NativeEligibilityDecision, evaluate_native
from .identity import IdentityVault, SecretValue
from .plan import AreaPlan, NativePlan, PlannedRequest
from .session import (
    SESSION_NAMESPACE,
    build_session_requests,
    evaluate_session_checks,
    extract_all_cookie_attributes,
)
from .setup_adapter import (
    IdentitySetupResult,
    build_setup_request,
    validate_setup_response,
)

USER_AGENT = "phase3-runtime-security/0.1 (native-verification)"
SAFE_NATIVE_METHODS = frozenset({"GET", "HEAD", "POST"})

DEFAULT_REQUEST_TIMEOUT = 10.0
MAX_AREA_TIMEOUT = 60.0
MAX_TOTAL_TIMEOUT = 180.0

FIXTURE_MAX_REQUESTS = 20
LOCAL_APP_MAX_REQUESTS = 21
SETUP_MAX_REQUESTS = 1

AREA_HARD_MAXIMUMS: dict[str, int] = {
    "authentication": 9,
    "session": 1,
    "authorization": 2,
    "idor_bola": 4,
    "tenant_isolation": 4,
}

VERIFICATION_AREAS = (
    "authentication",
    "session",
    "authorization",
    "idor_bola",
    "tenant_isolation",
)


class PinnedHTTPConnection(http.client.HTTPConnection):
    """HTTPConnection that connects directly to a validated IP without DNS lookup."""

    def __init__(
        self,
        pinned_ip: str,
        port: int,
        timeout: float = DEFAULT_REQUEST_TIMEOUT,
    ) -> None:
        super().__init__(pinned_ip, port, timeout=timeout)
        self.pinned_ip = pinned_ip

    def connect(self) -> None:
        addr = ipaddress.ip_address(self.pinned_ip)
        af = socket.AF_INET6 if isinstance(addr, ipaddress.IPv6Address) else socket.AF_INET
        sock = socket.socket(af, socket.SOCK_STREAM)
        sock.settimeout(self.timeout)
        sock.connect((self.pinned_ip, self.port))
        self.sock = sock


class PinnedHTTPSConnection(http.client.HTTPSConnection):
    """HTTPSConnection that connects directly to a validated IP without DNS lookup."""

    def __init__(
        self,
        pinned_ip: str,
        port: int,
        timeout: float = DEFAULT_REQUEST_TIMEOUT,
        context: ssl.SSLContext | None = None,
        sni_hostname: str | None = None,
    ) -> None:
        super().__init__(pinned_ip, port, timeout=timeout, context=context)
        self.pinned_ip = pinned_ip
        self.sni_hostname = sni_hostname

    def connect(self) -> None:
        addr = ipaddress.ip_address(self.pinned_ip)
        af = socket.AF_INET6 if isinstance(addr, ipaddress.IPv6Address) else socket.AF_INET
        raw_sock = socket.socket(af, socket.SOCK_STREAM)
        raw_sock.settimeout(self.timeout)
        raw_sock.connect((self.pinned_ip, self.port))
        try:
            sni = self.sni_hostname or self.pinned_ip
            self.sock = self._context.wrap_socket(raw_sock, server_hostname=sni)
        except Exception:
            raw_sock.close()
            raise


class NativeHttpClient:
    """Bounded, pinned HTTP client for native verification execution."""

    def __init__(
        self,
        cfg: Config,
        pinned_ip: str,
        max_budget: int = LOCAL_APP_MAX_REQUESTS,
    ) -> None:
        self.cfg = cfg
        self.pinned_ip = pinned_ip
        self.max_budget = max_budget
        self.sent = 0
        self.log: list[str] = []

    def _ssl_context(self) -> ssl.SSLContext:
        ctx = (
            ssl.create_default_context(cafile=self.cfg.ca_file)
            if self.cfg.ca_file
            else ssl.create_default_context()
        )
        ctx.check_hostname = True
        ctx.verify_mode = ssl.CERT_REQUIRED
        return ctx

    def request(
        self,
        method: str,
        path: str,
        headers: dict[str, Any] | None = None,
        body: bytes | str | None = None,
        timeout: float = DEFAULT_REQUEST_TIMEOUT,
    ) -> Response:
        base = self.cfg.base_url
        parts = urlsplit(base)

        if not path.startswith("/") or path.startswith("//") or "://" in path:
            raise RequestNotAllowed("only relative paths are allowed")

        if method not in SAFE_NATIVE_METHODS:
            raise RequestNotAllowed(f"method {method} not allowed for native verification")

        if self.sent >= self.max_budget:
            raise BudgetExceeded(f"request budget of {self.max_budget} exhausted")

        # Pacing between requests if configured
        if self.sent and self.cfg.delay_seconds:
            time.sleep(self.cfg.delay_seconds)

        self.sent += 1

        # Encode body and enforce bound
        raw_body: bytes | None = None
        if body is not None:
            if isinstance(body, str):
                raw_body = body.encode("utf-8")
            else:
                raw_body = body
            if len(raw_body) > MAX_BODY:
                raise RequestNotAllowed(f"request body exceeds maximum limit of {MAX_BODY} bytes")

        # Wire headers with secrets revealed
        netloc = parts.netloc
        send_headers: dict[str, str] = {
            "User-Agent": USER_AGENT,
            "Accept": "*/*",
            "Connection": "close",
            "Host": netloc,
        }
        if headers:
            for k, v in headers.items():
                if isinstance(v, SecretValue):
                    send_headers[k] = v.reveal_for_request()
                else:
                    send_headers[k] = str(v)

        port = parts.port or (443 if parts.scheme == "https" else 80)
        if parts.scheme == "https":
            conn: http.client.HTTPConnection = PinnedHTTPSConnection(
                self.pinned_ip,
                port,
                timeout=timeout,
                context=self._ssl_context(),
                sni_hostname=parts.hostname,
            )
        else:
            conn = PinnedHTTPConnection(self.pinned_ip, port, timeout=timeout)

        full_path = (parts.path.rstrip("/") + path) or "/"
        try:
            conn.request(method, full_path, body=raw_body, headers=send_headers)
            resp = conn.getresponse()
            raw = resp.read(MAX_BODY + 1)
            result = Response(
                url=f"{parts.scheme}://{parts.netloc}{full_path}",
                status=resp.status,
                reason=resp.reason,
                headers=list(resp.getheaders()),
                body=raw[:MAX_BODY].decode("utf-8", "replace"),
                truncated=len(raw) > MAX_BODY,
            )
        finally:
            conn.close()

        self.log.append(f"{method} {result.url} -> {result.status}")
        return result


@dataclass
class RequestExecutionResult:
    check_id: str
    area: str
    method: str
    path: str
    status: str  # "EXECUTED" | "INCOMPLETE"
    status_code: int | None = None
    response: Response | None = None
    elapsed_ms: float = 0.0
    timed_out: bool = False
    error: str | None = None
    actor: str | None = None
    expected: str = "allowed"
    marker_present: bool | None = None
    headers_sent: dict[str, str] = field(default_factory=dict)

    def __repr__(self) -> str:
        return (
            f"RequestExecutionResult(check_id={self.check_id!r}, area={self.area!r}, "
            f"method={self.method!r}, path={self.path!r}, status={self.status!r}, "
            f"status_code={self.status_code!r}, timed_out={self.timed_out!r})"
        )


@dataclass
class AreaExecutionResult:
    area: str
    status: str  # "EXECUTED" | "INCOMPLETE" | "NOT CONFIGURED" | "NOT VERIFIED" | "PASS" | "FAIL"
    configured: bool = True
    requests_sent: int = 0
    requests_planned: int = 0
    timed_out: bool = False
    budget_exceeded: bool = False
    error: str | None = None
    request_results: list[RequestExecutionResult] = field(default_factory=list)
    findings: list[Finding] = field(default_factory=list)
    checks: list[dict[str, Any]] = field(default_factory=list)
    reason: str = ""
    runtime_checks_executed: bool = False
    source: str = "native"

    def to_report_dict(self, actors: list[str] | None = None) -> dict[str, Any]:
        _ns_map = {
            "authentication": "RT-AUTH-*",
            "session": "RT-SESSION-*",
            "authorization": "RT-AUTHZ-*",
            "idor_bola": "RT-IDOR-*",
            "tenant_isolation": "RT-TENANT-*",
        }
        ns = _ns_map.get(self.area, f"RT-{self.area.upper()}-*")
        return {
            "status": self.status,
            "source": self.source,
            "reason": self.reason or self.error or ("all checks passed" if self.status == "PASS" else ""),
            "namespace": ns,
            "runtime_checks_executed": self.runtime_checks_executed,
            "credentials_read": False,
            "actors": list(actors) if actors else [],
            "requests_count": self.requests_sent,
            "request_budget": AREA_HARD_MAXIMUMS.get(self.area, 0),
            "checks": list(self.checks),
            "findings": [f.id for f in self.findings],
            "limitations": [
                "read paths only",
                "declared resources only",
                "local target only",
                "synthetic identities only",
            ],
        }

    def __repr__(self) -> str:
        return (
            f"AreaExecutionResult(area={self.area!r}, status={self.status!r}, "
            f"requests_sent={self.requests_sent}/{self.requests_planned}, "
            f"timed_out={self.timed_out!r}, error={self.error!r})"
        )


@dataclass
class NativeExecutionResult:
    status: str  # "EXECUTED" | "INCOMPLETE" | "REFUSED" | "PASS" | "FAIL"
    requests_sent: int = 0
    total_budget: int = FIXTURE_MAX_REQUESTS
    elapsed_seconds: float = 0.0
    timed_out: bool = False
    refused: bool = False
    refusal_reason: str = ""
    setup_result: IdentitySetupResult | None = None
    area_results: dict[str, AreaExecutionResult] = field(default_factory=dict)
    all_request_results: list[RequestExecutionResult] = field(default_factory=list)

    def area(self, name: str) -> AreaExecutionResult | None:
        return self.area_results.get(name)

    def get_area_result(self, name: str) -> AreaExecutionResult | None:
        return self.area_results.get(name)

    @property
    def findings(self) -> list[Finding]:
        f: list[Finding] = []
        for ar in self.area_results.values():
            f.extend(ar.findings)
        return f

    @property
    def is_incomplete(self) -> bool:
        return self.status == "INCOMPLETE" or self.timed_out

    @property
    def is_executed(self) -> bool:
        return self.status == "EXECUTED"

    def __repr__(self) -> str:
        return (
            f"NativeExecutionResult(status={self.status!r}, "
            f"requests_sent={self.requests_sent}/{self.total_budget}, "
            f"timed_out={self.timed_out!r}, refused={self.refused!r}, "
            f"setup_result={self.setup_result!r})"
        )


class NativeExecutor:
    """Bounded, safe executor for native verification plans."""

    def __init__(
        self,
        cfg: Config,
        eligibility: NativeEligibilityDecision | None = None,
        vault: IdentityVault | None = None,
        request_timeout: float | None = None,
        area_timeout: float = MAX_AREA_TIMEOUT,
        total_timeout: float = MAX_TOTAL_TIMEOUT,
    ) -> None:
        self.cfg = cfg
        if vault is not None:
            self.vault = vault
        elif self.cfg.runtime_verification and self.cfg.runtime_verification.actors:
            self.vault = IdentityVault(
                run_id=secrets.token_hex(16),
                actors=list(self.cfg.runtime_verification.actors.keys()),
            )
        else:
            self.vault = None

        # Timeouts: never exceed bounds
        self.request_timeout = (
            request_timeout if request_timeout is not None else float(self.cfg.timeout)
        )
        self.area_timeout = min(area_timeout, MAX_AREA_TIMEOUT)
        self.total_timeout = min(total_timeout, MAX_TOTAL_TIMEOUT)

        self._run_hmac_key = secrets.token_bytes(32)
        self._saved_pre_logout_sessions: dict[str, dict[str, str]] = {}
        self._pre_auth_fingerprints: dict[str, str | None] = {}
        self._pre_auth_cookie: SecretValue | None = None
        self._pre_auth_fingerprint: str | None = None
        self._pre_auth_sent: bool = False
        self._a3_cookie_attributes: dict[str, dict[str, bool] | None] = {}

        # Target safety gate & eligibility check before any connection
        self.eligibility = eligibility if eligibility is not None else evaluate_native(cfg)
        self.client: NativeHttpClient | None = None

        if self.eligibility.allowed and self.eligibility.resolved_ips:
            pinned_ip = self.eligibility.resolved_ips[0]
            mode = (
                self.cfg.runtime_verification.mode
                if self.cfg.runtime_verification
                else "fixture"
            )
            max_budget = (
                LOCAL_APP_MAX_REQUESTS if mode == "local-app" else FIXTURE_MAX_REQUESTS
            )
            self.client = NativeHttpClient(
                cfg=self.cfg,
                pinned_ip=pinned_ip,
                max_budget=max_budget,
            )

    def _sanitize_headers_for_recording(
        self, headers: dict[str, Any] | None
    ) -> dict[str, str]:
        if not headers:
            return {}
        recorded = {}
        for k, v in headers.items():
            if isinstance(v, SecretValue):
                recorded[k] = "<redacted>"
            else:
                recorded[k] = safe_header_value(k, str(v))
        return recorded

    def _execute_single_request(
        self,
        req: PlannedRequest,
        timeout: float,
    ) -> RequestExecutionResult:
        """Execute one planned request through the pinned client with bounds and redaction."""
        assert self.client is not None

        headers_recorded = self._sanitize_headers_for_recording(req.headers)
        t0 = time.monotonic()
        try:
            resp = self.client.request(
                method=req.method,
                path=req.path,
                headers=req.headers,
                body=req.body,
                timeout=timeout,
            )
            elapsed_ms = (time.monotonic() - t0) * 1000.0

            marker_present: bool | None = None
            if req.marker:
                marker_present = req.marker in resp.body

            return RequestExecutionResult(
                check_id=req.check_id,
                area=req.area,
                method=req.method,
                path=req.path,
                status="EXECUTED",
                status_code=resp.status,
                response=resp,
                elapsed_ms=elapsed_ms,
                timed_out=False,
                error=None,
                actor=req.actor,
                expected=req.expected,
                marker_present=marker_present,
                headers_sent=headers_recorded,
            )
        except TimeoutError:
            elapsed_ms = (time.monotonic() - t0) * 1000.0
            return RequestExecutionResult(
                check_id=req.check_id,
                area=req.area,
                method=req.method,
                path=req.path,
                status="INCOMPLETE",
                status_code=None,
                response=None,
                elapsed_ms=elapsed_ms,
                timed_out=True,
                error=clean(f"request timeout ({timeout:.1f}s)", 200),
                actor=req.actor,
                expected=req.expected,
                headers_sent=headers_recorded,
            )
        except BudgetExceeded as exc:
            elapsed_ms = (time.monotonic() - t0) * 1000.0
            return RequestExecutionResult(
                check_id=req.check_id,
                area=req.area,
                method=req.method,
                path=req.path,
                status="INCOMPLETE",
                status_code=None,
                response=None,
                elapsed_ms=elapsed_ms,
                timed_out=False,
                error=clean(str(exc), 200),
                actor=req.actor,
                expected=req.expected,
                headers_sent=headers_recorded,
            )
        except RequestNotAllowed as exc:
            elapsed_ms = (time.monotonic() - t0) * 1000.0
            return RequestExecutionResult(
                check_id=req.check_id,
                area=req.area,
                method=req.method,
                path=req.path,
                status="INCOMPLETE",
                status_code=None,
                response=None,
                elapsed_ms=elapsed_ms,
                timed_out=False,
                error=clean(str(exc), 200),
                actor=req.actor,
                expected=req.expected,
                headers_sent=headers_recorded,
            )
        except (ConnectionRefusedError, socket.error, OSError) as exc:
            elapsed_ms = (time.monotonic() - t0) * 1000.0
            return RequestExecutionResult(
                check_id=req.check_id,
                area=req.area,
                method=req.method,
                path=req.path,
                status="INCOMPLETE",
                status_code=None,
                response=None,
                elapsed_ms=elapsed_ms,
                timed_out=False,
                error=clean(f"connection error ({exc.__class__.__name__})", 200),
                actor=req.actor,
                expected=req.expected,
                headers_sent=headers_recorded,
            )
        except Exception as exc:
            elapsed_ms = (time.monotonic() - t0) * 1000.0
            return RequestExecutionResult(
                check_id=req.check_id,
                area=req.area,
                method=req.method,
                path=req.path,
                status="INCOMPLETE",
                status_code=None,
                response=None,
                elapsed_ms=elapsed_ms,
                timed_out=False,
                error=clean(f"execution error ({exc.__class__.__name__})", 200),
                actor=req.actor,
                expected=req.expected,
                headers_sent=headers_recorded,
            )

    def execute_plan(self, plan: NativePlan) -> NativeExecutionResult:
        mode = (
            self.cfg.runtime_verification.mode
            if self.cfg.runtime_verification
            else "fixture"
        )
        total_budget = (
            LOCAL_APP_MAX_REQUESTS if mode == "local-app" else FIXTURE_MAX_REQUESTS
        )

        result = NativeExecutionResult(
            status="EXECUTED",
            requests_sent=0,
            total_budget=total_budget,
            elapsed_seconds=0.0,
            timed_out=False,
            refused=False,
            refusal_reason="",
        )

        # ── 1. TARGET SAFETY ENFORCEMENT ──────────────────────────────
        if not self.eligibility.allowed:
            result.status = "INCOMPLETE"
            result.refused = True
            result.refusal_reason = self.eligibility.reason
            for area_name in VERIFICATION_AREAS:
                area_plan = plan.areas.get(area_name)
                configured = area_plan.configured if area_plan else False
                result.area_results[area_name] = AreaExecutionResult(
                    area=area_name,
                    status="NOT VERIFIED" if not configured else "INCOMPLETE",
                    configured=configured,
                    error=self.eligibility.reason,
                )
            return result

        # ── 2. BUDGET & PLAN VALIDATION BEFORE EXECUTION ─────────────
        if plan.is_over_budget:
            result.status = "INCOMPLETE"
            result.refused = True
            result.refusal_reason = "plan is marked over budget"
            self._mark_all_areas_incomplete(plan, result, "plan exceeds request budget")
            return result

        # Fixture mode must not use identity setup hook (Design §7.1, Requirement 1)
        if mode == "fixture" and (plan.setup_requests or plan.identity_setup_count > 0):
            result.status = "INCOMPLETE"
            result.refused = True
            result.refusal_reason = "fixture mode must not use identity setup hook"
            self._mark_all_areas_incomplete(plan, result, result.refusal_reason)
            return result

        if plan.total_verification_requests > FIXTURE_MAX_REQUESTS:
            result.status = "INCOMPLETE"
            result.refused = True
            result.refusal_reason = (
                f"total verification requests ({plan.total_verification_requests}) "
                f"exceeds limit ({FIXTURE_MAX_REQUESTS})"
            )
            self._mark_all_areas_incomplete(plan, result, result.refusal_reason)
            return result

        if plan.identity_setup_count > SETUP_MAX_REQUESTS:
            result.status = "INCOMPLETE"
            result.refused = True
            result.refusal_reason = (
                f"setup request count ({plan.identity_setup_count}) exceeds limit ({SETUP_MAX_REQUESTS})"
            )
            self._mark_all_areas_incomplete(plan, result, result.refusal_reason)
            return result

        total_planned = plan.total_verification_requests + plan.identity_setup_count
        if total_planned > total_budget:
            result.status = "INCOMPLETE"
            result.refused = True
            result.refusal_reason = (
                f"total planned requests ({total_planned}) exceeds budget ({total_budget})"
            )
            self._mark_all_areas_incomplete(plan, result, result.refusal_reason)
            return result

        # Check each area's hard maximum and count agreement
        for area_name, area_plan in plan.areas.items():
            if not area_plan.configured:
                continue
            hard_max = AREA_HARD_MAXIMUMS.get(area_name, 0)
            if area_plan.requests_count > hard_max:
                result.status = "INCOMPLETE"
                result.refused = True
                result.refusal_reason = (
                    f"area {area_name} requests count ({area_plan.requests_count}) "
                    f"exceeds hard maximum ({hard_max})"
                )
                self._mark_all_areas_incomplete(plan, result, result.refusal_reason)
                return result

            # Planner and executor must agree on count when requests are populated
            if area_plan.requests and len(area_plan.requests) != area_plan.requests_count:
                result.status = "INCOMPLETE"
                result.refused = True
                result.refusal_reason = (
                    f"area {area_name} planner count ({area_plan.requests_count}) "
                    f"does not match requests list count ({len(area_plan.requests)})"
                )
                self._mark_all_areas_incomplete(plan, result, result.refusal_reason)
                return result

        # Local-app mode auto-generates setup request if not already provided
        if (
            mode == "local-app"
            and plan.identity_setup_count == 1
            and not plan.setup_requests
        ):
            if (
                self.cfg.runtime_verification
                and self.cfg.runtime_verification.identity_setup
                and self.vault
            ):
                plan.setup_requests = [build_setup_request(self.cfg, self.vault)]

        if len(plan.setup_requests) > SETUP_MAX_REQUESTS:
            result.status = "INCOMPLETE"
            result.refused = True
            result.refusal_reason = (
                f"setup request count ({len(plan.setup_requests)}) exceeds limit ({SETUP_MAX_REQUESTS})"
            )
            self._mark_all_areas_incomplete(plan, result, result.refusal_reason)
            return result

        # ── 3. EXECUTION PHASE ─────────────────────────────────────────
        start_total = time.monotonic()

        # Step 3a: Identity setup (local-app mode only)
        if plan.setup_requests:
            setup_timed_out = False
            setup_failed = False
            setup_err = ""
            setup_req = plan.setup_requests[0]

            now = time.monotonic()
            rem_total = self.total_timeout - (now - start_total)
            if rem_total <= 0:
                setup_timed_out = True
                setup_err = "total run timeout exceeded during identity setup"
            else:
                curr_timeout = min(self.request_timeout, rem_total)
                s_res = self._execute_single_request(setup_req, timeout=curr_timeout)
                result.all_request_results.append(s_res)
                result.requests_sent += 1

                if s_res.timed_out:
                    setup_timed_out = True
                    setup_err = s_res.error or "identity setup timed out"
                    result.setup_result = IdentitySetupResult(
                        succeeded=False,
                        adapter="http-local",
                        path=setup_req.path,
                        run_id=self.vault.run_id if self.vault else "",
                        accepted=[],
                        error=setup_err,
                    )
                elif s_res.status == "INCOMPLETE":
                    setup_failed = True
                    setup_err = s_res.error or "identity setup connection error"
                    result.setup_result = IdentitySetupResult(
                        succeeded=False,
                        adapter="http-local",
                        path=setup_req.path,
                        run_id=self.vault.run_id if self.vault else "",
                        accepted=[],
                        error=setup_err,
                    )
                else:
                    expected_actors = (
                        list(self.cfg.runtime_verification.actors.keys())
                        if self.cfg.runtime_verification
                        else []
                    )
                    expected_run_id = self.vault.run_id if self.vault else ""
                    val_res = validate_setup_response(
                        resp=s_res.response,
                        expected_run_id=expected_run_id,
                        expected_labels=expected_actors,
                        vault=self.vault,
                        path=setup_req.path,
                    )
                    result.setup_result = val_res

                    # Response body discarded unread (Design §7.1)
                    if s_res.response is not None:
                        s_res.response.body = ""

                    if not val_res.succeeded:
                        setup_failed = True
                        setup_err = val_res.error or "identity setup validation failed"
                        s_res.status = "INCOMPLETE"
                        s_res.error = setup_err

            if setup_timed_out or setup_failed:
                result.status = "INCOMPLETE"
                result.timed_out = setup_timed_out
                reason = setup_err or (
                    "identity setup timed out" if setup_timed_out else "identity setup failed"
                )
                for area_name in VERIFICATION_AREAS:
                    ap = plan.areas.get(area_name)
                    result.area_results[area_name] = AreaExecutionResult(
                        area=area_name,
                        status="INCOMPLETE",
                        configured=ap.configured if ap else False,
                        timed_out=setup_timed_out,
                        error=reason,
                    )
                result.elapsed_seconds = time.monotonic() - start_total
                return result

        # Step 3b: Verification areas in deterministic order
        for area_name in VERIFICATION_AREAS:
            area_plan = plan.areas.get(area_name)
            if not area_plan or not area_plan.configured:
                reason = area_plan.reason if area_plan else "area not in plan"
                result.area_results[area_name] = AreaExecutionResult(
                    area=area_name,
                    status="NOT CONFIGURED",
                    configured=False,
                    error=reason,
                )
                continue

            # Check total timeout before starting area
            now = time.monotonic()
            rem_total = self.total_timeout - (now - start_total)
            if rem_total <= 0:
                result.timed_out = True
                result.status = "INCOMPLETE"
                result.area_results[area_name] = AreaExecutionResult(
                    area=area_name,
                    status="INCOMPLETE",
                    configured=True,
                    timed_out=True,
                    error="total run timeout exceeded (180s)",
                )
                continue

            area_start = time.monotonic()
            requests_to_run = area_plan.requests
            planned_count = (
                len(requests_to_run) if requests_to_run else area_plan.requests_count
            )

            area_res = AreaExecutionResult(
                area=area_name,
                status="EXECUTED",
                configured=True,
                requests_planned=planned_count,
            )

            # If no requests were attached to the plan, record area_res as EXECUTED
            if not requests_to_run:
                result.area_results[area_name] = area_res
                continue

            # If this is authentication verification with declared actors, run auth verification
            if area_name == "authentication" and any(r.actor is not None for r in requests_to_run):
                self._execute_auth_area(
                    area_plan=area_plan,
                    area_res=area_res,
                    start_total=start_total,
                    area_start=area_start,
                    result=result,
                )
                result.area_results[area_name] = area_res
                continue

            # If this is session verification with declared actors, run session evaluation
            # using authentication evidence. This enforces A3 prerequisites.
            if area_name == "session" and any(r.actor is not None for r in requests_to_run):
                self._execute_session_area(
                    area_plan=area_plan,
                    area_res=area_res,
                    start_total=start_total,
                    area_start=area_start,
                    result=result,
                    plan=plan,
                )
                result.area_results[area_name] = area_res
                continue

            # If this is authorization verification with declared actors, run authorization evaluation
            # using authentication evidence. This enforces A3 prerequisites.
            if area_name == "authorization" and any(r.actor is not None for r in requests_to_run):
                self._execute_authz_area(
                    area_plan=area_plan,
                    area_res=area_res,
                    start_total=start_total,
                    area_start=area_start,
                    result=result,
                    plan=plan,
                )
                result.area_results[area_name] = area_res
                continue

            # If this is idor_bola verification with declared actors, run idor evaluation
            # using authentication evidence. This enforces A3 prerequisites.
            if area_name == "idor_bola" and any(r.actor is not None for r in requests_to_run):
                self._execute_idor_area(
                    area_plan=area_plan,
                    area_res=area_res,
                    start_total=start_total,
                    area_start=area_start,
                    result=result,
                    plan=plan,
                )
                result.area_results[area_name] = area_res
                continue

            # If this is tenant_isolation verification with declared actors, run tenant evaluation
            # using authentication evidence. This enforces A3 prerequisites.
            if area_name == "tenant_isolation" and any(r.actor is not None for r in requests_to_run):
                self._execute_tenant_area(
                    area_plan=area_plan,
                    area_res=area_res,
                    start_total=start_total,
                    area_start=area_start,
                    result=result,
                    plan=plan,
                )
                result.area_results[area_name] = area_res
                continue

            # Execute requests for this area
            for req in requests_to_run:
                now = time.monotonic()
                rem_total = self.total_timeout - (now - start_total)
                if rem_total <= 0:
                    result.timed_out = True
                    result.status = "INCOMPLETE"
                    area_res.timed_out = True
                    area_res.status = "INCOMPLETE"
                    area_res.error = "total run timeout exceeded (180s)"
                    break

                rem_area = self.area_timeout - (now - area_start)
                if rem_area <= 0:
                    area_res.timed_out = True
                    area_res.status = "INCOMPLETE"
                    area_res.error = f"area timeout exceeded ({self.area_timeout:.1f}s)"
                    result.status = "INCOMPLETE"
                    break

                effective_timeout = min(self.request_timeout, rem_area, rem_total)

                # Check budget bounds before sending
                assert self.client is not None
                if self.client.sent >= self.client.max_budget:
                    area_res.budget_exceeded = True
                    area_res.status = "INCOMPLETE"
                    area_res.error = f"total request budget ({self.client.max_budget}) exhausted"
                    result.status = "INCOMPLETE"
                    break

                hard_max = AREA_HARD_MAXIMUMS.get(area_name, 0)
                if area_res.requests_sent >= hard_max:
                    area_res.budget_exceeded = True
                    area_res.status = "INCOMPLETE"
                    area_res.error = f"area hard maximum ({hard_max}) reached"
                    result.status = "INCOMPLETE"
                    break

                req_res = self._execute_single_request(req, timeout=effective_timeout)
                area_res.request_results.append(req_res)
                result.all_request_results.append(req_res)
                area_res.requests_sent += 1
                result.requests_sent += 1

                # If request timed out, stop remaining requests for this area (no retry)
                if req_res.timed_out:
                    area_res.timed_out = True
                    area_res.status = "INCOMPLETE"
                    area_res.error = req_res.error
                    result.status = "INCOMPLETE"
                    break

                # If connection failed or error occurred, stop remaining requests
                if req_res.status == "INCOMPLETE":
                    area_res.status = "INCOMPLETE"
                    area_res.error = req_res.error
                    result.status = "INCOMPLETE"
                    break

            result.area_results[area_name] = area_res

        result.elapsed_seconds = time.monotonic() - start_total

        # Set overall status
        active_areas = [
            ar for ar in result.area_results.values()
            if ar.configured and (ar.request_results or ar.checks or ar.error or ar.status != "EXECUTED")
        ]
        if any(ar.timed_out for ar in result.area_results.values()):
            result.timed_out = True
        if any(ar.status == "FAIL" for ar in active_areas):
            result.status = "FAIL"
        elif any(ar.status == "INCOMPLETE" for ar in active_areas) or result.timed_out:
            result.status = "INCOMPLETE"
        elif active_areas and all(ar.status == "PASS" for ar in active_areas):
            result.status = "PASS"
        else:
            result.status = "EXECUTED"

        return result

    def _execute_auth_area(
        self,
        area_plan: AreaPlan,
        area_res: AreaExecutionResult,
        start_total: float,
        area_start: float,
        result: NativeExecutionResult,
    ) -> None:
        """Execute and evaluate authentication checks (A1-A6) deterministically (Design §8)."""
        cfg = self.cfg
        deny_statuses = (
            cfg.runtime_verification.deny_statuses
            if cfg.runtime_verification and cfg.runtime_verification.deny_statuses
            else frozenset({401, 403, 404})
        )
        login_cfg = cfg.authentication.login if cfg.authentication else None
        username_field = login_cfg.username_field if login_cfg else "email"
        password_field = login_cfg.password_field if login_cfg else "password"
        content_type = login_cfg.content_type if login_cfg else "application/json"

        users = [k for k, v in sorted(cfg.runtime_verification.actors.items()) if v.role == "user"] if cfg.runtime_verification else []
        primary_user = "user_a" if "user_a" in users else (users[0] if users else "user_a")

        positive_control_failed = False
        ambiguous_detected = False

        for req in area_plan.requests:
            now = time.monotonic()
            rem_total = self.total_timeout - (now - start_total)
            if rem_total <= 0:
                result.timed_out = True
                result.status = "INCOMPLETE"
                area_res.timed_out = True
                area_res.status = "INCOMPLETE"
                area_res.error = "total run timeout exceeded (180s)"
                break

            rem_area = self.area_timeout - (now - area_start)
            if rem_area <= 0:
                area_res.timed_out = True
                area_res.status = "INCOMPLETE"
                area_res.error = f"area timeout exceeded ({self.area_timeout:.1f}s)"
                result.status = "INCOMPLETE"
                break

            assert self.client is not None
            if self.client.sent >= self.client.max_budget:
                area_res.budget_exceeded = True
                area_res.status = "INCOMPLETE"
                area_res.error = f"total request budget ({self.client.max_budget}) exhausted"
                result.status = "INCOMPLETE"
                break

            hard_max = AREA_HARD_MAXIMUMS.get("authentication", 9)
            if area_res.requests_sent >= hard_max:
                area_res.budget_exceeded = True
                area_res.status = "INCOMPLETE"
                area_res.error = "area hard maximum (9) reached"
                result.status = "INCOMPLETE"
                break

            headers = dict(req.headers)
            body = req.body

            if req.check_id == "A2":
                if body is None:
                    inv_secret = "invalid_synth_" + secrets.token_urlsafe(16)
                    payload_dict = {username_field: req.actor, password_field: inv_secret}
                    if content_type == "application/x-www-form-urlencoded":
                        body = urllib.parse.urlencode(payload_dict).encode("utf-8")
                        headers.setdefault("Content-Type", "application/x-www-form-urlencoded")
                    else:
                        body = json.dumps(payload_dict).encode("utf-8")
                        headers.setdefault("Content-Type", "application/json")

            elif req.check_id == "A3":
                if body is None and self.vault and req.actor:
                    sec_val = self.vault.get_actor_secret(req.actor).reveal_for_request()
                    payload_dict = {username_field: req.actor, password_field: sec_val}
                    if content_type == "application/x-www-form-urlencoded":
                        body = urllib.parse.urlencode(payload_dict).encode("utf-8")
                        headers.setdefault("Content-Type", "application/x-www-form-urlencoded")
                    else:
                        body = json.dumps(payload_dict).encode("utf-8")
                        headers.setdefault("Content-Type", "application/json")
                if (
                    req.actor == primary_user
                    and self._pre_auth_cookie is not None
                    and "Cookie" not in headers
                ):
                    headers["Cookie"] = self._pre_auth_cookie.reveal_for_request()
                    self._pre_auth_sent = True

            elif req.check_id in ("A4", "A5"):
                if (
                    self.vault
                    and req.actor
                    and "Cookie" not in headers
                    and "Authorization" not in headers
                ):
                    sess = self.vault.get_session(req.actor)
                    if sess.is_present("cookie"):
                        cookie_sec = sess.get("cookie")
                        if cookie_sec:
                            headers["Cookie"] = cookie_sec.reveal_for_request()
                    if sess.is_present("authorization"):
                        auth_sec = sess.get("authorization")
                        if auth_sec:
                            headers["Authorization"] = auth_sec.reveal_for_request()

            elif req.check_id == "A6":
                if (
                    "Cookie" not in headers
                    and "Authorization" not in headers
                    and req.actor in self._saved_pre_logout_sessions
                ):
                    old_sess = self._saved_pre_logout_sessions[req.actor]
                    if old_sess.get("cookie"):
                        headers["Cookie"] = old_sess["cookie"]
                    if old_sess.get("authorization"):
                        headers["Authorization"] = old_sess["authorization"]

            req_to_send = PlannedRequest(
                area=req.area,
                check_id=req.check_id,
                method=req.method,
                path=req.path,
                headers=headers,
                body=body,
                actor=req.actor,
                expected=req.expected,
                marker=req.marker,
            )
            effective_timeout = min(self.request_timeout, rem_area, rem_total)
            req_res = self._execute_single_request(req_to_send, timeout=effective_timeout)
            area_res.request_results.append(req_res)
            result.all_request_results.append(req_res)
            area_res.requests_sent += 1
            result.requests_sent += 1

            if req_res.timed_out:
                area_res.timed_out = True
                area_res.status = "INCOMPLETE"
                area_res.error = req_res.error
                result.status = "INCOMPLETE"
                break

            if req_res.status == "INCOMPLETE":
                area_res.status = "INCOMPLETE"
                area_res.error = req_res.error
                result.status = "INCOMPLETE"
                break

            resp = req_res.response
            if resp is None:
                area_res.status = "INCOMPLETE"
                break

            if is_mfa_challenge(resp):
                area_res.status = "NOT VERIFIED"
                area_res.error = "unsupported authentication flow: MFA/CAPTCHA challenge detected"
                break

            cookie_str, auth_str = extract_session(resp)
            session_issued = bool(cookie_str or auth_str)
            session_val = cookie_str or auth_str
            fingerprint = compute_fingerprint(self._run_hmac_key, session_val)
            marker_present = (req.marker in resp.body) if req.marker else False
            status_class = f"{resp.status // 100}xx"
            classification = "incomplete"

            if req.check_id == "A1":
                # Track pre-auth cookie for S4 rotation detection
                if cookie_str and fingerprint:
                    self._pre_auth_cookie = SecretValue(cookie_str)
                    self._pre_auth_fingerprint = fingerprint
                if resp.status in deny_statuses and not marker_present:
                    classification = "denied"
                elif 200 <= resp.status < 300 and marker_present:
                    classification = "allowed"
                    area_res.findings.append(make_auth_finding("A1", req.path, resp.status))
                else:
                    classification = "ambiguous"
                    ambiguous_detected = True
                    area_res.error = f"ambiguous response on A1 unauthenticated access (HTTP {resp.status})"

            elif req.check_id == "A2":
                if session_issued or (200 <= resp.status < 300):
                    classification = "allowed"
                    area_res.findings.append(make_auth_finding("A2", req.path, resp.status))
                elif (resp.status in deny_statuses or 400 <= resp.status < 500) and not session_issued:
                    classification = "denied"
                else:
                    classification = "ambiguous"
                    ambiguous_detected = True
                    area_res.error = f"ambiguous response on A2 invalid credentials (HTTP {resp.status})"

            elif req.check_id == "A3":
                if 200 <= resp.status < 400 and session_issued:
                    classification = "allowed"
                    if self.vault and req.actor:
                        sess = self.vault.get_session(req.actor)
                        if cookie_str:
                            sess.set("cookie", cookie_str)
                        if auth_str:
                            sess.set("authorization", auth_str)
                        self._saved_pre_logout_sessions[req.actor] = {
                            "cookie": cookie_str or "",
                            "authorization": auth_str or "",
                        }
                    # Store cookie attributes for S5 evaluation
                    if cookie_str and req.actor:
                        self._a3_cookie_attributes[req.actor] = extract_all_cookie_attributes(resp)
                    elif req.actor:
                        self._a3_cookie_attributes[req.actor] = None  # bearer token, no cookies
                    # If this was the actor sent with pre-auth cookie, record pre-auth fingerprint
                    if req.actor == primary_user and self._pre_auth_sent and self._pre_auth_fingerprint:
                        self._pre_auth_fingerprints[primary_user] = self._pre_auth_fingerprint
                else:
                    classification = "incomplete"
                    positive_control_failed = True
                    area_res.error = (
                        f"positive control failed: valid login for '{req.actor}' "
                        f"failed (HTTP {resp.status}, session_issued={session_issued})"
                    )

            elif req.check_id == "A4":
                if 200 <= resp.status < 300 and marker_present:
                    classification = "allowed"
                elif 200 <= resp.status < 300 and not marker_present:
                    classification = "ambiguous"
                    ambiguous_detected = True
                    area_res.error = f"ambiguous response on A4: HTTP {resp.status} but protected marker absent"
                elif resp.status in deny_statuses:
                    classification = "denied"
                    positive_control_failed = True
                    area_res.error = f"positive control failed: authenticated access to {req.path} denied (HTTP {resp.status})"
                else:
                    classification = "ambiguous"
                    ambiguous_detected = True
                    area_res.error = f"ambiguous response on A4: HTTP {resp.status}"

            elif req.check_id == "A5":
                if 200 <= resp.status < 400:
                    classification = "allowed"
                    if self.vault and req.actor:
                        self.vault.get_session(req.actor).clear()
                else:
                    classification = "incomplete"
                    area_res.error = f"logout request failed with HTTP {resp.status}"

            elif req.check_id == "A6":
                if resp.status in deny_statuses and not marker_present:
                    classification = "denied"
                elif 200 <= resp.status < 300 and marker_present:
                    classification = "allowed"
                    area_res.findings.append(make_auth_finding("A6", req.path, resp.status))
                else:
                    classification = "ambiguous"
                    ambiguous_detected = True
                    area_res.error = f"ambiguous response on A6 reuse after logout (HTTP {resp.status})"

            check_record = {
                "check": req.check_id,
                "area": "authentication",
                "actors": [req.actor or "anonymous"],
                "method": req.method,
                "path": req.path,
                "expected": req.expected,
                "status_class": status_class,
                "status": resp.status,
                "classification": classification,
                "marker_present": marker_present,
                "elapsed_ms": round(req_res.elapsed_ms, 1),
                "fingerprint": fingerprint,
            }
            # Attach cookie attributes to A3 checks for S5 evaluation
            if req.check_id == "A3" and req.actor and req.actor in self._a3_cookie_attributes:
                check_record["cookie_attributes"] = self._a3_cookie_attributes[req.actor]
            area_res.checks.append(check_record)

            if positive_control_failed or ambiguous_detected or (area_res.error and req.check_id in ("A5", "A6")):
                break

        if area_res.status == "NOT VERIFIED":
            area_res.reason = area_res.error or "unsupported authentication flow"
        elif positive_control_failed:
            area_res.findings = []
            area_res.status = "INCOMPLETE"
            area_res.reason = area_res.error or "positive control failed"
        elif area_res.findings:
            area_res.status = "FAIL"
            area_res.reason = f"{len(area_res.findings)} finding(s) detected"
            area_res.runtime_checks_executed = (area_res.requests_sent == area_res.requests_planned)
        elif ambiguous_detected or area_res.error or area_res.timed_out or area_res.budget_exceeded:
            area_res.status = "INCOMPLETE"
            area_res.reason = area_res.error or "execution incomplete"
        else:
            area_res.runtime_checks_executed = True
            has_logout = any(r.check_id == "A5" for r in area_plan.requests)
            if has_logout:
                area_res.status = "PASS"
                area_res.reason = "all authentication checks passed"
            else:
                area_res.status = "EXECUTED"
                area_res.reason = "authentication checks executed; logout not declared (at most EXECUTED)"

        return result

    def _execute_session_area(
        self,
        area_plan: AreaPlan,
        area_res: AreaExecutionResult,
        start_total: float,
        area_start: float,
        result: NativeExecutionResult,
        plan: NativePlan,
    ) -> None:
        """Execute and evaluate session checks (S1-S6) deterministically (Design §9).

        S1, S3, S4, S5, S6 reuse authentication evidence.
        S2 sends exactly 1 new request (GET protected with same session).
        """
        cfg = self.cfg
        deny_statuses = (
            cfg.runtime_verification.deny_statuses
            if cfg.runtime_verification and cfg.runtime_verification.deny_statuses
            else frozenset({401, 403, 404})
        )

        # Get authentication results for reuse
        auth_res = result.area_results.get("authentication")
        if not auth_res or not auth_res.checks:
            area_res.status = "INCOMPLETE"
            area_res.error = "authentication area not executed; session depends on authentication"
            area_res.reason = area_res.error
            return

        if auth_res.status == "INCOMPLETE" and not any(
            c.get("check") == "A3" and c.get("classification") == "allowed"
            for c in auth_res.checks
        ):
            area_res.status = "INCOMPLETE"
            area_res.error = "authentication positive control not established"
            area_res.reason = area_res.error
            return

        if auth_res.status == "NOT VERIFIED":
            area_res.status = "NOT VERIFIED"
            area_res.error = "authentication area not verified (MFA/unsupported flow)"
            area_res.reason = area_res.error
            return

        has_logout = any(r.check_id == "A5" for r in (plan.areas.get("authentication", AreaPlan(False)).requests or []))

        # Determine primary user
        users = [k for k, v in sorted(cfg.runtime_verification.actors.items()) if v.role == "user"] if cfg.runtime_verification else []
        primary_user = "user_a" if "user_a" in users else (users[0] if users else "user_a")

        # Execute S2 request (GET protected route with session)
        s2_check: dict[str, Any] | None = None
        for req in area_plan.requests:
            if req.check_id != "S2":
                continue

            now = time.monotonic()
            rem_total = self.total_timeout - (now - start_total)
            if rem_total <= 0:
                result.timed_out = True
                result.status = "INCOMPLETE"
                area_res.timed_out = True
                area_res.status = "INCOMPLETE"
                area_res.error = "total run timeout exceeded (180s)"
                area_res.reason = area_res.error
                return

            rem_area = self.area_timeout - (now - area_start)
            if rem_area <= 0:
                area_res.timed_out = True
                area_res.status = "INCOMPLETE"
                area_res.error = f"area timeout exceeded ({self.area_timeout:.1f}s)"
                area_res.reason = area_res.error
                result.status = "INCOMPLETE"
                return

            assert self.client is not None
            if self.client.sent >= self.client.max_budget:
                area_res.budget_exceeded = True
                area_res.status = "INCOMPLETE"
                area_res.error = f"total request budget ({self.client.max_budget}) exhausted"
                area_res.reason = area_res.error
                result.status = "INCOMPLETE"
                return

            hard_max = AREA_HARD_MAXIMUMS.get("session", 1)
            if area_res.requests_sent >= hard_max:
                area_res.budget_exceeded = True
                area_res.status = "INCOMPLETE"
                area_res.error = f"area hard maximum ({hard_max}) reached"
                area_res.reason = area_res.error
                result.status = "INCOMPLETE"
                return

            # Attach session from vault
            headers = dict(req.headers)
            sess_sec = None
            if self.vault and req.actor and "Cookie" not in headers and "Authorization" not in headers:
                sess = self.vault.get_session(req.actor)
                if sess.is_present("cookie"):
                    cookie_sec = sess.get("cookie")
                    if cookie_sec:
                        headers["Cookie"] = cookie_sec.reveal_for_request()
                        sess_sec = headers["Cookie"]
                if sess.is_present("authorization"):
                    auth_sec = sess.get("authorization")
                    if auth_sec:
                        headers["Authorization"] = auth_sec.reveal_for_request()
                        if not sess_sec:
                            sess_sec = headers["Authorization"]
            elif "Cookie" in headers:
                sess_sec = headers["Cookie"]
            elif "Authorization" in headers:
                sess_sec = headers["Authorization"]

            req_to_send = PlannedRequest(
                area=req.area,
                check_id=req.check_id,
                method=req.method,
                path=req.path,
                headers=headers,
                body=req.body,
                actor=req.actor,
                expected=req.expected,
                marker=req.marker,
            )
            effective_timeout = min(self.request_timeout, rem_area, rem_total)
            req_res = self._execute_single_request(req_to_send, timeout=effective_timeout)
            area_res.request_results.append(req_res)
            result.all_request_results.append(req_res)
            area_res.requests_sent += 1
            result.requests_sent += 1

            if req_res.timed_out:
                area_res.timed_out = True
                area_res.status = "INCOMPLETE"
                area_res.error = req_res.error
                area_res.reason = area_res.error or "S2 request timed out"
                result.status = "INCOMPLETE"
                return

            if req_res.status == "INCOMPLETE":
                area_res.status = "INCOMPLETE"
                area_res.error = req_res.error
                area_res.reason = area_res.error or "S2 request failed"
                result.status = "INCOMPLETE"
                return

            resp = req_res.response
            if resp is None:
                area_res.status = "INCOMPLETE"
                area_res.reason = "no response from S2 request"
                return

            if sess_sec is None and self.vault and req.actor:
                sess_obj = self.vault.get_session(req.actor)
                if sess_obj.is_present("cookie") and sess_obj.get("cookie"):
                    sess_sec = sess_obj.get("cookie").reveal_for_request()
                elif sess_obj.is_present("authorization") and sess_obj.get("authorization"):
                    sess_sec = sess_obj.get("authorization").reveal_for_request()

            from .auth import compute_fingerprint as _compute_fp
            # S2 continuity fingerprint MUST represent the exact active session identity sent in the request,
            # NOT derived from any new Set-Cookie, Authorization header, or token returned in the response.
            fingerprint = _compute_fp(self._run_hmac_key, sess_sec)
            marker_present = (req.marker in resp.body) if req.marker else False
            status_class = f"{resp.status // 100}xx"

            if 200 <= resp.status < 300 and marker_present:
                classification = "allowed"
            elif resp.status in deny_statuses and not marker_present:
                classification = "denied"
            elif 200 <= resp.status < 300 and not marker_present:
                classification = "ambiguous"
            else:
                classification = "incomplete"

            s2_check = {
                "check": "S2",
                "area": "session",
                "actors": [req.actor or primary_user],
                "method": req.method,
                "path": req.path,
                "expected": "allowed",
                "status_class": status_class,
                "status": resp.status,
                "classification": classification,
                "marker_present": marker_present,
                "elapsed_ms": round(req_res.elapsed_ms, 1),
                "fingerprint": fingerprint,
            }

        # Determine if HTTPS
        is_https = cfg.base_url.startswith("https://")

        # Evaluate S1-S6 using session module
        checks, findings, status, reason = evaluate_session_checks(
            auth_checks=auth_res.checks,
            s2_check=s2_check,
            vault=self.vault,
            run_hmac_key=self._run_hmac_key,
            is_https=is_https,
            has_logout=has_logout,
            pre_auth_fingerprints=self._pre_auth_fingerprints if self._pre_auth_fingerprints else None,
        )

        area_res.checks = checks
        area_res.findings = findings
        area_res.status = status
        area_res.reason = reason
        area_res.runtime_checks_executed = (
            area_res.requests_sent == area_res.requests_planned
            and status in ("PASS", "FAIL", "EXECUTED")
        )

    def _execute_authz_area(
        self,
        area_plan: AreaPlan,
        area_res: AreaExecutionResult,
        start_total: float,
        area_start: float,
        result: NativeExecutionResult,
        plan: NativePlan,
    ) -> None:
        """Execute and evaluate vertical authorization checks (Z1-Z2) deterministically (Design §10, §15, §16, §17).

        Z1: Privileged authorization positive control (admin actor GET privileged route).
        Z2: Low-privilege authorization denial (user actor GET privileged route).
        """
        cfg = self.cfg
        deny_statuses = (
            cfg.runtime_verification.deny_statuses
            if cfg.runtime_verification and cfg.runtime_verification.deny_statuses
            else frozenset({401, 403, 404})
        )

        # 1. Prerequisite: Authentication area must have executed successfully
        auth_res = result.area_results.get("authentication")
        if not auth_res or not auth_res.checks:
            area_res.status = "INCOMPLETE"
            area_res.error = "authentication area not executed; authorization depends on authentication"
            area_res.reason = area_res.error
            return

        if auth_res.status == "NOT VERIFIED":
            area_res.status = "NOT VERIFIED"
            area_res.error = "authentication area not verified (MFA/unsupported flow)"
            area_res.reason = area_res.error
            return

        # 2. Identify Z1 (admin) and Z2 (user) requests
        admin_req: PlannedRequest | None = None
        user_req: PlannedRequest | None = None
        for req in area_plan.requests:
            if req.check_id == "Z1":
                admin_req = req
            elif req.check_id == "Z2":
                user_req = req

        if not admin_req or not user_req or not admin_req.actor or not user_req.actor:
            area_res.status = "INCOMPLETE"
            area_res.error = "authorization requests (Z1, Z2) missing from plan or actors undeclared"
            area_res.reason = area_res.error
            return

        admin_actor = admin_req.actor
        user_actor = user_req.actor

        # 3. Prerequisite: Both admin and user must have succeeded in A3 positive control
        admin_a3_ok = any(
            c.get("check") == "A3"
            and admin_actor in c.get("actors", [])
            and c.get("classification") == "allowed"
            for c in auth_res.checks
        )
        user_a3_ok = any(
            c.get("check") == "A3"
            and user_actor in c.get("actors", [])
            and c.get("classification") == "allowed"
            for c in auth_res.checks
        )
        if not admin_a3_ok or not user_a3_ok:
            area_res.status = "INCOMPLETE"
            area_res.error = "authentication positive control (A3) not established for authorization actors"
            area_res.reason = area_res.error
            return

        # Helper to attach actor session
        def _attach_session(actor: str, headers_dict: dict[str, str]) -> None:
            if self.vault:
                sess = self.vault.get_session(actor)
                if sess.is_present("cookie") and sess.get("cookie"):
                    headers_dict["Cookie"] = sess.get("cookie").reveal_for_request()
                if sess.is_present("authorization") and sess.get("authorization"):
                    headers_dict["Authorization"] = sess.get("authorization").reveal_for_request()
            if "Cookie" not in headers_dict and "Authorization" not in headers_dict:
                old = self._saved_pre_logout_sessions.get(actor, {})
                if old.get("cookie"):
                    headers_dict["Cookie"] = old["cookie"]
                if old.get("authorization"):
                    headers_dict["Authorization"] = old["authorization"]

        # 4. Execute Z1: Privileged positive control
        now = time.monotonic()
        rem_total = self.total_timeout - (now - start_total)
        if rem_total <= 0:
            result.timed_out = True
            result.status = "INCOMPLETE"
            area_res.timed_out = True
            area_res.status = "INCOMPLETE"
            area_res.error = "total run timeout exceeded (180s)"
            area_res.reason = area_res.error
            return

        rem_area = self.area_timeout - (now - area_start)
        if rem_area <= 0:
            area_res.timed_out = True
            area_res.status = "INCOMPLETE"
            area_res.error = f"area timeout exceeded ({self.area_timeout:.1f}s)"
            area_res.reason = area_res.error
            result.status = "INCOMPLETE"
            return

        assert self.client is not None
        if self.client.sent >= self.client.max_budget:
            area_res.budget_exceeded = True
            area_res.status = "INCOMPLETE"
            area_res.error = f"total request budget ({self.client.max_budget}) exhausted"
            area_res.reason = area_res.error
            result.status = "INCOMPLETE"
            return

        hard_max = AREA_HARD_MAXIMUMS.get("authorization", 2)
        if area_res.requests_sent >= hard_max:
            area_res.budget_exceeded = True
            area_res.status = "INCOMPLETE"
            area_res.error = f"area hard maximum ({hard_max}) reached"
            area_res.reason = area_res.error
            result.status = "INCOMPLETE"
            return

        z1_headers = dict(admin_req.headers)
        _attach_session(admin_actor, z1_headers)

        req_to_send_z1 = PlannedRequest(
            area=admin_req.area,
            check_id=admin_req.check_id,
            method=admin_req.method,
            path=admin_req.path,
            headers=z1_headers,
            body=admin_req.body,
            actor=admin_req.actor,
            expected=admin_req.expected,
            marker=admin_req.marker,
        )
        effective_timeout = min(self.request_timeout, rem_area, rem_total)
        req_res_z1 = self._execute_single_request(req_to_send_z1, timeout=effective_timeout)
        area_res.request_results.append(req_res_z1)
        result.all_request_results.append(req_res_z1)
        area_res.requests_sent += 1
        result.requests_sent += 1

        if req_res_z1.timed_out:
            area_res.timed_out = True
            area_res.status = "INCOMPLETE"
            area_res.error = req_res_z1.error
            area_res.reason = area_res.error or "Z1 request timed out"
            result.status = "INCOMPLETE"
            return

        if req_res_z1.status == "INCOMPLETE":
            area_res.status = "INCOMPLETE"
            area_res.error = req_res_z1.error
            area_res.reason = area_res.error or "Z1 request failed"
            result.status = "INCOMPLETE"
            return

        resp_z1 = req_res_z1.response
        if resp_z1 is None:
            area_res.status = "INCOMPLETE"
            area_res.reason = "no response from Z1 request"
            return

        marker_present_z1 = (admin_req.marker in resp_z1.body) if admin_req.marker else False
        status_class_z1 = f"{resp_z1.status // 100}xx"

        if 200 <= resp_z1.status < 300 and marker_present_z1:
            z1_classification = "allowed"
        elif resp_z1.status in deny_statuses and not marker_present_z1:
            z1_classification = "denied"
        elif 200 <= resp_z1.status < 300 and not marker_present_z1:
            z1_classification = "ambiguous"
        elif resp_z1.status in (400, 405, 409, 422) or (300 <= resp_z1.status < 400):
            z1_classification = "ambiguous"
        elif resp_z1.status in deny_statuses and marker_present_z1:
            z1_classification = "ambiguous"
        else:
            z1_classification = "incomplete"

        z1_check = {
            "check": "Z1",
            "area": "authorization",
            "actors": [admin_actor],
            "method": admin_req.method,
            "path": admin_req.path,
            "expected": "allowed",
            "status_class": status_class_z1,
            "status": resp_z1.status,
            "classification": z1_classification,
            "marker_present": marker_present_z1,
            "elapsed_ms": round(req_res_z1.elapsed_ms, 1),
            "fingerprint": None,
        }

        # If positive control failed, stop and mark INCOMPLETE (no findings fabricated)
        if z1_classification != "allowed":
            area_res.checks = [z1_check]
            area_res.findings = []
            area_res.status = "INCOMPLETE"
            area_res.error = (
                f"privileged authorization positive control Z1 failed (classification={z1_classification})"
            )
            area_res.reason = area_res.error
            return

        # 5. Execute Z2: Low-privilege authorization denial
        now = time.monotonic()
        rem_total = self.total_timeout - (now - start_total)
        if rem_total <= 0:
            result.timed_out = True
            result.status = "INCOMPLETE"
            area_res.timed_out = True
            area_res.status = "INCOMPLETE"
            area_res.checks = [z1_check]
            area_res.error = "total run timeout exceeded (180s)"
            area_res.reason = area_res.error
            return

        rem_area = self.area_timeout - (now - area_start)
        if rem_area <= 0:
            area_res.timed_out = True
            area_res.status = "INCOMPLETE"
            area_res.checks = [z1_check]
            area_res.error = f"area timeout exceeded ({self.area_timeout:.1f}s)"
            area_res.reason = area_res.error
            result.status = "INCOMPLETE"
            return

        if self.client.sent >= self.client.max_budget:
            area_res.budget_exceeded = True
            area_res.status = "INCOMPLETE"
            area_res.checks = [z1_check]
            area_res.error = f"total request budget ({self.client.max_budget}) exhausted"
            area_res.reason = area_res.error
            result.status = "INCOMPLETE"
            return

        if area_res.requests_sent >= hard_max:
            area_res.budget_exceeded = True
            area_res.status = "INCOMPLETE"
            area_res.checks = [z1_check]
            area_res.error = f"area hard maximum ({hard_max}) reached"
            area_res.reason = area_res.error
            result.status = "INCOMPLETE"
            return

        z2_headers = dict(user_req.headers)
        _attach_session(user_actor, z2_headers)

        req_to_send_z2 = PlannedRequest(
            area=user_req.area,
            check_id=user_req.check_id,
            method=user_req.method,
            path=user_req.path,
            headers=z2_headers,
            body=user_req.body,
            actor=user_req.actor,
            expected=user_req.expected,
            marker=user_req.marker,
        )
        effective_timeout = min(self.request_timeout, rem_area, rem_total)
        req_res_z2 = self._execute_single_request(req_to_send_z2, timeout=effective_timeout)
        area_res.request_results.append(req_res_z2)
        result.all_request_results.append(req_res_z2)
        area_res.requests_sent += 1
        result.requests_sent += 1

        if req_res_z2.timed_out:
            area_res.timed_out = True
            area_res.status = "INCOMPLETE"
            area_res.checks = [z1_check]
            area_res.error = req_res_z2.error
            area_res.reason = area_res.error or "Z2 request timed out"
            result.status = "INCOMPLETE"
            return

        if req_res_z2.status == "INCOMPLETE":
            area_res.status = "INCOMPLETE"
            area_res.checks = [z1_check]
            area_res.error = req_res_z2.error
            area_res.reason = area_res.error or "Z2 request failed"
            result.status = "INCOMPLETE"
            return

        resp_z2 = req_res_z2.response
        if resp_z2 is None:
            area_res.checks = [z1_check]
            area_res.status = "INCOMPLETE"
            area_res.reason = "no response from Z2 request"
            return

        marker_present_z2 = (user_req.marker in resp_z2.body) if user_req.marker else False
        status_class_z2 = f"{resp_z2.status // 100}xx"

        if resp_z2.status in deny_statuses and not marker_present_z2:
            z2_classification = "denied"
        elif 200 <= resp_z2.status < 300 and marker_present_z2:
            z2_classification = "allowed"
        elif 200 <= resp_z2.status < 300 and not marker_present_z2:
            z2_classification = "ambiguous"
        elif resp_z2.status in (400, 405, 409, 422) or (300 <= resp_z2.status < 400):
            z2_classification = "ambiguous"
        elif resp_z2.status in deny_statuses and marker_present_z2:
            z2_classification = "ambiguous"
        else:
            z2_classification = "incomplete"

        z2_check = {
            "check": "Z2",
            "area": "authorization",
            "actors": [user_actor],
            "method": user_req.method,
            "path": user_req.path,
            "expected": "denied",
            "status_class": status_class_z2,
            "status": resp_z2.status,
            "classification": z2_classification,
            "marker_present": marker_present_z2,
            "elapsed_ms": round(req_res_z2.elapsed_ms, 1),
            "fingerprint": None,
        }

        # 6. Evaluate authorization checks using authz module
        from .authz import evaluate_authz_checks
        checks, findings, status, reason = evaluate_authz_checks(
            z1_check=z1_check,
            z2_check=z2_check,
            privileged_path=user_req.path,
            user_actor=user_actor,
        )

        area_res.checks = checks
        area_res.findings = findings
        area_res.status = status
        area_res.reason = reason
        area_res.runtime_checks_executed = (
            area_res.requests_sent == area_res.requests_planned
            and status in ("PASS", "FAIL")
        )

    def _execute_idor_area(
        self,
        area_plan: AreaPlan,
        area_res: AreaExecutionResult,
        start_total: float,
        area_start: float,
        result: NativeExecutionResult,
        plan: NativePlan,
    ) -> None:
        """Execute and evaluate horizontal IDOR/BOLA checks (I1-I4) deterministically (Design §11, §15, §16, §17).

        I1: user_a own object positive control (expected allowed).
        I2: user_a access to user_b object (expected denied).
        I3: user_b own object positive control (expected allowed).
        I4: user_b access to user_a object (expected denied).
        """
        cfg = self.cfg
        deny_statuses = (
            cfg.runtime_verification.deny_statuses
            if cfg.runtime_verification and cfg.runtime_verification.deny_statuses
            else frozenset({401, 403, 404})
        )

        # 1. Prerequisite: Authentication area must have executed successfully
        auth_res = result.area_results.get("authentication")
        if not auth_res or not auth_res.checks:
            area_res.status = "INCOMPLETE"
            area_res.error = "authentication area not executed; IDOR verification depends on authentication"
            area_res.reason = area_res.error
            return

        if auth_res.status == "NOT VERIFIED":
            area_res.status = "NOT VERIFIED"
            area_res.error = "authentication area not verified (MFA/unsupported flow)"
            area_res.reason = area_res.error
            return

        # 2. Identify I1, I2, I3, I4 requests from area_plan.requests
        i1_req = next((r for r in area_plan.requests if r.check_id == "I1"), None)
        i2_req = next((r for r in area_plan.requests if r.check_id == "I2"), None)
        i3_req = next((r for r in area_plan.requests if r.check_id == "I3"), None)
        i4_req = next((r for r in area_plan.requests if r.check_id == "I4"), None)

        if not i1_req or not i2_req or not i3_req or not i4_req:
            area_res.status = "INCOMPLETE"
            area_res.error = "IDOR requests (I1-I4) missing from plan"
            area_res.reason = area_res.error
            return

        user_a = i1_req.actor
        user_b = i3_req.actor
        if not user_a or not user_b or user_a == user_b:
            area_res.status = "INCOMPLETE"
            area_res.error = "two distinct user actors required for IDOR verification"
            area_res.reason = area_res.error
            return

        # 3. Prerequisite: Both user_a and user_b must have succeeded in A3 positive control
        user_a_a3_ok = any(
            c.get("check") == "A3"
            and user_a in c.get("actors", [])
            and c.get("classification") == "allowed"
            for c in auth_res.checks
        )
        user_b_a3_ok = any(
            c.get("check") == "A3"
            and user_b in c.get("actors", [])
            and c.get("classification") == "allowed"
            for c in auth_res.checks
        )
        if not user_a_a3_ok or not user_b_a3_ok:
            area_res.status = "INCOMPLETE"
            area_res.error = "authentication positive control (A3) not established for IDOR user actors"
            area_res.reason = area_res.error
            return

        # Helper to attach actor session
        def _attach_session(actor: str, headers_dict: dict[str, str]) -> None:
            if self.vault:
                sess = self.vault.get_session(actor)
                if sess.is_present("cookie") and sess.get("cookie"):
                    headers_dict["Cookie"] = sess.get("cookie").reveal_for_request()
                if sess.is_present("authorization") and sess.get("authorization"):
                    headers_dict["Authorization"] = sess.get("authorization").reveal_for_request()
            if "Cookie" not in headers_dict and "Authorization" not in headers_dict:
                old = self._saved_pre_logout_sessions.get(actor, {})
                if old.get("cookie"):
                    headers_dict["Cookie"] = old["cookie"]
                if old.get("authorization"):
                    headers_dict["Authorization"] = old["authorization"]

        def _classify(req: PlannedRequest, resp: Response, other_req: PlannedRequest) -> tuple[str, bool]:
            marker_present = (req.marker in resp.body) if req.marker else False
            other_marker = other_req.marker
            other_marker_present = (other_marker in resp.body) if other_marker else False

            if other_marker_present:
                return "ambiguous", marker_present
            if 200 <= resp.status < 300 and marker_present:
                return "allowed", marker_present
            if resp.status in deny_statuses and not marker_present:
                return "denied", marker_present
            if 200 <= resp.status < 300 and not marker_present:
                return "ambiguous", marker_present
            if resp.status in (400, 405, 409, 422) or (300 <= resp.status < 400):
                return "ambiguous", marker_present
            if resp.status in deny_statuses and marker_present:
                return "ambiguous", marker_present
            return "incomplete", marker_present

        hard_max = AREA_HARD_MAXIMUMS.get("idor_bola", 4)
        executed_checks: list[dict[str, Any]] = []

        # Helper to send a planned request with budget and timeout enforcement
        def _run_req(planned_req: PlannedRequest, actor_for_session: str) -> tuple[RequestExecutionResult | None, str | None]:
            now = time.monotonic()
            rem_total = self.total_timeout - (now - start_total)
            if rem_total <= 0:
                result.timed_out = True
                result.status = "INCOMPLETE"
                area_res.timed_out = True
                area_res.status = "INCOMPLETE"
                area_res.error = "total run timeout exceeded (180s)"
                area_res.reason = area_res.error
                return None, "total_timeout"

            rem_area = self.area_timeout - (now - area_start)
            if rem_area <= 0:
                area_res.timed_out = True
                area_res.status = "INCOMPLETE"
                area_res.error = f"area timeout exceeded ({self.area_timeout:.1f}s)"
                area_res.reason = area_res.error
                result.status = "INCOMPLETE"
                return None, "area_timeout"

            assert self.client is not None
            if self.client.sent >= self.client.max_budget:
                area_res.budget_exceeded = True
                area_res.status = "INCOMPLETE"
                area_res.error = f"total request budget ({self.client.max_budget}) exhausted"
                area_res.reason = area_res.error
                result.status = "INCOMPLETE"
                return None, "total_budget"

            if area_res.requests_sent >= hard_max:
                area_res.budget_exceeded = True
                area_res.status = "INCOMPLETE"
                area_res.error = f"area hard maximum ({hard_max}) reached"
                area_res.reason = area_res.error
                result.status = "INCOMPLETE"
                return None, "hard_max"

            headers = dict(planned_req.headers)
            _attach_session(actor_for_session, headers)

            req_to_send = PlannedRequest(
                area=planned_req.area,
                check_id=planned_req.check_id,
                method=planned_req.method,
                path=planned_req.path,
                headers=headers,
                body=planned_req.body,
                actor=planned_req.actor,
                expected=planned_req.expected,
                marker=planned_req.marker,
            )
            effective_timeout = min(self.request_timeout, rem_area, rem_total)
            req_res = self._execute_single_request(req_to_send, timeout=effective_timeout)
            area_res.request_results.append(req_res)
            result.all_request_results.append(req_res)
            area_res.requests_sent += 1
            result.requests_sent += 1
            return req_res, None

        # 4. Execute I1: user_a positive control on object-a
        req_res_i1, err = _run_req(i1_req, user_a)
        if err or not req_res_i1 or req_res_i1.timed_out or req_res_i1.status == "INCOMPLETE" or req_res_i1.response is None:
            area_res.status = "INCOMPLETE"
            if req_res_i1 and req_res_i1.timed_out:
                area_res.timed_out = True
            area_res.error = (req_res_i1.error if req_res_i1 else None) or area_res.error or "I1 request failed"
            area_res.reason = area_res.error
            result.status = "INCOMPLETE"
            return

        resp_i1 = req_res_i1.response
        i1_class, i1_marker = _classify(i1_req, resp_i1, i3_req)
        i1_check = {
            "check": "I1",
            "area": "idor_bola",
            "actors": [user_a],
            "method": i1_req.method,
            "path": i1_req.path,
            "expected": "allowed",
            "status_class": f"{resp_i1.status // 100}xx",
            "status": resp_i1.status,
            "classification": i1_class,
            "marker_present": i1_marker,
            "elapsed_ms": round(req_res_i1.elapsed_ms, 1),
            "fingerprint": None,
        }
        executed_checks.append(i1_check)

        # GATING: If I1 positive control failed, stop immediately
        if i1_class != "allowed":
            area_res.checks = executed_checks
            area_res.findings = []
            area_res.status = "INCOMPLETE"
            area_res.error = f"own-object positive control I1 failed (classification={i1_class})"
            area_res.reason = area_res.error
            return

        # 5. Execute I2: user_a cross-actor access to object-b
        req_res_i2, err = _run_req(i2_req, user_a)
        if err or not req_res_i2 or req_res_i2.timed_out or req_res_i2.status == "INCOMPLETE" or req_res_i2.response is None:
            area_res.status = "INCOMPLETE"
            if req_res_i2 and req_res_i2.timed_out:
                area_res.timed_out = True
            area_res.checks = executed_checks
            area_res.error = (req_res_i2.error if req_res_i2 else None) or area_res.error or "I2 request failed"
            area_res.reason = area_res.error
            result.status = "INCOMPLETE"
            return

        resp_i2 = req_res_i2.response
        i2_class, i2_marker = _classify(i2_req, resp_i2, i1_req)
        i2_check = {
            "check": "I2",
            "area": "idor_bola",
            "actors": [user_a],
            "method": i2_req.method,
            "path": i2_req.path,
            "expected": "denied",
            "status_class": f"{resp_i2.status // 100}xx",
            "status": resp_i2.status,
            "classification": i2_class,
            "marker_present": i2_marker,
            "elapsed_ms": round(req_res_i2.elapsed_ms, 1),
            "fingerprint": None,
        }
        executed_checks.append(i2_check)

        # 6. Execute I3: user_b positive control on object-b
        req_res_i3, err = _run_req(i3_req, user_b)
        if err or not req_res_i3 or req_res_i3.timed_out or req_res_i3.status == "INCOMPLETE" or req_res_i3.response is None:
            area_res.status = "INCOMPLETE"
            if req_res_i3 and req_res_i3.timed_out:
                area_res.timed_out = True
            area_res.checks = executed_checks
            area_res.error = (req_res_i3.error if req_res_i3 else None) or area_res.error or "I3 request failed"
            area_res.reason = area_res.error
            result.status = "INCOMPLETE"
            return

        resp_i3 = req_res_i3.response
        i3_class, i3_marker = _classify(i3_req, resp_i3, i1_req)
        i3_check = {
            "check": "I3",
            "area": "idor_bola",
            "actors": [user_b],
            "method": i3_req.method,
            "path": i3_req.path,
            "expected": "allowed",
            "status_class": f"{resp_i3.status // 100}xx",
            "status": resp_i3.status,
            "classification": i3_class,
            "marker_present": i3_marker,
            "elapsed_ms": round(req_res_i3.elapsed_ms, 1),
            "fingerprint": None,
        }
        executed_checks.append(i3_check)

        # GATING: If I3 positive control failed, stop immediately and suppress any finding from I2
        if i3_class != "allowed":
            area_res.checks = executed_checks
            area_res.findings = []
            area_res.status = "INCOMPLETE"
            area_res.error = f"own-object positive control I3 failed (classification={i3_class})"
            area_res.reason = area_res.error
            return

        # 7. Execute I4: user_b cross-actor access to object-a
        req_res_i4, err = _run_req(i4_req, user_b)
        resp_i4 = req_res_i4.response if req_res_i4 else None

        if resp_i4 is not None:
            i4_class, i4_marker = _classify(i4_req, resp_i4, i3_req)
            i4_status = resp_i4.status
            i4_status_class = f"{resp_i4.status // 100}xx"
        else:
            i4_class = "incomplete"
            i4_marker = False
            i4_status = 0
            i4_status_class = "0xx"

        i4_check = {
            "check": "I4",
            "area": "idor_bola",
            "actors": [user_b],
            "method": i4_req.method,
            "path": i4_req.path,
            "expected": "denied",
            "status_class": i4_status_class,
            "status": i4_status,
            "classification": i4_class,
            "marker_present": i4_marker,
            "elapsed_ms": round(req_res_i4.elapsed_ms, 1) if req_res_i4 else 0.0,
            "fingerprint": None,
        }
        executed_checks.append(i4_check)

        if req_res_i4 and req_res_i4.timed_out:
            area_res.timed_out = True

        # 8. Evaluate IDOR checks using idor module
        from .idor import evaluate_idor_checks
        checks, findings, status, reason = evaluate_idor_checks(
            check_records=executed_checks,
            user_a=user_a,
            user_b=user_b,
            res_a_path=i1_req.path,
            res_b_path=i3_req.path,
        )

        area_res.checks = checks
        area_res.findings = findings
        area_res.status = status
        area_res.reason = reason

        i4_failed = bool(
            err
            or not req_res_i4
            or req_res_i4.timed_out
            or req_res_i4.status == "INCOMPLETE"
            or resp_i4 is None
        )
        if i4_failed and status != "FAIL":
            area_res.status = "INCOMPLETE"
            area_res.error = (req_res_i4.error if req_res_i4 else None) or area_res.error or "I4 request failed"
            area_res.reason = area_res.error
            result.status = "INCOMPLETE"

        area_res.runtime_checks_executed = (
            area_res.requests_sent == area_res.requests_planned
            and area_res.status in ("PASS", "FAIL")
        )

    def _execute_tenant_area(
        self,
        area_plan: AreaPlan,
        area_res: AreaExecutionResult,
        start_total: float,
        area_start: float,
        result: NativeExecutionResult,
        plan: NativePlan,
    ) -> None:
        """Execute and evaluate tenant isolation checks (T1-T4) deterministically (Design §12, §15, §16, §17).

        T1: tenant-a actor own-tenant positive control (expected allowed).
        T2: tenant-a actor access to tenant-b resource (expected denied).
        T3: tenant-b actor own-tenant positive control (expected allowed).
        T4: tenant-b actor access to tenant-a resource (expected denied).

        Positive-control gating:
        - T1 failure -> stop immediately; no T2/T3/T4; no finding.
        - T3 failure -> suppress any T2 finding already observed; INCOMPLETE.
        - RT-TENANT-001 only when T1 allowed AND T3 allowed AND (T2 allowed OR T4 allowed).
        """
        cfg = self.cfg
        deny_statuses = (
            cfg.runtime_verification.deny_statuses
            if cfg.runtime_verification and cfg.runtime_verification.deny_statuses
            else frozenset({401, 403, 404})
        )

        # 1. Prerequisite: Authentication area must have executed successfully
        auth_res = result.area_results.get("authentication")
        if not auth_res or not auth_res.checks:
            area_res.status = "INCOMPLETE"
            area_res.error = "authentication area not executed; tenant isolation verification depends on authentication"
            area_res.reason = area_res.error
            return

        if auth_res.status == "NOT VERIFIED":
            area_res.status = "NOT VERIFIED"
            area_res.error = "authentication area not verified (MFA/unsupported flow)"
            area_res.reason = area_res.error
            return

        # 2. Identify T1, T2, T3, T4 requests from area_plan.requests
        t1_req = next((r for r in area_plan.requests if r.check_id == "T1"), None)
        t2_req = next((r for r in area_plan.requests if r.check_id == "T2"), None)
        t3_req = next((r for r in area_plan.requests if r.check_id == "T3"), None)
        t4_req = next((r for r in area_plan.requests if r.check_id == "T4"), None)

        if not t1_req or not t2_req or not t3_req or not t4_req:
            area_res.status = "INCOMPLETE"
            area_res.error = "tenant isolation requests (T1-T4) missing from plan"
            area_res.reason = area_res.error
            return

        actor_a = t1_req.actor  # tenant-a actor
        actor_b = t3_req.actor  # tenant-b actor
        if not actor_a or not actor_b or actor_a == actor_b:
            area_res.status = "INCOMPLETE"
            area_res.error = "two distinct tenant actors required for tenant isolation verification"
            area_res.reason = area_res.error
            return

        # 3. Prerequisite: Both actor_a and actor_b must have succeeded in A3 positive control
        actor_a_a3_ok = any(
            c.get("check") == "A3"
            and actor_a in c.get("actors", [])
            and c.get("classification") == "allowed"
            for c in auth_res.checks
        )
        actor_b_a3_ok = any(
            c.get("check") == "A3"
            and actor_b in c.get("actors", [])
            and c.get("classification") == "allowed"
            for c in auth_res.checks
        )
        if not actor_a_a3_ok or not actor_b_a3_ok:
            area_res.status = "INCOMPLETE"
            area_res.error = "authentication positive control (A3) not established for tenant actors"
            area_res.reason = area_res.error
            return

        # Helper to attach actor session credentials to request headers
        def _attach_session(actor: str, headers_dict: dict[str, str]) -> None:
            if self.vault:
                sess = self.vault.get_session(actor)
                if sess.is_present("cookie") and sess.get("cookie"):
                    headers_dict["Cookie"] = sess.get("cookie").reveal_for_request()
                if sess.is_present("authorization") and sess.get("authorization"):
                    headers_dict["Authorization"] = sess.get("authorization").reveal_for_request()
            if "Cookie" not in headers_dict and "Authorization" not in headers_dict:
                old = self._saved_pre_logout_sessions.get(actor, {})
                if old.get("cookie"):
                    headers_dict["Cookie"] = old["cookie"]
                if old.get("authorization"):
                    headers_dict["Authorization"] = old["authorization"]

        def _classify(req: PlannedRequest, resp: Response, other_req: PlannedRequest) -> tuple[str, bool]:
            """Classify response per design §15 evidence model.

            allowed:    2xx AND resource's declared marker present.
            denied:     status in deny_statuses AND marker absent.
            ambiguous:  2xx without marker, 3xx, 400/405/409/422, deny status with marker,
                        or another resource's marker present.
            incomplete: 5xx, timeout, connection error, budget exhausted.
            """
            marker_present = (req.marker in resp.body) if req.marker else False
            other_marker = other_req.marker
            other_marker_present = (other_marker in resp.body) if other_marker else False

            if other_marker_present:
                return "ambiguous", marker_present
            if 200 <= resp.status < 300 and marker_present:
                return "allowed", marker_present
            if resp.status in deny_statuses and not marker_present:
                return "denied", marker_present
            if 200 <= resp.status < 300 and not marker_present:
                return "ambiguous", marker_present
            if resp.status in (400, 405, 409, 422) or (300 <= resp.status < 400):
                return "ambiguous", marker_present
            if resp.status in deny_statuses and marker_present:
                return "ambiguous", marker_present
            return "incomplete", marker_present

        hard_max = AREA_HARD_MAXIMUMS.get("tenant_isolation", 4)
        executed_checks: list[dict[str, Any]] = []

        # Helper to send a planned request with budget and timeout enforcement
        def _run_req(planned_req: PlannedRequest, actor_for_session: str) -> tuple[RequestExecutionResult | None, str | None]:
            now = time.monotonic()
            rem_total = self.total_timeout - (now - start_total)
            if rem_total <= 0:
                result.timed_out = True
                result.status = "INCOMPLETE"
                area_res.timed_out = True
                area_res.status = "INCOMPLETE"
                area_res.error = "total run timeout exceeded (180s)"
                area_res.reason = area_res.error
                return None, "total_timeout"

            rem_area = self.area_timeout - (now - area_start)
            if rem_area <= 0:
                area_res.timed_out = True
                area_res.status = "INCOMPLETE"
                area_res.error = f"area timeout exceeded ({self.area_timeout:.1f}s)"
                area_res.reason = area_res.error
                result.status = "INCOMPLETE"
                return None, "area_timeout"

            assert self.client is not None
            if self.client.sent >= self.client.max_budget:
                area_res.budget_exceeded = True
                area_res.status = "INCOMPLETE"
                area_res.error = f"total request budget ({self.client.max_budget}) exhausted"
                area_res.reason = area_res.error
                result.status = "INCOMPLETE"
                return None, "total_budget"

            if area_res.requests_sent >= hard_max:
                area_res.budget_exceeded = True
                area_res.status = "INCOMPLETE"
                area_res.error = f"area hard maximum ({hard_max}) reached"
                area_res.reason = area_res.error
                result.status = "INCOMPLETE"
                return None, "hard_max"

            headers = dict(planned_req.headers)
            _attach_session(actor_for_session, headers)

            req_to_send = PlannedRequest(
                area=planned_req.area,
                check_id=planned_req.check_id,
                method=planned_req.method,
                path=planned_req.path,
                headers=headers,
                body=planned_req.body,
                actor=planned_req.actor,
                expected=planned_req.expected,
                marker=planned_req.marker,
            )
            effective_timeout = min(self.request_timeout, rem_area, rem_total)
            req_res = self._execute_single_request(req_to_send, timeout=effective_timeout)
            area_res.request_results.append(req_res)
            result.all_request_results.append(req_res)
            area_res.requests_sent += 1
            result.requests_sent += 1
            return req_res, None

        # 4. Execute T1: tenant-a actor positive control on tenant-a resource
        req_res_t1, err = _run_req(t1_req, actor_a)
        if err or not req_res_t1 or req_res_t1.timed_out or req_res_t1.status == "INCOMPLETE" or req_res_t1.response is None:
            area_res.status = "INCOMPLETE"
            if req_res_t1 and req_res_t1.timed_out:
                area_res.timed_out = True
            area_res.error = (req_res_t1.error if req_res_t1 else None) or area_res.error or "T1 request failed"
            area_res.reason = area_res.error
            result.status = "INCOMPLETE"
            return

        resp_t1 = req_res_t1.response
        t1_class, t1_marker = _classify(t1_req, resp_t1, t3_req)
        t1_check = {
            "check": "T1",
            "area": "tenant_isolation",
            "actors": [actor_a],
            "method": t1_req.method,
            "path": t1_req.path,
            "expected": "allowed",
            "status_class": f"{resp_t1.status // 100}xx",
            "status": resp_t1.status,
            "classification": t1_class,
            "marker_present": t1_marker,
            "elapsed_ms": round(req_res_t1.elapsed_ms, 1),
            "fingerprint": None,
        }
        executed_checks.append(t1_check)

        # GATING: If T1 positive control failed, stop immediately (design §22)
        if t1_class != "allowed":
            area_res.checks = executed_checks
            area_res.findings = []
            area_res.status = "INCOMPLETE"
            area_res.error = f"own-tenant positive control T1 failed (classification={t1_class})"
            area_res.reason = area_res.error
            return

        # 5. Execute T2: tenant-a actor cross-tenant access to tenant-b resource
        req_res_t2, err = _run_req(t2_req, actor_a)
        if err or not req_res_t2 or req_res_t2.timed_out or req_res_t2.status == "INCOMPLETE" or req_res_t2.response is None:
            area_res.status = "INCOMPLETE"
            if req_res_t2 and req_res_t2.timed_out:
                area_res.timed_out = True
            area_res.checks = executed_checks
            area_res.error = (req_res_t2.error if req_res_t2 else None) or area_res.error or "T2 request failed"
            area_res.reason = area_res.error
            result.status = "INCOMPLETE"
            return

        resp_t2 = req_res_t2.response
        t2_class, t2_marker = _classify(t2_req, resp_t2, t1_req)
        t2_check = {
            "check": "T2",
            "area": "tenant_isolation",
            "actors": [actor_a],
            "method": t2_req.method,
            "path": t2_req.path,
            "expected": "denied",
            "status_class": f"{resp_t2.status // 100}xx",
            "status": resp_t2.status,
            "classification": t2_class,
            "marker_present": t2_marker,
            "elapsed_ms": round(req_res_t2.elapsed_ms, 1),
            "fingerprint": None,
        }
        executed_checks.append(t2_check)

        # 6. Execute T3: tenant-b actor positive control on tenant-b resource
        req_res_t3, err = _run_req(t3_req, actor_b)
        if err or not req_res_t3 or req_res_t3.timed_out or req_res_t3.status == "INCOMPLETE" or req_res_t3.response is None:
            area_res.status = "INCOMPLETE"
            if req_res_t3 and req_res_t3.timed_out:
                area_res.timed_out = True
            area_res.checks = executed_checks
            area_res.error = (req_res_t3.error if req_res_t3 else None) or area_res.error or "T3 request failed"
            area_res.reason = area_res.error
            result.status = "INCOMPLETE"
            return

        resp_t3 = req_res_t3.response
        t3_class, t3_marker = _classify(t3_req, resp_t3, t1_req)
        t3_check = {
            "check": "T3",
            "area": "tenant_isolation",
            "actors": [actor_b],
            "method": t3_req.method,
            "path": t3_req.path,
            "expected": "allowed",
            "status_class": f"{resp_t3.status // 100}xx",
            "status": resp_t3.status,
            "classification": t3_class,
            "marker_present": t3_marker,
            "elapsed_ms": round(req_res_t3.elapsed_ms, 1),
            "fingerprint": None,
        }
        executed_checks.append(t3_check)

        # GATING: If T3 positive control failed, suppress any T2 finding and mark INCOMPLETE (design §22)
        if t3_class != "allowed":
            area_res.checks = executed_checks
            area_res.findings = []
            area_res.status = "INCOMPLETE"
            area_res.error = f"own-tenant positive control T3 failed (classification={t3_class})"
            area_res.reason = area_res.error
            return

        # 7. Execute T4: tenant-b actor cross-tenant access to tenant-a resource
        req_res_t4, err = _run_req(t4_req, actor_b)
        resp_t4 = req_res_t4.response if req_res_t4 else None

        if resp_t4 is not None:
            t4_class, t4_marker = _classify(t4_req, resp_t4, t3_req)
            t4_status = resp_t4.status
            t4_status_class = f"{resp_t4.status // 100}xx"
        else:
            t4_class = "incomplete"
            t4_marker = False
            t4_status = 0
            t4_status_class = "0xx"

        t4_check = {
            "check": "T4",
            "area": "tenant_isolation",
            "actors": [actor_b],
            "method": t4_req.method,
            "path": t4_req.path,
            "expected": "denied",
            "status_class": t4_status_class,
            "status": t4_status,
            "classification": t4_class,
            "marker_present": t4_marker,
            "elapsed_ms": round(req_res_t4.elapsed_ms, 1) if req_res_t4 else 0.0,
            "fingerprint": None,
        }
        executed_checks.append(t4_check)

        if req_res_t4 and req_res_t4.timed_out:
            area_res.timed_out = True

        # 8. Evaluate tenant isolation checks using tenant module
        from .tenant import evaluate_tenant_checks
        checks, findings, status, reason = evaluate_tenant_checks(
            check_records=executed_checks,
            actor_a=actor_a,
            actor_b=actor_b,
            res_a_path=t1_req.path,
            res_b_path=t3_req.path,
        )

        area_res.checks = checks
        area_res.findings = findings
        area_res.status = status
        area_res.reason = reason

        t4_failed = bool(
            err
            or not req_res_t4
            or (req_res_t4 and req_res_t4.timed_out)
            or (req_res_t4 and req_res_t4.status == "INCOMPLETE")
            or resp_t4 is None
        )
        if t4_failed and status != "FAIL":
            area_res.status = "INCOMPLETE"
            area_res.error = (req_res_t4.error if req_res_t4 else None) or area_res.error or "T4 request failed"
            area_res.reason = area_res.error
            result.status = "INCOMPLETE"

        area_res.runtime_checks_executed = (
            area_res.requests_sent == area_res.requests_planned
            and area_res.status in ("PASS", "FAIL")
        )

    def _mark_all_areas_incomplete(
        self, plan: NativePlan, result: NativeExecutionResult, reason: str
    ) -> None:
        for area_name in VERIFICATION_AREAS:
            ap = plan.areas.get(area_name)
            configured = ap.configured if ap else False
            result.area_results[area_name] = AreaExecutionResult(
                area=area_name,
                status="INCOMPLETE" if configured else "NOT CONFIGURED",
                configured=configured,
                error=reason,
            )


def execute_native_plan(
    cfg: Config,
    plan: NativePlan,
    eligibility: NativeEligibilityDecision | None = None,
    vault: IdentityVault | None = None,
    request_timeout: float | None = None,
    area_timeout: float = MAX_AREA_TIMEOUT,
    total_timeout: float = MAX_TOTAL_TIMEOUT,
) -> NativeExecutionResult:
    """Convenience function to execute a native verification plan."""
    executor = NativeExecutor(
        cfg=cfg,
        eligibility=eligibility,
        vault=vault,
        request_timeout=request_timeout,
        area_timeout=area_timeout,
        total_timeout=total_timeout,
    )
    return executor.execute_plan(plan)
