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
import socket
import ssl
import time
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional
from urllib.parse import urlsplit

from ..config import Config
from ..utils.http import MAX_BODY, BudgetExceeded, RequestNotAllowed, Response
from ..utils.redaction import clean, redact, safe_header_value
from .eligibility import NativeEligibilityDecision, evaluate_native
from .identity import IdentityVault, SecretValue
from .plan import AreaPlan, NativePlan, PlannedRequest
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
    status: str  # "EXECUTED" | "INCOMPLETE" | "NOT CONFIGURED" | "NOT VERIFIED"
    configured: bool = True
    requests_sent: int = 0
    requests_planned: int = 0
    timed_out: bool = False
    budget_exceeded: bool = False
    error: str | None = None
    request_results: list[RequestExecutionResult] = field(default_factory=list)

    def __repr__(self) -> str:
        return (
            f"AreaExecutionResult(area={self.area!r}, status={self.status!r}, "
            f"requests_sent={self.requests_sent}/{self.requests_planned}, "
            f"timed_out={self.timed_out!r}, error={self.error!r})"
        )


@dataclass
class NativeExecutionResult:
    status: str  # "EXECUTED" | "INCOMPLETE" | "REFUSED"
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
            import secrets

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

            # If no requests were attached to the plan, record EXECUTED if count is 0,
            # or INCOMPLETE if count > 0 (mismatch)
            if not requests_to_run:
                if area_plan.requests_count > 0:
                    area_res.status = "INCOMPLETE"
                    area_res.error = (
                        f"area {area_name} configured for {area_plan.requests_count} "
                        "requests but no planned requests provided"
                    )
                    result.status = "INCOMPLETE"
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
        if any(ar.timed_out for ar in result.area_results.values()):
            result.timed_out = True
            result.status = "INCOMPLETE"
        elif any(ar.status == "INCOMPLETE" for ar in result.area_results.values()):
            result.status = "INCOMPLETE"

        return result

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
