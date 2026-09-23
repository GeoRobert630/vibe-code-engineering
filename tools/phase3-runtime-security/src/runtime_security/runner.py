"""Run the safety gate, then each enabled check; assign RT- IDs; summarise.

Exit codes (same meaning as Phase 2):
  0  no findings above INFORMATIONAL
  1  non-blocking findings (MEDIUM/LOW, or HIGH with LOW confidence)
  2  blocking findings (CRITICAL, or HIGH with MEDIUM/HIGH confidence)
  3  refused by the safety gate, configuration error, or a check could not complete
Blocking takes precedence over 3 when both apply.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path
from datetime import datetime, timezone
from typing import Callable

from .checks import cookies, cors, error_leakage, headers, redirects, tls
from .config import CHECK_NAMES, Config
from .models import ID_PREFIX, SEVERITY_ORDER, CheckRun, Confidence, Finding, Outcome, Severity
from .utils import safety
from .utils.http import BudgetExceeded, Client, RequestNotAllowed
from .utils.redaction import clean
from .zap import baseline as zap_baseline_mod
from .zap.detect import ZapStatus
from .zap.importer import import_alerts
from .zap.results import ZapReportError, load_files

CHECKS: dict[str, Callable[[Client, Config], CheckRun]] = {
    "headers": headers.run,
    "cookies": cookies.run,
    "cors": cors.run,
    "redirects": redirects.run,
    "tls": tls.run,
    "error_leakage": error_leakage.run,
}

LIMITATIONS = [
    "Defensive slice only: security headers, cookie attributes, CORS, HTTP->HTTPS redirect, TLS certificate validity and error leakage.",
    "NOT covered: authentication, authorization, IDOR/BOLA, tenant isolation, CSRF behaviour, rate limiting, file access, webhooks, business logic.",
    "Only the configured paths are requested, unauthenticated. Cookies set after login and headers on authenticated pages are not observed.",
    "A passed check means the observed responses were correct for the requests sent; other routes, methods or states may behave differently.",
    "TLS: one verified handshake with a default client - no cipher-suite, protocol-downgrade or revocation testing.",
    "Error-leakage probes are a small fixed set of malformed requests; leakage on other error paths is not excluded.",
    "Results reflect this environment at this time; production configuration (CDN, proxy, platform headers) may differ from staging.",
]


def is_blocking(f: Finding) -> bool:
    if f.severity == Severity.CRITICAL:
        return True
    return f.severity == Severity.HIGH and f.confidence != Confidence.LOW


@dataclass
class RunReport:
    cfg: Config
    safety_reason: str
    refused: bool
    runs: list[CheckRun] = field(default_factory=list)
    findings: list[Finding] = field(default_factory=list)
    requests_sent: int = 0
    zap_baseline: dict | None = None
    correlations: list = field(default_factory=list)
    zap_failed: bool = False
    generated_at: str = field(default_factory=lambda: datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"))

    @property
    def check_failure(self) -> bool:
        return self.refused or any(r.error for r in self.runs) or self.zap_failed

    @property
    def counts(self) -> dict[str, int]:
        c = {s.value: 0 for s in SEVERITY_ORDER}
        for f in self.findings:
            c[f.severity.value] += 1
        return c

    @property
    def blocking(self) -> list[Finding]:
        return [f for f in self.findings if is_blocking(f)]

    def results(self, outcome: Outcome):
        return [r for run in self.runs for r in run.results if r.outcome == outcome]

    @property
    def exit_code(self) -> int:
        if self.blocking:
            return 2
        if self.check_failure:
            return 3
        if any(f.severity != Severity.INFORMATIONAL for f in self.findings):
            return 1
        return 0

    @property
    def summary(self) -> str:
        if self.refused:
            return "REFUSED - safety gate did not allow this target; nothing was sent."
        if self.blocking:
            return "FAIL - blocking runtime findings present."
        if self.check_failure:
            return "INCOMPLETE - one or more checks could not complete."
        if any(f.severity != Severity.INFORMATIONAL for f in self.findings):
            return "PASS WITH ISSUES - non-blocking findings; review and document."
        return "PASS (defensive checks only) - authorization/IDOR and other runtime areas remain unverified."


def run_zap_baseline(cfg: Config, report: RunReport, out_dir: Path | None) -> None:
    """Passive ZAP baseline, only after the safety gate allowed the target and only if enabled."""
    zc = cfg.zap_baseline
    if report.refused or zc is None or not zc.enabled:
        report.zap_baseline = {"enabled": bool(zc and zc.enabled), "available": None, "executed": False,
                               "reason": "safety gate refused the target" if report.refused else "ZAP baseline not enabled in configuration"}
        return
    if out_dir is None:
        report.zap_baseline = {"enabled": True, "available": None, "executed": False, "reason": "no output directory for ZAP files"}
        return
    run = zap_baseline_mod.run_baseline(cfg.base_url, out_dir, zc.image, zc.spider_minutes, zc.timeout_seconds)
    info = {"enabled": True, "available": run.available, "executed": run.executed, "reason": run.reason, "image": run.image,
            "mode": "baseline (passive)", "zap_target": run.zap_target, "exit_code": run.exit_code, "timed_out": run.timed_out,
            "command": run.command, "report_path": run.report_path, "output_path": run.output_path, "version": None,
            "rules": {"PASS": [], "WARN": [], "FAIL": [], "INFO": []}, "summary": None, "alerts": []}
    report.zap_baseline = info
    if not run.executed:
        return
    try:
        version, alerts, rules, summary = load_files(run.report_path, run.console)
    except (ZapReportError, OSError, ValueError) as exc:
        info["reason"] = f"ZAP output could not be imported ({exc.__class__.__name__})"
        report.zap_failed = True
        return
    if run.timed_out or run.report_path is None or run.exit_code not in (0, 1, 2):
        report.zap_failed = True
    report.zap = ZapStatus(True, version, "docker-image", run.image)
    passed = {r.check for r in report.results(Outcome.PASSED)}
    phase3a = [f for f in report.findings if f.category in ID_PREFIX and f.category not in ("zap", "authentication", "session")]
    new, correlations, disposition = import_alerts(alerts, phase3a, passed)
    for i, f in enumerate(new, start=1):
        f.id = f"RT-ZAP-{i:03d}"
        f.evidence = clean(f.evidence, 300)
    ids = {f.notes[0].split(": ", 1)[1]: f.id for f in new}
    info.update(version=version, rules=rules, summary=summary,
                alerts=[a.to_dict() | {"disposition": disposition.get(a.plugin_id, ""), "finding_id": ids.get(a.plugin_id)} for a in alerts])
    report.correlations = [c.to_dict() for c in correlations]
    report.findings.extend(new)
    report.findings.sort(key=lambda f: (SEVERITY_ORDER.index(f.severity), f.id))


def run_all(cfg: Config, zap_output_dir: Path | None = None) -> RunReport:
    decision = safety.evaluate(cfg)
    report = RunReport(cfg=cfg, safety_reason=decision.reason, refused=not decision.allowed)
    if not decision.allowed:
        run_zap_baseline(cfg, report, zap_output_dir)
        return report
    client = Client(cfg)
    for name in CHECK_NAMES:
        if not cfg.checks.get(name, False):
            report.runs.append(CheckRun(name, enabled=False))
            continue
        try:
            run = CHECKS[name](client, cfg)
        except (BudgetExceeded, RequestNotAllowed) as exc:
            run = CheckRun(name, error=clean(str(exc), 200))
        except OSError as exc:
            run = CheckRun(name, error=f"target unreachable or connection error ({exc.__class__.__name__})")
        except Exception as exc:  # noqa: BLE001 - a failing check must not abort the others
            run = CheckRun(name, error=f"internal error in check ({exc.__class__.__name__})")
        report.runs.append(run)
    counters: dict[str, int] = {}
    for run in report.runs:
        for f in run.findings:
            prefix = ID_PREFIX.get(f.category, f.category.upper())
            counters[prefix] = counters.get(prefix, 0) + 1
            f.id = f"RT-{prefix}-{counters[prefix]:03d}"
            f.evidence = clean(f.evidence, 300)
            f.actual = clean(f.actual, 200)
            report.findings.append(f)
    report.findings.sort(key=lambda f: (SEVERITY_ORDER.index(f.severity), f.id))
    report.requests_sent = client.sent
    run_zap_baseline(cfg, report, zap_output_dir)
    return report
