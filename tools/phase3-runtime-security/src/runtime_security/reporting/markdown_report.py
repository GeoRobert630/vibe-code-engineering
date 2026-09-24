"""runtime-security-report.md. Target-derived text is escaped (no raw HTML/links)."""

from __future__ import annotations

import re
from pathlib import Path

from .. import TOOL_NAME, __version__
from ..auth.status import AUTH_CATEGORIES, auth_area_status, auth_config_summary, report_zap
from ..authz.status import CATEGORIES as AUTHZ_CATEGORIES
from ..authz.status import authz_area_status
from ..models import SEVERITY_ORDER, Outcome
from ..runner import LIMITATIONS, RunReport, is_blocking
from ..verification.report import import_block

_SPECIAL = re.compile(r"([\\`*_\[\]()!|~#])")
_CONTROL = re.compile(r"[\x00-\x1f\x7f]")


def esc(value: object) -> str:
    text = _CONTROL.sub(" ", "" if value is None else str(value))
    text = text.replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;")
    return _SPECIAL.sub(r"\\\1", text)


def _results_table(rows) -> list[str]:
    if not rows:
        return ["None.", ""]
    out = ["| Check | Assertion | Endpoint | Detail |", "|---|---|---|---|"]
    out += [f"| {esc(r.check)} | {esc(r.name)} | {esc(r.endpoint)} | {esc(r.detail)} |" for r in rows]
    return out + [""]


def render(report: RunReport) -> str:
    cfg = report.cfg
    L = ["# Runtime Security Report", "", f"Generated {esc(report.generated_at)} by {TOOL_NAME} {__version__}. Read-only defensive checks.", ""]
    L += ["## Executive Summary", "", f"**{esc(report.summary)}**", ""]
    c = report.counts
    L += [", ".join(f"{s.value.title()}: {c[s.value]}" for s in SEVERITY_ORDER) + f". Blocking: {len(report.blocking)}. Requests sent: {report.requests_sent}.", ""]
    L += ["## Target", "", f"- Base URL: {esc(cfg.base_url)}", f"- HTTP URL checked for redirect: {esc(cfg.http_url or '(derived from base URL / not applicable)')}", ""]
    L += ["## Environment", "", f"- Environment: {esc(cfg.environment)}", f"- Production flag: {str(cfg.production).lower()}",
          f"- Safety gate: {'allowed' if not report.refused else 'REFUSED'} - {esc(report.safety_reason)}", ""]
    L += ["## Checks Run", "", "| Check | Status |", "|---|---|"]
    for r in report.runs:
        status = "disabled" if not r.enabled else (f"error: {esc(r.error)}" if r.error else "completed")
        L.append(f"| {esc(r.name)} | {status} |")
    L.append("")
    L += ["## Passed", ""] + _results_table(report.results(Outcome.PASSED))
    L += ["## Failed", ""] + _results_table(report.results(Outcome.FAILED))
    L += ["## Not Verified", ""] + _results_table(report.results(Outcome.NOT_VERIFIED) + report.results(Outcome.NOT_APPLICABLE))
    L += ["## Findings", ""]
    phase3a_findings = [f for f in report.findings if f.category not in AUTH_CATEGORIES and f.category not in ("zap", *AUTHZ_CATEGORIES)]
    if not phase3a_findings:
        L += ["No findings for the checks performed. This does not cover authorization, IDOR or other runtime areas (see Limitations).", ""]
    L += _findings(phase3a_findings)
    L += _auth_sections(report)
    L += _authz_section(report)
    L += _zap_sections(report)
    L += ["## Limitations", ""] + [f"- {esc(x)}" for x in LIMITATIONS] + [""]
    L += ["## Summary", "", f"{esc(report.summary)} Exit code {report.exit_code}.", ""]
    return "\n".join(L)


def _auth_sections(report: RunReport) -> list[str]:
    zap = report_zap(report)
    areas = auth_area_status(report.cfg, report.findings, report.refused, zap, report.verification)
    summary = auth_config_summary(report.cfg)
    L: list[str] = []
    zap_line = f"OWASP ZAP: {'Available' if zap.available else 'Unavailable'}"
    if zap.available:
        zap_line += f" (version {zap.version or 'unknown'}, found via {zap.source}: {zap.location})"
    zap_line = esc(zap_line) + " - authenticated runtime testing: " + zap.authentication_testing + "; authenticated testing was not executed."
    for category, label in AUTH_CATEGORIES.items():
        a = areas[category]
        L += [f"## {label}", "", f"Status: **{a['status']}**", "", esc(a["reason"]), ""]
        L += _coverage_lines(a)
        if category == "authentication":
            L += [zap_line, ""]
    if summary:
        L += ["Configured flow (endpoints and environment variable names only; no values read, no requests made):", ""]
        for key in ("login", "logout", "protected_endpoint"):
            value = summary[key]
            L.append(f"- {key}: " + (esc(", ".join(f"{k}={v}" for k, v in value.items())) if value else "not configured"))
        L += [f"- credential env names: {esc(', '.join(summary['credential_env_names'] or []) or 'not configured')}", ""]
    for category, label in AUTH_CATEGORIES.items():
        L += [f"## {label} Findings", ""]
        items = [f for f in report.findings if f.category == category]
        L += _findings(items) if items else ["None.", ""]
    return L


def _yes(value: object) -> str:
    return "yes" if value is True else "no"


def _coverage_lines(a: dict) -> list[str]:
    """Requests count, findings count and limitations of an area (imported values or the NOT VERIFIED defaults)."""
    L = [f"Runtime checks executed: {_yes(a.get('runtime_checks_executed'))}. Requests count: {a.get('requests_count', 0)}. "
         f"Findings: {len(a.get('findings') or [])}. Credentials read: no.", ""]
    limitations = a.get("limitations") or []
    L += ["Limitations:", ""] + ([f"- {esc(x)}" for x in limitations] or ["- not executed by this tool; see Reason"]) + [""]
    return L


def _authz_section(report: RunReport) -> list[str]:
    a = authz_area_status(report.findings, report.refused, report.verification)
    L = ["## Authorization", "", f"Status: **{a['status']}**", "", "Reason:", "", esc(a["reason"]), "",
         "Scope: " + esc(", ".join(a["scope"])) + f". Runtime authorization checks executed: {_yes(a['runtime_checks_executed'])}. "
         "Credentials read: no.", ""]
    L += ["| Sub-area | Status | Reserved namespace | Runtime checks executed | Credentials read | Requests count | Findings |",
          "|---|---|---|---|---|---|---|"]
    L += [f"| {esc(s['area'])} | {s['status']} | `{s['namespace']}` | {_yes(s['runtime_checks_executed'])} | no | "
          f"{s.get('requests_count', 0)} | {len(s['findings'])} |" for s in a["subareas"].values()]
    L.append("")
    for s in a["subareas"].values():
        L += [f"### {esc(s['area'])} limitations", ""]
        L += [f"- {esc(x)}" for x in s.get("limitations") or []] or ["- not executed by this tool; see Reason"]
        L.append("")
    imp = import_block(report.cfg.verification_results is not None, report.verification, report.refused)
    L += [f"Imported verification results: **{imp['status']}** - {esc(imp['reason'])}. "
          f"Requests count: {imp['requests_count']} (budget {imp['request_budget']}).", ""]
    L += ["## Authorization Findings", ""]
    items = [f for f in report.findings if f.category in AUTHZ_CATEGORIES]
    return L + (_findings(items) if items else ["None.", ""])


def _zap_sections(report: RunReport) -> list[str]:
    zb = report.zap_baseline or {}
    L = ["## ZAP Baseline", ""]
    if not zb.get("enabled"):
        return L + [esc(zb.get("reason") or "ZAP baseline not enabled in configuration") + ".", ""]
    L += ["The ZAP baseline is a passive scan only (no active scan, no authentication). Its results are partial "
          "coverage and do NOT mean the application is secure.", "",
          "| Field | Value |", "|---|---|",
          f"| Availability | {'available' if zb.get('available') else 'unavailable'} |",
          f"| Version | {esc(zb.get('version') or '-')} |",
          f"| Executed | {'yes' if zb.get('executed') else 'no'} |",
          f"| Target (as seen by ZAP) | {esc(zb.get('zap_target') or '-')} |",
          f"| Exit code | {esc(zb.get('exit_code'))} |",
          f"| Reason | {esc(zb.get('reason'))} |", ""]
    if not zb.get("executed"):
        return L
    rules = zb.get("rules") or {}
    summary = zb.get("summary") or {k: len(v) for k, v in rules.items()}
    L += ["| Baseline result | Rules |", "|---|---|"] + [f"| {k} | {summary.get(k, 0)} |" for k in ("PASS", "WARN", "FAIL", "INFO")] + [""]
    for kind in ("FAIL", "WARN", "INFO"):
        items = rules.get(kind) or []
        L += [f"### ZAP {kind}", ""] + ([f"- [{esc(r['id'])}] {esc(r['name'])}" for r in items] or ["None."]) + [""]
    L += ["### Alerts", "", "| ZAP alert | Name | Risk | Confidence | Baseline | Disposition |", "|---|---|---|---|---|---|"]
    for a in zb.get("alerts") or []:
        L.append(f"| {esc(a['plugin_id'])} | {esc(a['name'])} | {esc(a['risk'])} | {esc(a['confidence'])} | {esc(a['baseline_status'])} | {esc(a.get('disposition'))} |")
    L += ["", "### ZAP Findings", ""]
    zf = [f for f in report.findings if f.category == "zap"]
    L += _findings(zf) if zf else ["None.", ""]
    L += ["## Correlated Findings", ""]
    corr = report.correlations or []
    if corr:
        L += ["| ZAP alert | Name | Relation | Phase 3A findings |", "|---|---|---|---|"]
        L += [f"| {esc(c['zap_alert_id'])} | {esc(c['zap_alert'])} | {esc(c['relation'])} | {esc(', '.join(c['phase3a_findings']) or '-')} |" for c in corr]
    else:
        L.append("No ZAP alert corresponds to an existing Phase 3A finding.")
    return L + [""]


def _findings(findings) -> list[str]:
    L: list[str] = []
    for f in findings:
        L += [
            f"### {esc(f.id)} - {esc(f.title)}", "",
            "| Field | Value |", "|---|---|",
            f"| Category | {esc(f.category)} |",
            f"| Severity | {f.severity.value}{' (blocking)' if is_blocking(f) else ''} |",
            f"| Confidence | {f.confidence.value} |",
            f"| Endpoint | {esc(f.endpoint)} |",
            f"| Expected | {esc(f.expected)} |",
            f"| Actual | {esc(f.actual)} |",
            f"| Status | {f.status.value} |",
            f"| CWE / OWASP | {esc(f.cwe or '-')} / {esc(f.owasp or '-')} |",
            "", f"**Evidence:** {esc(f.evidence)}", "", f"**Impact:** {esc(f.impact)}", "",
            f"**Recommendation:** {esc(f.recommendation)}", "", f"**Validation:** {esc(f.validation)}", "",
        ]
        if f.notes:
            L += [f"- {esc(n)}" for n in f.notes] + [""]
    return L


def write(report: RunReport, out: Path) -> Path:
    out.mkdir(parents=True, exist_ok=True)
    path = out / "runtime-security-report.md"
    path.write_text(render(report), encoding="utf-8")
    return path
