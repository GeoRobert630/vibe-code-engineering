"""Human-readable report (security-report.md).

All text that originates from the scanned project (paths, evidence, tool
output) is escaped so it cannot inject Markdown/HTML (links, images, raw HTML,
table breaks, headings) into the report.
"""

from __future__ import annotations

import re
from pathlib import Path

from ..models import Finding, Severity, Status
from ..orchestrator import ScanReport, reported_findings, tool_info
from ..severity import NOT_READY, READY, SEVERITY_ORDER, is_blocking
from ..utils.redaction import strip_control

# Escaping these prevents links/images ([ ] ( ) !), emphasis, code spans, table
# breaks (|) and headings; < > & are converted to entities to block raw HTML.
_MD_SPECIAL = re.compile(r"([\\`*_\[\]()!|~#])")


def esc(value: object) -> str:
    text = strip_control("" if value is None else str(value))
    text = text.replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;")
    return _MD_SPECIAL.sub(r"\\\1", text)


def _location(f: Finding) -> str:
    if not f.file:
        return "(repository-wide)"
    loc = f.file
    if f.line:
        loc += f":{f.line}"
    return esc(loc)


def _finding_block(f: Finding) -> list[str]:
    out = [
        f"### {esc(f.id)} - {esc(f.title)}",
        "",
        "| Field | Value |",
        "|---|---|",
        f"| ID | {esc(f.id)} |",
        f"| Title | {esc(f.title)} |",
        f"| Severity | {f.severity.value}{' (blocking)' if is_blocking(f) else ''} |",
        f"| Confidence | {f.confidence.value} |",
        f"| Classification | {f.classification.value} |",
        f"| Category | {esc(f.category)} |",
        f"| Location | {_location(f)} |",
        f"| Status | {f.status.value} |",
        f"| Scanner / sources | {esc(f.scanner)} / {esc(', '.join(f.source))} |",
    ]
    if f.cwe or f.owasp:
        out.append(f"| CWE / OWASP | {esc(f.cwe or '-')} / {esc(f.owasp or '-')} |")
    out += [
        "",
        f"**Evidence:** {esc(f.evidence) or '-'}",
        "",
        f"**Description:** {esc(f.description)}",
        "",
        f"**Impact:** {esc(f.impact) or '-'}",
        "",
        f"**Recommendation:** {esc(f.recommendation) or '-'}",
        "",
        f"**Validation:** {esc(f.validation) or '-'}",
        "",
    ]
    if f.notes:
        out += ["**Notes:**", ""] + [f"- {esc(n)}" for n in f.notes] + [""]
    return out


def render(report: ScanReport, min_severity: Severity = Severity.INFORMATIONAL) -> str:
    shown = reported_findings(report, min_severity)
    active = [f for f in shown if f.status in (Status.OPEN, Status.REQUIRES_REVIEW)]
    blocking = [f for f in report.findings if is_blocking(f)]
    baselined = [f for f in report.findings if f.status == Status.BASELINED]
    ignored = [f for f in report.findings if f.status == Status.IGNORED]
    info = tool_info()
    L: list[str] = ["# Security Audit Report", ""]
    L.append(f"Generated {esc(report.generated_at)} by {esc(info['name'])} {esc(info['version'])}. Read-only static scan.")
    L.append("")

    L += ["## Project", "", "| Field | Value |", "|---|---|",
          f"| Name | {esc(report.project['name'])} |",
          f"| Path | {esc(report.project['path'])} |",
          f"| Files scanned | {report.project['files_scanned']} |",
          f"| Git repository | {'yes' if report.project.get('git_repository') else 'no'} |",
          f"| External tools | {'enabled' if report.configuration['external_tools'] else 'disabled (--no-external-tools)'} |",
          ""]

    L += ["## Technologies Detected", ""]
    if report.technologies:
        L += ["| Technology | Confidence | Evidence |", "|---|---|---|"]
        for t in report.technologies:
            L.append(f"| {esc(t.name)} | {t.confidence.value} | {esc('; '.join(t.evidence[:3]))} |")
    else:
        L.append("No technologies identified from project files.")
    L.append("")

    L += ["## Scanner Availability", "", "| Scanner | Status | Findings | Duration (s) |", "|---|---|---|---|"]
    for s in report.scanners:
        L.append(f"| {esc(s['name'])} | {esc(s['status'])} | {s['findings']} | {s['duration_seconds']} |")
    L += ["", "| External tool | Available | Used | Failed | Version | Detail |", "|---|---|---|---|---|---|"]
    for t in report.tools:
        L.append(
            f"| {esc(t.name)} | {'yes' if t.available else 'no'} | {'yes' if t.used else 'no'} | "
            f"{'YES' if t.failed else 'no'} | {esc(t.version or '-')} | {esc(t.detail or '-')} |"
        )
    errors = [(s["name"], e) for s in report.scanners for e in s.get("errors", [])]
    if errors:
        L += ["", "**Scanner errors:**", ""] + [f"- {esc(n)}: {esc(e)}" for n, e in errors]
    L.append("")

    counts = report.counts
    L += ["## Summary", "", "Active findings (OPEN or REQUIRES_REVIEW) by severity:", "", "| Severity | Count |", "|---|---|"]
    for sev in SEVERITY_ORDER:
        L.append(f"| {sev.value.title() if sev != Severity.INFORMATIONAL else 'Informational'} | {counts[sev.value]} |")
    L += ["", f"Blocking findings: **{len(blocking)}**. Baselined: {len(baselined)}. Ignored inline: {len(ignored)}. "
          f"Total (all statuses): {len(report.findings)}.", ""]
    if min_severity != Severity.INFORMATIONAL:
        L += [f"Report filtered to severity >= {min_severity.value}; counts and release status include all findings.", ""]

    L += ["## Blocking Findings", ""]
    if blocking:
        L += ["| ID | Severity | Confidence | Title | Location |", "|---|---|---|---|---|"]
        for f in blocking:
            L.append(f"| {esc(f.id)} | {f.severity.value} | {f.confidence.value} | {esc(f.title)} | {_location(f)} |")
    else:
        L.append("None. (Critical findings, and High findings with MEDIUM/HIGH confidence, are blocking.)")
    L.append("")

    L += ["## Findings", ""]
    if active:
        for f in active:
            L += _finding_block(f)
    else:
        L += ["No active findings at the selected severity. This does not mean the application is secure; see Limitations.", ""]

    L += ["## Baseline Findings", ""]
    if report.baseline is None:
        L.append("No baseline supplied (--baseline).")
    else:
        b = report.baseline
        L.append(f"Baseline file: {esc(b.get('path'))}. Matched: {b.get('matched', 0)}. Invalid entries ignored: {b.get('invalid_entries', 0)}.")
        if b.get("updated"):
            L.append(f"Baseline updated: {b.get('written', 0)} entries written; {b.get('critical_not_baselined', 0)} CRITICAL finding(s) were not baselined.")
        if b.get("refused_critical"):
            L.append("CRITICAL findings listed in the baseline but kept OPEN: " + esc(", ".join(b["refused_critical"])))
        if b.get("refused_severity_increase"):
            L.append("Findings whose severity increased since baselining (kept active): " + esc(", ".join(b["refused_severity_increase"])))
        if baselined:
            L += ["", "| ID | Severity | Title | Location |", "|---|---|---|---|"]
            for f in baselined:
                L.append(f"| {esc(f.id)} | {f.severity.value} | {esc(f.title)} | {_location(f)} |")
        stale = b.get("fixed_or_stale") or []
        if stale:
            L += ["", "Baseline entries no longer detected (FIXED or moved):", ""]
            L += [f"- {esc(s.get('id'))}: {esc(s.get('title', ''))} ({esc(s.get('file', ''))})" for s in stale[:50]]
    if ignored:
        L += ["", "Inline-ignored findings (phase2:ignore):", ""]
        L += [f"- {esc(f.id)} {f.severity.value} {esc(f.title)} at {_location(f)}" for f in ignored]
    L.append("")

    L += ["## Limitations", ""] + [f"- {esc(x)}" for x in report.limitations] + [""]

    status = report.release_status
    L += ["## Release Status", "", f"**{status}**", ""]
    if status == NOT_READY:
        reasons = []
        if blocking:
            reasons.append(f"{len(blocking)} blocking Critical/High finding(s) unresolved")
        if report.tool_failure:
            reasons.append("one or more scanners/tools failed, so the audit is incomplete")
        L.append("Reason: " + "; ".join(reasons) + ".")
    elif status == READY:
        L.append("No active findings above Informational. Static scanning cannot prove security: complete manual review and runtime verification before release.")
    else:
        L.append("Non-blocking or baselined findings remain; each must be documented and accepted by the responsible human.")
    L += ["", f"Exit code: {report.exit_code}", ""]
    return "\n".join(L)


def write(report: ScanReport, output_dir: Path, min_severity: Severity = Severity.INFORMATIONAL) -> Path:
    output_dir.mkdir(parents=True, exist_ok=True)
    path = output_dir / "security-report.md"
    path.write_text(render(report, min_severity), encoding="utf-8")
    return path
