"""JSON (source of truth) and Markdown reports. Every string is redacted; no page content is included."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from .models import KIND_REVIEW, KIND_VIOLATION
from .redaction import clean, safe_url
from .runner import LIMITATIONS, RunReport

SCHEMA_VERSION = "1.0"
JSON_NAME = "accessibility-report.json"
MD_NAME = "accessibility-report.md"
NOT_PROOF = ("A clean result is not proof of full WCAG compliance or of complete accessibility: only the rules "
             "listed under 'rules evaluated' were checked, automatically, on the listed pages.")


def build(report: RunReport) -> dict[str, Any]:
    cfg = report.cfg
    limitations = list(LIMITATIONS)
    blocked: dict[str, int] = {}
    for p in report.pages:
        for k, v in p.blocked_requests.items():
            blocked[k] = blocked.get(k, 0) + v
    if blocked:
        limitations.append("Requests blocked by the safety controls: " + ", ".join(f"{k} {v}" for k, v in sorted(blocked.items())))
    active = report.active
    return {
        "schema_version": SCHEMA_VERSION,
        "tool": report.tool,
        "phase": "4A",
        "area": "Accessibility",
        "namespace": "Q-A11Y",
        "run": {
            "status": report.status,
            "verdict": report.verdict,
            "reason": clean(report.reason, 400),
            "incomplete_reasons": list(dict.fromkeys(clean(r, 300) for r in report.incomplete_reasons)),
            "exit_code": report.exit_code,
            "started_at": report.started_at,
            "finished_at": report.finished_at,
        },
        "target": None if cfg is None else {
            "base_url": safe_url(cfg.base_url), "environment": cfg.environment, "production": cfg.production,
            "limits": {"max_pages": cfg.max_pages, "page_timeout_seconds": cfg.page_timeout_seconds,
                       "total_timeout_seconds": cfg.total_timeout_seconds, "max_page_bytes": cfg.max_page_bytes},
            "asset_origins": [safe_url(o) for o in cfg.allow_origins],
        },
        "engine": {k: (clean(v, 200) if isinstance(v, str) else v) for k, v in report.engine.items()},
        "pages_tested": [
            {"url": safe_url(p.url), "status": p.status, "reason": clean(p.reason, 300), "http_status": p.http_status,
             "violations": sum(len(r.targets) or 1 for r in p.violations),
             "needs_review": sum(len(r.targets) or 1 for r in p.incomplete),
             "rules_evaluated": len(p.rules_evaluated), "blocked_requests": p.blocked_requests,
             "duration_ms": p.duration_ms}
            for p in report.pages
        ],
        "rules_evaluated": report.rules_evaluated,
        "summary": {
            "pages_configured": len(report.pages),
            "pages_scanned": sum(1 for p in report.pages if p.ok),
            "rules_evaluated": len(report.rules_evaluated),
            "findings": len([f for f in report.findings if f.kind == KIND_VIOLATION]),
            "needs_review": len([f for f in report.findings if f.kind == KIND_REVIEW]),
            "blocking": sum(1 for f in active if f.blocking),
            "by_severity": {s: sum(1 for f in active if f.severity == s) for s in ("CRITICAL", "HIGH", "MEDIUM", "LOW")},
        },
        "findings": [f.to_dict() for f in report.findings],
        "limitations": limitations,
        "notice": NOT_PROOF + " Accessibility findings are quality findings and are never reported as security findings.",
    }


def write_json(report: RunReport, out: Path) -> Path:
    out.mkdir(parents=True, exist_ok=True)
    path = out / JSON_NAME
    path.write_text(json.dumps(build(report), indent=2, ensure_ascii=False) + "\n", encoding="utf-8")
    return path


def _esc(text: object) -> str:
    return clean(text, 400).replace("|", "\\|")


def render_markdown(report: RunReport) -> str:
    d = build(report)
    run = d["run"]
    L = ["# Quality CI - Accessibility Report (Phase 4A)", "",
         f"Tool: {d['tool']} | Engine: {_esc(d['engine'].get('name'))} {_esc(d['engine'].get('version', ''))}"
         + (f" ({_esc(d['engine'].get('browser'))})" if d["engine"].get("browser") else ""),
         f"Started: {run['started_at']} | Finished: {run['finished_at']}", ""]
    L += ["## Accessibility", "", f"Status: **{run['verdict']}** (run {run['status']})", "", f"Reason: {_esc(run['reason'])}", ""]
    for r in run["incomplete_reasons"]:
        L.append(f"- Incomplete: {_esc(r)}")
    if run["incomplete_reasons"]:
        L.append("")
    s = d["summary"]
    L += [f"Pages scanned: {s['pages_scanned']} of {s['pages_configured']}. Rules evaluated: {s['rules_evaluated']}. "
          f"Findings: {s['findings']} ({s['blocking']} blocking). Needs review (informational): {s['needs_review']}.", "",
          f"> {NOT_PROOF}", ""]
    L += ["## Findings", ""]
    violations = [f for f in d["findings"] if f["kind"] == KIND_VIOLATION]
    if not violations:
        L += ["None." if report.status != "NOT CONFIGURED" else "Not run.", ""]
    else:
        L += ["| ID | Rule | Impact | Severity | Blocking | Occurrences | Pages |", "|---|---|---|---|---|---|---|"]
        for f in violations:
            L.append(f"| {f['id']} | `{_esc(f['rule_id'])}` | {f['impact'] or '-'} | {f['severity']} | "
                     f"{'yes' if f['blocking'] else 'no'} | {f['occurrence_count']} | {len(f['urls'])} |")
        L.append("")
        for f in violations:
            L += [f"### {f['id']} - {_esc(f['title'])}", "",
                  f"- Rule: `{_esc(f['engine_rule'])}`; impact {f['impact'] or '-'}; severity {f['severity']}; "
                  f"source {_esc(f['source'])}",
                  f"- Description: {_esc(f['description'])}",
                  f"- Help: {_esc(f['help'])} ({_esc(f['help_url'])})" if f["help_url"] else f"- Help: {_esc(f['help'])}",
                  f"- WCAG tags: {', '.join(f['wcag']) or '-'}",
                  f"- Occurrences: {f['occurrence_count']}"]
            for p in f["pages"]:
                sels = ", ".join(f"`{_esc(x)}`" for x in p["selectors"]) or "-"
                L.append(f"  - {_esc(p['url'])}: {p['occurrences']} (e.g. {sels})")
            L.append("")
    review = [f for f in d["findings"] if f["kind"] == KIND_REVIEW]
    if review:
        L += ["### Needs review (informational, not failures)", "", "| ID | Rule | Occurrences | Pages |", "|---|---|---|---|"]
        L += [f"| {f['id']} | `{_esc(f['rule_id'])}` | {f['occurrence_count']} | {len(f['urls'])} |" for f in review]
        L.append("")
    L += ["## Pages Tested", ""]
    if d["pages_tested"]:
        L += ["| URL | Status | Violations | Needs review | Rules evaluated | Note |", "|---|---|---|---|---|---|"]
        L += [f"| {_esc(p['url'])} | {p['status']} | {p['violations']} | {p['needs_review']} | {p['rules_evaluated']} | "
              f"{_esc(p['reason']) or '-'} |" for p in d["pages_tested"]]
    else:
        L.append("None.")
    L += ["", "## Limitations", ""] + [f"- {_esc(x)}" for x in d["limitations"]] + [""]
    return "\n".join(L)


def write_markdown(report: RunReport, out: Path) -> Path:
    out.mkdir(parents=True, exist_ok=True)
    path = out / MD_NAME
    path.write_text(render_markdown(report), encoding="utf-8")
    return path


def load(path: Path) -> dict[str, Any]:
    """Read an accessibility JSON report (for SARIF export / gate). Raises ValueError on malformed input."""
    try:
        data = json.loads(Path(path).read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise ValueError(f"cannot read accessibility report: {type(exc).__name__}") from exc
    if not isinstance(data, dict) or data.get("namespace") != "Q-A11Y" or not isinstance(data.get("findings"), list) \
            or not isinstance(data.get("run"), dict):
        raise ValueError("not a quality-ci accessibility report")
    from .models import FINDING_ID_RE

    for f in data["findings"]:
        if not isinstance(f, dict) or not FINDING_ID_RE.match(str(f.get("id", ""))):
            raise ValueError(f"malformed finding id {clean(str(f.get('id') if isinstance(f, dict) else f), 60)!r}")
    return data
