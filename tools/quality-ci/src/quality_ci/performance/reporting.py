"""performance-report.json (source of truth) and performance-report.md. Every string redacted; no page content."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from ..redaction import clean, safe_url
from .config import WARMUP_RUNS
from .findings import FINDING_ID_RE
from .measure import RECORDED, TIMING_CHECKS
from .runner import PerfReport

SCHEMA_VERSION = "1.0"
JSON_NAME = "performance-report.json"
MD_NAME = "performance-report.md"
NOTICE = ("Lab measurement under fixed emulation; not field data; not proof of real-user performance. A PASS means only "
          "that the listed pages met the listed budgets under the listed profile on this host, in this run. "
          "Performance findings are quality findings, never security findings.")
LIMITATIONS = [
    "Lab data only (fixed emulation, cold cache, headless Chromium); not field or real-user (Core Web Vitals) data.",
    "Network performance is not measured: responses are served through the safety route handler, so network "
    "throttling is not applied; network cost is modelled (model.critical-path).",
    "INP / responsiveness to input is not measured: the page is never interacted with.",
    "Warm-cache, repeat-visit, authenticated and post-interaction states are not measured.",
    "TBT here is measured from FCP to the end of the observation window; it is not Lighthouse TBT (which ends at TTI) "
    "and results are not equivalent to Lighthouse scores.",
    "Not a load, capacity or scalability test: one browser, strictly sequential page loads.",
    "Only the explicitly configured pages are loaded; requests to other origins (except configured asset origins) are blocked.",
]


def build(report: PerfReport) -> dict[str, Any]:
    cfg = report.cfg
    limitations = list(LIMITATIONS)
    if report.timing_reliability == "LOW":
        limitations.append("Host timing reliability LOW (benchmark index below MIN_BENCHMARK): timing FAILs were capped at WARN.")
    if cfg is not None and cfg.changed_budgets:
        limitations.append("Budgets changed from the defaults: " + ", ".join(cfg.changed_budgets))
    blocked: dict[str, int] = {}
    for p in report.pages:
        for k, v in p.blocked.items():
            blocked[k] = blocked.get(k, 0) + v
    if blocked:
        limitations.append("Requests blocked by the safety controls: " + ", ".join(f"{k} {v}" for k, v in sorted(blocked.items())))
    active = report.active
    checks_evaluated = sorted(cfg.budgets) if cfg is not None else []
    return {
        "schema_version": SCHEMA_VERSION,
        "tool": report.tool,
        "phase": "4B",
        "area": "Performance",
        "namespace": "Q-PERF",
        "run": {
            "status": report.status, "verdict": report.verdict, "reason": clean(report.reason, 400),
            "incomplete_reasons": [clean(r, 300) for r in report.incomplete_reasons], "exit_code": report.exit_code,
            "started_at": report.started_at, "finished_at": report.finished_at,
        },
        "target": None if cfg is None else {
            "base_url": safe_url(cfg.base_url), "environment": cfg.environment, "production": cfg.production,
            "limits": {"max_pages": cfg.max_pages, "page_timeout_seconds": cfg.page_timeout_seconds,
                       "total_timeout_seconds": cfg.total_timeout_seconds, "max_page_bytes": cfg.max_page_bytes,
                       "max_requests": cfg.max_requests, "observation_window_ms": cfg.observation_window_ms},
            "asset_origins": [safe_url(o) for o in cfg.allow_origins],
        },
        "engine": {k: (clean(v, 200) if isinstance(v, str) else v) for k, v in report.engine.items()},
        "profile": None if cfg is None else {**cfg.profile.to_dict(), "runs": cfg.runs, "warmup_runs": WARMUP_RUNS,
                                             "observation_window_ms": cfg.observation_window_ms},
        "host": {k: (clean(v, 120) if isinstance(v, str) else v) for k, v in report.host.items()},
        "budgets": {} if cfg is None else {cid: {"warn": w, "fail": f, "default": cid not in cfg.changed_budgets}
                                           for cid, (w, f) in sorted(cfg.budgets.items())},
        "pages_tested": [
            {"url": safe_url(p.url), "status": p.status, "verdict": p.verdict, "reason": clean(p.reason, 300),
             "runs": p.runs, "median": {**{cid: p.checks[cid].value for cid in TIMING_CHECKS if cid in p.checks},
                                        **{k: p.median.get(k) for k in RECORDED}},
             "deterministic": p.deterministic, "lcp_element": p.lcp_element,
             "checks": {cid: r.to_dict() for cid, r in sorted(p.checks.items())},
             "blocked_requests": p.blocked, "duration_ms": p.duration_ms}
            for p in report.pages
        ],
        "checks_evaluated": checks_evaluated,
        "summary": {
            "pages_configured": len(report.pages), "pages_measured": sum(1 for p in report.pages if p.ok),
            "findings": len(report.findings), "blocking": sum(1 for f in active if f.blocking),
            "by_severity": {s: sum(1 for f in active if f.severity == s) for s in ("HIGH", "MEDIUM", "LOW")},
            "needs_review": sum(1 for f in report.findings if not f.active),
            "timing_reliability": report.timing_reliability,
        },
        "findings": [f.to_dict() for f in report.findings],
        "limitations": limitations,
        "notice": NOTICE,
    }


def write_json(report: PerfReport, out: Path) -> Path:
    out.mkdir(parents=True, exist_ok=True)
    path = out / JSON_NAME
    path.write_text(json.dumps(build(report), indent=2, ensure_ascii=False) + "\n", encoding="utf-8")
    return path


def _e(value: object) -> str:
    return clean(value, 300).replace("|", "\\|")


def _v(value: object) -> str:
    return "-" if value is None else str(value)


def render_markdown(report: PerfReport) -> str:
    d = build(report)
    run, s = d["run"], d["summary"]
    eng = d["engine"]
    L = ["# Quality CI - Performance Report (Phase 4B)", "",
         f"Tool: {d['tool']} | Engine: {_e(eng.get('name'))}"
         + (f" (web-vitals {eng['web_vitals']['version']}, {_e(eng.get('browser'))})" if eng.get("web_vitals") else ""),
         f"Started: {run['started_at']} | Finished: {run['finished_at']}", "",
         "## Performance", "", f"Status: **{run['verdict']}** (run {run['status']})", "", f"Reason: {_e(run['reason'])}", ""]
    L += [f"- Incomplete: {_e(r)}" for r in run["incomplete_reasons"]]
    if run["incomplete_reasons"]:
        L.append("")
    if d["profile"]:
        p = d["profile"]
        L += [f"Profile: {p['name']} (viewport {p['viewport']['width']}x{p['viewport']['height']}, DPR {p['dpr']}, "
              f"CPU {p['cpu_throttle']:g}x, model RTT {p['model_rtt_ms']} ms / {p['model_throughput_kbps']} kbit/s), "
              f"{p['runs']} measured runs + {p['warmup_runs']} warm-up per page.",
              f"Host timing reliability: {_v(d['host'].get('timing_reliability'))} (benchmark index "
              f"{_v(d['host'].get('benchmark_index'))}, minimum {d['host'].get('min_benchmark')}).", ""]
    L += [f"Pages measured: {s['pages_measured']} of {s['pages_configured']}. Findings: {s['findings']} "
          f"({s['blocking']} blocking).", "", f"> {NOTICE}", "", "## Findings", ""]
    if not d["findings"]:
        L += ["None." if report.status != "NOT CONFIGURED" else "Not run.", ""]
    else:
        L += ["| ID | Check | Severity | Blocking | Values | Warn > | Fail > |", "|---|---|---|---|---|---|---|"]
        for f in d["findings"]:
            vals = ", ".join(f"{_v(p['value'])}{' (unstable)' if p['unstable'] else ''}{' (capped)' if p['capped_by_host'] else ''}"
                             for p in f["pages"])
            L.append(f"| {f['id']} | `{f['check_id']}` | {f['severity']} | {'yes' if f['blocking'] else 'no'} | {_e(vals)} | "
                     f"{_v(f['threshold']['warn'])} | {_v(f['threshold']['fail'])} |")
        L.append("")
        for f in d["findings"]:
            L += [f"### {f['id']} - {_e(f['title'])}", "", f"- {_e(f['description'])}", f"- Help: {_e(f['help']) or '-'}"]
            L += [f"- Note: {_e(n)}" for n in f["notes"]]
            for p in f["pages"]:
                L.append(f"  - {_e(p['url'])}: {_v(p['value'])} {f['unit']} ({p['status']}); runs {p['runs']}")
                L += [f"    - {_e(c)}" for c in p["contributors"]]
            L.append("")
    L += ["## Pages Tested", ""]
    if d["pages_tested"]:
        L += ["| URL | Status | Verdict | FCP | LCP | CLS | TBT | TTFB | DCL | Load | Long tasks |",
              "|---|---|---|---|---|---|---|---|---|---|---|"]
        for p in d["pages_tested"]:
            m = p["median"]
            L.append(f"| {_e(p['url'])} | {p['status']} | {p['verdict']} | {_v(m.get('timing.fcp'))} | {_v(m.get('timing.lcp'))} | "
                     f"{_v(m.get('timing.cls'))} | {_v(m.get('timing.tbt'))} | {_v(m.get('ttfb_ms'))} | {_v(m.get('dcl_ms'))} | "
                     f"{_v(m.get('load_ms'))} | {_v(m.get('long_tasks'))} |")
        L += ["", "| URL | Total bytes | Script | Stylesheet | Image | Font | Document | Requests | Render-blocking | DOM nodes | Critical path (ms, model) |",
              "|---|---|---|---|---|---|---|---|---|---|---|"]
        for p in d["pages_tested"]:
            t = p["deterministic"]
            if t:
                L.append(f"| {_e(p['url'])} | {t['budget.total-bytes']} | {t['budget.script-bytes']} | {t['budget.stylesheet-bytes']} | "
                         f"{t['budget.image-bytes']} | {t['budget.font-bytes']} | {t['budget.document-bytes']} | "
                         f"{t['budget.request-count']} | {t['budget.render-blocking']} | {t['budget.dom-nodes']} | "
                         f"{t['model.critical-path']} |")
        notes = [f"- {_e(p['url'])}: {_e(p['reason'])}" for p in d["pages_tested"] if p["reason"]]
        if notes:
            L += [""] + notes
    else:
        L.append("None.")
    L += ["", "## Budgets", "", "| Check | Warn > | Fail > | Default |", "|---|---|---|---|"]
    L += [f"| `{cid}` | {_v(b['warn'])} | {_v(b['fail'])} | {'yes' if b['default'] else '**changed**'} |" for cid, b in d["budgets"].items()]
    L += ["", "## Limitations", ""] + [f"- {_e(x)}" for x in d["limitations"]] + [""]
    return "\n".join(L)


def write_markdown(report: PerfReport, out: Path) -> Path:
    out.mkdir(parents=True, exist_ok=True)
    path = out / MD_NAME
    path.write_text(render_markdown(report), encoding="utf-8")
    return path


def load(path: Path) -> dict[str, Any]:
    try:
        data = json.loads(Path(path).read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise ValueError(f"cannot read performance report: {type(exc).__name__}") from exc
    if not isinstance(data, dict) or data.get("namespace") != "Q-PERF" or not isinstance(data.get("findings"), list) \
            or not isinstance(data.get("run"), dict):
        raise ValueError("not a quality-ci performance report")
    for f in data["findings"]:
        if not isinstance(f, dict) or not FINDING_ID_RE.match(str(f.get("id", ""))):
            raise ValueError(f"malformed finding id {clean(str(f.get('id') if isinstance(f, dict) else f), 60)!r}")
    return data
