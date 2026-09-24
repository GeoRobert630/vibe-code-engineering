"""SARIF 2.1.0 export for Q-PERF findings (same principles as the 4A accessibility export).

One run, driver ``quality-ci-performance``, automationDetails ``vibe-code-engineering/quality/performance/``,
ruleId ``perf/<check_id>``. Level: HIGH (FAIL) -> error, MEDIUM (WARN) -> warning, LOW / INFORMATIONAL -> note.
Unstable and NOT MEASURED / needs-review results use ``kind: "review"``. No ``security-severity``: these are
quality results. Upload category: ``...-quality-performance``. Strings re-redacted; deterministic output.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from ..redaction import clean, safe_url
from . import TOOL_NAME, __version__

SARIF_VERSION = "2.1.0"
SARIF_SCHEMA = "https://json.schemastore.org/sarif-2.1.0.json"
LEVEL = {"HIGH": "error", "MEDIUM": "warning", "LOW": "note", "INFORMATIONAL": "note"}
DRIVER = "quality-ci-performance"
NOTICE = ("Performance (quality) lab results; not security findings and not field data. A clean report is not proof of "
          "real-user performance. Needs-review and unstable results are marked kind=review.")


def _rule(f: dict[str, Any]) -> dict[str, Any]:
    return {
        "id": f"perf/{clean(f['check_id'], 80)}",
        "name": clean(f["check_id"], 80),
        "shortDescription": {"text": clean(f.get("title") or f["check_id"], 200)},
        "fullDescription": {"text": clean(f.get("title") or f["check_id"], 1000)},
        "help": {"text": clean(f.get("help") or "See the performance report.", 1000)},
        "defaultConfiguration": {"level": LEVEL.get(f["severity"], "warning")},
        "properties": {"tags": ["performance", "quality", f.get("kind", "")], "unit": f.get("unit")},
    }


def _result(f: dict[str, Any], anchor: str | None) -> dict[str, Any]:
    pages = f.get("pages") or []
    review = f.get("status") != "OPEN" or any(p.get("unstable") for p in pages)
    values = ", ".join(str(p.get("value")) for p in pages)
    result: dict[str, Any] = {
        "ruleId": f"perf/{clean(f['check_id'], 80)}",
        "kind": "review" if review else "fail",
        "level": LEVEL.get(f["severity"], "warning"),
        "message": {"text": clean(f"[{f['id']}] {f.get('title')}: {values} {f.get('unit')} "
                                  f"(warn > {f['threshold']['warn']}, fail > {f['threshold']['fail']})", 400)},
        "partialFingerprints": {"findingId/v1": f["id"]},
        "properties": {
            "findingId": f["id"], "category": "performance", "layer": "quality", "source": clean(f.get("source"), 60),
            "severity": f["severity"], "status": f.get("status"), "blocking": bool(f.get("blocking")),
            "threshold": f.get("threshold"), "unit": f.get("unit"), "notes": [clean(n, 200) for n in f.get("notes", [])],
            "pages": [{"url": safe_url(p["url"]), "value": p.get("value"), "runs": p.get("runs"), "status": p.get("status"),
                       "unstable": bool(p.get("unstable")), "cappedByHost": bool(p.get("capped_by_host")),
                       "contributors": [safe_url(c) for c in p.get("contributors", [])[:5]]} for p in pages],
        },
    }
    location: dict[str, Any] = {}
    if anchor:
        location["physicalLocation"] = {"artifactLocation": {"uri": anchor, "uriBaseId": "%SRCROOT%"}, "region": {"startLine": 1}}
    if pages:
        location["logicalLocations"] = [{"name": safe_url(p["url"]), "kind": "resource"} for p in pages]
    if location:
        result["locations"] = [location]
    return result


def build(report: dict[str, Any], anchor: str | None = None) -> dict[str, Any]:
    findings = sorted(report.get("findings", []), key=lambda f: f["id"])
    rules: dict[str, dict[str, Any]] = {}
    for f in findings:
        rules.setdefault(f"perf/{clean(f['check_id'], 80)}", _rule(f))
    run = report.get("run", {})
    engine = report.get("engine", {})
    return {"$schema": SARIF_SCHEMA, "version": SARIF_VERSION, "runs": [{
        "tool": {"driver": {"name": DRIVER, "version": __version__, "semanticVersion": __version__,
                            "informationUri": "https://github.com/GoogleChrome/web-vitals",
                            "fullDescription": {"text": "Lab performance checks run by quality-ci Phase 4B"},
                            "rules": [rules[k] for k in sorted(rules)]}},
        "automationDetails": {"id": "vibe-code-engineering/quality/performance/"},
        "columnKind": "unicodeCodePoints",
        "results": [_result(f, anchor) for f in findings],
        "properties": {
            "exporter": f"{TOOL_NAME} {__version__}", "notice": NOTICE, "runStatus": run.get("status"),
            "verdict": run.get("verdict"), "incomplete": [clean(x, 300) for x in run.get("incomplete_reasons", [])],
            "timingReliability": (report.get("host") or {}).get("timing_reliability"),
            "webVitals": (engine.get("web_vitals") or {}).get("version"),
            "pagesTested": [{"url": safe_url(p["url"]), "status": p["status"]} for p in report.get("pages_tested", [])],
        },
    }]}


def write(report: dict[str, Any], path: Path, anchor: str | None = None) -> Path:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(build(report, anchor), indent=2, ensure_ascii=False) + "\n", encoding="utf-8")
    return path
