"""SARIF 2.1.0 export for Q-A11Y findings (same principles as security-ci, separate tool and category).

* one run, driver ``quality-ci-accessibility``, automationDetails ``vibe-code-engineering/quality/accessibility/``;
* ruleId ``a11y/<axe rule id>``; one result per grouped finding (occurrences/pages kept in properties);
* level: CRITICAL/HIGH -> error, MEDIUM -> warning, LOW/INFORMATIONAL -> note; needs-review results use
  ``kind: "review"``;
* **no** ``security-severity`` property and tags ``accessibility``/``quality``: code-scanning platforms treat these
  as quality results, never as security alerts;
* pages are logical locations (URL with query values removed, representative selector); ``--anchor`` adds a
  repository-relative physical location for platforms that require one;
* every string is re-redacted; output is deterministic (sorted, no timestamps in results).
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from . import TOOL_NAME, __version__
from .redaction import clean, safe_selector, safe_url

SARIF_VERSION = "2.1.0"
SARIF_SCHEMA = "https://json.schemastore.org/sarif-2.1.0.json"
LEVEL = {"CRITICAL": "error", "HIGH": "error", "MEDIUM": "warning", "LOW": "note", "INFORMATIONAL": "note"}
DRIVER = "quality-ci-accessibility"
NOTICE = ("Accessibility (quality) results from axe-core; not security findings. A clean report is not proof of full "
          "WCAG compliance. Needs-review results are informational.")


def _rule(f: dict[str, Any]) -> dict[str, Any]:
    tags = ["accessibility", "quality"] + [clean(t, 40) for t in f.get("wcag", [])]
    rule: dict[str, Any] = {
        "id": f"a11y/{clean(f['rule_id'], 80)}",
        "name": clean(f["rule_id"], 80),
        "shortDescription": {"text": clean(f.get("title") or f["rule_id"], 200)},
        "fullDescription": {"text": clean(f.get("description") or f.get("title") or f["rule_id"], 1000)},
        "help": {"text": clean(f.get("help") or "See the engine documentation.", 1000)},
        "defaultConfiguration": {"level": LEVEL.get(f["severity"], "warning")},
        "properties": {"tags": tags, "engine": "axe-core"},
    }
    if f.get("help_url"):
        rule["helpUri"] = safe_url(f["help_url"])
    return rule


def _result(f: dict[str, Any], anchor: str | None) -> dict[str, Any]:
    pages = f.get("pages") or []
    text = f"[{f['id']}] {clean(f.get('title'), 200)} ({f.get('occurrence_count', 0)} occurrence(s) on {len(pages)} page(s))"
    result: dict[str, Any] = {
        "ruleId": f"a11y/{clean(f['rule_id'], 80)}",
        "kind": "review" if f.get("kind") == "needs-review" else "fail",
        "level": LEVEL.get(f["severity"], "warning"),
        "message": {"text": text},
        "partialFingerprints": {"findingId/v1": f["id"]},
        "properties": {
            "findingId": f["id"], "category": "accessibility", "layer": "quality", "source": clean(f.get("source"), 60),
            "severity": f["severity"], "impact": f.get("impact"), "status": f.get("status"), "blocking": bool(f.get("blocking")),
            "occurrenceCount": f.get("occurrence_count", 0),
            "pages": [{"url": safe_url(p["url"]), "occurrences": p.get("occurrences", 0),
                       "selectors": [safe_selector(s) for s in p.get("selectors", [])]} for p in pages],
        },
    }
    location: dict[str, Any] = {}
    if anchor:
        location["physicalLocation"] = {"artifactLocation": {"uri": anchor, "uriBaseId": "%SRCROOT%"}, "region": {"startLine": 1}}
    logical = []
    for p in pages:
        logical.append({"name": safe_url(p["url"]), "kind": "resource"})
        if p.get("selectors"):
            logical.append({"name": safe_selector(p["selectors"][0]), "kind": "element",
                            "fullyQualifiedName": f"{safe_url(p['url'])} {safe_selector(p['selectors'][0])}"})
    if logical:
        location["logicalLocations"] = logical
    if location:
        result["locations"] = [location]
    return result


def build(report: dict[str, Any], anchor: str | None = None) -> dict[str, Any]:
    findings = sorted(report.get("findings", []), key=lambda f: f["id"])
    rules: dict[str, dict[str, Any]] = {}
    for f in findings:
        rules.setdefault(f"a11y/{clean(f['rule_id'], 80)}", _rule(f))
    run_props = {
        "exporter": f"{TOOL_NAME} {__version__}", "notice": NOTICE,
        "runStatus": report.get("run", {}).get("status"), "verdict": report.get("run", {}).get("verdict"),
        "incomplete": report.get("run", {}).get("incomplete_reasons", []),
        "rulesEvaluated": len(report.get("rules_evaluated", [])),
        "pagesTested": [{"url": safe_url(p["url"]), "status": p["status"]} for p in report.get("pages_tested", [])],
    }
    engine = report.get("engine", {})
    return {"$schema": SARIF_SCHEMA, "version": SARIF_VERSION, "runs": [{
        "tool": {"driver": {"name": DRIVER, "version": clean(engine.get("version") or __version__, 40),
                            "semanticVersion": clean(engine.get("version") or __version__, 40),
                            "informationUri": "https://github.com/dequelabs/axe-core",
                            "fullDescription": {"text": "Accessibility checks (axe-core) run by quality-ci Phase 4A"},
                            "rules": [rules[k] for k in sorted(rules)]}},
        "automationDetails": {"id": "vibe-code-engineering/quality/accessibility/"},
        "columnKind": "unicodeCodePoints",
        "results": [_result(f, anchor) for f in findings],
        "properties": run_props,
    }]}


def write(report: dict[str, Any], path: Path, anchor: str | None = None) -> Path:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(build(report, anchor), indent=2, ensure_ascii=False, sort_keys=False) + "\n", encoding="utf-8")
    return path
