"""SARIF 2.1.0 export.

Severity mapping (unchanged five-level model, carried in properties and in GitHub's
``security-severity`` score; no promotion or demotion):

    CRITICAL      -> level "error",   security-severity 9.5
    HIGH          -> level "error",   security-severity 8.0
    MEDIUM        -> level "warning", security-severity 5.5
    LOW           -> level "note",    security-severity 3.0
    INFORMATIONAL -> level "note",    security-severity 0.0  (properties.severity keeps "INFORMATIONAL")

One run per layer (Phase 2 scanner, Phase 3 runtime, AI review). Runtime findings have no
source file; they carry the endpoint as a logical location and, if ``runtime_anchor`` is
given, a physical location on that repository file so platforms that require one accept them.
SARIF does not change any verification status: Authentication/Session status is copied into
run properties as reported (currently NOT VERIFIED).
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from . import TOOL_NAME, __version__
from .inputs import Bundle, UnifiedFinding
from .redaction import clean

SARIF_VERSION = "2.1.0"
SARIF_SCHEMA = "https://json.schemastore.org/sarif-2.1.0.json"
LEVEL = {"CRITICAL": "error", "HIGH": "error", "MEDIUM": "warning", "LOW": "note", "INFORMATIONAL": "note"}
SECURITY_SEVERITY = {"CRITICAL": "9.5", "HIGH": "8.0", "MEDIUM": "5.5", "LOW": "3.0", "INFORMATIONAL": "0.0"}
RUN_TOOLS = {
    "phase2": ("phase2-security-scanner", "Static security scanner (Layer 1)"),
    "phase3": ("phase3-runtime-security", "Runtime security checks (Layer 3: 3A defensive checks, optional passive ZAP baseline)"),
    "ai": ("ai-code-review", "AI/source-code security review findings (Layer 2)"),
}
NOTICE = ("SARIF export of existing findings. It does not change verification status; a clean SARIF report is not proof "
          "of security. Authentication/Session and Authorization runtime verification status is reported separately "
          "(a NOT VERIFIED status is a coverage gap, not a finding).")


def _rule(f: UnifiedFinding) -> dict[str, Any]:
    tags = ["security", f.layer, f.category] + ([f.cwe] if f.cwe else [])
    props: dict[str, Any] = {"tags": [t for t in tags if t], "security-severity": SECURITY_SEVERITY[f.severity]}
    if f.cwe:
        props["cwe"] = f.cwe
    if f.zap_alert_id:
        props["zapAlertId"] = f.zap_alert_id
    return {
        "id": f.rule_id,
        "name": clean(f.title, 120),
        "shortDescription": {"text": clean(f.title, 200) or f.rule_id},
        "fullDescription": {"text": clean(f.description or f.title, 1000) or f.rule_id},
        "help": {"text": clean(f.recommendation or "See the source report for remediation guidance.", 1000)},
        "defaultConfiguration": {"level": LEVEL[f.severity]},
        "properties": props,
    }


def _result(f: UnifiedFinding, runtime_anchor: str | None) -> dict[str, Any]:
    text = f"[{f.id}] {clean(f.title, 200)}"
    if f.evidence:
        text += f" Evidence: {clean(f.evidence, 300)}"
    result: dict[str, Any] = {
        "ruleId": f.rule_id,
        "level": LEVEL[f.severity],
        "message": {"text": text},
        "partialFingerprints": {"findingId/v1": f.id},
        "properties": {
            "findingId": f.id, "layer": f.layer, "source": f.source, "severity": f.severity,
            "security-severity": SECURITY_SEVERITY[f.severity], "confidence": f.confidence, "status": f.status,
            "blocking": f.blocking, "category": f.category,
        },
    }
    props = result["properties"]
    if f.cwe:
        props["cwe"] = f.cwe
    if f.zap_alert_id:
        props["zapAlertId"] = f.zap_alert_id
    if f.url:
        props["url"] = f.url
    if f.correlated_zap_alerts:
        props["correlatedZapAlerts"] = f.correlated_zap_alerts
    if f.cross_references:
        props["crossReferences"] = f.cross_references
    for key, value in f.extra.items():   # safe metadata only (RT-AUTHZ actor/resource labels, evidence count, origin)
        props[key] = value
    if f.status in ("BASELINED", "IGNORED"):
        result["suppressions"] = [{"kind": "external", "justification": f"status {f.status} in source report"}]
    location: dict[str, Any] = {}
    if f.file:
        phys: dict[str, Any] = {"artifactLocation": {"uri": f.file, "uriBaseId": "%SRCROOT%"}}
        if f.line:
            phys["region"] = {"startLine": f.line, **({"startColumn": f.column} if f.column else {})}
        location["physicalLocation"] = phys
    elif runtime_anchor and f.layer == "phase3":
        location["physicalLocation"] = {"artifactLocation": {"uri": runtime_anchor, "uriBaseId": "%SRCROOT%"},
                                        "region": {"startLine": 1}}
    if f.endpoint:
        location["logicalLocations"] = [{"name": clean(f.endpoint, 300), "kind": "resource"}]
    if location:
        result["locations"] = [location]
    return result


def build(bundle: Bundle, runtime_anchor: str | None = None) -> dict[str, Any]:
    runs = []
    for layer in ("phase2", "phase3", "ai"):
        items = [f for f in bundle.findings if f.layer == layer]
        if not items and layer not in bundle.tools:
            continue
        name, desc = RUN_TOOLS[layer]
        rules: dict[str, dict[str, Any]] = {}
        for f in items:
            rules.setdefault(f.rule_id, _rule(f))
        run_props: dict[str, Any] = {"exporter": f"{TOOL_NAME} {__version__}", "notice": NOTICE}
        if layer == "phase3":
            run_props["verificationStatus"] = dict(bundle.verification)
            if bundle.verification_subareas:
                run_props["verificationSubareas"] = dict(bundle.verification_subareas)
            if bundle.imported_verification is not None:
                run_props["importedVerification"] = dict(bundle.imported_verification)
            run_props["zapBaseline"] = "passive only (zap-baseline.py); not authenticated testing"
        if layer == "phase2" and bundle.phase2_exit_code is not None:
            run_props["sourceExitCode"] = bundle.phase2_exit_code
        if layer == "phase3" and bundle.phase3_exit_code is not None:
            run_props["sourceExitCode"] = bundle.phase3_exit_code
        dups = [d for d in bundle.duplicates if (d["id"].startswith("P2-") and layer == "phase2") or
                (d["id"].startswith("RT-") and layer == "phase3") or (d["id"].startswith("AI-") and layer == "ai")]
        if dups:
            run_props["deduplicated"] = dups
        runs.append({
            "tool": {"driver": {"name": name, "fullDescription": {"text": desc},
                                "informationUri": "https://sarifweb.azurewebsites.net/", "version": clean(bundle.tools.get(layer, ""), 60).split(" ")[-1] or "0",
                                "rules": list(rules.values())}},
            "automationDetails": {"id": f"vibe-code-engineering/{layer}/"},
            "columnKind": "unicodeCodePoints",
            "results": [_result(f, runtime_anchor) for f in items],
            "properties": run_props,
        })
    if not runs:  # empty input still yields a valid document
        runs.append({"tool": {"driver": {"name": TOOL_NAME, "version": __version__, "rules": []}}, "results": [],
                     "properties": {"notice": NOTICE, "verificationStatus": dict(bundle.verification)}})
    return {"$schema": SARIF_SCHEMA, "version": SARIF_VERSION, "runs": runs}


def write(bundle: Bundle, path: Path, runtime_anchor: str | None = None) -> Path:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(build(bundle, runtime_anchor), indent=2, ensure_ascii=False) + "\n", encoding="utf-8")
    return path
