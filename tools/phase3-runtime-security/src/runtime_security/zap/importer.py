"""Map ZAP baseline alerts to RT-ZAP findings and correlate them with Phase 3A findings.

Release-policy mapping (conservative, never CRITICAL):
* Informational alerts and alerts ZAP itself marks "False Positive" -> listed, no finding.
* An alert that matches an existing Phase 3A finding (same underlying issue) -> no new
  finding; a correlation "ZAP confirms RT-..." is recorded instead.
* Otherwise: ZAP High -> HIGH (OPEN), Medium -> MEDIUM (OPEN), Low -> LOW (REQUIRES_REVIEW).
  Confidence: Confirmed/High -> HIGH, Medium -> MEDIUM, Low -> LOW. A HIGH finding therefore
  blocks only when ZAP's own confidence is at least Medium (Phase 3 blocking rule).
The ZAP baseline is passive coverage only; a clean result does not mean the target is secure.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any

from ..models import Confidence, Finding, Severity, Status
from .results import ZapAlert

# plugin id -> (Phase 3A category, substrings identifying the Phase 3A finding title)
CORRELATION: dict[str, tuple[str, tuple[str, ...]]] = {
    "10021": ("headers", ("X-Content-Type-Options",)),
    "10035": ("headers", ("Strict-Transport-Security",)),
    "10038": ("headers", ("Content-Security-Policy",)),
    "10055": ("headers", ("Content-Security-Policy",)),
    "10020": ("headers", ("clickjacking", "frame-ancestors")),
    "10063": ("headers", ("Permissions-Policy",)),
    "10036": ("headers", ("server header",)),
    "10037": ("headers", ("x-powered-by",)),
    "10010": ("cookies", ("HttpOnly",)),
    "10011": ("cookies", ("Secure flag",)),
    "10054": ("cookies", ("SameSite",)),
    "10098": ("cors", ("CORS",)),
    "40040": ("cors", ("CORS",)),
    "90022": ("error_leakage", ("Error response leaks",)),
    "10023": ("error_leakage", ("Error response leaks",)),
}
_SEVERITY = {3: Severity.HIGH, 2: Severity.MEDIUM, 1: Severity.LOW}
_CONFIDENCE = {4: Confidence.HIGH, 3: Confidence.HIGH, 2: Confidence.MEDIUM, 1: Confidence.LOW}


@dataclass
class Correlation:
    zap_plugin_id: str
    zap_alert: str
    phase3a_ids: list[str]
    relation: str  # "confirms" | "related-phase3a-passed"

    def to_dict(self) -> dict[str, Any]:
        return {"zap_alert_id": self.zap_plugin_id, "zap_alert": self.zap_alert, "phase3a_findings": self.phase3a_ids, "relation": self.relation}


def _matches(f: Finding, category: str, needles: tuple[str, ...]) -> bool:
    return f.category == category and any(n.lower() in f.title.lower() for n in needles)


def import_alerts(alerts: list[ZapAlert], phase3a_findings: list[Finding], phase3a_passed: set[str]) -> tuple[list[Finding], list[Correlation], dict[str, str]]:
    """Returns (new RT-ZAP findings without IDs, correlations, {plugin_id: disposition})."""
    findings: list[Finding] = []
    correlations: list[Correlation] = []
    disposition: dict[str, str] = {}
    for a in alerts:
        corr = CORRELATION.get(a.plugin_id)
        if corr:
            matched = [f.id for f in phase3a_findings if _matches(f, *corr)]
            if matched:
                correlations.append(Correlation(a.plugin_id, a.name, matched, "confirms"))
                disposition[a.plugin_id] = "correlated with " + ", ".join(matched)
                continue
        if a.risk_code == 0:
            disposition[a.plugin_id] = "informational (listed, no finding)"
            continue
        if a.confidence_code == 0:
            disposition[a.plugin_id] = "ZAP marked false positive (listed, no finding)"
            continue
        notes = [f"ZAP alert: {a.plugin_id}", f"ZAP risk: {a.risk} (confidence {a.confidence})", f"ZAP baseline status: {a.baseline_status}",
                 "Passive baseline observation; verify before remediation."]
        if corr and corr[0] in phase3a_passed:
            correlations.append(Correlation(a.plugin_id, a.name, [], "related-phase3a-passed"))
            notes.append(f"Phase 3A check '{corr[0]}' passed its narrower assertion; ZAP flags a related issue.")
        inst = a.instances[0] if a.instances else None
        evidence = f"ZAP alert {a.plugin_id} ({a.name}); {a.count} instance(s)"
        if inst:
            evidence += f"; e.g. {inst.method} {inst.url}" + (f" param={inst.param}" if inst.param else "") + (f" evidence={inst.evidence}" if inst.evidence else "")
        findings.append(Finding(
            category="zap", severity=_SEVERITY[a.risk_code], confidence=_CONFIDENCE.get(a.confidence_code, Confidence.LOW),
            title=f"ZAP: {a.name}", endpoint=f"{inst.method} {inst.url}" if inst else "(site-wide)",
            expected=f"no '{a.name}' alert", actual=f"ZAP {a.risk} risk, {a.confidence} confidence, {a.count} instance(s)",
            evidence=evidence, impact="See the ZAP alert description for this rule; impact depends on the affected pages.",
            recommendation=f"Review ZAP alert {a.plugin_id} and apply the ZAP solution guidance where applicable.",
            validation="Re-run the ZAP baseline against the same target and confirm the alert no longer appears.",
            status=Status.OPEN if a.risk_code >= 2 else Status.REQUIRES_REVIEW, cwe=a.cwe,
            owasp=None, notes=notes, source="OWASP ZAP",
        ))
        disposition[a.plugin_id] = "RT-ZAP finding"
    return findings, correlations, disposition
