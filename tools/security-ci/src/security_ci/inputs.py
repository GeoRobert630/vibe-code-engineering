"""Load and normalise findings from the existing report formats.

Inputs (all optional, at least one required):
* Phase 2 ``security-report.json`` (schema 1.0): ``P2-*`` findings.
* Phase 3 ``runtime-security-report.json`` (schema 1.0): ``RT-*`` findings, including
  ``RT-ZAP-*`` (passive ZAP baseline) and ``RT-AUTH-*`` / ``RT-SESSION-*``, plus the
  ``correlations`` list and the Authentication/Session area status.
* AI review findings JSON: ``{"findings": [{"id": "AI-...", "title": ..., "severity": ..., ...}]}``
  (format documented in the README). Optional ``duplicate_of`` marks an AI finding as the same
  underlying issue as an existing P2/RT finding.

Every text field is redacted and length-limited here, before it can reach SARIF.
"""

from __future__ import annotations

import json
import re
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from .redaction import clean, safe_url

SEVERITIES = ("CRITICAL", "HIGH", "MEDIUM", "LOW", "INFORMATIONAL")
ACTIVE = {"OPEN", "REQUIRES_REVIEW"}
MAX_REPORT_BYTES = 50 * 1024 * 1024
P2_ID = re.compile(r"^P2-[0-9a-f]{12}$")
RT_ID = re.compile(r"^RT-(HEADERS|COOKIE|CORS|REDIRECT|TLS|ERROR|AUTH|SESSION|ZAP|AUTHZ|IDOR|TENANT|CSRF)-\d{3}$")
AI_ID = re.compile(r"^AI-[A-Za-z0-9_-]{1,40}$")
# Status vocabulary of imported verification results; PASS/EXECUTED need runtime_checks_executed=true.
VERIFICATION_STATUSES = ("NOT CONFIGURED", "READY", "EXECUTED", "PASS", "FAIL", "INCOMPLETE", "NOT VERIFIED")
REQUEST_BUDGET = 20
SUBAREAS = ("authorization", "idor_bola", "tenant_isolation")


class InputError(ValueError):
    pass


@dataclass
class UnifiedFinding:
    id: str
    layer: str                 # "phase2" | "phase3" | "ai"
    source: str                # tool/source name, e.g. "phase2-security-scanner", "OWASP ZAP"
    rule_id: str
    title: str
    description: str
    severity: str              # one of SEVERITIES, unchanged from the report
    confidence: str
    status: str
    blocking: bool
    category: str
    file: str | None = None
    line: int | None = None
    column: int | None = None
    url: str | None = None
    endpoint: str | None = None
    evidence: str | None = None
    recommendation: str = ""
    cwe: str | None = None
    zap_alert_id: str | None = None
    extra: dict = field(default_factory=dict)   # safe passthrough metadata (e.g. RT-AUTHZ actor labels)
    correlated_zap_alerts: list[str] = field(default_factory=list)
    cross_references: list[str] = field(default_factory=list)

    @property
    def active(self) -> bool:
        return self.status in ACTIVE


@dataclass
class Bundle:
    findings: list[UnifiedFinding] = field(default_factory=list)
    duplicates: list[dict[str, str]] = field(default_factory=list)   # skipped results and why
    verification: dict[str, str] = field(default_factory=dict)        # e.g. {"Authentication": "NOT VERIFIED"}
    verification_subareas: dict[str, str] = field(default_factory=dict)  # authorization / idor_bola / tenant_isolation
    imported_verification: dict[str, Any] | None = None              # {"status", "requestsCount"} when reported
    native_verification: dict[str, Any] | None = None                # {"status", "requestsCount"} when reported
    verification_source: dict[str, Any] | None = None
    verification_subarea_source: dict[str, Any] | None = None
    incomplete: list[str] = field(default_factory=list)               # layers whose scan did not complete
    tools: dict[str, str] = field(default_factory=dict)               # layer -> tool name/version
    phase2_exit_code: int | None = None
    phase3_exit_code: int | None = None


def _load(path: Path) -> dict[str, Any]:
    if path.is_dir():
        raise InputError(f"{path} is a directory; pass the JSON report file")
    if not path.is_file():
        raise InputError(f"report not found: {path}")
    if path.stat().st_size > MAX_REPORT_BYTES:
        raise InputError(f"report too large: {path}")
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except (ValueError, RecursionError) as exc:
        raise InputError(f"{path.name} is not valid JSON ({exc.__class__.__name__})") from exc
    if not isinstance(data, dict):
        raise InputError(f"{path.name} is not a JSON object")
    return data


def _sev(value: Any) -> str:
    v = str(value or "").upper()
    return v if v in SEVERITIES else "INFORMATIONAL"


def _int(value: Any) -> int | None:
    return value if isinstance(value, int) and not isinstance(value, bool) and value >= 1 else None


def _cwe(value: Any) -> str | None:
    m = re.fullmatch(r"CWE-(\d{1,5})", str(value or "").strip())
    return f"CWE-{m.group(1)}" if m else None


def _rel_path(value: Any) -> str | None:
    if not isinstance(value, str) or not value.strip():
        return None
    p = value.replace("\\", "/").strip()
    if p.startswith("/") or re.match(r"^[A-Za-z]:", p) or ".." in p.split("/"):
        return None  # only repository-relative paths are emitted
    return clean(p, 400)


def load_phase2(path: Path, bundle: Bundle) -> None:
    data = _load(path)
    if data.get("schema_version") != "1.0" or not isinstance(data.get("findings"), list):
        raise InputError(f"{path.name}: not a Phase 2 security-report.json (schema 1.0)")
    tool = data.get("tool") or {}
    bundle.tools["phase2"] = f"{clean(tool.get('name', 'phase2-security-scanner'), 60)} {clean(tool.get('version', ''), 20)}".strip()
    bundle.phase2_exit_code = data.get("exit_code") if isinstance(data.get("exit_code"), int) else None
    if (data.get("summary") or {}).get("tool_failure"):
        bundle.incomplete.append("phase2")
    for f in data["findings"]:
        if not isinstance(f, dict) or not P2_ID.match(str(f.get("id", ""))):
            continue
        bundle.findings.append(UnifiedFinding(
            id=f["id"], layer="phase2", source="phase2-security-scanner",
            rule_id=clean(f.get("rule_id") or f.get("category") or "phase2", 120),
            title=clean(f.get("title"), 200), description=clean(f.get("description"), 1000),
            severity=_sev(f.get("severity")), confidence=clean(f.get("confidence"), 10),
            status=clean(f.get("status"), 20), blocking=f.get("blocking") is True,
            category=clean(f.get("category"), 60), file=_rel_path(f.get("file")),
            line=_int(f.get("line")), column=_int(f.get("column")),
            evidence=clean(f.get("evidence"), 300) or None, recommendation=clean(f.get("recommendation"), 600),
            cwe=_cwe(f.get("cwe")),
        ))


def _endpoint_url(endpoint: str) -> tuple[str | None, str | None]:
    endpoint = str(endpoint or "")
    m = re.match(r"^([A-Z]{3,12})\s+(\S+)$", endpoint)
    target = m.group(2) if m else endpoint
    if re.match(r"^https?://", target):
        return clean(f"{m.group(1)} {safe_url(target)}" if m else safe_url(target), 300), safe_url(target)
    return clean(endpoint, 300) or None, None


def _authz_extra(f: dict) -> dict:
    """Safe metadata for (future, imported) RT-AUTHZ findings: actor labels A/B only, resource label, evidence count."""
    out: dict = {}
    actors = [a for a in (f.get("actors") or []) if a in ("A", "B")]
    if actors:
        out["actors"] = actors
    if isinstance(f.get("resource"), str):
        out["resource"] = clean(f["resource"], 80)
    notes = [str(n) for n in f.get("notes") or []]
    count = sum(1 for n in notes if n.startswith("Check:") or n.startswith("Probe:"))
    if count:
        out["evidenceCount"] = count
    return out


def _valid_count(value: Any) -> bool:
    return isinstance(value, int) and not isinstance(value, bool) and 0 <= value <= REQUEST_BUDGET


def _coverage_status(block: dict, allowed: tuple[str, ...], unbacked: tuple[str, ...]) -> str:
    """Status as reported, restricted to the vocabulary; unbacked claims become NOT VERIFIED, malformed imports INCOMPLETE."""
    status = block.get("status")
    if status not in allowed:
        return "NOT VERIFIED"
    if block.get("source") == "mixed":
        return "INCOMPLETE"
    if status in unbacked and block.get("runtime_checks_executed") is not True:
        return "NOT VERIFIED"
    if block.get("source") in ("imported", "native") and not _valid_count(block.get("requests_count", 0)):
        return "INCOMPLETE"
    return status


def load_phase3(path: Path, bundle: Bundle) -> None:
    data = _load(path)
    if data.get("schema_version") != "1.0" or (data.get("tool") or {}).get("name") != "phase3-runtime-security":
        raise InputError(f"{path.name}: not a Phase 3 runtime-security-report.json (schema 1.0)")
    tool = data["tool"]
    bundle.tools["phase3"] = f"phase3-runtime-security {clean(tool.get('version', ''), 20)}".strip()
    bundle.phase3_exit_code = data.get("exit_code") if isinstance(data.get("exit_code"), int) else None
    safety = data.get("safety") or {}
    if not safety.get("allowed", False):
        bundle.incomplete.append("phase3 (refused by safety gate)")
    elif any(isinstance(c, dict) and c.get("error") for c in data.get("checks") or []):
        bundle.incomplete.append("phase3")
    zb = data.get("zap_baseline") or {}
    if zb.get("enabled") and zb.get("executed") and zb.get("exit_code") not in (0, 1, 2):
        bundle.incomplete.append("zap-baseline")
    for key, label in (("authentication", "Authentication"), ("session", "Session"), ("csrf", "CSRF")):
        if key == "csrf" and key not in (data.get("auth_areas") or {}):
            continue
        area = (data.get("auth_areas") or {}).get(key) or {}
        area = area if isinstance(area, dict) else {}
        bundle.verification[label] = _coverage_status(area, VERIFICATION_STATUSES + ("NOT APPLICABLE",), ("PASS", "EXECUTED"))
    az = data.get("authorization")
    if isinstance(az, dict):   # Phase 3C coverage status (absent in older reports: left out, not guessed)
        bundle.verification["Authorization"] = _coverage_status(az, VERIFICATION_STATUSES, ("PASS", "EXECUTED"))
        subs = az.get("subareas") if isinstance(az.get("subareas"), dict) else {}
        for key in SUBAREAS if subs else ():
            b = subs.get(key)
            bundle.verification_subareas[key] = (_coverage_status(b, VERIFICATION_STATUSES, ("PASS", "FAIL", "EXECUTED"))
                                                 if isinstance(b, dict) else "NOT VERIFIED")
        if "verification_source" in az:
            bundle.verification_source = {"authorization": az["verification_source"]}
        if "verification_subarea_source" in az:
            bundle.verification_subarea_source = dict(az["verification_subarea_source"])
    vi = data.get("verification_import")
    if isinstance(vi, dict):   # imported results (separate test suite); absent in older reports
        vstatus = vi.get("status") if vi.get("status") in VERIFICATION_STATUSES else "INCOMPLETE"
        count = vi.get("requests_count", 0)
        if not _valid_count(count):
            vstatus, count = "INCOMPLETE", 0
        bundle.imported_verification = {"status": vstatus, "requestsCount": count}
        if vstatus == "INCOMPLETE":
            bundle.incomplete.append("phase3 imported verification")
    nv = data.get("native_verification")
    if isinstance(nv, dict):
        nstatus = nv.get("status") if nv.get("status") in VERIFICATION_STATUSES else "INCOMPLETE"
        count = nv.get("requests_count", 0)
        if not _valid_count(count):
            nstatus, count = "INCOMPLETE", 0
        bundle.native_verification = {"status": nstatus, "requestsCount": count}
        if nstatus == "INCOMPLETE":
            bundle.incomplete.append("phase3 native verification")
    for inc in data.get("incomplete") or []:
        if isinstance(inc, str) and inc not in bundle.incomplete:
            bundle.incomplete.append(clean(inc, 100))
    if bundle.verification.get("CSRF") == "INCOMPLETE" and "phase3 csrf verification" not in bundle.incomplete:
        bundle.incomplete.append("phase3 csrf verification")
    if not safety.get("allowed", False):   # refused target: nothing verified at runtime
        for label in list(bundle.verification):
            bundle.verification[label] = "NOT VERIFIED"
        for key in list(bundle.verification_subareas):
            bundle.verification_subareas[key] = "NOT VERIFIED"
    confirmed: dict[str, list[str]] = {}   # phase3a finding id -> zap alert ids that confirm it
    confirming_alerts: set[str] = set()
    for c in data.get("correlations") or []:
        if isinstance(c, dict) and c.get("relation") == "confirms":
            alert = clean(c.get("zap_alert_id"), 10)
            confirming_alerts.add(alert)
            for fid in c.get("phase3a_findings") or []:
                confirmed.setdefault(str(fid), []).append(alert)
    for f in data.get("findings") or []:
        if not isinstance(f, dict) or not RT_ID.match(str(f.get("id", ""))):
            continue
        fid = f["id"]
        zap_id = None
        if fid.startswith("RT-ZAP-"):
            notes = " ".join(str(n) for n in f.get("notes") or [])
            m = re.search(r"ZAP alert:\s*(\d{1,6})", notes)
            zap_id = m.group(1) if m else None
            if zap_id and zap_id in confirming_alerts:
                # Already represented by the Phase 3A finding it confirms: never emit twice.
                bundle.duplicates.append({"id": fid, "reason": f"ZAP alert {zap_id} is correlated with a Phase 3A finding"})
                continue
        endpoint, url = _endpoint_url(f.get("endpoint"))
        category = clean(f.get("category"), 40)
        rule = (
            f"zap/{zap_id}"
            if zap_id
            else (
                f"RT-CSRF/{fid}"
                if fid.startswith("RT-CSRF-")
                else f"{fid.rsplit('-', 1)[0]}/{re.sub(r'[^a-z0-9]+', '-', str(f.get('title', '')).lower()).strip('-')[:60]}"
            )
        )
        bundle.findings.append(UnifiedFinding(
            id=fid, layer="phase3", source="OWASP ZAP" if f.get("source") == "OWASP ZAP" else "phase3-runtime-security",
            rule_id=rule, title=clean(f.get("title"), 200),
            description=clean(f"Expected: {f.get('expected', '')}. Actual: {f.get('actual', '')}.", 1000),
            severity=_sev(f.get("severity")), confidence=clean(f.get("confidence"), 10), status=clean(f.get("status"), 20),
            blocking=f.get("blocking") is True, category=category, url=url, endpoint=endpoint,
            evidence=clean(f.get("evidence"), 300) or None, recommendation=clean(f.get("recommendation"), 600),
            cwe=_cwe(f.get("cwe")) or ("CWE-352" if fid.startswith("RT-CSRF-") else None),
            zap_alert_id=zap_id, correlated_zap_alerts=sorted(set(confirmed.get(fid, []))),
            extra=(_authz_extra(f) if fid.startswith("RT-AUTHZ-") else {})
            | ({"origin": f["source"]} if f.get("source") in ("imported-verification", "native-verification") else {}),
        ))


def load_ai(path: Path, bundle: Bundle) -> None:
    data = _load(path)
    if not isinstance(data.get("findings"), list):
        raise InputError(f"{path.name}: expected an object with a 'findings' list")
    bundle.tools["ai"] = "ai-code-review"
    known = {f.id for f in bundle.findings}
    for f in data["findings"]:
        if not isinstance(f, dict) or not AI_ID.match(str(f.get("id", ""))):
            raise InputError(f"{path.name}: every AI finding needs an id like AI-01")
        dup = str(f.get("duplicate_of") or "")
        if dup:
            target = next((x for x in bundle.findings if x.id == dup), None)
            if target is not None:
                target.cross_references.append(f["id"])
                bundle.duplicates.append({"id": f["id"], "reason": f"same underlying issue as {dup}"})
                continue
        if f["id"] in known:
            bundle.duplicates.append({"id": f["id"], "reason": "duplicate id"})
            continue
        known.add(f["id"])
        bundle.findings.append(UnifiedFinding(
            id=f["id"], layer="ai", source="ai-code-review", rule_id=f"ai/{clean(f.get('category') or 'review', 40)}",
            title=clean(f.get("title") or f["id"], 200), description=clean(f.get("description"), 1000),
            severity=_sev(f.get("severity")), confidence=clean(f.get("confidence") or "MEDIUM", 10),
            status=clean(f.get("status") or "OPEN", 20),
            blocking=_sev(f.get("severity")) == "CRITICAL" or (_sev(f.get("severity")) == "HIGH" and str(f.get("confidence", "MEDIUM")).upper() != "LOW"),
            category=clean(f.get("category") or "review", 60), file=_rel_path(f.get("file")),
            line=_int(f.get("line")), column=_int(f.get("column")), evidence=clean(f.get("evidence"), 300) or None,
            recommendation=clean(f.get("recommendation"), 600), cwe=_cwe(f.get("cwe")),
            cross_references=[clean(x, 40) for x in f.get("cross_references") or [] if isinstance(x, str)],
        ))


def load_all(phase2: Path | None, phase3: Path | None, ai: Path | None) -> Bundle:
    if not (phase2 or phase3 or ai):
        raise InputError("at least one of --phase2, --phase3 or --ai is required")
    bundle = Bundle()
    if phase2:
        load_phase2(phase2, bundle)
    if phase3:
        load_phase3(phase3, bundle)
    if ai:
        load_ai(ai, bundle)
    if not phase3:
        bundle.verification.setdefault("Authentication", "NOT VERIFIED")
        bundle.verification.setdefault("Session", "NOT VERIFIED")
        bundle.verification.setdefault("Authorization", "NOT VERIFIED")
    return bundle
