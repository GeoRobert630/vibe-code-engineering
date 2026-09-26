"""Load and validate an externally produced verification-results file (schema 1.0).

The file is produced by a separate, authorized test suite. This module only reads a local JSON file:
it sends no requests and never receives, reads or stores credentials. Validation is strict and
all-or-nothing: any schema violation, credential-shaped field, invalid finding ID or request-budget
violation rejects the whole import (the configured areas then report INCOMPLETE).

Schema (see ``schemas/verification-results.schema.json``)::

    {
      "schema_version": "1.0",
      "kind": "vibe-code-engineering/verification-results",
      "producer": {"name": str, "version": str},
      "target": {"base_url": "http(s)://host[:port]"},          # must match the Phase 3 target origin
      "areas": {                                                # any subset of AREAS
        "<area>": {
          "status": one of STATUSES,
          "runtime_checks_executed": bool,
          "requests_count": int 0..20,                          # total over all areas also <= 20
          "findings": [finding, ...],                           # IDs RT-<NAMESPACE>-NNN of that area only
          "evidence": [{"check", "expected", "observed", "endpoint"?, "fingerprint"?}, ...],
          "limitations": [str, ...]
        }
      }
    }
"""

from __future__ import annotations

import json
import re
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any
from urllib.parse import urlsplit

from ..models import Confidence, Finding, Severity, Status
from . import status as st
from .redaction import is_credential_key, strict_clean

SCHEMA_VERSION = "1.0"
SUPPORTED_SCHEMA_VERSIONS = frozenset({"1.0", "1.1"})
KIND = "vibe-code-engineering/verification-results"
MAX_BYTES = 1024 * 1024
REQUEST_BUDGET = 20
REQUEST_BUDGET_10 = 20
REQUEST_BUDGET_11 = 27
MAX_FINDINGS, MAX_EVIDENCE, MAX_LIMITATIONS = 50, 50, 20
# area key -> (label, finding category, ID namespace)
AREAS_10 = {
    "authentication": ("Authentication", "authentication", "AUTH"),
    "session": ("Session", "session", "SESSION"),
    "authorization": ("Authorization", "authorization", "AUTHZ"),
    "idor_bola": ("IDOR/BOLA", "idor", "IDOR"),
    "tenant_isolation": ("Tenant isolation", "tenant_isolation", "TENANT"),
}
AREAS_11 = {
    **AREAS_10,
    "csrf": ("CSRF", "csrf", "CSRF"),
}
AREAS = AREAS_10
NAMESPACES = tuple(ns for _, _, ns in AREAS.values())
IMPORTED_ID = re.compile(r"^RT-(AUTH|SESSION|AUTHZ|IDOR|TENANT|CSRF)-\d{3}$")
OBSERVATIONS = ("allowed", "denied", "not_applicable", "error")
FINGERPRINT = re.compile(r"^[0-9a-f]{12}$")
SOURCE = "imported-verification"

TOP_KEYS = {"schema_version", "kind", "producer", "target", "areas"}
AREA_KEYS = {"status", "runtime_checks_executed", "requests_count", "findings", "evidence", "limitations"}
AREA_REQUIRED = {"status", "runtime_checks_executed", "requests_count"}
EVIDENCE_KEYS = {"check", "expected", "observed", "endpoint", "fingerprint"}
FINDING_REQUIRED = {"id", "severity", "confidence", "title", "endpoint", "expected", "actual", "evidence", "impact",
                    "recommendation", "validation", "status"}
FINDING_OPTIONAL = {"cwe", "owasp", "notes"}


class ImportRejected(ValueError):
    """The imported result was refused. Messages name fields only, never values."""


@dataclass
class ImportedArea:
    key: str
    label: str
    claimed: str
    status: str
    runtime_checks_executed: bool
    requests_count: int
    findings: list[Finding] = field(default_factory=list)
    evidence: list[dict[str, str]] = field(default_factory=list)
    limitations: list[str] = field(default_factory=list)


@dataclass
class ImportedVerification:
    """Outcome of loading a configured import. ``status``: EXECUTED (loaded) or INCOMPLETE (unusable)."""

    status: str
    reason: str
    producer: dict[str, str] | None = None
    areas: dict[str, ImportedArea] = field(default_factory=dict)
    redactions: int = 0

    @property
    def usable(self) -> bool:
        return self.status == st.EXECUTED

    @property
    def requests_count(self) -> int:
        return sum(a.requests_count for a in self.areas.values())

    @property
    def findings(self) -> list[Finding]:
        return sorted((f for a in self.areas.values() for f in a.findings), key=lambda f: f.id)

    def area_status(self, key: str) -> str:
        """Effective status of an area for a configured import (absent => NOT VERIFIED, unusable => INCOMPLETE)."""
        if not self.usable:
            return st.INCOMPLETE
        a = self.areas.get(key)
        return a.status if a else st.resolve(configured=True, present=False)

    def to_dict(self) -> dict[str, Any]:
        return {"status": self.status, "reason": self.reason, "schema_version": SCHEMA_VERSION, "producer": self.producer,
                "requests_count": self.requests_count, "request_budget": REQUEST_BUDGET,
                "areas": sorted(self.areas), "redactions": self.redactions, "credentials_read": False}


class _Ctx:
    def __init__(self) -> None:
        self.redactions = 0

    def text(self, value: Any, where: str, limit: int = 240, required: bool = True) -> str:
        if not isinstance(value, str) or (required and not value.strip()):
            raise ImportRejected(f"{where} must be a non-empty string")
        out = strict_clean(value, limit)
        if out.count("<redacted>") > value.count("<redacted>"):
            self.redactions += 1
        return out


def _reject_credential_keys(obj: Any, where: str) -> None:
    """Walk the document; any credential-shaped key rejects the import. Area names under ``areas`` are exempt."""
    if isinstance(obj, dict):
        for k, v in obj.items():
            path = f"{where}.{k}" if where else str(k)
            if not (where == "areas" and k in AREAS) and is_credential_key(k):
                raise ImportRejected(f"credential-shaped field {strict_clean(path, 120)} is not accepted")
            _reject_credential_keys(v, path)
    elif isinstance(obj, list):
        for i, v in enumerate(obj):
            _reject_credential_keys(v, f"{where}[{i}]")


def _keys(obj: Any, where: str, allowed: set[str], required: set[str]) -> dict:
    if not isinstance(obj, dict):
        raise ImportRejected(f"{where} must be an object")
    unknown = set(obj) - allowed
    if unknown:
        raise ImportRejected(f"unknown field(s) in {where}: " + ", ".join(sorted(strict_clean(k, 40) for k in unknown)))
    missing = required - set(obj)
    if missing:
        raise ImportRejected(f"missing field(s) in {where}: " + ", ".join(sorted(missing)))
    return obj


def _count(value: Any, where: str, max_budget: int = REQUEST_BUDGET) -> int:
    if not isinstance(value, int) or isinstance(value, bool):
        raise ImportRejected(f"{where} must be an integer")
    if value < 0:
        raise ImportRejected(f"{where} must not be negative")
    if value > max_budget:
        raise ImportRejected(f"{where} exceeds the request budget of {max_budget}")
    return value


def _list(value: Any, where: str, limit: int) -> list:
    if value is None:
        return []
    if not isinstance(value, list):
        raise ImportRejected(f"{where} must be a list")
    if len(value) > limit:
        raise ImportRejected(f"{where} has more than {limit} entries")
    return value


def _finding(raw: Any, where: str, category: str, namespace: str, ctx: _Ctx) -> Finding:
    f = _keys(raw, where, FINDING_REQUIRED | FINDING_OPTIONAL, FINDING_REQUIRED)
    fid = f["id"]
    if not isinstance(fid, str) or not IMPORTED_ID.fullmatch(fid):
        raise ImportRejected(f"{where}.id is not a valid RT-<AUTH|SESSION|AUTHZ|IDOR|TENANT|CSRF>-NNN id")
    if fid.split("-")[1] != namespace:
        raise ImportRejected(f"{where}.id {fid} is outside the RT-{namespace}-* namespace of this area")
    try:
        severity, confidence, status = Severity(f["severity"]), Confidence(f["confidence"]), Status(f["status"])
    except ValueError as exc:
        raise ImportRejected(f"{where} has an invalid severity, confidence or status") from exc
    cwe = f.get("cwe")
    if cwe is not None and not (isinstance(cwe, str) and re.fullmatch(r"CWE-\d{1,5}", cwe)):
        raise ImportRejected(f"{where}.cwe must look like CWE-639")
    notes = [ctx.text(n, f"{where}.notes[{i}]", 200) for i, n in enumerate(_list(f.get("notes"), f"{where}.notes", 10))]
    return Finding(
        category=category, severity=severity, confidence=confidence, status=status,
        title=ctx.text(f["title"], f"{where}.title", 200), endpoint=ctx.text(f["endpoint"], f"{where}.endpoint", 200),
        expected=ctx.text(f["expected"], f"{where}.expected", 200), actual=ctx.text(f["actual"], f"{where}.actual", 200),
        evidence=ctx.text(f["evidence"], f"{where}.evidence", 300), impact=ctx.text(f["impact"], f"{where}.impact", 400),
        recommendation=ctx.text(f["recommendation"], f"{where}.recommendation", 400),
        validation=ctx.text(f["validation"], f"{where}.validation", 300), cwe=cwe,
        owasp=ctx.text(f["owasp"], f"{where}.owasp", 80) if f.get("owasp") is not None else None,
        notes=notes, source=SOURCE, id=fid,
    )


def _evidence(raw: Any, where: str, ctx: _Ctx) -> dict[str, str]:
    e = _keys(raw, where, EVIDENCE_KEYS, {"check", "expected", "observed"})
    for key in ("expected", "observed"):
        if e[key] not in OBSERVATIONS:
            raise ImportRejected(f"{where}.{key} must be one of {', '.join(OBSERVATIONS)}")
    out = {"check": ctx.text(e["check"], f"{where}.check", 160), "expected": e["expected"], "observed": e["observed"]}
    if e.get("endpoint") is not None:
        out["endpoint"] = ctx.text(e["endpoint"], f"{where}.endpoint", 200)
    if e.get("fingerprint") is not None:
        if not isinstance(e["fingerprint"], str) or not FINGERPRINT.match(e["fingerprint"]):
            raise ImportRejected(f"{where}.fingerprint must be 12 lower-case hex characters (HMAC prefix)")
        out["fingerprint"] = e["fingerprint"]
    return out


def _area(key: str, raw: Any, ctx: _Ctx, max_budget: int = REQUEST_BUDGET) -> ImportedArea:
    where = f"areas.{key}"
    a = _keys(raw, where, AREA_KEYS, AREA_REQUIRED)
    label, category, namespace = AREAS_11[key] if key in AREAS_11 else AREAS[key]
    if a["status"] not in st.STATUSES:
        raise ImportRejected(f"{where}.status must be one of {', '.join(st.STATUSES)}")
    if not isinstance(a["runtime_checks_executed"], bool):
        raise ImportRejected(f"{where}.runtime_checks_executed must be true or false")
    count = _count(a["requests_count"], f"{where}.requests_count", max_budget)
    findings = [_finding(f, f"{where}.findings[{i}]", category, namespace, ctx)
                for i, f in enumerate(_list(a.get("findings"), f"{where}.findings", MAX_FINDINGS))]
    evidence = [_evidence(e, f"{where}.evidence[{i}]", ctx) for i, e in enumerate(_list(a.get("evidence"), f"{where}.evidence", MAX_EVIDENCE))]
    limitations = [ctx.text(x, f"{where}.limitations[{i}]", 300)
                   for i, x in enumerate(_list(a.get("limitations"), f"{where}.limitations", MAX_LIMITATIONS))]
    active = sum(1 for f in findings if f.status in (Status.OPEN, Status.REQUIRES_REVIEW))
    status = st.resolve(configured=True, present=True, claimed=a["status"], executed=a["runtime_checks_executed"],
                        requests_count=count, active_findings=active, evidence_items=len(evidence))
    return ImportedArea(key, label, a["status"], status, a["runtime_checks_executed"], count,
                        sorted(findings, key=lambda f: f.id), evidence, limitations)


def _origin(url: str) -> tuple[str, str, int | None]:
    p = urlsplit(url)
    port = p.port or {"http": 80, "https": 443}.get(p.scheme)
    return p.scheme, (p.hostname or "").lower(), port


def validate(data: Any, base_url: str) -> ImportedVerification:
    """Validate a parsed document. Raises ImportRejected; never returns a partially accepted result."""
    _reject_credential_keys(data, "")
    doc = _keys(data, "document", TOP_KEYS, TOP_KEYS)
    ver = doc["schema_version"]
    if ver not in SUPPORTED_SCHEMA_VERSIONS:
        raise ImportRejected(f"schema_version must be one of {sorted(SUPPORTED_SCHEMA_VERSIONS)!r}")
    if doc["kind"] != KIND:
        raise ImportRejected(f"kind must be {KIND!r}")
    allowed_areas = AREAS_10 if ver == "1.0" else AREAS_11
    budget = REQUEST_BUDGET_10 if ver == "1.0" else REQUEST_BUDGET_11

    ctx = _Ctx()
    producer = _keys(doc["producer"], "producer", {"name", "version"}, {"name", "version"})
    producer = {"name": ctx.text(producer["name"], "producer.name", 60), "version": ctx.text(producer["version"], "producer.version", 30)}
    target = _keys(doc["target"], "target", {"base_url"}, {"base_url"})
    t = target["base_url"]
    if not isinstance(t, str) or urlsplit(t).scheme not in ("http", "https") or urlsplit(t).username or urlsplit(t).password:
        raise ImportRejected("target.base_url must be an http(s) URL without credentials")
    if _origin(t) != _origin(base_url):
        raise ImportRejected("target.base_url does not match the Phase 3 target origin")
    areas_raw = doc["areas"]
    if not isinstance(areas_raw, dict) or not areas_raw:
        raise ImportRejected("areas must be a non-empty object")
    unknown = set(areas_raw) - set(allowed_areas)
    if unknown:
        raise ImportRejected("unknown area(s): " + ", ".join(sorted(strict_clean(k, 40) for k in unknown)))
    areas = {k: _area(k, areas_raw[k], ctx, max_budget=budget) for k in allowed_areas if k in areas_raw}
    total = sum(a.requests_count for a in areas.values())
    if total > budget:
        raise ImportRejected(f"total requests_count {total} exceeds the request budget of {budget}")
    ids = [f.id for a in areas.values() for f in a.findings]
    if len(ids) != len(set(ids)):
        raise ImportRejected("duplicate finding id in imported result")
    return ImportedVerification(st.EXECUTED, "imported result validated", producer, areas, ctx.redactions)


def load(path: Path, base_url: str) -> ImportedVerification:
    """Load a configured import. Unusable files give an INCOMPLETE result (never an exception, never a PASS)."""
    try:
        if not path.is_file():
            raise ImportRejected("imported result file not found")
        if path.stat().st_size > MAX_BYTES:
            raise ImportRejected("imported result file too large")
        try:
            data = json.loads(path.read_text(encoding="utf-8"))
        except (ValueError, RecursionError) as exc:
            raise ImportRejected(f"imported result is not valid JSON ({exc.__class__.__name__})") from exc
        return validate(data, base_url)
    except ImportRejected as exc:
        return ImportedVerification(st.INCOMPLETE, f"imported result rejected: {exc}")
    except OSError as exc:
        return ImportedVerification(st.INCOMPLETE, f"imported result could not be read ({exc.__class__.__name__})")
