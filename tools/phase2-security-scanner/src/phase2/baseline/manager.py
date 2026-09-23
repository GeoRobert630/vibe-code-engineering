"""Baseline management (security-baseline.json).

Rules:
* A finding is BASELINED only if its id or fingerprint is in the baseline AND
  its current severity is not CRITICAL AND its severity has not increased since
  it was accepted.
* CRITICAL findings are never baselined, neither when applying nor when writing.
* Baseline entries that no longer match anything are reported as FIXED (stale).
* The baseline is only written when --update-baseline is passed explicitly.
* Malformed entries are ignored and reported; a malformed file is an error.
"""

from __future__ import annotations

import json
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from .. import TOOL_NAME, __version__
from ..models import Finding, Severity, Status
from ..severity import is_active, rank

BASELINE_VERSION = 1
MAX_BASELINE_BYTES = 10 * 1024 * 1024
_REQUIRED = ("id", "fingerprint", "severity")


class BaselineError(ValueError):
    pass


@dataclass
class BaselineResult:
    matched: list[str] = field(default_factory=list)
    refused_critical: list[str] = field(default_factory=list)
    refused_escalated: list[str] = field(default_factory=list)
    stale: list[dict[str, Any]] = field(default_factory=list)
    invalid_entries: int = 0
    path: str | None = None

    def to_dict(self) -> dict[str, Any]:
        return {
            "path": self.path,
            "matched": len(self.matched),
            "refused_critical": self.refused_critical,
            "refused_severity_increase": self.refused_escalated,
            "fixed_or_stale": self.stale,
            "invalid_entries": self.invalid_entries,
        }


def load(path: Path) -> list[dict[str, Any]]:
    if not path.exists():
        return []
    if path.stat().st_size > MAX_BASELINE_BYTES:
        raise BaselineError(f"baseline file larger than {MAX_BASELINE_BYTES} bytes")
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except (ValueError, OSError) as exc:
        raise BaselineError(f"cannot read baseline: {exc.__class__.__name__}") from exc
    if not isinstance(data, dict) or not isinstance(data.get("findings"), list):
        raise BaselineError("baseline must be an object with a 'findings' list")
    if data.get("version") != BASELINE_VERSION:
        raise BaselineError(f"unsupported baseline version {data.get('version')!r}")
    return data["findings"]


def _valid(entry: Any) -> bool:
    if not isinstance(entry, dict) or not all(isinstance(entry.get(k), str) for k in _REQUIRED):
        return False
    try:
        Severity(entry["severity"])
    except ValueError:
        return False
    return True


def apply(findings: list[Finding], entries: list[dict[str, Any]], path: str | None = None) -> BaselineResult:
    result = BaselineResult(path=path)
    valid = []
    for e in entries:
        if _valid(e):
            valid.append(e)
        else:
            result.invalid_entries += 1
    by_id = {e["id"]: e for e in valid}
    by_fp = {e["fingerprint"]: e for e in valid}
    used: set[int] = set()
    for f in findings:
        entry = by_id.get(f.id) or by_fp.get(f.fingerprint)
        if entry is None:
            continue
        used.add(id(entry))
        if f.severity == Severity.CRITICAL or entry["severity"] == Severity.CRITICAL.value:
            result.refused_critical.append(f.id)
            f.notes.append("Listed in baseline but CRITICAL findings cannot be baselined.")
            continue
        if rank(f.severity) > rank(Severity(entry["severity"])):
            result.refused_escalated.append(f.id)
            f.notes.append(f"Baseline accepted this at {entry['severity']}; severity is now {f.severity.value}, so it needs re-review.")
            continue
        if is_active(f):
            f.status = Status.BASELINED
            reason = entry.get("reason")
            if isinstance(reason, str) and reason:
                f.notes.append("Baseline reason: " + reason[:200])
            result.matched.append(f.id)
    for e in valid:
        if id(e) not in used:
            result.stale.append({k: e.get(k) for k in ("id", "title", "file", "severity") if k in e} | {"status": Status.FIXED.value})
    return result


def write(path: Path, findings: list[Finding], previous: list[dict[str, Any]]) -> tuple[int, int]:
    """Write accepted findings. Returns (written, skipped_critical)."""
    reasons = {e.get("id"): e for e in previous if isinstance(e, dict)}
    out, skipped = [], 0
    for f in sorted(findings, key=lambda x: x.id):
        if f.status not in (Status.OPEN, Status.REQUIRES_REVIEW, Status.BASELINED):
            continue
        if f.severity == Severity.CRITICAL:
            skipped += 1
            continue
        prev = reasons.get(f.id, {})
        out.append(
            {
                "id": f.id,
                "fingerprint": f.fingerprint,
                "rule_id": f.rule_id,
                "title": f.title,
                "category": f.category,
                "severity": f.severity.value,
                "file": f.file,
                "line": f.line,
                "reason": prev.get("reason", "Accepted via --update-baseline; document the justification here."),
                "accepted_at": prev.get("accepted_at", datetime.now(timezone.utc).strftime("%Y-%m-%d")),
            }
        )
    doc = {"version": BASELINE_VERSION, "tool": f"{TOOL_NAME} {__version__}", "findings": out}
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(doc, indent=2) + "\n", encoding="utf-8")
    return len(out), skipped
