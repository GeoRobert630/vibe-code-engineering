"""Common data model shared by every scanner, the orchestrator and the reporters."""

from __future__ import annotations

import hashlib
import re
from dataclasses import asdict, dataclass, field
from enum import Enum
from pathlib import Path
from typing import Any


class Severity(str, Enum):
    CRITICAL = "CRITICAL"
    HIGH = "HIGH"
    MEDIUM = "MEDIUM"
    LOW = "LOW"
    INFORMATIONAL = "INFORMATIONAL"


class Confidence(str, Enum):
    HIGH = "HIGH"
    MEDIUM = "MEDIUM"
    LOW = "LOW"


class Status(str, Enum):
    OPEN = "OPEN"
    FIXED = "FIXED"
    IGNORED = "IGNORED"
    BASELINED = "BASELINED"
    REQUIRES_REVIEW = "REQUIRES_REVIEW"


class Classification(str, Enum):
    """How strongly the evidence supports the finding (skill rule: distinguish confirmed vs unverified)."""

    CONFIRMED = "CONFIRMED"  # evidence directly shows the issue (e.g. tool-reported advisory, privileged: true)
    POTENTIAL = "POTENTIAL"  # pattern strongly suggests the issue but was not proven
    REQUIRES_RUNTIME_VERIFICATION = "REQUIRES_RUNTIME_VERIFICATION"  # only runtime/staging testing can decide
    INFORMATIONAL = "INFORMATIONAL"  # hygiene / context, not a vulnerability


ACTIVE_STATUSES = frozenset({Status.OPEN, Status.REQUIRES_REVIEW})


def normalize_title(title: str) -> str:
    return re.sub(r"[^a-z0-9]+", "-", title.lower()).strip("-")


def short_hash(*parts: object, length: int = 12) -> str:
    joined = "\x1f".join("" if p is None else str(p) for p in parts)
    return hashlib.sha256(joined.encode("utf-8", "replace")).hexdigest()[:length]


@dataclass
class Finding:
    scanner: str
    category: str
    severity: Severity
    confidence: Confidence
    title: str
    description: str
    file: str | None = None
    line: int | None = None
    column: int | None = None
    evidence: str = ""
    impact: str = ""
    recommendation: str = ""
    validation: str = ""
    cwe: str | None = None
    owasp: str | None = None
    source: list[str] = field(default_factory=list)
    status: Status = Status.OPEN
    classification: Classification = Classification.POTENTIAL
    rule_id: str = ""
    # Key used to merge findings from different scanners describing the same issue.
    # Defaults to the normalized title; scanners reporting the same *kind* of issue
    # (e.g. internal secret rule vs. gitleaks rule) set the same dedup_key.
    dedup_key: str = ""
    # Stable, secret-free description of the matched code used for baseline matching
    # when line numbers shift. Never contains a secret value.
    context: str = ""
    tags: list[str] = field(default_factory=list)
    notes: list[str] = field(default_factory=list)
    project: str = ""
    id: str = ""
    fingerprint: str = ""

    def compute_ids(self) -> None:
        key = self.dedup_key or normalize_title(self.title)
        self.id = "P2-" + short_hash(self.category, self.file, self.line, key)
        self.fingerprint = short_hash(self.category, self.file, key, self.context or self.line, length=24)

    def to_dict(self) -> dict[str, Any]:
        data = asdict(self)
        for key in ("severity", "confidence", "status", "classification"):
            data[key] = getattr(self, key).value
        data.pop("dedup_key", None)
        data.pop("context", None)  # fingerprint input only; never emitted (SR-10)
        return data


@dataclass
class ToolStatus:
    name: str
    available: bool
    used: bool = False
    version: str | None = None
    detail: str = ""
    failed: bool = False

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


@dataclass
class ScannerRun:
    name: str
    findings: list[Finding] = field(default_factory=list)
    tools: list[ToolStatus] = field(default_factory=list)
    errors: list[str] = field(default_factory=list)
    limitations: list[str] = field(default_factory=list)
    duration_seconds: float = 0.0

    @property
    def failed(self) -> bool:
        return bool(self.errors) or any(t.failed for t in self.tools)


@dataclass
class Technology:
    name: str
    confidence: Confidence
    evidence: list[str] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        return {"name": self.name, "confidence": self.confidence.value, "evidence": self.evidence}


@dataclass
class FileEntry:
    rel: str  # POSIX-style path relative to the project root
    path: Path
    size: int
    build_output: bool = False

    @property
    def name(self) -> str:
        return self.rel.rsplit("/", 1)[-1]

    @property
    def suffix(self) -> str:
        name = self.name
        dot = name.rfind(".")
        return name[dot:].lower() if dot > 0 else ""
