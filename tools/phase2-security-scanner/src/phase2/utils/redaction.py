"""Secret redaction and safe text rendering.

Every piece of evidence that leaves a scanner passes through ``sanitize_evidence``
which (1) masks anything matching a secret rule, (2) strips control characters
and (3) truncates. Reports therefore never contain a matched secret value even if
a scanner accidentally puts a raw source line in its evidence.
"""

from __future__ import annotations

import math
import re
from collections import Counter

MAX_EVIDENCE = 240

# Compact, self-contained patterns used only for masking. They intentionally
# over-match: masking a harmless string is fine, leaking a secret is not.
_MASK_PATTERNS = [
    re.compile(r"-----BEGIN[ A-Z]*PRIVATE KEY[ A-Z]*-----"),
    re.compile(r"\b(?:AKIA|ASIA|ABIA|ACCA)[A-Z0-9]{16}\b"),
    re.compile(r"\bgh[pousr]_[A-Za-z0-9]{20,255}\b"),
    re.compile(r"\bgithub_pat_[A-Za-z0-9_]{20,255}\b"),
    re.compile(r"\b(?:sk|rk|pk)_(?:live|test)_[A-Za-z0-9]{8,}\b"),
    re.compile(r"\bsk-[A-Za-z0-9_-]{16,}\b"),
    re.compile(r"\bsb_secret_[A-Za-z0-9_-]{8,}\b"),
    re.compile(r"\bxox[abposr]-[A-Za-z0-9-]{10,}\b"),
    re.compile(r"\bAIza[0-9A-Za-z_-]{30,}\b"),
    re.compile(r"\beyJ[A-Za-z0-9_-]{5,}\.[A-Za-z0-9_-]{5,}\.[A-Za-z0-9_-]*"),
    re.compile(r"(?i)\bbearer\s+[A-Za-z0-9._~+/=-]{8,}"),
    # user:password@ in URLs -> keep scheme/user, mask password
    re.compile(r"(?<=://)([^\s:/@'\"]{1,128}):([^\s@'\"/]{1,256})@"),
    # key = "value" / key: value for secret-looking keys
    re.compile(
        r"(?i)((?:pass(?:word|wd)?|pwd|secret|token|api[_-]?key|access[_-]?key|private[_-]?key|client[_-]?secret|credential|auth)[A-Za-z0-9_.-]{0,40}[\"']?\s*(?:[:=]|=>)\s*)([\"']?)([^\s\"',;)]{4,})"
    ),
    # long high-entropy-looking runs
    re.compile(r"[A-Za-z0-9+/_=-]{40,}"),
]

_CONTROL = re.compile(r"[\x00-\x08\x0b-\x1f\x7f\x1b]")


def mask(value: str, label: str = "secret") -> str:
    return f"<redacted:{label}:{len(value)} chars>"


def redact_text(text: str) -> str:
    for pattern in _MASK_PATTERNS:
        if pattern.groups >= 3:
            text = pattern.sub(lambda m: m.group(1) + m.group(2) + "<redacted>", text)
        elif pattern.groups == 2:
            text = pattern.sub(lambda m: m.group(1) + ":<redacted>@", text)
        else:
            text = pattern.sub("<redacted>", text)
    return text


def strip_control(text: str) -> str:
    return _CONTROL.sub("?", text.replace("\r", " ").replace("\n", " ").replace("\t", " "))


def sanitize_evidence(text: str, limit: int = MAX_EVIDENCE) -> str:
    text = strip_control(redact_text(text or "")).strip()
    if len(text) > limit:
        text = text[: limit - 3] + "..."
    return text


def shannon_entropy(value: str) -> float:
    if not value:
        return 0.0
    counts = Counter(value)
    n = len(value)
    return -sum((c / n) * math.log2(c / n) for c in counts.values())


PLACEHOLDER_HINTS = (
    "example", "sample", "dummy", "placeholder", "changeme", "change_me", "your_", "your-",
    "yourkey", "xxxx", "****", "<", "${", "{{", "%(", "redacted", "insert", "replace",
    "todo", "notreal", "not-a-real", "not_a_real", "...",
)


def looks_like_placeholder(value: str) -> bool:
    low = value.lower()
    if any(h in low for h in PLACEHOLDER_HINTS):
        return True
    if len(set(low)) <= 2 or low.startswith("-----"):
        return True
    return low in {"password", "secret", "token", "none", "null", "undefined", "true", "false", "test", "admin"}
