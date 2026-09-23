"""Redaction for runtime evidence.

Reports may contain header *names*, cookie *names and attributes*, status codes and
short redacted body snippets. Never cookie values, Authorization/Cookie headers,
tokens, passwords or API keys.
"""

from __future__ import annotations

import re

SENSITIVE_HEADERS = frozenset(
    {"cookie", "set-cookie", "authorization", "proxy-authorization", "x-api-key", "x-auth-token", "x-csrf-token", "x-xsrf-token"}
)

_PATTERNS = [
    re.compile(r"-----BEGIN[ A-Z]*PRIVATE KEY-----.*?(-----END[ A-Z]*PRIVATE KEY-----|$)", re.S),
    re.compile(r"\b(?:AKIA|ASIA)[A-Z0-9]{16}\b"),
    re.compile(r"\bgh[pousr]_[A-Za-z0-9]{20,}\b"),
    re.compile(r"\b(?:sk|rk)_(?:live|test)_[A-Za-z0-9]{8,}\b"),
    re.compile(r"\bsk-[A-Za-z0-9_-]{16,}\b"),
    re.compile(r"\bxox[abposr]-[A-Za-z0-9-]{10,}\b"),
    re.compile(r"\beyJ[A-Za-z0-9_-]{5,}\.[A-Za-z0-9_-]{5,}\.[A-Za-z0-9_-]*"),
    re.compile(r"(?i)\bbearer\s+[A-Za-z0-9._~+/=-]{8,}"),
]
# user:password@ in URLs
_URL_CREDS = re.compile(r"(?<=://)([^\s:/@'\"]{1,128}):([^\s@'\"/]{1,256})@")
# key=value / key: value for secret-looking keys
_KEY_VALUE = re.compile(
    r"(?i)((?:pass(?:word|wd)?|pwd|secret|token|api[_-]?key|access[_-]?key|private[_-]?key|client[_-]?secret|session(?:id)?|sid|auth|cookie)"
    r"[A-Za-z0-9_.-]{0,30}[\"']?\s*(?:[:=]|=>)\s*[\"']?)([^\s\"',;&<>]{3,})"
)
_LONG_TOKEN = re.compile(r"[A-Za-z0-9+/_=-]{40,}")
_CONTROL = re.compile(r"[\x00-\x08\x0b-\x1f\x7f]")


def redact(text: str) -> str:
    text = text or ""
    for p in _PATTERNS:
        text = p.sub("<redacted>", text)
    text = _URL_CREDS.sub(lambda m: m.group(1) + ":<redacted>@", text)
    text = _KEY_VALUE.sub(lambda m: m.group(1) + "<redacted>", text)
    return _LONG_TOKEN.sub("<redacted>", text)


def clean(text: str, limit: int = 240) -> str:
    text = _CONTROL.sub("?", redact(text).replace("\r", " ").replace("\n", " ").replace("\t", " "))
    text = re.sub(r"\s{2,}", " ", text).strip()
    return text if len(text) <= limit else text[: limit - 3] + "..."


def safe_header_value(name: str, value: str) -> str:
    """Header value suitable for a report; sensitive headers never show a value."""
    if name.lower() in SENSITIVE_HEADERS:
        return "<redacted>"
    return clean(value, 200)
