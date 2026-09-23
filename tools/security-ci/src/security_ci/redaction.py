"""Redaction applied to every string before it can reach SARIF or console output.

The source reports are already redacted; this is a second, independent layer so a
mistake upstream cannot leak a credential into a code-scanning platform.
"""

from __future__ import annotations

import re
from urllib.parse import parse_qsl, urlsplit, urlunsplit

_PATTERNS = [
    re.compile(r"-----BEGIN[ A-Z]*PRIVATE KEY-----.*?(-----END[ A-Z]*PRIVATE KEY-----|$)", re.S),
    re.compile(r"\b(?:AKIA|ASIA)[A-Z0-9]{16}\b"),
    re.compile(r"\bgh[pousr]_[A-Za-z0-9]{20,}\b"),
    re.compile(r"\bgithub_pat_[A-Za-z0-9_]{20,}\b"),
    re.compile(r"\b(?:sk|rk)_(?:live|test)_[A-Za-z0-9]{8,}\b"),
    re.compile(r"\bsk-[A-Za-z0-9_-]{16,}\b"),
    re.compile(r"\bxox[abposr]-[A-Za-z0-9-]{10,}\b"),
    re.compile(r"\beyJ[A-Za-z0-9_-]{5,}\.[A-Za-z0-9_-]{5,}\.[A-Za-z0-9_-]*"),
    re.compile(r"(?i)\b(?:bearer|basic)\s+[A-Za-z0-9._~+/=-]{8,}"),
]
_URL_CREDS = re.compile(r"(?<=://)([^\s:/@'\"]{1,128}):([^\s@'\"/]{1,256})@")
_KEY_VALUE = re.compile(
    r"(?i)((?:pass(?:word|wd)?|pwd|secret|token|api[_-]?key|access[_-]?key|private[_-]?key|client[_-]?secret|"
    r"session(?:id|_id)?|sid|authorization|cookie|set-cookie|auth)[A-Za-z0-9_.-]{0,30}[\"']?\s*(?:[:=]|=>)\s*[\"']?)"
    r"(?!<redacted)([^\s\"',;&<>]{3,})"
)
_QUERY_VALUE = re.compile(r"(?<=[?&])([A-Za-z0-9_.\-\[\]]{1,60})=([^&#\s\"'<>]+)")
_LONG_TOKEN = re.compile(r"(?<![A-Za-z0-9/])[A-Za-z0-9+/_=-]{40,}")
_CONTROL = re.compile(r"[\x00-\x08\x0b-\x1f\x7f]")


def redact(text: str) -> str:
    text = text or ""
    for p in _PATTERNS:
        text = p.sub("<redacted>", text)
    text = _URL_CREDS.sub(lambda m: m.group(1) + ":<redacted>@", text)
    text = _KEY_VALUE.sub(lambda m: m.group(1) + "<redacted>", text)
    text = _QUERY_VALUE.sub(lambda m: m.group(1) + "=<redacted>", text)
    return _LONG_TOKEN.sub("<redacted>", text)


def clean(value: object, limit: int = 300) -> str:
    text = "" if value is None else str(value)
    text = _CONTROL.sub(" ", redact(text).replace("\r", " ").replace("\n", " ").replace("\t", " "))
    text = re.sub(r"\s{2,}", " ", text).strip()
    return text if len(text) <= limit else text[: limit - 3] + "..."


def safe_url(url: str) -> str:
    """Scheme/host/path plus query parameter *names* only; userinfo and fragment removed."""
    try:
        p = urlsplit(url)
    except ValueError:
        return clean(url, 300)
    names = sorted({k for k, _ in parse_qsl(p.query, keep_blank_values=True)})
    netloc = (p.hostname or "") + (f":{p.port}" if p.port else "")
    return clean(urlunsplit((p.scheme, netloc, p.path, "&".join(f"{n}=<redacted>" for n in names), "")), 300)
