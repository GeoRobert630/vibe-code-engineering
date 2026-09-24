"""Strict redaction and credential-field detection for imported verification evidence.

Imported results come from a separate test suite. Field *names* that look like credentials are rejected
(the whole import is refused); string *values* pass through the runtime redaction plus stricter rules
(any header line for Cookie/Set-Cookie/Authorization/API keys, any bearer/basic value, every query value).
"""

from __future__ import annotations

import re

from ..utils.redaction import clean

# Normalized (lower-case, no "-", "_", ".", " ") key fragments that are never accepted in an imported result.
FORBIDDEN_KEY_PARTS = (
    "password", "passwd", "passphrase", "secret", "token", "cookie", "bearer", "authorization", "apikey",
    "sessionid", "sessionkey", "credential", "privatekey", "jwt", "otp", "mfacode",
)
FORBIDDEN_KEYS = frozenset({"pwd", "sid", "auth", "session", "key", "pin"})

_HEADER_LINE = re.compile(
    r"(?i)\b(cookie|set-cookie|authorization|proxy-authorization|x-api-key|x-auth-token|api-key)\s*:\s*[^\r\n|]*")
_AUTH_SCHEME = re.compile(r"(?i)\b(bearer|basic|digest|token)\s+[^\s\"',;|]{3,}")
_QUERY_VALUE = re.compile(r"(?<=[?&])([A-Za-z0-9_.\-\[\]]{1,60})=([^&#\s\"'<>|]*)")


def normalize_key(key: str) -> str:
    return re.sub(r"[-_. ]", "", str(key).lower())


def is_credential_key(key: str) -> bool:
    k = normalize_key(key)
    return k in FORBIDDEN_KEYS or any(part in k for part in FORBIDDEN_KEY_PARTS)


def strict_redact(text: str) -> str:
    text = "" if text is None else str(text)
    text = _HEADER_LINE.sub(lambda m: m.group(1) + ": <redacted>", text)
    text = _AUTH_SCHEME.sub(lambda m: m.group(1) + " <redacted>", text)
    return _QUERY_VALUE.sub(lambda m: m.group(1) + "=<redacted>", text)


def strict_clean(text: object, limit: int = 240) -> str:
    return clean(strict_redact("" if text is None else str(text)), limit)
