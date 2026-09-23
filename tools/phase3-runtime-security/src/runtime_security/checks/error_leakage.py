"""Error-message leakage with safe malformed requests.

Probes (no exploit payloads, nothing that can create or change data):
* GET a random non-existent path
* GET a configured intentionally-invalid resource ID path
* GET a configured endpoint without its required parameter
* POST a truncated JSON document (rejected by the client if it would parse)
* an unsupported method token (PHASE3PROBE)

Responses are searched for stack traces, framework debug pages, filesystem/source
paths, SQL/database errors and secrets. Evidence is the pattern name plus a short,
redacted snippet.

Correlation: the same disclosure is often reproduced by several probes (e.g. one
global error handler answering every malformed request with the same stack trace).
Hits are grouped by (leak category, disclosure signature). The signature is derived
only from *redacted* identifying details of the leak - stack frames (file:line) and
exception type, SQL error class/code, the leaked path, the redacted secret pattern -
never from raw secrets, tokens or whole bodies. One finding is emitted per group; every
probe that reproduced it is kept as a per-probe check result and listed in the
finding's evidence and notes. Severity is the category's severity and does not grow
with the number of probes. Different categories or different signatures (other
exception, other file, other path, other error code) stay separate findings. The HTTP
method is recorded per probe but is not part of the key because it does not change
the disclosed information.
"""

from __future__ import annotations

import hashlib
import re
import secrets

from ..config import Config
from ..models import CheckRun, Confidence, Finding, Outcome, Severity
from ..utils.http import PROBE_METHOD, Client
from ..utils.redaction import clean, redact

NAME = "error_leakage"
MALFORMED_JSON = b'{"phase3_probe": ['

SIGNATURES: list[tuple[str, Severity, re.Pattern]] = [
    ("Python stack trace", Severity.MEDIUM, re.compile(r"Traceback \(most recent call last\)|File \"[^\"]+\", line \d+")),
    ("Node.js stack trace", Severity.MEDIUM, re.compile(r"\n?\s+at [\w$.<>\[\] ]+ \((?:/|[A-Za-z]:\\|node:)[^)]+:\d+:\d+\)|at Object\.<anonymous>")),
    ("Java/.NET stack trace", Severity.MEDIUM, re.compile(r"\bat (?:java|javax|org\.springframework|System)\.[\w.$]+\(|Exception in thread|System\.[A-Za-z]+Exception:")),
    ("PHP error", Severity.MEDIUM, re.compile(r"(?:Fatal error|Warning|Parse error)</b>?:.* on line \d+|Stack trace:\s*#0")),
    ("Ruby/Rails error", Severity.MEDIUM, re.compile(r"ActionController::RoutingError|\.rb:\d+:in `")),
    ("Framework debug page", Severity.HIGH, re.compile(r"Werkzeug Debugger|<title>[^<]*Django[^<]*</title>|DEBUG\s*=\s*True|Whoops! There was an error|Laravel|Symfony Exception|Server Error in '/' Application")),
    ("SQL/database error", Severity.MEDIUM, re.compile(
        r"SQLSTATE\[|syntax error at or near|You have an error in your SQL syntax|ORA-\d{5}|psycopg2?\.errors|"
        r"sqlite3\.OperationalError|SQLITE_ERROR|PG::\w+Error|SequelizeDatabaseError|PrismaClient\w*Error|MongoServerError|"
        r"unterminated quoted string|Microsoft OLE DB Provider|ODBC SQL Server Driver", re.I)),
    ("Filesystem/source path", Severity.LOW, re.compile(r"(?:/home/[\w.-]+|/var/www|/usr/src/app|/app/src|/opt/[\w.-]+|/srv/[\w.-]+)/[\w./-]+\.\w{1,5}|[A-Za-z]:\\(?:Users|inetpub|Program Files)\\[^\s\"<>]+")),
    ("Secret-like value", Severity.HIGH, re.compile(
        r"(?i)(?:password|passwd|secret|api[_-]?key|token|database_url)\s*[=:]\s*\S{4,}|(?:postgres(?:ql)?|mysql|mongodb(?:\+srv)?|redis)://[^:\s]+:[^@\s]+@|"
        r"\b(?:AKIA|ASIA)[A-Z0-9]{16}\b|-----BEGIN[ A-Z]*PRIVATE KEY-----")),
]


def _probes(cfg: Config) -> list[tuple[str, str, bytes | None, dict[str, str]]]:
    probes: list[tuple[str, str, bytes | None, dict[str, str]]] = [
        ("GET", f"/phase3-nonexistent-{secrets.token_hex(4)}", None, {}),
        ("POST", cfg.json_endpoint, MALFORMED_JSON, {"Content-Type": "application/json"}),
        (PROBE_METHOD, cfg.paths[0], None, {}),
    ]
    if cfg.invalid_resource_path:
        probes.insert(1, ("GET", cfg.invalid_resource_path, None, {}))
    if cfg.missing_parameter_path:
        probes.insert(1, ("GET", cfg.missing_parameter_path, None, {}))
    return probes


_FRAME_PY = re.compile(r'File "([^"]+)", line (\d+)')
_FRAME_NODE = re.compile(r"\(((?:/|[A-Za-z]:\\|node:)[^)\s]+:\d+):\d+\)")
_FRAME_JAVA = re.compile(r"\bat ([\w$.]+\([\w.]*:?\d*\))")
_EXC_TYPE = re.compile(r"(?m)^\s*([A-Za-z_][\w.]*(?:Error|Exception|Fault))\b")
_SQL_TOKEN = re.compile(r"SQLSTATE\[?\w*|ORA-\d{5}|psycopg2?\.errors\.\w+|sqlite3\.\w+Error|PG::\w+Error|SequelizeDatabaseError|"
                        r"PrismaClient\w*Error|MongoServerError|syntax error at or near \S+|You have an error in your SQL syntax", re.I)
_PHP_LINE = re.compile(r"in (\S+) on line (\d+)")


def signature(label: str, pattern: re.Pattern, body: str) -> str:
    """Stable, secret-free signature of *what* was disclosed (not where it was requested)."""
    if label == "Python stack trace":
        parts = [f"{f}:{n}" for f, n in _FRAME_PY.findall(body)] + _EXC_TYPE.findall(body)[-1:]
    elif label == "Node.js stack trace":
        parts = _FRAME_NODE.findall(body)[:5] + _EXC_TYPE.findall(body)[:1]
    elif label == "Java/.NET stack trace":
        parts = _EXC_TYPE.findall(body)[:1] + _FRAME_JAVA.findall(body)[:3]
    elif label == "PHP error":
        parts = [f"{f}:{n}" for f, n in _PHP_LINE.findall(body)[:3]]
    elif label == "SQL/database error":
        parts = sorted({t.lower() for t in _SQL_TOKEN.findall(body)})
    elif label in ("Filesystem/source path", "Secret-like value", "Framework debug page", "Ruby/Rails error"):
        parts = sorted({m.group(0) for m in pattern.finditer(body)})
    else:
        parts = []
    if not parts:  # fall back to the redacted first match only
        m = pattern.search(body)
        parts = [m.group(0)] if m else []
    normalized = "|".join(re.sub(r"\s+", " ", redact(x)).strip().lower() for x in parts)
    return hashlib.sha256(f"{label}|{normalized}".encode("utf-8", "replace")).hexdigest()[:16]


def _snippet(body: str, match: re.Match) -> str:
    start = max(0, match.start() - 40)
    return clean(redact(body[start: match.end() + 60]), 160)


def run(client: Client, cfg: Config) -> CheckRun:
    run = CheckRun(NAME)
    groups: dict[tuple[str, str], dict] = {}   # (label, signature) -> group; insertion order = first seen
    for method, path, body, headers in _probes(cfg):
        ep = f"{method} {path}"
        resp = client.request(method, path, headers=headers, body=body)
        hits = []
        for label, sev, pattern in SIGNATURES:
            m = pattern.search(resp.body)
            if m:
                hits.append((label, sev, _snippet(resp.body, m), signature(label, pattern, resp.body)))
        if not hits:
            run.add("malformed request", ep, Outcome.PASSED, f"status {resp.status}; no internal details in response")
            continue
        for label, sev, snippet, sig in hits:
            g = groups.setdefault((label, sig), {"label": label, "severity": sev, "snippet": snippet, "sig": sig, "probes": []})
            g["probes"].append((ep, resp.status))
            # One check result per probe, so the report keeps every probe that reproduced the leak.
            run.add(label, ep, Outcome.FAILED, f"status {resp.status}; {label} in response body (signature {sig})")
    for g in groups.values():
        label, sev, probes = g["label"], g["severity"], g["probes"]
        first_ep = probes[0][0]
        conf = Confidence.HIGH if sev != Severity.LOW else Confidence.MEDIUM
        probe_list = "; ".join(f"{ep} -> {st}" for ep, st in probes)
        statuses = sorted({st for _, st in probes})
        run.findings.append(Finding(
            category=NAME, severity=sev, confidence=conf, title=f"Error response leaks {label.lower()}", endpoint=first_ep,
            expected="generic error message without internal details",
            actual=f"status {', '.join(map(str, statuses))}; {label} in response body; reproduced by {len(probes)} probe(s)",
            evidence=f"{label}: \"{g['snippet']}\" (reproduced by {len(probes)} probe(s): {probe_list})",
            impact="Internal implementation details (code paths, queries, framework versions, secrets) help attackers target further attacks.",
            recommendation="Return generic error bodies in staging/production; log details server-side only; disable debug mode.",
            validation=f"Repeat `{first_ep}` and confirm the body contains only a generic message and a correlation ID.",
            cwe="CWE-209", owasp="A05:2021-Security Misconfiguration",
            notes=[f"Disclosure signature: {g['sig']}", f"Reproduced by {len(probes)} probe(s)"] + [f"Probe: {ep} -> status {st}" for ep, st in probes],
        ))
    return run
