"""Parse ZAP baseline output: the ``-J`` JSON report and the console rule summary.

* JSON (``site[].alerts[]``): one ``ZapAlert`` per alert, with redacted instances.
* Console lines ``PASS: <name> [<id>]``, ``WARN-NEW: ...``, ``FAIL-NEW: ...``, ``INFO: ...``:
  the baseline's own per-rule verdict. PASS rules only exist in the console output.

Nothing here trusts ZAP output: every string is length-limited, control characters are
stripped and secret-looking values (cookies, tokens, Authorization, passwords) redacted.
Query-string values in URLs are dropped (names kept).
"""

from __future__ import annotations

import json
import re
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any
from urllib.parse import parse_qsl, urlsplit, urlunsplit

from ..utils.redaction import clean

RISK = {"0": "Informational", "1": "Low", "2": "Medium", "3": "High"}
CONFIDENCE = {"0": "False Positive", "1": "Low", "2": "Medium", "3": "High", "4": "Confirmed"}
SENSITIVE_PARAM = re.compile(r"cookie|set-cookie|authorization|token|session|sid|passw|secret|api[-_]?key|jwt|bearer", re.I)
CONSOLE_RULE = re.compile(r"^(PASS|WARN-NEW|WARN-INPROG|FAIL-NEW|FAIL-INPROG|INFO|IGNORE):\s*(.+?)\s*\[(\d{1,6})\](?:\s*x\s*(\d+))?\s*$")
CONSOLE_SUMMARY = re.compile(r"FAIL-NEW:\s*(\d+).*?WARN-NEW:\s*(\d+).*?INFO:\s*(\d+).*?PASS:\s*(\d+)")
MAX_INSTANCES = 5


class ZapReportError(ValueError):
    pass


@dataclass
class ZapInstance:
    method: str
    url: str
    param: str
    evidence: str


@dataclass
class ZapAlert:
    plugin_id: str
    alert_ref: str
    name: str
    risk_code: int
    risk: str
    confidence_code: int
    confidence: str
    cwe: str | None
    count: int
    instances: list[ZapInstance] = field(default_factory=list)
    baseline_status: str = "WARN"  # PASS/WARN/FAIL/INFO (from console, else derived from risk)

    def to_dict(self) -> dict[str, Any]:
        return {
            "plugin_id": self.plugin_id, "alert_ref": self.alert_ref, "name": self.name, "risk": self.risk,
            "risk_code": self.risk_code, "confidence": self.confidence, "confidence_code": self.confidence_code,
            "cwe": self.cwe, "count": self.count, "baseline_status": self.baseline_status, "source": "OWASP ZAP",
            "instances": [vars(i) for i in self.instances],
        }


def safe_url(url: str) -> str:
    try:
        p = urlsplit(url)
    except ValueError:
        return clean(url, 200)
    names = sorted({k for k, _ in parse_qsl(p.query, keep_blank_values=True)})
    query = "&".join(f"{n}=<redacted>" for n in names)
    netloc = p.hostname or ""
    if p.port:
        netloc += f":{p.port}"
    return clean(urlunsplit((p.scheme, netloc, p.path, query, "")), 200)


def safe_evidence(param: str, evidence: str) -> str:
    if not evidence:
        return ""
    if SENSITIVE_PARAM.search(param or "") or SENSITIVE_PARAM.search(evidence.split(":", 1)[0] if ":" in evidence else ""):
        # keep only the header/cookie *name* part, never a value
        head = evidence.split("=", 1)[0].split(":", 1)[0]
        return clean(head, 60) + ": <redacted>"
    return clean(evidence, 160)


def _int(value: Any, default: int = 0) -> int:
    try:
        return int(str(value))
    except (TypeError, ValueError):
        return default


def parse_report(text: str) -> tuple[str | None, list[ZapAlert]]:
    try:
        data = json.loads(text)
    except (ValueError, RecursionError) as exc:
        raise ZapReportError(f"ZAP JSON report is not valid JSON ({exc.__class__.__name__})") from exc
    if not isinstance(data, dict) or not isinstance(data.get("site", []), list):
        raise ZapReportError("ZAP JSON report has an unexpected structure")
    version = data.get("@version")
    version = version if isinstance(version, str) and re.fullmatch(r"\d{1,3}\.\d{1,3}\.\d{1,3}", version) else None
    alerts: dict[str, ZapAlert] = {}
    for site in data.get("site", []):
        if not isinstance(site, dict):
            continue
        for a in site.get("alerts", []) or []:
            if not isinstance(a, dict):
                continue
            pid = str(a.get("pluginid", "")).strip()
            if not re.fullmatch(r"\d{1,6}", pid):
                continue
            risk_code = min(max(_int(a.get("riskcode")), 0), 3)
            conf_code = min(max(_int(a.get("confidence"), 2), 0), 4)
            instances = []
            for inst in (a.get("instances") or [])[:MAX_INSTANCES]:
                if isinstance(inst, dict):
                    param = clean(str(inst.get("param", "")), 80)
                    instances.append(ZapInstance(clean(str(inst.get("method", "")), 10), safe_url(str(inst.get("uri", ""))),
                                                 param,
                                                 safe_evidence(param, str(inst.get("evidence", "")))))
            alert = alerts.get(pid)
            if alert is None:
                cwe = str(a.get("cweid", "")).strip()
                alerts[pid] = ZapAlert(
                    plugin_id=pid, alert_ref=clean(str(a.get("alertRef", pid)), 20), name=clean(str(a.get("alert") or a.get("name") or "unknown alert"), 150),
                    risk_code=risk_code, risk=RISK[str(risk_code)], confidence_code=conf_code, confidence=CONFIDENCE[str(conf_code)],
                    cwe=f"CWE-{cwe}" if re.fullmatch(r"\d{1,5}", cwe) and cwe not in ("0", "-1") else None,
                    count=_int(a.get("count"), len(instances)), instances=instances,
                    baseline_status="INFO" if risk_code == 0 else "WARN",
                )
            else:  # same rule on several sites: merge
                alert.count += _int(a.get("count"), len(instances))
                alert.instances = (alert.instances + instances)[:MAX_INSTANCES]
    return version, sorted(alerts.values(), key=lambda x: (-x.risk_code, x.plugin_id))


def parse_console(text: str) -> tuple[dict[str, list[dict[str, str]]], dict[str, int] | None]:
    """Per-rule baseline verdicts. Returns ({PASS/WARN/FAIL/INFO: [{id, name}]}, summary counts or None)."""
    rules: dict[str, list[dict[str, str]]] = {"PASS": [], "WARN": [], "FAIL": [], "INFO": []}
    for line in text.splitlines():
        m = CONSOLE_RULE.match(line.strip())
        if not m:
            continue
        kind = m.group(1).split("-")[0]
        if kind == "IGNORE":
            continue
        rules[kind].append({"id": m.group(3), "name": clean(m.group(2), 150)})
    s = CONSOLE_SUMMARY.search(text.replace("\n", " "))
    summary = {"FAIL": int(s.group(1)), "WARN": int(s.group(2)), "INFO": int(s.group(3)), "PASS": int(s.group(4))} if s else None
    return rules, summary


def apply_console_status(alerts: list[ZapAlert], rules: dict[str, list[dict[str, str]]]) -> None:
    status = {r["id"]: kind for kind, items in rules.items() for r in items}
    for a in alerts:
        a.baseline_status = status.get(a.plugin_id, a.baseline_status)


def sanitized_report(text: str) -> str:
    """Rewrite the raw ZAP JSON with redacted instances (evidence/attack/otherinfo/query values)."""
    data = json.loads(text)
    for site in data.get("site", []) if isinstance(data, dict) else []:
        for a in (site.get("alerts", []) if isinstance(site, dict) else []) or []:
            if not isinstance(a, dict):
                continue
            for inst in a.get("instances", []) or []:
                if isinstance(inst, dict):
                    param = str(inst.get("param", ""))
                    inst["uri"] = safe_url(str(inst.get("uri", "")))
                    inst["evidence"] = safe_evidence(param, str(inst.get("evidence", "")))
                    inst["attack"] = clean(str(inst.get("attack", "")), 100)
                    inst["otherinfo"] = clean(str(inst.get("otherinfo", "")), 200)
    return json.dumps(data, indent=2)


def load_files(report_path: str | None, console: str) -> tuple[str | None, list[ZapAlert], dict[str, list[dict[str, str]]], dict[str, int] | None]:
    rules, summary = parse_console(console)
    version, alerts = (None, [])
    if report_path:
        raw = Path(report_path).read_text(encoding="utf-8", errors="replace")
        version, alerts = parse_report(raw)
        Path(report_path).write_text(sanitized_report(raw), encoding="utf-8")
    apply_console_status(alerts, rules)
    return version, alerts, rules, summary
