#!/usr/bin/env python3
"""Read a Phase 3A runtime-security-report.json and print the Layer 3 evidence.

Read-only, standard library only. Used by skills/06-security/17-security-audit/SKILL.md.

    python read_phase3_report.py <report-dir-or-runtime-security-report.json> [--json]

Per audit area it derives one status:
  FAIL            at least one FAILED assertion
  PASS            no failures and at least one PASSED assertion
  NOT APPLICABLE  every assertion was NOT_APPLICABLE
  NOT VERIFIED    check disabled, errored, refused by the safety gate, or only NOT_VERIFIED results

Exit codes: 0 report read, 3 report missing/unreadable/unsupported.
"""

from __future__ import annotations

import argparse
import json
import re
import sys
from pathlib import Path

SUPPORTED_SCHEMA = "1.0"
AREAS = [
    ("headers", "Security headers"),
    ("cookies", "Cookies"),
    ("cors", "CORS"),
    ("redirects", "HTTP to HTTPS"),
    ("tls", "TLS"),
    ("error_leakage", "Error leakage"),
]
# Phase 3A categories plus Phase 3B plumbing categories (AUTH/SESSION) and reserved authorization
# namespaces (AUTHZ, IDOR, TENANT; none are generated yet).
FINDING_ID = re.compile(r"^RT-(HEADERS|COOKIE|CORS|REDIRECT|TLS|ERROR|AUTH|SESSION|ZAP|AUTHZ|IDOR|TENANT)-\d{3}$")
AUTH_AREAS = [("authentication", "Authentication"), ("session", "Session")]
# Authorization sub-areas: (key, label, finding category). Reports without them default to NOT VERIFIED.
AUTHZ_SUBAREAS = [("authorization", "Authorization", "authorization"), ("idor_bola", "IDOR/BOLA", "idor"),
                  ("tenant_isolation", "Tenant isolation", "tenant_isolation")]
AUTHZ_STATUSES = ("PASS", "FAIL", "NOT CONFIGURED", "NOT VERIFIED", "INCOMPLETE")
# Status vocabulary of imported verification results (docs/AUTH-SESSION-AUTHORIZATION-DESIGN.md, "Imported Results").
VERIFICATION_STATUSES = ("NOT CONFIGURED", "READY", "EXECUTED", "PASS", "FAIL", "INCOMPLETE", "NOT VERIFIED")
REQUEST_BUDGET = 20


def valid_count(value: object) -> bool:
    return isinstance(value, int) and not isinstance(value, bool) and 0 <= value <= REQUEST_BUDGET


def coverage(block: object, findings: list[dict], category: str, refused: bool, statuses: tuple[str, ...],
             unbacked: tuple[str, ...]) -> dict:
    """Normalize an area block. Missing => NOT VERIFIED; claims in ``unbacked`` without executed checks => NOT VERIFIED;
    malformed imported blocks (bad requests_count, PASS with findings) => INCOMPLETE. Never an automatic PASS."""
    ids = [f["id"] for f in findings if f["category"] == category]
    if not isinstance(block, dict):
        return {"status": "NOT VERIFIED", "reported": False, "runtime_checks_executed": False, "credentials_read": False,
                "requests_count": 0, "findings": ids, "limitations": [], "detail": "not reported by this runtime report"}
    executed = block.get("runtime_checks_executed") is True
    status = block.get("status") if block.get("status") in statuses else "NOT VERIFIED"
    if status in unbacked and not executed:
        status = "NOT VERIFIED"
    count = block.get("requests_count", 0)
    imported = block.get("source") == "imported"
    if imported and (not valid_count(count) or (status == "PASS" and ids)):
        status = "INCOMPLETE"
    if refused:
        status = "NOT VERIFIED"
    limitations = block.get("limitations") if isinstance(block.get("limitations"), list) else []
    return {"status": status, "reported": True, "runtime_checks_executed": executed and not refused,
            "credentials_read": block.get("credentials_read") is True, "requests_count": count if valid_count(count) else 0,
            "findings": ids, "limitations": [clean(x, 300) for x in limitations[:20]], "detail": clean(block.get("reason"), 200),
            "source": "imported" if imported else "phase3"}
REQUIRED_FINDING_FIELDS = {
    "id", "category", "severity", "confidence", "title", "endpoint", "expected", "actual",
    "evidence", "impact", "recommendation", "validation", "status",
}
# Phase 3A does not verify these; they stay "not verified" until Phase 3B or later.
NOT_COVERED = [
    "authenticated sessions", "authorization", "IDOR/BOLA", "tenant isolation", "authenticated page behavior",
    "post-login cookies", "logout invalidation", "CSRF for authenticated flows", "authenticated API behavior",
]
try:
    from runtime_security.verification.redaction import strict_clean
except ImportError:
    _pkg_dir = Path(__file__).resolve().parents[4] / "tools" / "phase3-runtime-security" / "src"
    if _pkg_dir.is_dir() and str(_pkg_dir) not in sys.path:
        sys.path.insert(0, str(_pkg_dir))
    from runtime_security.verification.redaction import strict_clean


def clean(value: object, limit: int = 300) -> str:
    return strict_clean(value, limit)


def load(path: Path) -> dict:
    if path.is_dir():
        path = path / "runtime-security-report.json"
    data = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(data, dict):
        raise ValueError("report is not a JSON object")
    if data.get("schema_version") != SUPPORTED_SCHEMA or (data.get("tool") or {}).get("name") != "phase3-runtime-security":
        raise ValueError("not a phase3-runtime-security report with schema_version 1.0")
    for key in ("target", "environment", "safety", "checks", "findings", "summary", "exit_code", "limitations"):
        if key not in data:
            raise ValueError(f"report missing key {key!r}")
    for f in data["findings"]:
        if not isinstance(f, dict) or REQUIRED_FINDING_FIELDS - set(f):
            raise ValueError("finding missing required fields")
        if not FINDING_ID.match(str(f["id"])):
            raise ValueError(f"runtime finding id {clean(f['id'], 40)!r} is not a recognised RT-<CATEGORY>-NNN id")
    return data


def area_status(check: dict | None, refused: bool) -> tuple[str, str]:
    if refused:
        return "NOT VERIFIED", "safety gate refused the target; nothing was sent"
    if check is None or not check.get("enabled", True):
        return "NOT VERIFIED", "check disabled or not run"
    if check.get("error"):
        return "NOT VERIFIED", f"check did not complete: {clean(check['error'], 120)}"
    outcomes = [r.get("outcome") for r in check.get("results", [])]
    if "FAILED" in outcomes:
        return "FAIL", f"{outcomes.count('FAILED')} failed, {outcomes.count('PASSED')} passed"
    if "PASSED" in outcomes:
        extra = f", {outcomes.count('NOT_VERIFIED')} not verified" if "NOT_VERIFIED" in outcomes else ""
        return "PASS", f"{outcomes.count('PASSED')} passed{extra}"
    if outcomes and all(o == "NOT_APPLICABLE" for o in outcomes):
        return "NOT APPLICABLE", "no applicable assertion for this target"
    details = "; ".join(clean(r.get("detail"), 120) for r in check.get("results", [])[:2])
    return "NOT VERIFIED", details or "no results"


def build_summary(data: dict) -> dict:
    refused = not data["safety"].get("allowed", False)
    checks = {c["name"]: c for c in data["checks"]}
    areas = []
    for key, label in AREAS:
        status, detail = area_status(checks.get(key), refused)
        areas.append({"area": label, "check": key, "status": status, "detail": detail,
                      "findings": [f["id"] for f in data["findings"] if f["category"] == key]})
    auth_areas = data.get("auth_areas") or {}
    for key, label in AUTH_AREAS:
        a = auth_areas.get(key)
        if not isinstance(a, dict):
            areas.append({"area": label, "check": key, "status": "NOT VERIFIED",
                          "detail": "no authentication/session data in this report", "findings": []})
            continue
        status = coverage(a, data["findings"], key, refused, VERIFICATION_STATUSES + ("NOT APPLICABLE",), ("PASS", "EXECUTED"))["status"]
        areas.append({"area": label, "check": key, "status": status, "detail": clean(a.get("reason"), 200),
                      "findings": [f["id"] for f in data["findings"] if f["category"] == key]})
    # Phase 3C authorization coverage status (separate from Authentication/Session).
    az = data.get("authorization") if isinstance(data.get("authorization"), dict) else None
    if az is None:
        areas.append({"area": "Authorization", "check": "authorization", "status": "NOT VERIFIED",
                      "detail": "not reported by this runtime report; runtime authorization/IDOR/BOLA/tenant isolation not verified",
                      "findings": []})
    else:
        az_status = coverage(az, data["findings"], "authorization", refused, VERIFICATION_STATUSES, ("PASS", "EXECUTED"))["status"]
        areas.append({"area": "Authorization", "check": "authorization", "status": az_status, "detail": clean(az.get("reason"), 300),
                      "findings": [f["id"] for f in data["findings"] if f["category"] == "authorization"]})
    authorization_subareas = authz_subareas(az, data["findings"], refused)
    auth_blocks = data.get("auth_areas") if isinstance(data.get("auth_areas"), dict) else {}
    coverage_summary = {
        "authentication": coverage(auth_blocks.get("authentication"), data["findings"], "authentication", refused,
                                   VERIFICATION_STATUSES + ("NOT APPLICABLE",), ("PASS", "EXECUTED")),
        "session": coverage(auth_blocks.get("session"), data["findings"], "session", refused,
                            VERIFICATION_STATUSES + ("NOT APPLICABLE",), ("PASS", "EXECUTED")),
        "authorization": coverage(az, data["findings"], "authorization", refused, VERIFICATION_STATUSES, ("PASS", "EXECUTED")),
    }
    vi = data.get("verification_import") if isinstance(data.get("verification_import"), dict) else {}
    vi_status = vi.get("status") if vi.get("status") in VERIFICATION_STATUSES else "NOT CONFIGURED"
    verification_import = {
        "status": vi_status, "reason": clean(vi.get("reason"), 200) if vi else "not reported by this runtime report",
        "requests_count": vi.get("requests_count") if valid_count(vi.get("requests_count")) else 0,
        "credentials_read": False,
    }
    if vi and not valid_count(vi.get("requests_count", 0)):
        verification_import["status"] = "INCOMPLETE"
    zap = data.get("zap") if isinstance(data.get("zap"), dict) else {}
    zap_summary = {
        "available": zap.get("available") is True,
        "version": clean(zap.get("version"), 20) if zap.get("version") else None,
        "source": clean(zap.get("source") or "unknown", 30),
        "executed": zap.get("authenticated_testing_executed") is True or zap.get("executed") is True,
        "reported": bool(zap),
    }
    zb = data.get("zap_baseline") if isinstance(data.get("zap_baseline"), dict) else {}
    zap_baseline = {
        "enabled": zb.get("enabled") is True,
        "executed": zb.get("executed") is True,
        "exit_code": zb.get("exit_code") if isinstance(zb.get("exit_code"), int) else None,
        "summary": {k: v for k, v in (zb.get("summary") or {}).items() if k in ("PASS", "WARN", "FAIL", "INFO") and isinstance(v, int)},
        "reason": clean(zb.get("reason"), 200),
        "correlations": [c for c in data.get("correlations") or [] if isinstance(c, dict)],
    }
    return {
        "zap_baseline": zap_baseline,
        "zap": zap_summary,
        "target": data["target"].get("base_url"),
        "environment": data["environment"].get("name"),
        "production": data["environment"].get("production"),
        "safety_allowed": not refused,
        "safety_reason": data["safety"].get("reason"),
        "requests_sent": data.get("requests_sent"),
        "phase3a_result": data["summary"].get("result"),
        "phase3a_exit_code": data["exit_code"],
        "findings_by_severity": data["summary"].get("findings_by_severity"),
        "blocking": [f["id"] for f in data["findings"] if f.get("blocking")],
        "areas": areas,
        "authorization_subareas": authorization_subareas,
        "authentication": coverage_summary["authentication"],
        "session": coverage_summary["session"],
        "authorization": coverage_summary["authorization"],
        "idor_bola": next(a for a in authorization_subareas if a["key"] == "idor_bola"),
        "tenant_isolation": next(a for a in authorization_subareas if a["key"] == "tenant_isolation"),
        "requests_count": verification_import["requests_count"],
        "verification_import": verification_import,
        "findings": data["findings"],
        "limitations": data["limitations"],
        "not_covered_by_phase3a": NOT_COVERED,
    }


def authz_subareas(az: dict | None, findings: list[dict], refused: bool) -> list[dict]:
    """Authorization / IDOR/BOLA / tenant-isolation sub-areas. A missing block defaults to NOT VERIFIED.

    A reported PASS/FAIL is only kept when the block says runtime checks were executed; no finding is synthesized.
    """
    blocks = az.get("subareas") if isinstance(az, dict) and isinstance(az.get("subareas"), dict) else {}
    out = []
    for key, label, category in AUTHZ_SUBAREAS:
        b = blocks.get(key) if isinstance(blocks.get(key), dict) else None
        c = coverage(b, findings, category, refused, VERIFICATION_STATUSES, ("PASS", "FAIL", "EXECUTED"))
        out.append({
            "key": key, "area": label, "status": c["status"],
            "detail": c["detail"],
            "reported": b is not None,
            "runtime_checks_executed": c["runtime_checks_executed"],
            "credentials_read": c["credentials_read"],
            "requests_count": c["requests_count"],
            "limitations": c["limitations"],
            "findings": c["findings"],
        })
    return out


def render(s: dict) -> str:
    out = [
        "PHASE 3A RUNTIME EVIDENCE (Layer 3)",
        f"target: {clean(s['target'])}  environment: {clean(s['environment'])}  production flag: {str(s['production']).lower()}",
        f"safety gate: {'allowed' if s['safety_allowed'] else 'REFUSED'} - {clean(s['safety_reason'])}; requests sent: {s['requests_sent']}",
        f"phase3a result: {clean(s['phase3a_result'])} (exit {s['phase3a_exit_code']})",
        "findings: " + ", ".join(f"{k}={v}" for k, v in (s["findings_by_severity"] or {}).items()) + f"; blocking: {len(s['blocking'])}",
        "",
        "OWASP ZAP: " + ("Available" + (f" (version {s['zap']['version']})" if s["zap"]["version"] else "") if s["zap"]["available"]
                         else ("Unavailable" if s["zap"]["reported"] else "Unavailable (not reported by this runtime report)"))
        + ("" if s["zap"]["executed"] else "; authenticated testing not executed"),
        ("ZAP baseline (passive): " + ("executed, exit " + str(s["zap_baseline"]["exit_code"]) + ", " +
                                        ", ".join(f"{k} {v}" for k, v in s["zap_baseline"]["summary"].items())
                                        if s["zap_baseline"]["executed"] else "not executed - " + s["zap_baseline"]["reason"])
         + "; passive coverage only, not proof of security; correlations: " + str(len(s["zap_baseline"]["correlations"]))),
        "",
        "AREA STATUS:",
    ]
    out += [f"- {a['area']}: {a['status']} ({clean(a['detail'], 160)})" + (f" [{', '.join(a['findings'])}]" if a["findings"] else "") for a in s["areas"]]
    out += ["", "AUTHORIZATION SUB-AREAS:"]
    out += [f"- {a['area']}: {a['status']} (runtime checks executed: {'yes' if a['runtime_checks_executed'] else 'no'}; "
            f"credentials read: {'yes' if a['credentials_read'] else 'no'}; requests: {a['requests_count']}; "
            f"findings: {len(a['findings'])}; {clean(a['detail'], 160)})"
            + (f" [{', '.join(a['findings'])}]" if a["findings"] else "") for a in s["authorization_subareas"]]
    vi = s["verification_import"]
    out += ["", f"IMPORTED VERIFICATION: {vi['status']} - {clean(vi['reason'], 160)}; requests count: {vi['requests_count']} "
            f"(budget {REQUEST_BUDGET}); credentials read: no"]
    out += ["", f"RUNTIME FINDINGS ({len(s['findings'])}):"]
    for f in s["findings"]:
        out.append(
            f"- {clean(f['id'])} [{f['severity']}/{f['confidence']}/{f['status']}]{' BLOCKING' if f.get('blocking') else ''} "
            f"{clean(f['title'])} @ {clean(f['endpoint'])}\n"
            f"    expected: {clean(f['expected'], 160)} | actual: {clean(f['actual'], 160)}\n"
            f"    evidence: {clean(f['evidence'])}"
        )
    if not s["findings"]:
        out.append("- none")
    out += ["", "PHASE 3A LIMITATIONS:"] + [f"- {clean(x, 300)}" for x in s["limitations"]]
    out += ["", "NOT VERIFIED BY PHASE 3A (Phase 3B and later):"] + [f"- {x}" for x in s["not_covered_by_phase3a"]]
    return "\n".join(out)


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("report", help="report directory or runtime-security-report.json")
    ap.add_argument("--json", action="store_true", help="print the summary as JSON")
    args = ap.parse_args(argv)
    try:
        summary = build_summary(load(Path(args.report)))
    except (OSError, ValueError) as exc:
        print(f"read_phase3_report: error: {clean(exc)}", file=sys.stderr)
        return 3
    except (KeyError, TypeError, AttributeError) as exc:
        print(f"read_phase3_report: error: malformed report ({exc.__class__.__name__})", file=sys.stderr)
        return 3
    print(json.dumps(summary, indent=2) if args.json else render(summary))
    return 0


if __name__ == "__main__":
    sys.exit(main())
