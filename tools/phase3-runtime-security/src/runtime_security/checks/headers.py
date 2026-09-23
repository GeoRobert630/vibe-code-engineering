"""Security response headers.

Context-aware: HTML documents need anti-framing and CSP; JSON/API responses mainly
need nosniff. HSTS is only meaningful over HTTPS. A present CSP is defence in
depth - it does not by itself fix XSS, and the report says so.
"""

from __future__ import annotations

import re

from ..config import Config
from ..models import CheckRun, Confidence, Finding, Outcome, Severity
from ..utils.http import Client
from ..utils.redaction import safe_header_value

NAME = "headers"
VERSION_RE = re.compile(r"\d+\.\d+")


def _is_document(content_type: str) -> bool:
    return content_type in ("text/html", "application/xhtml+xml", "")


def _finding(endpoint: str, sev: Severity, title: str, expected: str, actual: str, evidence: str, impact: str, rec: str, cwe: str, conf: Confidence = Confidence.HIGH) -> Finding:
    return Finding(
        category=NAME, severity=sev, confidence=conf, title=title, endpoint=endpoint, expected=expected, actual=actual,
        evidence=evidence, impact=impact, recommendation=rec,
        validation=f"Request {endpoint} again and confirm the response headers match the expected value.",
        cwe=cwe, owasp="A05:2021-Security Misconfiguration",
    )


def run(client: Client, cfg: Config) -> CheckRun:
    run = CheckRun(NAME)
    https = cfg.scheme == "https"
    for path in cfg.paths:
        resp = client.request("GET", path)
        ep = f"GET {path}"
        doc = _is_document(resp.content_type)
        kind = "HTML document" if doc else f"non-HTML response ({resp.content_type})"

        # HSTS
        hsts = resp.header("strict-transport-security")
        if not https:
            run.add("Strict-Transport-Security", ep, Outcome.NOT_VERIFIED, "target is plain HTTP; HSTS only applies to HTTPS (verify on the HTTPS staging URL)")
        elif not hsts:
            run.fail("Strict-Transport-Security", _finding(ep, Severity.MEDIUM, "Missing Strict-Transport-Security header", "Strict-Transport-Security: max-age>=15552000",
                     "header absent", "Strict-Transport-Security not present on HTTPS response", "Browsers may be downgraded to HTTP on first visit or via SSL stripping.",
                     "Send Strict-Transport-Security: max-age=31536000; includeSubDomains (add preload only after review).", "CWE-319"))
        else:
            m = re.search(r"max-age\s*=\s*(\d+)", hsts, re.I)
            if not m or int(m.group(1)) < 15552000:
                run.fail("Strict-Transport-Security", _finding(ep, Severity.LOW, "Weak Strict-Transport-Security max-age", "max-age>=15552000 (180 days)",
                         safe_header_value("strict-transport-security", hsts), f"Strict-Transport-Security: {safe_header_value('strict-transport-security', hsts)}",
                         "Short HSTS lifetime leaves longer windows for downgrade attacks.", "Raise max-age to at least 180 days once HTTPS is stable.", "CWE-319"))
            else:
                run.add("Strict-Transport-Security", ep, Outcome.PASSED, f"max-age={m.group(1)}")

        # nosniff (all responses)
        xcto = (resp.header("x-content-type-options") or "").strip().lower()
        if xcto == "nosniff":
            run.add("X-Content-Type-Options", ep, Outcome.PASSED, "nosniff")
        else:
            run.fail("X-Content-Type-Options", _finding(ep, Severity.LOW, "Missing X-Content-Type-Options: nosniff", "X-Content-Type-Options: nosniff",
                     xcto or "header absent", f"X-Content-Type-Options: {xcto or '(absent)'} on {kind}",
                     "Browsers may MIME-sniff responses (e.g. user uploads) into executable content.", "Send X-Content-Type-Options: nosniff on all responses.", "CWE-693"))

        csp = resp.header("content-security-policy") or ""
        csp_ro = resp.header("content-security-policy-report-only")
        frame_ancestors = re.search(r"frame-ancestors\s+([^;]+)", csp, re.I)
        if doc:
            # CSP
            if csp:
                weak = [t for t in ("'unsafe-inline'", "'unsafe-eval'") if t in csp and "script-src" in csp and "'nonce-" not in csp and "'strict-dynamic'" not in csp]
                if weak:
                    run.fail("Content-Security-Policy", _finding(ep, Severity.LOW, "Content-Security-Policy allows unsafe script sources", "script-src without 'unsafe-inline'/'unsafe-eval' (or nonce/strict-dynamic based)",
                             ", ".join(weak), f"Content-Security-Policy: {safe_header_value('content-security-policy', csp)}",
                             "The policy provides little protection against injected scripts.", "Move to nonce- or hash-based script-src; remove unsafe-inline/unsafe-eval.", "CWE-693", Confidence.MEDIUM))
                else:
                    run.add("Content-Security-Policy", ep, Outcome.PASSED, "present (defence in depth; does not by itself prevent XSS - output encoding still required)")
            else:
                note = " (Report-Only policy present, not enforced)" if csp_ro else ""
                run.fail("Content-Security-Policy", _finding(ep, Severity.LOW, "Missing Content-Security-Policy on HTML document", "an enforced Content-Security-Policy",
                         "header absent" + note, f"Content-Security-Policy absent on {kind}{note}",
                         "No browser-side mitigation if an XSS bug exists. CSP is defence in depth; it does not replace output encoding.",
                         "Deploy a CSP (start with Report-Only, then enforce), including frame-ancestors.", "CWE-693", Confidence.MEDIUM))
            # Anti-framing: CSP frame-ancestors supersedes X-Frame-Options in modern browsers.
            xfo = (resp.header("x-frame-options") or "").strip().upper()
            if frame_ancestors:
                value = frame_ancestors.group(1).strip()
                if value in ("*",) or "*" == value.split()[0]:
                    run.fail("Framing protection", _finding(ep, Severity.MEDIUM, "CSP frame-ancestors allows any origin", "frame-ancestors 'none' or 'self' or an allowlist",
                             value, f"frame-ancestors {value}", "Any site can frame the page (clickjacking).", "Restrict frame-ancestors.", "CWE-1021"))
                else:
                    run.add("Framing protection", ep, Outcome.PASSED, f"CSP frame-ancestors {value}" + (f"; X-Frame-Options {xfo}" if xfo else ""))
            elif xfo in ("DENY", "SAMEORIGIN"):
                run.add("Framing protection", ep, Outcome.PASSED, f"X-Frame-Options {xfo}")
            else:
                run.fail("Framing protection", _finding(ep, Severity.MEDIUM, "No clickjacking protection on HTML document", "CSP frame-ancestors or X-Frame-Options DENY/SAMEORIGIN",
                         xfo or "both absent", f"X-Frame-Options: {xfo or '(absent)'}; CSP frame-ancestors: (absent)",
                         "The page can be framed by other sites (clickjacking), relevant if it has state-changing UI.",
                         "Send Content-Security-Policy: frame-ancestors 'none' (or 'self'); optionally X-Frame-Options: DENY for old browsers.", "CWE-1021", Confidence.MEDIUM))
            # Referrer-Policy
            rp = (resp.header("referrer-policy") or "").strip().lower()
            if not rp or rp in ("unsafe-url", "no-referrer-when-downgrade"):
                run.fail("Referrer-Policy", _finding(ep, Severity.LOW, "Missing or permissive Referrer-Policy", "strict-origin-when-cross-origin, same-origin or no-referrer",
                         rp or "header absent", f"Referrer-Policy: {rp or '(absent)'}",
                         "Full URLs (which may contain tokens or IDs) can leak to third parties. Modern browsers default to strict-origin-when-cross-origin.",
                         "Send Referrer-Policy: strict-origin-when-cross-origin (or stricter).", "CWE-200", Confidence.MEDIUM))
            else:
                run.add("Referrer-Policy", ep, Outcome.PASSED, rp)
            # Permissions-Policy (hardening only)
            pp = resp.header("permissions-policy")
            if pp:
                run.add("Permissions-Policy", ep, Outcome.PASSED, "present")
            else:
                run.fail("Permissions-Policy", _finding(ep, Severity.INFORMATIONAL, "Permissions-Policy not set", "Permissions-Policy disabling unused features",
                         "header absent", "Permissions-Policy absent", "Hardening only: powerful browser features are not explicitly disabled.",
                         "Send Permissions-Policy: camera=(), microphone=(), geolocation=() (adjust to features actually used).", "CWE-693", Confidence.MEDIUM))
        else:
            for name in ("Content-Security-Policy", "Framing protection", "Referrer-Policy", "Permissions-Policy"):
                run.add(name, ep, Outcome.NOT_APPLICABLE, f"{kind}: document-level header not required")

        # Version disclosure
        for hname in ("server", "x-powered-by", "x-aspnet-version"):
            value = resp.header(hname)
            if value and (VERSION_RE.search(value) or hname == "x-powered-by"):
                run.fail(f"{hname} disclosure", _finding(ep, Severity.LOW, f"Technology/version disclosed in {hname} header", f"{hname} absent or without version",
                         safe_header_value(hname, value), f"{hname}: {safe_header_value(hname, value)}",
                         "Version details help attackers pick known exploits.", f"Remove or genericise the {hname} header.", "CWE-200", Confidence.HIGH))
    return run
