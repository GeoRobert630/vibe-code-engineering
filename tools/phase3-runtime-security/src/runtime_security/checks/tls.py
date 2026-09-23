"""TLS certificate checks for HTTPS targets. One normal, verified handshake.

Checks: chain validates (system trust store or target.ca_file), hostname matches,
certificate not expired / not near expiry, negotiated protocol is TLS 1.2+.
No cipher enumeration, no protocol downgrade attempts, no other intrusive probing.
"""

from __future__ import annotations

import socket
import ssl
import time
from urllib.parse import urlsplit

from ..config import Config
from ..models import CheckRun, Confidence, Finding, Outcome, Severity
from ..utils.http import BudgetExceeded, Client
from ..utils.redaction import clean

NAME = "tls"
NEAR_EXPIRY_DAYS = 14


def _f(ep: str, sev: Severity, title: str, expected: str, actual: str, evidence: str, impact: str, rec: str) -> Finding:
    return Finding(
        category=NAME, severity=sev, confidence=Confidence.HIGH, title=title, endpoint=ep, expected=expected, actual=actual, evidence=evidence,
        impact=impact, recommendation=rec, validation=f"openssl s_client -connect {ep}:443 -servername <host> (or a browser) shows a valid chain for the host.",
        cwe="CWE-295", owasp="A02:2021-Cryptographic Failures",
    )


def run(client: Client, cfg: Config) -> CheckRun:
    run = CheckRun(NAME)
    if cfg.scheme != "https":
        run.add("certificate", cfg.base_url, Outcome.NOT_VERIFIED, "target is plain HTTP; TLS not in use here (verify on the HTTPS staging URL)")
        return run
    parts = urlsplit(cfg.base_url)
    host, port = parts.hostname or "", parts.port or 443
    ep = f"{host}:{port}"
    if client.sent >= cfg.max_requests:
        raise BudgetExceeded("request budget exhausted before TLS check")
    client.sent += 1
    ctx = ssl.create_default_context(cafile=cfg.ca_file) if cfg.ca_file else ssl.create_default_context()
    try:
        with socket.create_connection((host, port), timeout=cfg.timeout) as sock:
            with ctx.wrap_socket(sock, server_hostname=host) as tls:
                cert = tls.getpeercert()
                version = tls.version() or "unknown"
    except ssl.SSLCertVerificationError as exc:
        reason = clean(exc.verify_message or str(exc), 160)
        mismatch = "hostname" in reason.lower() or "ip address mismatch" in reason.lower()
        title = "TLS certificate hostname mismatch" if mismatch else "TLS certificate does not validate"
        run.fail("certificate", _f(ep, Severity.HIGH, title, "certificate chain valid for the requested host", reason,
                 f"handshake verification failed: {reason}",
                 "Clients either reject the site or users are trained to click through warnings, enabling interception.",
                 "Install a certificate from a trusted CA covering this hostname (or configure target.ca_file for an internal staging CA)."))
        return run
    except (ssl.SSLError, OSError) as exc:
        run.add("certificate", ep, Outcome.NOT_VERIFIED, f"TLS handshake failed: {exc.__class__.__name__}")
        return run

    run.add("certificate", ep, Outcome.PASSED, "chain validates and hostname matches" + (" (custom CA file)" if cfg.ca_file else ""))
    not_after = cert.get("notAfter")
    if not_after:
        days = int((ssl.cert_time_to_seconds(not_after) - time.time()) // 86400)
        if days < NEAR_EXPIRY_DAYS:
            run.fail("expiry", _f(ep, Severity.MEDIUM if days >= 0 else Severity.HIGH, "TLS certificate near expiry", f">= {NEAR_EXPIRY_DAYS} days remaining",
                     f"{days} days remaining", f"notAfter {not_after}", "Imminent outage / warnings when the certificate expires.", "Renew and automate renewal."))
        else:
            run.add("expiry", ep, Outcome.PASSED, f"{days} days remaining")
    if version in ("TLSv1", "TLSv1.1", "SSLv3"):
        run.fail("protocol", _f(ep, Severity.MEDIUM, "Obsolete TLS protocol negotiated", "TLSv1.2 or TLSv1.3", version, f"negotiated {version} with a default client",
                 "Deprecated protocols have known weaknesses.", "Disable TLS 1.0/1.1 on the server."))
    else:
        run.add("protocol", ep, Outcome.PASSED, f"negotiated {version}")
    return run
