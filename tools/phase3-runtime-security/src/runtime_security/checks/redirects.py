"""HTTP -> HTTPS redirect behaviour. Redirects are inspected, never followed.

* HTTPS target: request http://<same host>/ (or target.http_url) and expect a
  permanent redirect to https on the same host. Also flag HTTPS pages that
  redirect to http (downgrade).
* HTTP target with target.http_url: same check (used for local mocks where HTTPS
  terminates elsewhere).
* HTTP target without http_url: HTTPS is not in use -> NOT_VERIFIED, noted.
"""

from __future__ import annotations

from urllib.parse import urlsplit

from ..config import Config
from ..models import CheckRun, Confidence, Finding, Outcome, Severity
from ..utils.http import Client
from ..utils.redaction import clean

NAME = "redirects"
REDIRECT_CODES = {301, 302, 303, 307, 308}


def _f(ep: str, sev: Severity, title: str, expected: str, actual: str, evidence: str, impact: str, rec: str, conf: Confidence = Confidence.HIGH) -> Finding:
    return Finding(
        category=NAME, severity=sev, confidence=conf, title=title, endpoint=ep, expected=expected, actual=actual, evidence=evidence,
        impact=impact, recommendation=rec, validation=f"curl -sI {ep.split(' ', 1)[1]} and confirm a 301/308 to the https:// URL on the same host.",
        cwe="CWE-319", owasp="A02:2021-Cryptographic Failures",
    )


def run(client: Client, cfg: Config) -> CheckRun:
    run = CheckRun(NAME)
    http_url = cfg.http_url
    if http_url is None and cfg.scheme == "https":
        http_url = f"http://{cfg.host}"
    if http_url is None:
        run.add("HTTP to HTTPS", cfg.base_url, Outcome.NOT_VERIFIED, "target is plain HTTP and no target.http_url configured; HTTPS redirect cannot be verified here")
    else:
        ep = f"GET {http_url.rstrip('/')}/"
        try:
            resp = client.request("GET", "/", base=http_url)
        except OSError as exc:
            run.add("HTTP to HTTPS", ep, Outcome.PASSED if cfg.scheme == "https" else Outcome.NOT_VERIFIED,
                    f"plain HTTP not reachable ({exc.__class__.__name__}); no insecure listener observed")
            resp = None
        if resp is not None:
            location = resp.header("location") or ""
            loc = urlsplit(location)
            if resp.status in REDIRECT_CODES and loc.scheme == "https":
                if loc.hostname and loc.hostname != cfg.host:
                    run.fail("HTTP to HTTPS", _f(ep, Severity.LOW, "HTTP redirect goes to a different host", f"https://{cfg.host}/...", clean(location, 120),
                             f"{resp.status} Location: {clean(location, 120)}", "Users are sent to another host; confirm it is intended.", "Redirect to the same host over HTTPS.", Confidence.MEDIUM))
                elif resp.status in (302, 303, 307):
                    run.fail("HTTP to HTTPS", _f(ep, Severity.INFORMATIONAL, "HTTP to HTTPS redirect is temporary", "301 or 308", str(resp.status),
                             f"{resp.status} Location: {clean(location, 120)}", "Temporary redirects are not cached; every first request stays on HTTP.", "Use 301/308 and HSTS.", Confidence.HIGH))
                else:
                    run.add("HTTP to HTTPS", ep, Outcome.PASSED, f"{resp.status} to https (same host)")
            elif resp.status in REDIRECT_CODES:
                run.fail("HTTP to HTTPS", _f(ep, Severity.MEDIUM, "HTTP redirect does not go to HTTPS", "redirect to https://", clean(location, 120) or "(no Location)",
                         f"{resp.status} Location: {clean(location, 120) or '(absent)'}", "Traffic stays on unencrypted HTTP.", "Redirect all HTTP requests to https://."))
            else:
                run.fail("HTTP to HTTPS", _f(ep, Severity.MEDIUM, "Content served over plain HTTP without redirect", "301/308 redirect to https://", f"status {resp.status}",
                         f"GET over http returned {resp.status} with no redirect", "Users and cookies can be exposed on unencrypted connections.",
                         "Redirect every HTTP request to HTTPS and enable HSTS."))

    if cfg.scheme == "https":
        resp = client.request("GET", cfg.paths[0])
        location = resp.header("location") or ""
        if resp.status in REDIRECT_CODES and location.lower().startswith("http://"):
            run.fail("HTTPS downgrade", _f(f"GET {cfg.paths[0]}", Severity.MEDIUM, "HTTPS page redirects to HTTP", "no redirect to http://", clean(location, 120),
                     f"{resp.status} Location: {clean(location, 120)}", "A secure request is downgraded to plaintext.", "Keep redirects on https://."))
        else:
            run.add("HTTPS downgrade", f"GET {cfg.paths[0]}", Outcome.PASSED, "no redirect to http://")
    return run
