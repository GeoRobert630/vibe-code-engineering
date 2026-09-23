"""Set-Cookie attribute checks. Cookie *values* are never stored or reported.

Session-like cookies (name suggests session/auth/token) are held to a stricter bar
than preference cookies. SameSite is assessed, not dictated: None is acceptable for
legitimate cross-site use only together with Secure.
"""

from __future__ import annotations

import re
from dataclasses import dataclass

from ..config import Config
from ..models import CheckRun, Confidence, Finding, Outcome, Severity
from ..utils.http import Client

NAME = "cookies"
SESSION_NAME = re.compile(r"sess|sid|auth|token|jwt|login|remember|connect\.sid|csrf|xsrf|identity", re.I)
CSRF_NAME = re.compile(r"csrf|xsrf", re.I)
LONG_LIVED = 30 * 24 * 3600


@dataclass
class ParsedCookie:
    name: str
    secure: bool
    httponly: bool
    samesite: str | None
    path: str | None
    domain: str | None
    max_age: int | None
    expires: str | None
    value_length: int

    def describe(self) -> str:
        parts = [f"name={self.name}", f"value=<redacted {self.value_length} chars>"]
        parts.append("Secure" if self.secure else "no Secure")
        parts.append("HttpOnly" if self.httponly else "no HttpOnly")
        parts.append(f"SameSite={self.samesite}" if self.samesite else "no SameSite")
        if self.path:
            parts.append(f"Path={self.path}")
        if self.domain:
            parts.append(f"Domain={self.domain}")
        if self.max_age is not None:
            parts.append(f"Max-Age={self.max_age}")
        elif self.expires:
            parts.append("Expires=<set>")
        else:
            parts.append("session cookie (no expiry)")
        return "; ".join(parts)


def parse_set_cookie(header: str) -> ParsedCookie | None:
    parts = [p.strip() for p in header.split(";")]
    if not parts or "=" not in parts[0]:
        return None
    name, value = parts[0].split("=", 1)
    attrs: dict[str, str | None] = {}
    for p in parts[1:]:
        if "=" in p:
            k, v = p.split("=", 1)
            attrs[k.strip().lower()] = v.strip()
        elif p:
            attrs[p.lower()] = None
    max_age = None
    if attrs.get("max-age"):
        try:
            max_age = int(attrs["max-age"] or "")
        except ValueError:
            max_age = None
    return ParsedCookie(
        name=re.sub(r"[^A-Za-z0-9_.\-]", "?", name.strip())[:64],
        secure="secure" in attrs,
        httponly="httponly" in attrs,
        samesite=(attrs.get("samesite") or None) and str(attrs["samesite"]).capitalize(),
        path=attrs.get("path"),
        domain=attrs.get("domain"),
        max_age=max_age,
        expires=attrs.get("expires"),
        value_length=len(value.strip()),
    )


def _f(ep: str, c: ParsedCookie, sev: Severity, title: str, expected: str, actual: str, impact: str, rec: str, cwe: str, conf: Confidence = Confidence.HIGH) -> Finding:
    return Finding(
        category=NAME, severity=sev, confidence=conf, title=f"{title} ({c.name})", endpoint=ep, expected=expected, actual=actual,
        evidence=f"Cookie attributes: {c.describe()}", impact=impact, recommendation=rec,
        validation=f"Request {ep} and inspect the Set-Cookie attributes for '{c.name}' (browser devtools or curl -I).",
        cwe=cwe, owasp="A07:2021-Identification and Authentication Failures",
    )


def run(client: Client, cfg: Config) -> CheckRun:
    run = CheckRun(NAME)
    https = cfg.scheme == "https"
    seen = 0
    for path in cfg.cookie_paths:
        resp = client.request("GET", path)
        ep = f"GET {path}"
        for header in resp.header_all("set-cookie"):
            c = parse_set_cookie(header)
            if c is None:
                continue
            seen += 1
            session = bool(SESSION_NAME.search(c.name))
            label = "session/auth cookie" if session else "cookie"
            problems = 0
            if not c.secure:
                sev = Severity.MEDIUM if session else Severity.LOW
                note = "" if https else " Target is plain HTTP here; verify the flag on the HTTPS staging URL."
                run.fail("Secure", _f(ep, c, sev, "Cookie without Secure flag", "Secure", "Secure absent" + note,
                         f"The {label} can be sent over plain HTTP and intercepted.", "Set the Secure attribute (serve the app over HTTPS).", "CWE-614",
                         Confidence.HIGH if https else Confidence.MEDIUM))
                problems += 1
            if session and not c.httponly and not CSRF_NAME.search(c.name):
                run.fail("HttpOnly", _f(ep, c, Severity.MEDIUM, "Session cookie without HttpOnly", "HttpOnly", "HttpOnly absent",
                         "Any XSS can read the session cookie and hijack the session.", "Set HttpOnly on session/auth cookies.", "CWE-1004"))
                problems += 1
            if c.samesite == "None" and not c.secure:
                run.fail("SameSite", _f(ep, c, Severity.MEDIUM, "SameSite=None without Secure", "SameSite=None requires Secure", "SameSite=None, no Secure",
                         "Modern browsers reject this cookie; older ones send it cross-site over HTTP.", "Add Secure, or use SameSite=Lax if cross-site use is not needed.", "CWE-1275"))
                problems += 1
            elif session and c.samesite is None:
                run.fail("SameSite", _f(ep, c, Severity.LOW, "Session cookie without explicit SameSite", "SameSite=Lax or Strict (None only if cross-site use is required, with Secure)",
                         "SameSite absent (browser default applies, usually Lax)",
                         "Behaviour depends on browser defaults; cross-site request protection is not explicit.", "Set SameSite=Lax (or Strict) explicitly.", "CWE-1275", Confidence.MEDIUM))
                problems += 1
            elif session and c.samesite == "None":
                run.add("SameSite", ep, Outcome.PASSED, f"{c.name}: SameSite=None with Secure - acceptable only if cross-site use is intended (verify CSRF protection)")
            if c.domain and c.domain.lstrip(".").count(".") <= 1 and cfg.host.count(".") >= 2:
                run.fail("Domain", _f(ep, c, Severity.INFORMATIONAL, "Cookie scoped to parent domain", f"Domain unset (host-only, {cfg.host})", f"Domain={c.domain}",
                         "All sibling subdomains receive the cookie.", "Omit Domain unless sharing across subdomains is required.", "CWE-1275", Confidence.MEDIUM))
            if session and c.max_age is not None and c.max_age > LONG_LIVED:
                run.fail("Expiration", _f(ep, c, Severity.LOW, "Long-lived session cookie", "session cookie or Max-Age <= 30 days", f"Max-Age={c.max_age}",
                         "Stolen sessions stay valid for a long time.", "Shorten lifetime and rotate/re-authenticate.", "CWE-613", Confidence.MEDIUM))
            if problems == 0:
                run.add("attributes", ep, Outcome.PASSED, c.describe())
    if seen == 0:
        run.add("Set-Cookie", ", ".join(cfg.cookie_paths), Outcome.NOT_VERIFIED,
                "no Set-Cookie observed on configured paths (cookies set after login are not covered by this slice)")
    return run
