"""CORS behaviour with controlled origins.

The untrusted origin defaults to an ``.invalid`` domain (RFC 2606): it is only sent as
an ``Origin`` header value, never contacted. CORS is a browser read-permission
mechanism, not authorization - a correct CORS policy does not protect an endpoint
from direct (non-browser) requests.
"""

from __future__ import annotations

from ..config import Config
from ..models import CheckRun, Confidence, Finding, Outcome, Severity
from ..utils.http import Client
from ..utils.redaction import safe_header_value

NAME = "cors"
NOTE = "CORS controls which browser origins may read responses; it is not authorization."


def _f(ep: str, sev: Severity, title: str, expected: str, actual: str, evidence: str, impact: str, conf: Confidence = Confidence.HIGH) -> Finding:
    return Finding(
        category=NAME, severity=sev, confidence=conf, title=title, endpoint=ep, expected=expected, actual=actual, evidence=evidence,
        impact=impact, recommendation="Allow only an explicit list of trusted origins; never reflect arbitrary Origin values, and never combine credentials with a wildcard/reflected origin.",
        validation=f"curl -si -H 'Origin: https://untrusted.invalid' <target>{ep.split(' ', 1)[1]} and confirm no Access-Control-Allow-Origin is returned for it.",
        cwe="CWE-942", owasp="A05:2021-Security Misconfiguration", notes=[NOTE],
    )


def _acao(resp) -> tuple[str | None, bool]:
    acao = resp.header("access-control-allow-origin")
    creds = (resp.header("access-control-allow-credentials") or "").strip().lower() == "true"
    return (acao.strip() if acao else None), creds


def run(client: Client, cfg: Config) -> CheckRun:
    run = CheckRun(NAME)
    evil = cfg.untrusted_origin
    for path in cfg.cors_paths:
        # 1. simple request from an untrusted origin
        resp = client.request("GET", path, headers={"Origin": evil})
        ep = f"GET {path}"
        acao, creds = _acao(resp)
        ev = f"Origin: {evil} -> Access-Control-Allow-Origin: {safe_header_value('acao', acao or '(absent)')}; Access-Control-Allow-Credentials: {'true' if creds else '(absent/false)'}"
        if acao == evil:
            run.fail("untrusted origin", _f(ep, Severity.HIGH if creds else Severity.MEDIUM,
                     "CORS reflects arbitrary Origin" + (" with credentials" if creds else ""), "no Access-Control-Allow-Origin for an untrusted origin",
                     f"origin reflected{', credentials allowed' if creds else ''}", ev,
                     "Any website can read authenticated responses of logged-in users." if creds else "Any website can read responses from this endpoint in a browser."))
        elif acao == "*":
            if creds:
                run.fail("wildcard", _f(ep, Severity.MEDIUM, "CORS wildcard combined with Allow-Credentials", "no credentials with '*'", "'*' + credentials", ev,
                         "Browsers reject this combination, but it indicates a policy mistake likely to become reflection."))
            else:
                run.fail("wildcard", _f(ep, Severity.LOW, "CORS allows any origin (wildcard)", "explicit allowlist, or '*' only for truly public, unauthenticated data", "'*'", ev,
                         "Any site can read responses; acceptable only for public data.", Confidence.MEDIUM))
        elif acao:
            run.add("untrusted origin", ep, Outcome.PASSED, f"untrusted origin not allowed (ACAO is a fixed value: {safe_header_value('acao', acao)})")
        else:
            run.add("untrusted origin", ep, Outcome.PASSED, "no Access-Control-Allow-Origin for untrusted origin")

        # 2. 'null' origin (sandboxed iframes, file://)
        resp = client.request("GET", path, headers={"Origin": "null"})
        acao, creds = _acao(resp)
        if acao == "null":
            run.fail("null origin", _f(ep, Severity.HIGH if creds else Severity.MEDIUM, "CORS allows the 'null' origin", "'null' origin rejected", "Access-Control-Allow-Origin: null" + (" + credentials" if creds else ""),
                     f"Origin: null -> Access-Control-Allow-Origin: null; credentials: {creds}", "Sandboxed iframes on any site send Origin: null and can read responses."))
        else:
            run.add("null origin", ep, Outcome.PASSED, "'null' origin not allowed")

        # 3. preflight from the untrusted origin
        resp = client.request("OPTIONS", path, headers={"Origin": evil, "Access-Control-Request-Method": "PUT", "Access-Control-Request-Headers": "content-type"})
        pep = f"OPTIONS {path}"
        acao, creds = _acao(resp)
        methods = (resp.header("access-control-allow-methods") or "").upper()
        if acao in (evil, "*") and ("PUT" in methods or "*" in methods):
            run.fail("preflight", _f(pep, Severity.MEDIUM if not creds else Severity.HIGH, "CORS preflight approves untrusted origin for state-changing method",
                     "preflight rejected for untrusted origin", f"ACAO {acao}; methods {methods or '(absent)'}",
                     f"Preflight Origin: {evil}, method PUT -> status {resp.status}, ACAO {acao}, Allow-Methods {safe_header_value('m', methods)}",
                     "Untrusted sites can send cross-origin PUT requests with custom headers from users' browsers."))
        else:
            run.add("preflight", pep, Outcome.PASSED, f"untrusted preflight not approved (status {resp.status})")

        # 4. configured trusted origin is accepted (functional sanity check, informational)
        for origin in cfg.allowed_origins[:1]:
            resp = client.request("GET", path, headers={"Origin": origin})
            acao, _ = _acao(resp)
            if acao in (origin, "*"):
                run.add("trusted origin", ep, Outcome.PASSED, f"configured origin {origin} allowed")
            else:
                run.add("trusted origin", ep, Outcome.NOT_VERIFIED, f"configured origin {origin} not allowed on this path (may be intended)")
    return run
