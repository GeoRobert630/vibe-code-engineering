# phase3-runtime-security (defensive slice)

Read-only runtime checks against a **local or explicitly authorized staging** application.
This slice verifies what static scanning (Phase 2) cannot see: the headers, cookies, CORS
responses, redirects, TLS certificate and error bodies the running application actually returns.

It is integrated into `skills/06-security/17-security-audit/SKILL.md` as Layer 3 (Phase 3 Runtime Security).

Checks in this slice:

| Check | What is verified |
|---|---|
| `headers` | HSTS (HTTPS only), CSP (HTML only; noted as defence in depth, not an XSS fix), X-Content-Type-Options, framing protection (CSP `frame-ancestors` preferred, X-Frame-Options accepted), Referrer-Policy, Permissions-Policy (informational), Server/X-Powered-By version disclosure |
| `cookies` | Secure, HttpOnly (session-like cookies), SameSite (None requires Secure; None+Secure accepted as intentional cross-site use), Domain scope, Max-Age of session cookies. Values are never recorded |
| `cors` | untrusted origin reflected, wildcard, credentials with wildcard/reflection, `null` origin, preflight approval for PUT, configured trusted origin still works |
| `redirects` | plain HTTP redirects (301/308) to HTTPS on the same host; HTTPS pages do not redirect to HTTP. Redirects are never followed |
| `tls` | chain validates (system store or `ca_file`), hostname matches, expiry, negotiated protocol >= TLS 1.2. One normal handshake |
| `error_leakage` | stack traces (Python, Node, Java/.NET, PHP, Ruby), framework debug pages, SQL/DB errors, filesystem/source paths, secret-like values in error bodies |

**Optional passive ZAP baseline** (`zap_baseline.enabled`, off by default): runs `zap-baseline.py` from the
locally present `zaproxy/zap-stable` Docker image after the safety gate passes (`--pull=never`, only the
`<output>/zap` directory mounted, no environment variables or credentials passed, output redacted). Alerts become
`RT-ZAP-*` findings or are correlated with existing findings; see the skill's section 6.7. Passive and
unauthenticated only - not proof of security. `zap-full-scan.py` / `zap-api-scan.py` are refused.

## Runtime coverage matrix

| Area | Runtime status |
|---|---|
| Headers | checked (3A): PASS / FAIL / NOT VERIFIED / NOT APPLICABLE as reported |
| Cookies | checked (3A), unauthenticated pages only |
| CORS | checked (3A) |
| HTTP to HTTPS | checked (3A); NOT VERIFIED without HTTPS / `http_url` |
| TLS | checked (3A); NOT VERIFIED on plain-HTTP targets |
| Error leakage | checked (3A), fixed probe set; duplicate disclosures correlated |
| Authentication | NOT VERIFIED (3B plumbing only) |
| Session | NOT VERIFIED (3B plumbing only) |
| Authorization / IDOR / BOLA | NOT VERIFIED (3C status only: no actor credentials, no authorization requests, no ID enumeration) |
| Tenant isolation | NOT VERIFIED (3C status only) |

The JSON report carries `auth_areas` (Authentication, Session) and `authorization` (status, reason, scope,
`runtime_checks_executed: false`, `credentials_read: false`, and `subareas` `authorization`, `idor_bola`,
`tenant_isolation`, each always NOT VERIFIED with no findings); the Markdown report has `## Authorization` (with a
sub-area table) and `## Authorization Findings`. `RT-AUTHZ-*`, `RT-IDOR-*` and `RT-TENANT-*` are reserved for future
results; none are generated. Readers treat a report without `subareas` as all three NOT VERIFIED.
NOT VERIFIED is a coverage status, not a security verdict.

**Imported verification results** (optional, `verification_results: {path: results.json}`). A separate, authorized
test suite can supply Authentication, Session, Authorization, IDOR/BOLA and Tenant-isolation results as a JSON file
([schema 1.0](schemas/verification-results.schema.json)).
- **What this tool does.** It only reads and validates the file. It sends no request, never receives credentials and
  reports `credentials_read: false`.
- **Validation.**
  - Credential-shaped field names are rejected; values are redacted.
  - `requests_count` must be 0-20 per area, and 20 at most in total.
  - Finding IDs must stay within each area's namespace (`RT-AUTH`, `RT-SESSION`, `RT-AUTHZ`, `RT-IDOR`, `RT-TENANT`).
  - Ambiguous evidence becomes INCOMPLETE; a PASS needs executed checks, evidence and no findings.
- **In the report.** Valid results fill `auth_areas`, `authorization` and its sub-areas, with statuses, request counts,
  limitations and findings. A rejected file makes the configured areas INCOMPLETE (exit 3). Without the option,
  nothing changes: `verification_import` is NOT CONFIGURED and every area stays NOT VERIFIED.
- **More detail.** See section 17 of the design document.

**Out of scope:** CSRF, rate limiting, file access, webhooks, and business logic.
In v1.3, bounded runtime verification for authentication, session, authorization, IDOR/BOLA,
and tenant isolation is implemented natively under `runtime_verification` for authorized local targets
(see [docs/V1.3-AUTH-SESSION-AUTHORIZATION-DESIGN.md](../../docs/V1.3-AUTH-SESSION-AUTHORIZATION-DESIGN.md)).
For external targets or applications tested via separate test suites, the v1.2 imported-results path remains supported.

## Install / run

```bash
cd tools/phase3-runtime-security
python -m pip install -e ".[dev]"
runtime-security --config examples/runtime-security.yaml --output reports
# or without installing
PYTHONPATH=src python -m runtime_security.cli --config examples/runtime-security.yaml
```

Options: `--config` (required), `--output DIR` (default `./reports`), `--format json|markdown|both`, `--verbose`.

Before any request the tool prints the safety gate:

```
=== Safety gate ===
Target: http://127.0.0.1:3000
Environment: local
Production flag: false
Allowed: local target
```

## Safety model

- **Production refused, no override in this slice**: `production: true`, an environment named
  `prod`/`production`/`live`, or a host label `prod`/`production`/`live` stops the run before any request.
  `production` must be set explicitly.
- **Local by default**: loopback, private IPs, `localhost`, `*.localhost`, `*.local`, `*.test`, `*.internal`.
  Any other host needs environment `staging`/`test`/`qa`/`dev`/... **and** `authorized: true` **and**
  `authorized_by` (who approved the test).
- **Single target host**: all requests go to the configured host. Config paths must be relative; `http_url`
  must be on the same host. CORS test origins are only sent as `Origin` header values (default
  `https://phase3-untrusted-origin.invalid`, a reserved TLD) and are never contacted.
- **Read-only requests**: GET, HEAD, OPTIONS; one POST whose body is deliberately *invalid* JSON (the client
  refuses to POST a body that parses as JSON); one unsupported method token (`PHASE3PROBE`). No PUT/PATCH/DELETE.
  This describes the tool's own HTTP client; the optional ZAP baseline spider (if enabled) sends its own passive
  crawl requests to the same target.
- **No exploitation, no brute force, no uploads, no fuzzing**: a fixed, small probe set.
- **Bounded**: hard request budget (default 60, max 200), per-request timeout, delay between requests,
  256 KiB response cap, redirects never followed, TLS verification always on.
- **No secrets in reports**: cookie values, `Cookie`/`Set-Cookie`/`Authorization`/API-key headers are never
  written; evidence snippets pass through redaction (URL credentials, `key=value` secrets, tokens, JWTs, keys).
  Markdown escapes target-controlled text.
- No credentials are needed or read in this slice.

## Finding model

IDs `RT-<CATEGORY>-NNN` (`RT-HEADERS-001`, `RT-COOKIE-001`, `RT-CORS-001`, `RT-REDIRECT-001`, `RT-TLS-001`,
`RT-ERROR-001`; optional ZAP baseline: `RT-ZAP-001`; reserved for Phase 3B: `RT-AUTH-*`, `RT-SESSION-*`; reserved for
3C imported results: `RT-AUTHZ-*`; reserved, none generated: `RT-IDOR-*`, `RT-TENANT-*`). Fields: `id, category, severity, confidence, title, endpoint, expected, actual, evidence,
impact, recommendation, validation, status` plus `cwe, owasp, notes, source` and `blocking` in JSON.
Severity/confidence/status vocabulary matches Phase 2.

Every assertion is also recorded as a check result with outcome `PASSED`, `FAILED`, `NOT_VERIFIED` or
`NOT_APPLICABLE` (e.g. HSTS on a plain-HTTP target is NOT_VERIFIED; CSP on a JSON response is NOT_APPLICABLE).

## Reports

`runtime-security-report.json` and `runtime-security-report.md` with: Executive Summary, Target, Environment,
Checks Run, Passed, Failed, Not Verified, Findings, Limitations, Summary.

## Exit codes

| Code | Meaning |
|---|---|
| 2 | blocking findings (CRITICAL, or HIGH with MEDIUM/HIGH confidence) |
| 3 | refused by the safety gate, config error, usage error, or a check could not complete (unreachable, budget exhausted) |
| 1 | non-blocking findings |
| 0 | no findings above INFORMATIONAL |

## CI / SARIF

`tools/security-ci/` converts `runtime-security-report.json` (including `RT-ZAP-*`, and correlations so confirmed ZAP
alerts are not duplicated) to SARIF 2.1.0 and applies an explicit CI gate. This tool's exit codes are unchanged.
Authentication, Session and Authorization remain NOT VERIFIED in SARIF; the ZAP baseline remains passive.

## Tests

```bash
python -m pytest
```

`tests/mock_app.py` is a local mock application (binds 127.0.0.1 only) with `safe` and `unsafe` modes, a
plain-HTTP `redirect` role and optional TLS (tests generate throwaway certificates with `openssl`; TLS tests
skip if `openssl` is missing). Run it manually:

```bash
python tests/mock_app.py --mode unsafe --port 3001
```

## Limitations

- Unauthenticated requests to configured paths only: cookies set after login and headers on authenticated
  pages are not observed.
- A PASSED result covers the requests actually sent; other routes/methods/states may differ.
- TLS: no cipher/protocol enumeration, no revocation checks.
- Error-leakage probes are a small fixed set.
- Staging results may differ from production (CDN, proxy and platform headers).
- CORS results describe browser read permissions only; CORS is not authorization.
