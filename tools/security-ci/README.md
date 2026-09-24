# security-ci

SARIF 2.1.0 export and an explicit CI gate for the existing security reports. Standard library only.
It **reads** reports; it never runs scanners, never changes their exit codes and never changes a
finding's verification status.

```
CI pipeline
    ↓
Phase 2 (static)                      phase2-scan              -> security-report.json/.md
    ↓
Phase 3A (runtime, safe target only)  runtime-security         -> runtime-security-report.json/.md
    ↓
optional ZAP baseline (passive)       zap_baseline.enabled     -> RT-ZAP-* in the runtime report
    ↓
JSON / Markdown                       (unchanged)
    ↓
SARIF                                 security-ci sarif        -> security.sarif
    ↓
CI gate                               security-ci gate         -> exit 0 pass / 1 fail / 3 error
```

- Authentication and Session remain **NOT VERIFIED** (Phase 3B is plumbing only) and Authorization / IDOR / BOLA /
  tenant isolation remains **NOT VERIFIED** (Phase 3C is status only); SARIF and the gate copy these statuses into
  run properties, they do not change them and never turn NOT VERIFIED into a finding.
- **Imported verification results.** A Phase 3 report can carry results that a separate suite produced and Phase 3
  validated (see the Phase 3 README).
  - Their findings (`RT-AUTH/SESSION/AUTHZ/IDOR/TENANT-*`) are exported as ordinary runtime results with
    `origin: imported-verification`, using the unchanged severity mapping.
  - The Phase 3 run's properties add `verificationSubareas` and `importedVerification` (status, requestsCount).
  - A PASS or EXECUTED without `runtime_checks_executed: true` is read as NOT VERIFIED.
  - An invalid `requests_count` (not 0-20) or an INCOMPLETE import is INCOMPLETE and fails the gate unless
    `--allow-incomplete` is given.
- A clean SARIF report or a passing gate is **not** proof of security.
- The ZAP baseline remains **passive** (`zap-baseline.py` only).

## Usage

```bash
cd tools/security-ci && python -m pip install -e ".[dev]"

security-ci sarif --phase2 reports/security-report.json \
                  --phase3 runtime/runtime-security-report.json \
                  [--ai ai-findings.json] [--runtime-anchor path/in/repo] \
                  --sarif security.sarif

security-ci gate  --phase2 reports/security-report.json [--phase3 ...] [--ai ...] \
                  [--fail-on release|critical|high|medium|low] [--allow-incomplete] [--sarif security.sarif]
```

Without installing: `PYTHONPATH=src python -m security_ci.cli ...`.

## SARIF mapping

| Source | IDs | SARIF run (`tool.driver.name`) | ruleId |
|---|---|---|---|
| Phase 2 | `P2-*` | `phase2-security-scanner` | the Phase 2 `rule_id` |
| Phase 3 | `RT-HEADERS/COOKIE/CORS/REDIRECT/TLS/ERROR-*`, `RT-AUTH-*`, `RT-SESSION-*` | `phase3-runtime-security` | `RT-<CATEGORY>/<title-slug>` |
| ZAP baseline | `RT-ZAP-*` (source `OWASP ZAP`) | `phase3-runtime-security` | `zap/<ZAP alert id>` |
| Authorization (reserved, imported only) | `RT-AUTHZ-*` | `phase3-runtime-security` | `RT-AUTHZ/<title-slug>`; keeps actor labels (A/B only), resource label, evidence count |
| IDOR/BOLA, tenant isolation (reserved, none generated) | `RT-IDOR-*`, `RT-TENANT-*` | `phase3-runtime-security` | `RT-IDOR/<title-slug>`, `RT-TENANT/<title-slug>`; accepted if present, never synthesized |
| AI review | `AI-*` | `ai-code-review` | `ai/<category>` |

Each result keeps: finding ID (`properties.findingId`, `partialFingerprints`), title, description, severity,
confidence, status, `blocking`, source, file/line/column (repository-relative only), URL (query values
removed), redacted evidence, CWE, and the original ZAP alert ID (`properties.zapAlertId`).

Severity (existing five-level model, never promoted or demoted):

| Severity | SARIF `level` | `security-severity` |
|---|---|---|
| CRITICAL | error | 9.5 |
| HIGH | error | 8.0 |
| MEDIUM | warning | 5.5 |
| LOW | note | 3.0 |
| INFORMATIONAL | note | 0.0 |

`properties.severity` always carries the original value, so INFORMATIONAL and LOW stay distinguishable.

Deduplication (recorded under the run's `properties.deduplicated`):
- an `RT-ZAP-*` finding whose ZAP alert is listed in the runtime report's `correlations` as *confirming* a
  Phase 3A finding is not emitted; the Phase 3A result gets `properties.correlatedZapAlerts`;
- an AI finding with `"duplicate_of": "<P2/RT id>"` is not emitted; the target result gets
  `properties.crossReferences`.

BASELINED / IGNORED findings are emitted with an external `suppressions` entry (not dropped).
Runtime findings have no source file; they carry the endpoint as a logical location. Pass
`--runtime-anchor <repo file>` if your code-scanning platform requires a physical location.

Redaction: every string is re-redacted (tokens, JWTs, keys, `Bearer`/`Basic` values, `password=`/`session=`/
`cookie=`-style values, URL credentials, query-string values, long token-like strings) before it is written,
independent of the upstream redaction.

## AI review findings input (optional)

```json
{"findings": [
  {"id": "AI-01", "title": "...", "severity": "HIGH", "confidence": "HIGH", "category": "authorization",
   "file": "src/api/users.ts", "line": 42, "description": "...", "recommendation": "...", "cwe": "CWE-639",
   "status": "OPEN", "cross_references": ["RT-CORS-001"], "duplicate_of": null}
]}
```

## CI gate policy

| `--fail-on` | Fails when |
|---|---|
| `release` (default) | any finding the source report marks `blocking` (active CRITICAL, or active HIGH with MEDIUM/HIGH confidence) - the project's release semantics |
| `critical` | any active CRITICAL |
| `high` | any active CRITICAL or HIGH |
| `medium` | also active MEDIUM |
| `low` | also active LOW (explicit opt-in; LOW is review-only otherwise) |

Active = `OPEN` or `REQUIRES_REVIEW`. BASELINED, IGNORED and INFORMATIONAL never fail the gate. An
incomplete scan (Phase 2 tool failure, Phase 3 check error, safety-gate refusal, ZAP error) fails the gate unless
`--allow-incomplete` is given. Gate exit codes: `0` pass, `1` policy violation, `3` input/usage error. The
scanners' own exit codes are unchanged.

## CI safety

The example workflow (`examples/github-actions-security-ci.yml`) keeps the existing guarantees:
production is never targeted (generated config has `production: false`; the safety gate still refuses
production-looking hosts/environments), runtime checks are skipped visibly when no target is configured, the
ZAP image is never pulled (`--pull=never`; unavailable on GitHub-hosted runners unless pre-provisioned), no
credentials exist in the workflow and none are passed to ZAP, runtime requests stay bounded by the Phase 3
limits, and reports are redacted before they are written. Configuration uses repository variables, not secrets.

## Validation

SARIF output is checked in the test suite against the structural requirements of SARIF 2.1.0 used here
(version, runs, tool.driver, unique rule ids, results referencing known rules, valid levels, relative artifact
URIs, regions >= 1). Full JSON-Schema validation is not bundled (no network download of the schema).
