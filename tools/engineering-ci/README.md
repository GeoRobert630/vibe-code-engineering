# engineering-ci

Orchestration only: one GitHub Actions workflow that runs the existing **Security CI** and **Quality CI** tools and
produces one combined result. It adds no scanner, rule, finding, severity, gate or SARIF format of its own.

```
Security CI + Quality CI
        ↓
  Engineering CI
```

```
Engineering CI  (examples/github-actions-engineering-ci.yml)
    ↓
Security CI  job "security"  phase2-scan -> runtime-security (only with RUNTIME_TARGET_URL; optional passive ZAP)
                             -> security-ci sarif -> security-ci gate            => security-reports/
    ↓
Quality CI   job "quality"   quality-ci a11y (only with a target) -> quality-ci sarif -> quality-ci gate
                                                                                   => quality-reports/
    ↓
Collect reports              separate artifacts and separate SARIF categories
    ↓
Combined result  job "engineering" (needs both, always runs) -> engineering-reports/engineering-summary.json
                             fails when either gate fails (or a job never reached its gate)
```

Security and Quality run as independent jobs, so a failure in one never prevents the other from producing its report.

## Pinned tooling

Both jobs check out the public `GeoRobert630/vibe-code-engineering` at exact reviewed commits, never a branch, so a
toolkit change cannot alter a project's CI result (or run unreviewed code) until the SHAs are deliberately updated:

| Job | Commit | Tag |
|---|---|---|
| security | `bd71c46f1584063254dfc0b668fcff2ba0ea26d0` | `security-baseline-v1` |
| quality | `fa816aad46fb46f3dade2173b53da5d920177e21` | `quality-ci-v1.1` |

## Configuration

Only the non-secret repository variables already used by the Security CI and Quality CI examples:
`RUNTIME_TARGET_URL`, `RUNTIME_ENVIRONMENT`, `RUNTIME_AUTHORIZED_BY`, `ENABLE_ZAP_BASELINE`, `SECURITY_GATE_POLICY`,
`QUALITY_TARGET_URL`, `QUALITY_ENVIRONMENT`, `QUALITY_AUTHORIZED_BY`, `QUALITY_PAGES`, `QUALITY_GATE_POLICY`.
No secrets, tokens, passwords or cookies. Permissions: `contents: read`, `actions: read`, `security-events: write`
(SARIF upload) - the same as the existing workflows.

As a reusable workflow (`workflow_call`) it accepts `project_path` (subdirectory to check), `quality_site_dir`
(static directory served on 127.0.0.1 inside the job for the accessibility scan), `quality_pages`, `artifact_suffix`
(unique artifact names / SARIF categories when called several times in one run) and `enforce` (default `true`;
push, pull_request and workflow_dispatch runs always enforce).

## Statuses

| | Status values | Gate result |
|---|---|---|
| Security | `PASS`, `FAIL` (policy violation), `INCOMPLETE` (gate fails only because a scan was incomplete/refused, or could not be evaluated) | `PASS` / `FAIL` = `security-ci gate` exit code |
| Quality | `PASS`, `FAIL`, `INCOMPLETE`, `NOT CONFIGURED` (the `Outcome:` of `quality-ci gate`) | `PASS` / `FAIL` = `quality-ci gate` exit code |

A job that never reached its gate (tool error, cancellation) is `INCOMPLETE` with gate `FAIL`, never a pass.
**overall** is `PASS` only when both gates pass.

## engineering-summary.json

```json
{
  "schema_version": "1.0",
  "security": {"status": "FAIL", "gate_result": "FAIL", "gate_exit_code": 1, "job_result": "success",
               "artifact": "security-reports", "report_path": "security-reports/phase2/security-report.json",
               "sarif_path": "security-reports/security.sarif", "runtime": "NOT RUN"},
  "quality":  {"status": "PASS", "gate_result": "PASS", "gate_exit_code": 0, "job_result": "success",
               "artifact": "quality-reports", "report_path": "quality-reports/accessibility-report.json",
               "sarif_path": "quality-reports/accessibility.sarif"},
  "verification": {"authentication": "NOT VERIFIED", "session": "NOT VERIFIED", "authorization": "NOT VERIFIED"},
  "overall": "FAIL",
  "notice": "..."
}
```

`verification` is copied from the `security-ci gate` output (`NOT VERIFIED` when not reported). `runtime` is
`NOT RUN` (no `RUNTIME_TARGET_URL`), `INCOMPLETE` (runtime-security refused/incomplete) or `EXECUTED`. The summary
contains no findings; findings stay in each tool's own report and SARIF.

## What a combined PASS means

- Security findings (`P2-*`, `RT-*`, `RT-ZAP-*`, `RT-AUTH-*`, `RT-SESSION-*`, `AI-*`) and Quality findings (`Q-A11Y-*`)
  remain separate: separate reports, artifacts, SARIF files and SARIF categories.
- A combined PASS does **not** mean all verification areas are complete. Authentication, Session and Authorization
  remain **NOT VERIFIED** unless independently verified; without `RUNTIME_TARGET_URL` Phase 3 does not run.
  NOT VERIFIED / NOT CONFIGURED are coverage statuses and are never turned into findings or into a runtime PASS.
- The ZAP baseline remains optional and passive (`zap-baseline.py` only, image never pulled, no credentials).
- A clean accessibility scan is not proof of full WCAG compliance.

## Tests

`python -m pytest tools/engineering-ci/tests` checks the workflow's policy (triggers, permissions, pins, no
credentials, ZAP/browser settings, separate artifacts and SARIF categories) and executes the workflow's own
result-classification and combination scripts against stubbed gate results. The external repository
`GeoRobert630/vibe-engineering-test` runs the unchanged workflow against four cases (clean, security failure,
quality failure, both).
