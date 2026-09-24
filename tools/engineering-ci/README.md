# engineering-ci

Orchestration only: one GitHub Actions workflow that runs the existing **Security CI** and **Quality CI**
(accessibility and performance) tools and produces one combined result. It adds no scanner, rule, finding, severity, gate or SARIF format of its own.

```
Security CI + Quality CI (accessibility) + Quality CI (performance)
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
Performance  job "performance"  quality-ci-perf perf (only with a target) -> quality-ci-perf sarif -> quality-ci-perf gate
                                                                                   => performance-reports/
    ↓
Collect reports              separate artifacts and separate SARIF categories
    ↓
Combined result  job "engineering" (needs all three, always runs) -> engineering-reports/engineering-summary.json
                             fails when any gate fails (or a job never reached its gate)
```

Security, Accessibility and Performance run as independent jobs, so a failure in one never prevents the others from
producing their reports. Each keeps its own gate policy and finding namespace (`P2-*`/`RT-*`/`AI-*`, `Q-A11Y-*`,
`Q-PERF-*`); Engineering CI only reads each gate's exit code and `Outcome:` line.

## Pinned tooling

All three jobs check out the public `GeoRobert630/vibe-code-engineering` at exact reviewed commits, never a branch, so a
toolkit change cannot alter a project's CI result (or run unreviewed code) until the SHAs are deliberately updated:

| Job | Commit | Tag |
|---|---|---|
| security | `bd71c46f1584063254dfc0b668fcff2ba0ea26d0` | `security-baseline-v1` |
| quality | `fa816aad46fb46f3dade2173b53da5d920177e21` | `quality-ci-v1.1` |
| performance | `c6b82c0739f0342a3ac6b2952532e86343985e1f` | `quality-ci-v1.2` (hosted-calibrated `MIN_BENCHMARK`) |

## Configuration

Only the non-secret repository variables already used by the Security CI and Quality CI examples:
`RUNTIME_TARGET_URL`, `RUNTIME_ENVIRONMENT`, `RUNTIME_AUTHORIZED_BY`, `ENABLE_ZAP_BASELINE`, `SECURITY_GATE_POLICY`,
`QUALITY_TARGET_URL`, `QUALITY_ENVIRONMENT`, `QUALITY_AUTHORIZED_BY`, `QUALITY_PAGES`, `QUALITY_GATE_POLICY`,
`PERF_PROFILE`, `PERF_GATE_POLICY` (the performance job measures the same `QUALITY_*` target/pages). No secrets, tokens, passwords or cookies. Permissions: `contents: read`, `actions: read`, `security-events: write`
(SARIF upload) - the same as the existing workflows.

As a reusable workflow (`workflow_call`) it accepts `project_path` (subdirectory to check), `quality_site_dir`
(static directory served on 127.0.0.1 inside the job for the accessibility and performance scans), `quality_pages`, `artifact_suffix`
(unique artifact names / SARIF categories when called several times in one run) and `enforce` (default `true`;
push, pull_request and workflow_dispatch runs always enforce).

## Statuses

| | Status values | Gate result |
|---|---|---|
| Security | `PASS`, `FAIL` (policy violation), `INCOMPLETE` (gate fails only because a scan was incomplete/refused, or could not be evaluated) | `PASS` / `FAIL` = `security-ci gate` exit code |
| Quality (accessibility) | `PASS`, `FAIL`, `INCOMPLETE`, `NOT CONFIGURED` (the `Outcome:` of `quality-ci gate`) | `PASS` / `FAIL` = `quality-ci gate` exit code |
| Performance | `PASS`, `FAIL`, `INCOMPLETE`, `NOT CONFIGURED` (the `Outcome:` of `quality-ci-perf gate`; policy `PERF_GATE_POLICY`, default `release`) | `PASS` / `FAIL` = `quality-ci-perf gate` exit code |

A job that never reached its gate (tool error, cancellation) is `INCOMPLETE` with gate `FAIL`, never a pass.
**overall** is `PASS` only when all three gates pass. `NOT CONFIGURED` keeps each tool's own gate semantics (the gate
passes unless `--require-configured`), so an unconfigured quality target does not fail Engineering CI but is reported
as `NOT CONFIGURED`, never as a pass of the check. The summary and step summary list
`Security: …`, `Accessibility: …`, `Performance: …` and `Final enforcement: PASS|FAIL` (marked "not enforced" when
`enforce: false`). The performance timing reliability (HIGH / LOW) is copied from the gate output.

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
  "performance": {"status": "PASS", "gate_result": "PASS", "gate_exit_code": 0, "job_result": "success",
               "artifact": "performance-reports", "report_path": "performance-reports/performance-report.json",
               "sarif_path": "performance-reports/performance.sarif", "timing_reliability": "HIGH"},
  "verification": {"authentication": "NOT VERIFIED", "session": "NOT VERIFIED", "authorization": "NOT VERIFIED"},
  "overall": "FAIL",
  "enforced": true,
  "notice": "..."
}
```

`verification` is copied from the `security-ci gate` output (`NOT VERIFIED` when not reported). `runtime` is
`NOT RUN` (no `RUNTIME_TARGET_URL`), `INCOMPLETE` (runtime-security refused/incomplete) or `EXECUTED`. The summary
contains no findings; findings stay in each tool's own report and SARIF.

## SARIF upload categories

Each tool stamps its SARIF with a fixed `runs[].automationDetails.id` (`vibe-code-engineering/phase2/`,
`vibe-code-engineering/phase3/`, `vibe-code-engineering/quality/accessibility/`,
`vibe-code-engineering/quality/performance/`). GitHub's `upload-sarif` keeps an existing `automationDetails.id` and
does not replace it with its `category` input, so without further handling every upload of the same tool for the same
commit (for example several `artifact_suffix` cases) would share one code-scanning category and replace the previous
analysis.

The workflow therefore uploads a **GitHub-upload-specific copy**: right before each upload, the step
"Prepare … SARIF for upload" writes `sarif-upload/<file>.sarif` with every run's `automationDetails.id` set to that
upload's category plus a trailing `/` (the same form `upload-sarif` derives from `category`). Nothing else in the file
changes - results, finding IDs (`P2-*`/`RT-*`/`AI-*`, `Q-A11Y-*`, `Q-PERF-*`), rules and properties are identical, and
the quality SARIF still has no `security-severity`. The report artifacts (`security-reports/`, `quality-reports/`,
`performance-reports/`) keep the tools' original SARIF unchanged. If the SARIF was not created, the copy is not made
and the upload is skipped.

| Gate | Uploaded file | Category / `automationDetails.id` |
|---|---|---|
| Security | `sarif-upload/security.sarif` | `vibe-code-engineering-security<artifact_suffix>` / `…<artifact_suffix>/` |
| Accessibility | `sarif-upload/accessibility.sarif` | `vibe-code-engineering-quality-accessibility<artifact_suffix>` / `…<artifact_suffix>/` |
| Performance | `sarif-upload/performance.sarif` | `vibe-code-engineering-quality-performance<artifact_suffix>` / `…<artifact_suffix>/` |

The category is stable for the same gate and suffix and differs between gates and between suffixes, so each analysis
of a commit keeps its own code-scanning category. Use a distinct `artifact_suffix` for every call of the reusable
workflow within one run.

## What a combined PASS means

- Security findings (`P2-*`, `RT-*`, `RT-ZAP-*`, `RT-AUTH-*`, `RT-SESSION-*`, `AI-*`), accessibility findings
  (`Q-A11Y-*`) and performance findings (`Q-PERF-*`) remain separate: separate reports, artifacts, SARIF files and
  SARIF categories, each judged by its own gate policy.
- A combined PASS does **not** mean all verification areas are complete. Authentication, Session and Authorization
  remain **NOT VERIFIED** unless independently verified; without `RUNTIME_TARGET_URL` Phase 3 does not run.
  NOT VERIFIED / NOT CONFIGURED are coverage statuses and are never turned into findings or into a runtime PASS.
- The ZAP baseline remains optional and passive (`zap-baseline.py` only, image never pulled, no credentials).
- A clean accessibility scan is not proof of full WCAG compliance; a passing performance gate is lab data, not proof
  of real-user performance.

## Tests

`python -m pytest tools/engineering-ci/tests` checks the workflow's policy (triggers, permissions, pins, no
credentials, ZAP/browser settings, separate artifacts and SARIF categories, unchanged security/accessibility job
  definitions) and executes the workflow's own
result-classification and combination scripts against stubbed gate results, including the three-gate
(security x accessibility x performance) result matrix, incomplete performance runs and `enforce: false`.

External validation of the three-gate workflow uses `GeoRobert630/vibe-engineering-test`, which runs an unchanged
copy of this workflow per case directory and asserts the combined result. The three-gate cases are: all gates PASS;
security failure; accessibility failure; performance failure (the intentionally slow Quality CI performance fixture);
and security + accessibility + performance failure. In every case Authentication, Session and Authorization must stay
NOT VERIFIED. Its workflow copy is this three-gate version at `62461a6` (`engineering-ci-v1.1`), checked byte-for-byte
against the toolkit by the acceptance run.
