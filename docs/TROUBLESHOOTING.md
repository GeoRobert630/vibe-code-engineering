# Troubleshooting

Problems that were actually hit while building and validating the system, and what they mean.

## A gate says INCOMPLETE

INCOMPLETE always counts as a gate FAIL, so the final Engineering result fails (when enforced). It means the scan did
not produce a complete result - never that the project passed. Look at the gate output in the job log and at the
report artifact of that gate. Causes seen in practice:

| Cause | Where it shows |
|---|---|
| Runtime or quality target refused by the safety gate: production flag, `prod`/`production`/`live` environment or host, or a non-local host without `RUNTIME_AUTHORIZED_BY` / `QUALITY_AUTHORIZED_BY` | "Safety gate refused the target" in the report; nothing was requested from the target |
| More than 10 configured pages (`QUALITY_PAGES`) | "page limit reached" in the quality or performance report |
| Invalid setting, e.g. an unknown `PERF_PROFILE` | configuration error, no report written; the gate cannot read a report |
| Page could not be measured: timeout, redirect (redirects are not followed), oversize page, too many requests, navigation away from the page | page status `TIMEOUT` / `NAVIGATION BLOCKED` / `OVERSIZE` / `TOO MANY REQUESTS` |
| A job stopped before its gate (tool install failure, cancellation) | job result `failure`/`cancelled`; `engineering-summary.json` shows INCOMPLETE with that job result |

The runs are never retried automatically: an intermittent failure is reported, not hidden.

## Accessibility or Performance says NOT CONFIGURED

No quality target was set (`QUALITY_TARGET_URL` empty and no `quality_site_dir` input). Both quality gates pass and
report NOT CONFIGURED - nothing was checked. Set `QUALITY_TARGET_URL` to a local/development/staging deployment, or
call the workflow with `quality_site_dir` for a static site kept in the repository (see
[ADOPTION.md](ADOPTION.md#reusable-workflow-inputs-workflow_call-only)).

## Authentication, Session and Authorization say NOT VERIFIED

Expected in every run. These areas have no runtime checks in the released tools: Phase 3B/3C report status only, no
credentials are used and no authenticated or authorization requests are made. NOT VERIFIED is a coverage status, not a
finding; it neither fails nor passes a gate. Setting `RUNTIME_TARGET_URL` enables the unauthenticated Phase 3A checks
only; it does not change these three statuses.

## Code-scanning results of one gate replace another run's results

Seen with `engineering-ci-v1.1`: each tool writes a fixed `runs[].automationDetails.id` into its SARIF
(`vibe-code-engineering/phase2/`, `vibe-code-engineering/quality/accessibility/`,
`vibe-code-engineering/quality/performance/`), and `github/codeql-action/upload-sarif` keeps an existing id instead of
using its `category` input. Several analyses of the same tool for one commit (for example several `artifact_suffix`
calls) therefore landed in one category and replaced each other. `engineering-ci-v1.2` uploads a copy of each SARIF
whose `automationDetails.id` is the per-gate category (`vibe-code-engineering-<gate><artifact_suffix>/`). Upgrade to
`engineering-ci-v1.2` and give every call in one run a distinct `artifact_suffix`.

## Performance timing reliability is LOW

The performance tool times a fixed benchmark on the runner before measuring. Below `MIN_BENCHMARK` (3571, calibrated
as 50% of the ubuntu-latest median of 7142.9 over 30 hosted runs) timing reliability is LOW and timing FAILs (FCP, LCP,
CLS, TBT) are reported as WARN instead; budget checks (bytes, requests, DOM size, render-blocking) are never capped.
Seen when the machine was busy with other heavy work at the same time. Keep the performance job free of other heavy
steps (the canonical workflow already runs it as its own job).

## Timing values differ between runs or hosts

Hosted runners differ in speed (the benchmark ranged from 4878 to 14705.9 across 30 ubuntu-latest runs) and Chrome
versions change on hosted runners. The tool reduces this with a discarded warm-up run, the median of 3 measured runs, a
majority rule for timing FAILs and an `unstable` flag (coefficient of variation > 0.35 never FAILs). Deterministic
budget values do not vary between runs. A local machine's timings are not comparable to CI timings.

## Running the Engineering CI tests on Windows picks up WSL instead of Git Bash

The Engineering CI tests execute the workflow's shell steps with bash. On Windows, `bash.exe` on `PATH` can be the WSL
launcher (`%LOCALAPPDATA%\Microsoft\WindowsApps\bash.exe` or `System32\bash.exe`), which starts WSL rather than a bash
for these scripts. The tests use Git for Windows Bash (`C:\Program Files\Git\bin\bash.exe`, then
`...\Git\usr\bin\bash.exe`) and never a WSL launcher; if neither Git Bash nor another non-WSL bash is available, the
bash-dependent tests are skipped. Install Git for Windows to run them.

## The push-triggered run fails although the pull request looked fine

The canonical workflow scans the whole repository on push. If the repository contains intentionally vulnerable test
fixtures (as the acceptance repositories do), the Security gate fails by design. Normal projects do not have such
fixtures.
