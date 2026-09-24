# Vibe-Code Engineering System

A composable skill system for building AI-assisted software like a disciplined software engineer, security engineer, QA engineer, and release engineer.

## Core workflow

```text
Requirements
    ↓
Architecture
    ↓
Threat Model
    ↓
Implement
    ↓
Test
    ↓
Code Review
    ↓
Security Audit
    ↓
Runtime Validation
    ↓
Production Readiness
    ↓
Deploy
    ↓
Monitor / Re-audit
```

## Skill layout

- `MASTER-SKILL.md` — orchestration and operating rules
- `skills/00-requirements-review` — clarify what is being built
- `skills/01-architecture-review` — design and trust boundaries
- `skills/02-threat-model` — threats, abuse cases, attack paths
- `skills/03-secure-coding` — secure implementation rules
- `skills/04-testing` — functional, negative, regression and security tests
- `skills/05-code-review` — human-style review of generated changes
- `skills/06-security/*` — specialized AppSec controls
- `skills/07-quality/*` — performance, accessibility, privacy and site trust
- `skills/08-release/*` — CI/CD, production gate, recovery and spend protection

## Tools

| Tool | What it does |
|---|---|
| `tools/phase2-security-scanner` | Layer 1 static scanner: secrets, dangerous code, dependencies, configuration, Git history (`P2-*`) |
| `tools/phase3-runtime-security` | Layer 3 runtime checks against local/development/staging targets only: 3A defensive checks (headers, cookies, CORS, HTTP to HTTPS, TLS, error leakage), 3B authentication/session plumbing (status only), 3C authorization/IDOR/BOLA/tenant-isolation status (status only), optional passive OWASP ZAP baseline (`RT-*`) |
| `tools/security-ci` | SARIF 2.1.0 export and the security gate over the Phase 2 / Phase 3 reports |
| `tools/quality-ci` | Quality CI: Phase 4A accessibility (`quality-ci`, axe-core, `Q-A11Y-*`) and Phase 4B performance (`quality-ci-perf`, lab budgets and web-vitals timings, `Q-PERF-*`), each with JSON/Markdown/SARIF reports and its own gate |
| `tools/engineering-ci` | The canonical adoption workflow: runs Security CI, Quality CI accessibility and Quality CI performance independently and enforces one combined result |

## Released components

| Component | Tag | Commit | Contents |
|---|---|---|---|
| Security baseline | `security-baseline-v1` | `bd71c46` | Phase 2 scanner, Phase 3 runtime security (3A, 3B/3C status only, passive ZAP baseline), security-ci |
| Quality CI | `quality-ci-v1.1` | `fa816aa` | Phase 4A accessibility (axe-core 4.10.3, byte-exact vendored) |
| Quality CI | `quality-ci-v1.2` | `c6b82c0` | Phase 4B performance (web-vitals 6.2.2; `MIN_BENCHMARK` calibrated on ubuntu-latest) |
| Engineering CI | `engineering-ci-v1.2` | `70d52f8` | Three-gate orchestration workflow pinning the three releases above, with isolated SARIF uploads (one code-scanning category per gate and case) |

Older tags (`quality-ci-v1`, `engineering-ci-v1`, `engineering-ci-v1.1`) are kept unchanged for history; use the
versions above. `engineering-ci-v1.1` (`62461a6`) uploads each tool's SARIF with the tool's own fixed category, so
several analyses of the same tool for one commit replace each other in code scanning; `engineering-ci-v1.2` fixes
this.

## Adopting the system (canonical workflow)

`tools/engineering-ci/examples/github-actions-engineering-ci.yml` is the one canonical workflow for adopting the
complete system. It only orchestrates the released tools; it adds no scanner, finding, severity, gate or SARIF format.

1. Copy the file from tag `engineering-ci-v1.2` (`70d52f8`) to `.github/workflows/engineering-ci.yml` in your project,
   unchanged.
   It already pins released tooling by commit SHA (security `bd71c46`, accessibility `fa816aa`, performance
   `c6b82c0`); change those pins only to another reviewed release.
2. Optionally set repository **variables** (never secrets; nothing needs a credential):
   - Security: `RUNTIME_TARGET_URL` (local/development/staging only; unset = Phase 3 not run), `RUNTIME_ENVIRONMENT`,
     `RUNTIME_AUTHORIZED_BY` (required for non-local staging hosts), `ENABLE_ZAP_BASELINE` (passive, image never
     pulled), `SECURITY_GATE_POLICY`.
   - Quality: `QUALITY_TARGET_URL` (unset = accessibility and performance NOT CONFIGURED), `QUALITY_ENVIRONMENT`,
     `QUALITY_AUTHORIZED_BY`, `QUALITY_PAGES`, `QUALITY_GATE_POLICY`, `PERF_PROFILE`, `PERF_GATE_POLICY`.
   - Production targets are always refused.
3. It runs on push to `master` (change the branch name if yours differs), on pull requests and on manual dispatch,
   and always enforces the combined result.
   When called as a reusable workflow (`workflow_call`) it also accepts `project_path`, `quality_site_dir` (a static
   directory served on 127.0.0.1 inside the job), `quality_pages`, `artifact_suffix` and `enforce` (default `true`;
   only an explicit `enforce: false` disables the final enforcement).

The per-tool examples (`tools/*/examples/`) show a single tool on its own; they are not needed for adoption.

```
Security CI (security)          Quality CI accessibility (quality)    Quality CI performance (performance)
Phase 2 -> Phase 3 (if target)  quality-ci a11y (if target)            quality-ci-perf perf (if target)
-> security-ci sarif / gate     -> quality-ci sarif / gate             -> quality-ci-perf sarif / gate
security-reports/, security.sarif  quality-reports/, accessibility.sarif  performance-reports/, performance.sarif
                 \                               |                               /
                  Engineering CI result (engineering): engineering-summary.json, final enforcement
```

The three jobs run independently: a failure in one never prevents the others from producing their reports and SARIF.
Each SARIF file is uploaded under its own code-scanning category: security
`vibe-code-engineering-security<artifact_suffix>`, accessibility `vibe-code-engineering-quality-accessibility<artifact_suffix>`,
performance `vibe-code-engineering-quality-performance<artifact_suffix>`. The tools stamp their SARIF with a fixed
`runs[].automationDetails.id`, which GitHub's `upload-sarif` does not replace with its `category` input; the workflow
therefore uploads a copy of each SARIF whose `automationDetails.id` is that category (plus a trailing `/`) and changes
nothing else. The report artifacts keep the tools' original SARIF. Give every call of the reusable workflow in one run
its own `artifact_suffix`.

## What the gates mean

| Gate | Status values | Fails when |
|---|---|---|
| Security | PASS / FAIL / INCOMPLETE | `security-ci gate` fails (default policy `release`: blocking findings), or a scan was incomplete/refused |
| Accessibility | PASS / FAIL / INCOMPLETE / NOT CONFIGURED | `quality-ci gate` fails (default `release`: axe critical/serious violations), or the scan was incomplete |
| Performance | PASS / FAIL / INCOMPLETE / NOT CONFIGURED | `quality-ci-perf gate` fails (default `release`: any budget or timing FAIL), or the measurement was incomplete |
| Final enforcement | PASS / FAIL | any of the three gates fails; a job that never reached its gate counts as INCOMPLETE and FAIL |

NOT CONFIGURED (no quality target) keeps each tool's own gate semantics: the gate passes, and the status is reported
as NOT CONFIGURED, never as a verified pass. Findings stay in separate namespaces - security `P2-*`, `RT-*`, `AI-*`;
accessibility `Q-A11Y-*`; performance `Q-PERF-*` - and accessibility and performance findings never become security
findings (their SARIF carries no `security-severity`).

## What is and is not verified

Verified when configured and passing:
- static security checks of the repository (Phase 2);
- unauthenticated runtime defensive checks of a local/development/staging target (Phase 3A) and, if enabled, a
  passive ZAP baseline;
- the automated accessibility rules axe-core evaluates on the configured pages;
- performance budgets (bytes, requests, render-blocking resources, DOM size, modelled critical path) and lab timings
  (FCP, LCP, CLS, TBT) of the configured pages under a fixed emulation profile.

Not verified:
- **Authentication, Session and Authorization (IDOR/BOLA, tenant isolation) are NOT VERIFIED.** Phase 3B and 3C report
  status only; no credentials are used and no authenticated or authorization requests are made. These remain for
  source-code review until runtime checks are implemented.
- Performance is a **budget-based lab check**, not a load, stress, capacity or scalability test and not field
  (real-user) measurement; it measures the listed pages only, cold, one page load at a time.
- Accessibility automation covers a subset of WCAG; a passing scan is not proof of WCAG compliance.
- A passing security gate or a clean SARIF report is not proof of security.

A combined PASS therefore means only that the three gates passed for what was configured and checked.

`engineering-ci-v1.2` was validated end to end on GitHub Actions from a new external project,
`GeoRobert630/vibe-adoption-test` (clean, vulnerable, inaccessible, slow and all-fail cases, plus `enforce: true` on a
failing case), with one code-scanning category per gate and case. Earlier releases were validated in the acceptance
repositories `vibe-engineering-test`, `vibe-performance-test`, `vibe-quality-test` and `vibe-security-test`.

## Operating rule

Audit mode is read-only by default. Fixes require explicit approval.

Do not claim that a project is secure simply because an AI agent completed a checklist. Evidence and runtime verification matter.
