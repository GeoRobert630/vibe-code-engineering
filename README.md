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

- `tools/phase2-security-scanner` — Layer 1 static scanner (secrets, dangerous code, dependencies, configuration, Git)
- `tools/phase3-runtime-security` — Layer 3 runtime checks against local/staging targets (3A defensive checks,
  3B authentication/session plumbing - currently NOT VERIFIED, 3C authorization/IDOR/BOLA/tenant-isolation
  status only - currently NOT VERIFIED, optional passive ZAP baseline)
- `tools/security-ci` — SARIF 2.1.0 export and CI gate over the reports above
- `tools/quality-ci` — Quality CI, Phase 4A accessibility: axe-core in headless Chromium against configured
  local/staging pages, JSON/Markdown/SARIF reports and a quality gate
- `tools/engineering-ci` — Engineering CI example workflow: orchestrates Security CI + Quality CI into one result

The CI architecture is **Security CI + Quality CI**, two independent pipelines:

```
Security CI                                         Quality CI
    ↓                                                   ↓
Phase 2 (static scan)                               Accessibility (Phase 4A, axe-core -
    ↓                                                 only with a safe local/staging target)
Phase 3A (runtime defensive checks - only with          ↓
  a safe local/staging target)                      JSON / Markdown reports
    ↓                                                   ↓
optional ZAP baseline (passive)                     SARIF (quality-ci sarif)
    ↓                                                   ↓
JSON / Markdown reports                             Quality gate (quality-ci gate)
    ↓
SARIF (security-ci sarif)
    ↓
CI gate (security-ci gate)
```

Authentication, Session and Authorization (IDOR/BOLA, tenant isolation) remain NOT VERIFIED at runtime; SARIF does
not change verification status; a clean SARIF report
is not proof of security; the ZAP baseline is passive only.

Security findings (`P2-*`, `RT-*`, `AI-*`) and quality findings (`Q-A11Y-*`) are separate namespaces with separate
reports, SARIF categories and gates. Accessibility findings never become security findings. A clean accessibility
scan is not proof of complete accessibility or WCAG compliance.

## Engineering CI

`tools/engineering-ci` provides one example workflow that runs Security CI, Quality CI accessibility and Quality CI
performance and produces one combined result.
It only orchestrates the existing tools; it adds no scanner, finding, severity, gate or SARIF format.

```
Security CI + Quality CI (accessibility) + Quality CI (performance)
        ↓
  Engineering CI
```

- The Security, Accessibility and Performance jobs run independently. Each uploads its own reports
  (`security-reports/`, `quality-reports/`, `performance-reports/`) and SARIF (separate categories). A final job writes
  `engineering-summary.json` and fails when any gate fails.
- Tooling is pinned to reviewed commits: security `bd71c46` (`security-baseline-v1`), accessibility `fa816aa`
  (`quality-ci-v1.1`) and performance `c6b82c0` (`quality-ci-v1.2`).
- Security, accessibility (`Q-A11Y-*`) and performance (`Q-PERF-*`) findings remain separate, each with its own gate
  policy; the summary repeats none of them.
- A combined PASS does not mean all verification areas are complete. Authentication, Session and Authorization
  remain NOT VERIFIED unless independently verified; without `RUNTIME_TARGET_URL` Phase 3 does not run.
- ZAP remains optional and passive.

## Operating rule

Audit mode is read-only by default. Fixes require explicit approval.

Do not claim that a project is secure simply because an AI agent completed a checklist. Evidence and runtime verification matter.
