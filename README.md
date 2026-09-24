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

## Getting started

**Adopt the system with one file:** copy `tools/engineering-ci/examples/github-actions-engineering-ci.yml` from release
tag `engineering-ci-v1.2` to `.github/workflows/engineering-ci.yml` in your project, unchanged. It runs the three gates -
Security, Accessibility, Performance - as independent jobs and enforces one combined result, with released tooling
pinned by commit SHA. Nothing needs a secret; optional settings are repository variables.

| Document | Contents |
|---|---|
| [docs/ADOPTION.md](docs/ADOPTION.md) | The adoption guide: which file to copy, the **released versions and pins** (authoritative table), every configuration variable and input with defaults and valid values, what the gates mean, SARIF categories, verification boundaries |
| [docs/TROUBLESHOOTING.md](docs/TROUBLESHOOTING.md) | INCOMPLETE, NOT CONFIGURED, NOT VERIFIED, SARIF category collisions, performance timing reliability, runner variability, Windows/WSL bash |
| [docs/UPGRADING.md](docs/UPGRADING.md) | `engineering-ci-v1.1` to `v1.2`, `quality-ci-v1.1` to `v1.2`, older tags; `v1.0.0` stays immutable |
| [templates/adopter-project/](templates/adopter-project/) | Minimal starter: the canonical workflow, an optional static-site caller and one page |

The per-tool example workflows (`tools/*/examples/`) run a single tool on its own; they are not needed for adoption.

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
- Performance is a **budget-based lab check**, not a load, stress, capacity or scalability test, not field
  (real-user) measurement and not equivalent to Lighthouse; it measures the listed pages only, cold, one page load at a
  time.
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
