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

```
CI pipeline
    ↓
Phase 2 (static scan)
    ↓
Phase 3A (runtime defensive checks - only with a safe local/staging target)
    ↓
optional ZAP baseline (passive)
    ↓
JSON / Markdown reports
    ↓
SARIF (security-ci sarif)
    ↓
CI gate (security-ci gate)
```

Authentication, Session and Authorization (IDOR/BOLA, tenant isolation) remain NOT VERIFIED at runtime; SARIF does
not change verification status; a clean SARIF report
is not proof of security; the ZAP baseline is passive only.

## Operating rule

Audit mode is read-only by default. Fixes require explicit approval.

Do not claim that a project is secure simply because an AI agent completed a checklist. Evidence and runtime verification matter.
