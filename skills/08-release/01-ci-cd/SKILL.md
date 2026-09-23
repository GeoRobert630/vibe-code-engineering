---
name: ci-cd
description: Build a release pipeline that blocks known quality/security failures before deployment.
---

# CI/CD

Preferred pipeline:

`Lint/Typecheck → Tests → SAST → Secret Scan → Dependency Scan → Build → Staging → Runtime Security → Release Gate`

Protect:
- repository secrets
- deployment credentials
- environments
- protected branches
- production approval

Do not auto-deploy unreviewed high-risk security changes.

Use dependency/secret/security checks as gates where appropriate.
