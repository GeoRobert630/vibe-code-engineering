---
name: production-readiness
description: Final production release gate for application, security, infrastructure, monitoring, recovery and cost controls.
---

# Production Readiness

## Verify

- production build
- tests
- authentication
- authorization
- secrets
- database
- storage
- APIs
- HTTPS/headers
- dependencies
- infrastructure
- logging/monitoring
- environment separation
- backups/recovery
- cost controls
- AI-agent permissions

## Production configuration

Confirm:
- debug disabled
- safe error handling
- correct callback/webhook URLs
- production secret storage
- correct CORS
- correct cookies
- protected admin routes

## Decision

`NOT READY` — Critical/High blocker or essential control unverified.

`READY WITH DOCUMENTED RISKS` — no critical/high blockers; remaining risks explicitly accepted.

`READY` — required controls verified and evidence recorded.
