---
name: runtime-security
description: Verify security controls in a safe staging environment rather than relying only on source-code inspection.
---

# Runtime Security

## Preferred path

`Build → Staging → Security tests → Evidence`

Test:
- unauthenticated access
- cross-user access
- cross-tenant access
- admin boundary
- rate limits
- security headers
- cookies
- upload controls
- webhook validation
- error leakage

Do not perform destructive or intrusive testing against production without explicit authorization.

A runtime test can disprove a false assumption in source review; a static review can still identify issues that runtime tests miss.
