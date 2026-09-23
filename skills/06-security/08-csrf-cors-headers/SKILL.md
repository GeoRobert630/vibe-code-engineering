---
name: csrf-cors-headers
description: Audit CSRF, CORS and HTTP security headers without confusing them with authentication or authorization.
---

# CSRF, CORS & Headers

## CSRF

Determine whether credentials are automatically attached by the browser.

If cookie-authenticated state-changing requests are possible, implement an appropriate CSRF strategy.

## CORS

Check:
- explicit origins
- credential handling
- preflight behavior
- wildcard + credentials mistakes

CORS is not an authorization mechanism.

## Headers

Review, as applicable:
- HSTS
- CSP
- X-Frame-Options or frame-ancestors
- X-Content-Type-Options
- Referrer-Policy
- Permissions-Policy

Do not add a generic CSP that breaks the application. Tailor it to actual resources.
