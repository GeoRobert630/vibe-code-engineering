---
name: logging-observability
description: Secure application logging and security observability without leaking sensitive data.
---

# Logging & Observability

Capture useful security events such as:
- authentication failures
- authorization failures
- administrative actions
- rate-limit abuse
- important configuration changes
- critical errors

Do not log:
- passwords
- session tokens
- API keys
- authorization headers
- cookies
- private keys
- unnecessary PII

Use structured logging with explicit fields.

Production errors should not expose internal stack traces to end users.
