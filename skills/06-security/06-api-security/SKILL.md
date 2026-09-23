---
name: api-security
description: Secure application APIs, webhooks and externally exposed endpoints.
---

# API Security

For each endpoint verify:

1. authentication
2. authorization
3. input validation
4. output minimization
5. rate limiting
6. safe errors
7. logging
8. abuse controls

High-risk endpoints:
- login
- password reset
- signup
- AI generation
- search
- uploads
- payments/orders
- admin actions
- webhooks

## Webhooks

Verify:
- signature validation
- replay protection where applicable
- idempotency
- payload validation
- source assumptions

## Responses

Do not return full internal objects when only a subset is required.
