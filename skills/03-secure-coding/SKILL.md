---
name: secure-coding
description: Secure implementation rules for AI-generated application code.
---

# Secure Coding

## Non-negotiable

- Never put secrets in browser code.
- Never trust client-side authorization.
- Validate input server-side.
- Parameterize database queries.
- Use safe framework rendering.
- Avoid shell execution with user data.
- Use secure session handling.
- Enforce resource ownership/tenant checks server-side.
- Verify dependencies before installation.
- Add tests for security-sensitive behavior.

## Authentication

Use maintained framework/library facilities. Do not invent cryptography or password storage.

## Authorization

For every protected operation identify:

`actor → resource → tenant → permission → server-side check`

## Data access

Use least-privilege credentials and scoped queries.

## Errors/logging

Never expose credentials, tokens, cookies, authorization headers, stack traces or unnecessary PII.

## File handling

Validate size, type/content, name and access policy. Keep private content private.

## AI-generated code

Treat generated code as an untrusted draft until reviewed and tested.
