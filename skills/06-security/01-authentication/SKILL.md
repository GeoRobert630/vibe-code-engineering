---
name: authentication
description: Audit and implement secure authentication flows.
---

# Authentication

Check:
- server-side credential validation
- password hashing with a modern password-hashing mechanism
- secure session creation
- expiration
- logout invalidation
- session rotation after authentication/privilege changes where appropriate
- password reset
- email verification
- account enumeration resistance
- brute-force protection
- MFA where required

Reject:
- client-only authentication decisions
- plaintext passwords
- custom cryptography
- permanent sessions
- authentication bypass paths

Output exact route/file evidence and tests required.
