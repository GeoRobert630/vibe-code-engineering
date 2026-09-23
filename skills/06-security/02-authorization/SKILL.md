---
name: authorization
description: Audit authorization, IDOR/BOLA, role boundaries and multi-tenant isolation.
---

# Authorization

Authentication does not establish permission.

For every resource:
- identify actor
- identify target resource
- identify tenant
- identify required permission
- verify the server enforces it

Test:
- User A → A data
- User A → B data
- Tenant A → Tenant B
- Employee → Admin action
- unauthorized update/delete

Check path/query/body identifiers and alternate API routes.

Prefer authorization checks close to the data access boundary.
