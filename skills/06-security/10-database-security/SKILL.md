---
name: database-security
description: Audit database access, least privilege, tenant isolation, RLS/policies, migrations and exposure.
---

# Database Security

Check:
- credentials
- connection exposure
- DB user permissions
- parameterized queries
- ownership checks
- tenant filters
- RLS/policies when applicable
- public tables/views
- sensitive columns
- migrations
- backups

## Multi-tenant rule

Test:
- Tenant A cannot read Tenant B
- Tenant A cannot modify/delete Tenant B
- admin privileges are scoped
- IDs cannot bypass tenant boundaries

Do not assume RLS or an application tenant filter is automatically correct. Verify its behavior.
