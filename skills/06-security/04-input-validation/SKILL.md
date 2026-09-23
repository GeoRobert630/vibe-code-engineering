---
name: input-validation
description: Ensure all trust-boundary inputs are validated and constrained server-side.
---

# Input Validation

Inventory:
- body
- query
- route params
- headers
- cookies
- webhooks
- uploads
- external API responses
- environment/config values

Validate:
- type
- format
- length
- range
- enum
- nested structures
- collection limits
- allowed characters where appropriate

Prefer schema libraries already used by the project.

Client-side validation improves UX; server-side validation enforces security.
