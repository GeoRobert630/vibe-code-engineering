---
name: environment-separation
description: Prevent development, staging and production environments from leaking into each other.
---

# Environment Separation

Separate:
- secrets
- databases
- storage
- cloud accounts/roles
- webhooks
- OAuth clients
- queues/jobs

Environment flow:

`Local → Development → Staging → Production`

Agents should normally operate in local/dev/staging.

Production credentials should not be required for ordinary coding tasks.

Check that development debug settings, test accounts and service endpoints cannot accidentally reach production data.
