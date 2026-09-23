---
name: architecture-review
description: Review application architecture, boundaries, dependencies, data flows and trust boundaries before or after implementation.
---

# Architecture Review

## Inspect

- frontend
- backend/API
- authentication
- authorization
- database
- storage
- queues/jobs
- webhooks
- external APIs
- cloud infrastructure
- CI/CD
- observability
- AI components

## Map

```text
User → Browser → API/Server → Auth → Database/Storage
                     ↓
                 External APIs
```

Adapt the map to the actual application.

## Identify

- trust boundaries
- public endpoints
- sensitive assets
- secrets
- privilege boundaries
- tenant boundaries
- external trust relationships
- single points of failure
- expensive/unbounded operations

## Review questions

- Can the browser directly reach sensitive services?
- Where are authorization decisions made?
- Is the database unintentionally public?
- Are secrets kept server-side?
- Can one tenant cross into another?
- What happens when a dependency or API fails?
- Can an AI agent reach production?
- What is the rollback path?

## Output

Architecture summary, trust-boundary map, risks, assumptions, and recommendations.
