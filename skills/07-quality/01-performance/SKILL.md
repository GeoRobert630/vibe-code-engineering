---
name: performance
description: Review application performance, scalability and resource usage without sacrificing correctness or security.
---

# Performance

Check:
- bundle size
- unused dependencies
- image optimization
- lazy loading
- caching
- database indexes
- N+1 queries
- pagination
- connection pooling
- expensive API calls
- unnecessary re-renders
- server resource usage
- background jobs

Security must not be weakened for performance.

For expensive endpoints consider:
- pagination
- quotas
- rate limits
- caching
- timeouts
