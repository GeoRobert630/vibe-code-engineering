---
name: secrets
description: Detect and prevent secrets in source, Git, browser bundles, URLs, logs, CI/CD and AI prompts.
---

# Secrets

Search for:
- API keys
- tokens
- passwords
- database credentials
- private keys
- service-role keys
- cloud credentials

Inspect:
- source
- config
- `.env*`
- Git history where available
- build output
- frontend bundles
- CI/CD
- logs
- URLs

Rules:
- server-side secret storage
- `.env` appropriately ignored
- `.env.example` uses placeholders
- no real credentials in AI prompts

If an actual credential is exposed:
1. stop further disclosure
2. treat it as compromised
3. identify where it was exposed
4. recommend rotation/revocation
5. check downstream impact
