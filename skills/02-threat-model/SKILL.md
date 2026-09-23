---
name: threat-model
description: Build a practical threat model for features and applications, including AI-agent and multi-tenant risks.
---

# Threat Model

## Identify

### Assets
Examples:
- credentials
- customer data
- payment data
- source code
- cloud resources
- tenant data
- private files
- AI/tool credentials

### Actors
- anonymous user
- authenticated user
- malicious authenticated user
- administrator
- tenant administrator
- third party
- compromised dependency
- manipulated AI agent

## For each important flow

Document:

`Asset → Actor → Attack surface → Attack path → Control → Test`

## Focus areas

- authentication bypass
- authorization/IDOR
- cross-tenant access
- injection
- secret theft
- malicious uploads
- webhook abuse
- rate-limit abuse
- supply chain compromise
- cloud misconfiguration
- prompt injection
- excessive AI-agent permissions
- data exfiltration
- cost/resource abuse

## Output

Top threats, attack paths, existing controls, missing controls, and tests that would prove the controls.
