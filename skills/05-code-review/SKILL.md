---
name: code-review
description: Review generated changes as a senior engineer with security, correctness, maintainability and regression concerns.
---

# Code Review

Review the actual diff.

## Correctness
- Does it satisfy the requirement?
- Are edge cases handled?
- Are errors handled?
- Are transactions/races considered?
- Can retries duplicate side effects?

## Security
- auth
- authorization
- tenant isolation
- input validation
- secrets
- injection
- storage
- logging
- dependency changes
- cloud/config changes

## Maintainability
- follows project conventions
- minimal duplication
- clear naming
- typed interfaces
- reasonable abstraction
- no unnecessary complexity

## AI-specific review

Look for:
- invented APIs/packages
- copied insecure patterns
- unnecessary dependencies
- broad permissions
- hidden side effects
- destructive commands
- changes that weaken existing security controls

## Output

Approve, request changes, or block, with evidence.
