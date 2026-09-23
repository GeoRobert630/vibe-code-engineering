---
name: testing
description: Create functional, negative, regression, integration, E2E and security-focused tests for AI-generated applications.
---

# Testing

## Required layers

- unit
- integration
- API
- end-to-end
- regression
- negative/abuse
- security
- performance when relevant

## For each security-sensitive feature test

### Authentication
- unauthenticated request
- expired session
- invalid credentials
- logout then replay

### Authorization
- correct owner
- different user
- different tenant
- insufficient role
- modified resource ID

### Input
- missing fields
- wrong types
- oversized values
- malformed values
- unexpected fields

### Abuse
- repeated requests
- duplicate submissions
- replayed webhooks
- large uploads
- expensive queries

## Rule

A test should prove behavior, not simply repeat the implementation.

## Report

For every test suite record:
- command
- environment
- pass/fail
- important failures
- coverage gaps
