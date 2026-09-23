---
name: injection
description: Audit for SQL, NoSQL, XSS, command, path, template and code injection.
---

# Injection

## SQL/NoSQL
Look for:
- string concatenation
- template interpolation
- unsafe raw queries
- dynamic query fragments

Prefer parameterized queries or safe query builders.

## XSS
Look for:
- `dangerouslySetInnerHTML`
- `innerHTML`
- `document.write`
- unsafe HTML templates
- unsanitized rich text

## Command injection
Look for:
- `exec`
- `spawn`
- `system`
- subprocess APIs
- shell interpolation

Prefer native libraries. If a process is unavoidable, use argument arrays and allowlists.

## Path/template/code injection
Trace user-controlled values into:
- file paths
- templates
- dynamic imports
- evaluators

Provide reproducible evidence before classifying a finding as confirmed.
