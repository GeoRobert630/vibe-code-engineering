---
name: dependency-supply-chain
description: Review dependency integrity, hallucinated packages, CVEs, lockfiles and install/build scripts.
---

# Dependency & Supply Chain

Before adding a dependency:
- verify exact package name
- verify official registry
- verify maintainer/repository where relevant
- inspect release/version
- check known vulnerabilities
- check whether the package is actually needed

Run ecosystem audit tools where available.

Review:
- direct dependencies
- transitive dependencies
- lockfile
- postinstall/build scripts
- unusual new packages

Never install a package solely because an AI suggested it.
