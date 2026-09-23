"""CI integration for the vibe-code-engineering security pipeline: SARIF export and an explicit CI gate.

Consumes the existing JSON reports (Phase 2 ``security-report.json``, Phase 3
``runtime-security-report.json`` and an optional AI-review findings file). It never
runs scanners itself and never changes a finding's verification status.
"""

__version__ = "0.1.0"
TOOL_NAME = "security-ci"
