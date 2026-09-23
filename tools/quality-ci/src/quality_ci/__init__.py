"""Quality CI for the vibe-code-engineering pipeline. Phase 4A: accessibility.

Runs the axe-core accessibility engine (vendored, pinned) in a headless Chromium against
explicitly configured local/development/staging pages, and writes JSON, Markdown and optional
SARIF reports plus an explicit CI gate. Quality findings (``Q-A11Y-*``) are a separate namespace
from security findings and never become security findings. A clean scan is not proof of WCAG
compliance.
"""

__version__ = "0.1.0"
TOOL_NAME = "quality-ci"
