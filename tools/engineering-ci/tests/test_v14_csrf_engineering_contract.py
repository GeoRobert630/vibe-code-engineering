"""v1.4 acceptance: Engineering CI summary extraction and CSRF source reporting (Design §8, §11).

Locks down:
- Engineering CI summary extraction includes csrf:
  - s["verification_source"]["csrf"] reports "native", "imported", or "none"
  - csrf individual area source is never "mixed"
- Human-readable summary displays CSRF: <status> (<source>)
- When unconfigured, reports CSRF: NOT VERIFIED (none) or NOT CONFIGURED (none)
"""

from __future__ import annotations

import sys
from pathlib import Path

_TESTS_DIR = str(Path(__file__).resolve().parent)
if _TESTS_DIR not in sys.path:
    sys.path.insert(0, _TESTS_DIR)

import pytest
from test_engineering_workflow import BASH, NV, PERF_PASS, combine, job, wf  # noqa: F401

pending_eng_ci = pytest.mark.xfail(
    strict=True,
    reason="v1.4 design contract: Engineering CI CSRF source summary pending in summarize.py",
)

SOURCE_VALUES = {"native", "imported", "none"}


@pending_eng_ci
def test_summary_includes_csrf_in_verification_source(wf, tmp_path):
    """Engineering summary extraction records csrf in verification_source defaulting to none."""
    s, _ = combine(
        wf,
        tmp_path,
        **NV,
        **job("SECURITY", "PASS", "PASS", 0),
        **job("QUALITY", "PASS", "PASS", 0),
        **PERF_PASS,
    )
    assert "csrf" in s["verification_source"]
    assert s["verification_source"]["csrf"] in SOURCE_VALUES


@pending_eng_ci
def test_csrf_individual_source_never_mixed(wf, tmp_path):
    """The individual csrf area has a single source (native, imported, none); never mixed."""
    s, _ = combine(
        wf,
        tmp_path,
        **NV,
        **job("SECURITY", "PASS", "PASS", 0),
        **job("QUALITY", "PASS", "PASS", 0),
        **PERF_PASS,
    )
    assert s["verification_source"]["csrf"] in SOURCE_VALUES
    assert s["verification_source"]["csrf"] != "mixed"


@pending_eng_ci
def test_human_summary_shows_csrf_status_and_source(wf, tmp_path):
    """Engineering CI Markdown summary contains CSRF status and source tag."""
    combine(
        wf,
        tmp_path,
        **NV,
        **job("SECURITY", "PASS", "PASS", 0),
        **job("QUALITY", "PASS", "PASS", 0),
        **PERF_PASS,
    )
    md = (tmp_path / "summary.md").read_text(encoding="utf-8")
    assert "CSRF:" in md
    assert any(f"({src})" in md for src in SOURCE_VALUES)
