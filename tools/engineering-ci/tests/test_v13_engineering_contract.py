"""Engineering CI v1.3 acceptance: strict gate authority for INCOMPLETE and source reporting (design section 21).

Reuses the workflow harness from test_engineering_workflow.py (the workflow's own run: scripts with stubbed gates).
No network, no application fixture, no credentials. Source reporting is a strict xfail until implemented.
"""

from __future__ import annotations

import pytest

from test_engineering_workflow import BASH, NV, PERF_PASS, SEC_TEXT, combine, job, run_gate_step, wf  # noqa: F401

pending = pytest.mark.xfail(strict=True, reason="v1.3 implementation pending")
SOURCE_VALUES = {"native", "imported", "none"}


@pytest.mark.skipif(BASH is None, reason="bash not available")
def test_strict_gate_is_authoritative_when_lenient_passes(wf, tmp_path):
    """Strict gate fails only because of incompleteness; the lenient run passes. Result: INCOMPLETE/FAIL, never PASS."""
    body = SEC_TEXT + 'case " $* " in *" --allow-incomplete "*) exit 0;; esac\nexit 1\n'
    o = run_gate_step(wf, tmp_path, "security", "security-ci", body, {"PHASE3_RAN": "true", "PHASE3_EXIT": "3"})
    assert (o["status"], o["gate_result"], o["gate_exit_code"]) == ("INCOMPLETE", "FAIL", "1")
    assert o["runtime"] == "INCOMPLETE"
    s, out = combine(wf, tmp_path, **NV, **job("SECURITY", o["status"], o["gate_result"], o["gate_exit_code"]),
                     **job("QUALITY", "PASS", "PASS", 0), **PERF_PASS)
    assert s["security"]["status"] == "INCOMPLETE" and s["overall"] == out["overall"] == "FAIL"


@pytest.mark.skipif(BASH is None, reason="bash not available")
def test_gate_invoked_strictly_first(wf, tmp_path):
    """The recorded exit code is the strict run's, whatever the lenient run returns."""
    log = tmp_path / "calls.log"
    body = SEC_TEXT + f'echo "$*" >> "{log.as_posix()}"\ncase " $* " in *" --allow-incomplete "*) exit 0;; esac\nexit 1\n'
    o = run_gate_step(wf, tmp_path, "security", "security-ci", body)
    calls = log.read_text().splitlines()
    assert "--allow-incomplete" not in calls[0] and any("--allow-incomplete" in c for c in calls[1:])
    assert o["gate_exit_code"] == "1" and o["gate_result"] == "FAIL"


@pytest.mark.parametrize("status", ["INCOMPLETE"])
def test_incomplete_security_never_combines_to_pass(wf, tmp_path, status):
    for gate, code in (("FAIL", 1), ("FAIL", 3)):
        s, _ = combine(wf, tmp_path, **NV, **job("SECURITY", status, gate, code), **job("QUALITY", "PASS", "PASS", 0), **PERF_PASS)
        assert s["overall"] == "FAIL"


def test_existing_verification_field_unchanged(wf, tmp_path):
    s, _ = combine(wf, tmp_path, **NV, **job("SECURITY", "PASS", "PASS", 0), **job("QUALITY", "PASS", "PASS", 0), **PERF_PASS)
    assert s["verification"] == {"authentication": "NOT VERIFIED", "session": "NOT VERIFIED", "authorization": "NOT VERIFIED"}


# ------------------------------------------------------------------------------------ source reporting (pending)

def test_summary_has_authoritative_source_fields_defaulting_to_none(wf, tmp_path):
    s, _ = combine(wf, tmp_path, **NV, **job("SECURITY", "PASS", "PASS", 0), **job("QUALITY", "PASS", "PASS", 0), **PERF_PASS)
    assert s["verification_source"] == {"authentication": "none", "session": "none", "authorization": "none"}
    assert s["verification_subarea_source"] == {"authorization": "none", "idor_bola": "none", "tenant_isolation": "none"}


def test_individual_sources_never_mixed(wf, tmp_path):
    s, _ = combine(wf, tmp_path, **NV, **job("SECURITY", "PASS", "PASS", 0), **job("QUALITY", "PASS", "PASS", 0), **PERF_PASS)
    assert set(s["verification_subarea_source"].values()) <= SOURCE_VALUES
    assert s["verification_source"]["authentication"] in SOURCE_VALUES and s["verification_source"]["session"] in SOURCE_VALUES
    assert s["verification_source"]["authorization"] in SOURCE_VALUES | {"mixed"}


def test_human_summary_shows_source(wf, tmp_path):
    combine(wf, tmp_path, **NV, **job("SECURITY", "PASS", "PASS", 0), **job("QUALITY", "PASS", "PASS", 0), **PERF_PASS)
    md = (tmp_path / "summary.md").read_text()
    assert "Authentication: NOT VERIFIED (none)" in md and "Authorization: NOT VERIFIED (none)" in md
