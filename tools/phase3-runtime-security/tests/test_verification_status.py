"""Status model for imported verification results: every state and transition (pure functions, no I/O)."""

from __future__ import annotations

import pytest

from runtime_security.verification import status as st
from runtime_security.verification.status import (EXECUTED, FAIL, INCOMPLETE, NOT_CONFIGURED, NOT_VERIFIED, PASS, READY,
                                                  STATUSES, aggregate, resolve)


def test_vocabulary():
    assert STATUSES == ("NOT CONFIGURED", "READY", "EXECUTED", "PASS", "FAIL", "INCOMPLETE", "NOT VERIFIED")


def test_no_configuration_is_not_configured():
    assert resolve(configured=False) == NOT_CONFIGURED
    # nothing else matters without configuration, not even a claimed PASS with evidence
    assert resolve(configured=False, present=True, claimed=PASS, executed=True, requests_count=3, evidence_items=2) == NOT_CONFIGURED


def test_configured_unusable_import_is_incomplete():
    assert resolve(configured=True, valid=False) == INCOMPLETE
    assert resolve(configured=True, valid=False, present=True, claimed=PASS, executed=True, requests_count=3, evidence_items=1) == INCOMPLETE


def test_configured_area_absent_is_not_verified():
    assert resolve(configured=True, present=False) == NOT_VERIFIED


@pytest.mark.parametrize("claimed, expected", [
    (READY, READY), (NOT_VERIFIED, NOT_VERIFIED), (NOT_CONFIGURED, NOT_CONFIGURED), (INCOMPLETE, INCOMPLETE),
    (PASS, INCOMPLETE), (FAIL, INCOMPLETE), (EXECUTED, INCOMPLETE),     # results claimed without execution: ambiguous
])
def test_not_executed_transitions(claimed, expected):
    assert resolve(configured=True, present=True, claimed=claimed, executed=False, requests_count=0) == expected


@pytest.mark.parametrize("claimed, findings, evidence, expected", [
    (PASS, 0, 1, PASS),
    (PASS, 0, 0, INCOMPLETE),          # PASS without evidence
    (PASS, 1, 3, INCOMPLETE),          # PASS contradicted by findings
    (FAIL, 1, 0, FAIL),                # proven unauthorized access
    (FAIL, 0, 2, INCOMPLETE),          # FAIL without a finding
    (EXECUTED, 0, 0, EXECUTED),
    (EXECUTED, 2, 0, FAIL),
    (INCOMPLETE, 0, 1, INCOMPLETE),
    (READY, 0, 1, INCOMPLETE),         # contradictory: READY while claiming execution
    (NOT_VERIFIED, 0, 1, INCOMPLETE),
    (NOT_CONFIGURED, 0, 1, INCOMPLETE),
])
def test_executed_transitions(claimed, findings, evidence, expected):
    assert resolve(configured=True, present=True, claimed=claimed, executed=True, requests_count=2,
                   active_findings=findings, evidence_items=evidence) == expected


@pytest.mark.parametrize("claimed", [PASS, FAIL, EXECUTED])
def test_executed_with_zero_requests_is_incomplete(claimed):
    assert resolve(configured=True, present=True, claimed=claimed, executed=True, requests_count=0,
                   active_findings=1 if claimed == FAIL else 0, evidence_items=1) == INCOMPLETE


def test_unknown_claim_is_incomplete():
    assert resolve(configured=True, present=True, claimed="SECURE", executed=True, requests_count=1, evidence_items=1) == INCOMPLETE
    assert resolve(configured=True, present=True, claimed=None) == INCOMPLETE


def test_not_verified_never_becomes_pass():
    for executed in (False, True):
        for evidence in (0, 5):
            assert resolve(configured=True, present=True, claimed=NOT_VERIFIED, executed=executed, requests_count=5,
                           evidence_items=evidence) != PASS
    assert aggregate([NOT_VERIFIED, NOT_VERIFIED, NOT_VERIFIED]) == NOT_VERIFIED
    assert aggregate([PASS, PASS, NOT_VERIFIED]) == EXECUTED


@pytest.mark.parametrize("parts, expected", [
    ([], NOT_VERIFIED),
    ([PASS, PASS, PASS], PASS),
    ([PASS, FAIL, INCOMPLETE], FAIL),
    ([PASS, INCOMPLETE, PASS], INCOMPLETE),
    ([PASS, EXECUTED, PASS], EXECUTED),
    ([READY, NOT_VERIFIED, READY], READY),
    ([NOT_CONFIGURED] * 3, NOT_CONFIGURED),
    ([NOT_CONFIGURED, NOT_VERIFIED, NOT_CONFIGURED], NOT_VERIFIED),
])
def test_aggregate(parts, expected):
    assert aggregate(parts) == expected


def test_module_is_pure():
    import inspect

    src = inspect.getsource(st)
    for forbidden in ("socket", "http", "urllib", "open(", "environ"):
        assert forbidden not in src
