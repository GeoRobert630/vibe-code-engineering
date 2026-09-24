"""v1.3 acceptance: request budgets and timeouts (design sections 13 and 22). No network.

Only existing public behaviour is tested: the per-request timeout default and the status rules that make timed-out
evidence INCOMPLETE. The native planner and executor have no public boundary yet, so they are not prescribed here.
"""

from __future__ import annotations

from runtime_security.config import parse
from runtime_security.verification import status as vst


def test_existing_per_request_timeout_default_is_10_seconds():
    cfg = parse({"target": {"base_url": "http://127.0.0.1:3000", "environment": "local", "production": False}})
    assert cfg.timeout == 10.0


def test_timeout_evidence_resolves_incomplete_never_pass():
    """A timed-out area has not executed every planned request, so its evidence cannot satisfy PASS."""
    for claimed in ("PASS", "EXECUTED", "FAIL"):
        assert vst.resolve(configured=True, present=True, claimed=claimed, executed=False, requests_count=3,
                           evidence_items=3) == "INCOMPLETE"
    assert vst.resolve(configured=True, present=True, claimed="INCOMPLETE", executed=True, requests_count=3,
                       evidence_items=3) == "INCOMPLETE"
