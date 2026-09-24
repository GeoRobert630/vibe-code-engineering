"""v1.3 acceptance: target safety (design sections 5 and 14). No sockets, no network.

Only the existing public safety gate (``utils.safety.evaluate``) is tested here. The native address policy has no
public boundary yet, so it is not prescribed by this suite.
"""

from __future__ import annotations

import pytest

from runtime_security.config import parse
from runtime_security.utils import safety


@pytest.mark.parametrize("target", [
    {"base_url": "http://127.0.0.1:3000", "environment": "local", "production": True},
    {"base_url": "http://127.0.0.1:3000", "environment": "production", "production": False},
    {"base_url": "http://prod.internal:3000", "environment": "test", "production": False},
])
def test_existing_gate_refuses_production(target):
    assert safety.evaluate(parse({"target": target})).allowed is False


def test_existing_gate_requires_authorization_for_non_local_hosts():
    cfg = parse({"target": {"base_url": "https://staging.example.com", "environment": "staging", "production": False}})
    assert safety.evaluate(cfg).allowed is False
    cfg = parse({"target": {"base_url": "https://staging.example.com", "environment": "staging", "production": False,
                            "authorized": True}})
    assert safety.evaluate(cfg).allowed is False            # authorized_by also required
