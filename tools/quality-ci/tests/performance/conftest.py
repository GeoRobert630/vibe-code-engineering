from __future__ import annotations

from typing import Any

import pytest

from quality_ci.performance.config import parse

from .fake_engine import BASE, FakeEngine


def cfg_dict(**over: Any) -> dict[str, Any]:
    d: dict[str, Any] = {"target": {"base_url": BASE, "environment": "local", "production": False}, "pages": ["/page.html"]}
    d.update(over)
    return d


def make_cfg(**over: Any):
    return parse(cfg_dict(**over))


@pytest.fixture(autouse=True)
def _reset_fake():
    FakeEngine.instances.clear()
    yield
