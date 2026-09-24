"""Repeatability: GOOD / SLOW / FIXED must reach the expected verdict and identical deterministic values every time.

Deselected by default (marker ``repeat``). Run: ``python -m pytest -m repeat tests/performance/test_repeat.py``.
The count is fixed at 20 per fixture. No retries: every repetition counts.
"""

from __future__ import annotations

import pytest

from quality_ci.performance import reporting
from quality_ci.performance.config import parse
from quality_ci.performance.runner import run

from .perf_server import PerfServer
from .test_browser import SLOW_FAIL, SLOW_WARN, _channel

pytestmark = [pytest.mark.repeat, pytest.mark.browser]
REPETITIONS = 20
EXPECTED = {"/good.html": "PASS", "/slow.html": "FAIL", "/fixed.html": "PASS"}


@pytest.fixture(scope="module")
def env():
    channel = _channel()
    with PerfServer() as s:
        yield s, channel


@pytest.mark.parametrize("page", list(EXPECTED))
def test_repeatability(env, page):
    server, channel = env
    verdicts, deterministic, fails, warns, results = [], [], [], [], []
    for _ in range(REPETITIONS):
        d = reporting.build(run(parse({"target": {"base_url": server.url, "environment": "local", "production": False},
                                       "pages": [page], "browser": {"channel": channel}})))
        p = d["pages_tested"][0]
        verdicts.append(d["run"]["verdict"])
        deterministic.append({k: v for k, v in p["deterministic"].items()})
        fails.append({f["check_id"] for f in d["findings"] if f["pages"][0]["status"] == "FAIL"})
        warns.append({f["check_id"] for f in d["findings"] if f["pages"][0]["status"] == "WARN"})
        results.append((p["median"]["timing.tbt"], p["median"]["timing.cls"], p["median"]["timing.lcp"]))
    print(f"{page}: verdicts {sorted(set(verdicts))}; timing medians (tbt, cls, lcp): {results}")
    assert verdicts == [EXPECTED[page]] * REPETITIONS
    assert all(x == deterministic[0] for x in deterministic)
    if page == "/slow.html":
        assert all(f == SLOW_FAIL for f in fails) and all(SLOW_WARN <= w for w in warns)
    else:
        assert all(not f for f in fails)
