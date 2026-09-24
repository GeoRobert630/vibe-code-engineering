"""Deterministic stand-in for PerfEngine: canned RunOutcomes, records calls, sends no requests."""

from __future__ import annotations

import copy

from quality_ci.performance.engine import RunOutcome
from quality_ci.performance.measure import Resource, RunData

BASE = "http://127.0.0.1:8080"


def run_data(fcp=200.0, lcp=400.0, cls=0.0, tbt_tasks=(), dom=200, scripts=(), styles=(), imports=(), resources=None,
             unsized=(), oversized=(), ttfb=10.0, lcp_target="html>body>main>p") -> RunData:
    res = resources if resources is not None else [
        Resource(f"{BASE}/page.html", "document", 5_000, "text/html", "", True),
        Resource(f"{BASE}/app.js", "script", 20_000, "text/javascript"),
        Resource(f"{BASE}/img/a.png", "image", 30_000, "image/png"),
    ]
    return RunData(resources=list(res), fcp=fcp, lcp=lcp, lcp_target=lcp_target, cls=cls, ttfb=ttfb, dcl=150.0,
                   load=300.0, long_tasks=list(tbt_tasks), dom_nodes=dom, blocking_scripts=list(scripts),
                   blocking_styles=list(styles), imports=list(imports), unsized_images=list(unsized),
                   oversized_images=list(oversized))


def ok(data: RunData) -> RunOutcome:
    return RunOutcome(status="SCANNED", data=data)


class FakeEngine:
    instances: list["FakeEngine"] = []

    def __init__(self, cfg, script: dict | None = None, default=None, index: float | None = 5000.0):
        """script: path -> list of RunOutcome (consumed in order, last one repeated) or a single RunOutcome."""
        self.cfg = cfg
        self.script = script or {}
        self.default = default or ok(run_data())
        self.index = index
        self.calls: list[tuple[str, float]] = []
        self.counters: dict[str, int] = {}
        self.info = {"name": "chromium-performance-apis", "web_vitals": {"version": "6.2.2", "sha256": "fake"},
                     "browser": "fake", "runner": "fake"}
        FakeEngine.instances.append(self)

    def __enter__(self):
        return self

    def __exit__(self, *exc):
        return None

    def benchmark(self):
        return self.index

    def run(self, url: str, timeout_s: float) -> RunOutcome:
        self.calls.append((url, timeout_s))
        key = url.replace(BASE, "")
        seq = self.script.get(key, self.default)
        if isinstance(seq, list):
            i = self.counters.get(key, 0)
            self.counters[key] = i + 1
            out = seq[min(i, len(seq) - 1)]
        else:
            out = seq
        return copy.deepcopy(out)


def factory(script=None, default=None, index=5000.0):
    return lambda cfg: FakeEngine(cfg, script, default, index)
