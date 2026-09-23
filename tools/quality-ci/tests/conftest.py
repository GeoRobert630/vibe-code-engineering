from __future__ import annotations

import copy
from typing import Any

import pytest

from quality_ci.config import parse
from quality_ci.models import PAGE_OK, PageScan, RuleResult

BASE = "http://127.0.0.1:8080"


def cfg_dict(**over: Any) -> dict[str, Any]:
    d: dict[str, Any] = {"target": {"base_url": BASE, "environment": "local", "production": False},
                         "pages": ["/good.html"]}
    for k, v in over.items():
        d[k] = v
    return d


def make_cfg(**over: Any):
    return parse(cfg_dict(**over))


def rr(rule_id: str, impact: str | None = "serious", targets: list[str] | None = None, tags: list[str] | None = None) -> RuleResult:
    return RuleResult(rule_id=rule_id, impact=impact, help=f"{rule_id} help", description=f"{rule_id} description",
                      help_url=f"https://dequeuniversity.com/rules/axe/4.10/{rule_id}?application=axeAPI",
                      tags=tags or ["wcag2a", "wcag111", "cat.text-alternatives"], targets=targets or ["img"])


class FakeEngine:
    """Deterministic stand-in for AxeEngine: returns canned PageScans, records calls, sends no requests."""

    instances: list["FakeEngine"] = []

    def __init__(self, cfg, pages: dict[str, PageScan] | None = None, default: PageScan | None = None):
        self.cfg = cfg
        self.pages = pages or {}
        self.default = default
        self.calls: list[tuple[str, float]] = []
        self.info = {"name": "axe-core", "version": "4.10.3", "sha256": "fake", "tags": list(cfg.tags),
                     "runner": "fake", "browser": "fake"}
        FakeEngine.instances.append(self)

    def __enter__(self):
        return self

    def __exit__(self, *exc):
        return None

    def scan(self, url: str, timeout_s: float) -> PageScan:
        self.calls.append((url, timeout_s))
        tpl = self.pages.get(url.replace(BASE, "")) or self.default or PageScan(url=url, status=PAGE_OK, rules_evaluated=["image-alt", "label"])
        scan = copy.deepcopy(tpl)
        scan.url = url
        return scan


def factory(pages: dict[str, PageScan] | None = None, default: PageScan | None = None):
    return lambda cfg: FakeEngine(cfg, pages, default)


@pytest.fixture(autouse=True)
def _reset_fake():
    FakeEngine.instances.clear()
    yield
