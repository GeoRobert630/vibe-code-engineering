"""Measurement definitions: pure functions over one run's raw data (tested without a browser).

Deterministic accounting comes from the route handler (decoded body bytes per response, by Playwright resource
type) and from the DOM; timings come from web-vitals / Long Tasks collected in the page.
"""

from __future__ import annotations

import math
from dataclasses import dataclass, field
from typing import Any

from .config import Profile

BYTE_TYPES = {"script": "budget.script-bytes", "stylesheet": "budget.stylesheet-bytes", "image": "budget.image-bytes",
              "font": "budget.font-bytes", "document": "budget.document-bytes"}
TEXT_TYPES = ("text/", "javascript", "json", "xml", "svg", "css")
LONG_TASK_MS = 50
TIMING_CHECKS = ("timing.fcp", "timing.lcp", "timing.cls", "timing.tbt")
RECORDED = ("ttfb_ms", "dcl_ms", "load_ms", "long_tasks")


@dataclass
class Resource:
    url: str
    resource_type: str
    bytes: int
    content_type: str = ""
    content_encoding: str = ""
    main_document: bool = False


@dataclass
class RunData:
    """Raw data of one measured run (already reduced; no bodies, no page text)."""
    resources: list[Resource] = field(default_factory=list)
    fcp: float | None = None
    lcp: float | None = None
    lcp_target: str | None = None
    cls: float | None = None
    ttfb: float | None = None
    dcl: float | None = None
    load: float | None = None
    long_tasks: list[tuple[float, float]] = field(default_factory=list)     # (startTime, duration) ms
    dom_nodes: int = 0
    blocking_scripts: list[str] = field(default_factory=list)
    blocking_styles: list[str] = field(default_factory=list)
    imports: list[tuple[str, int]] = field(default_factory=list)            # (href, nesting depth >= 1)
    unsized_images: list[str] = field(default_factory=list)
    oversized_images: list[str] = field(default_factory=list)


def tbt(long_tasks: list[tuple[float, float]], fcp: float | None) -> float | None:
    """Total Blocking Time after FCP until the end of observation (lab approximation, not Lighthouse TBT).

    Each long task contributes (duration - 50 ms); a task straddling FCP contributes only its part after FCP,
    minus 50 ms, if positive.
    """
    if fcp is None:
        return None
    total = 0.0
    for start, duration in long_tasks:
        end = start + duration
        if end <= fcp:
            continue
        counted = duration if start >= fcp else end - fcp
        total += max(0.0, counted - LONG_TASK_MS)
    return total


def render_blocking_depth(run: RunData) -> int:
    """0 = nothing render-blocking; 1 = blocking resources fetched in parallel; +1 per @import nesting level."""
    if not (run.blocking_scripts or run.blocking_styles or run.imports):
        return 0
    return 1 + max((d for _, d in run.imports), default=0)


def critical_path_ms(profile: Profile, depth: int, document_bytes: int, render_blocking_bytes: int) -> float:
    """model.critical-path = (1 + depth) x RTT + (document + render-blocking bytes) / throughput."""
    transfer_ms = (document_bytes + render_blocking_bytes) * 8 / profile.model_throughput_kbps   # bytes*8 / (kbit/s) = ms
    return (1 + depth) * profile.model_rtt_ms + transfer_ms


def _norm(url: str) -> str:
    return url.split("#", 1)[0]


def deterministic(run: RunData, profile: Profile, local: bool) -> dict[str, Any]:
    """Deterministic check values of one run, plus contributors (raw URLs; redacted later)."""
    by_type = {cid: 0 for cid in BYTE_TYPES.values()}
    for r in run.resources:
        if r.resource_type in BYTE_TYPES:
            by_type[BYTE_TYPES[r.resource_type]] += r.bytes
    size = {}
    for r in run.resources:
        size[_norm(r.url)] = size.get(_norm(r.url), 0) + r.bytes
    blocking_urls = list(dict.fromkeys([_norm(u) for u in run.blocking_scripts + run.blocking_styles] +
                                       [_norm(u) for u, _ in run.imports]))
    doc_bytes = sum(r.bytes for r in run.resources if r.main_document)
    rb_bytes = sum(size.get(u, 0) for u in blocking_urls)
    depth = render_blocking_depth(run)
    uncompressed = [r.url for r in run.resources
                    if r.bytes > 1024 and not r.content_encoding and any(t in r.content_type.lower() for t in TEXT_TYPES)]
    values = {
        "budget.total-bytes": sum(r.bytes for r in run.resources),
        **by_type,
        "budget.request-count": len(run.resources),
        "budget.render-blocking": len(blocking_urls),
        "budget.dom-nodes": run.dom_nodes,
        "model.critical-path": round(critical_path_ms(profile, depth, doc_bytes, rb_bytes)),
        "diagnostic.unsized-images": len(run.unsized_images),
        "diagnostic.oversized-images": len(run.oversized_images),
        "diagnostic.text-compression": None if local else len(uncompressed),
    }

    def top(resources):
        return [r.url for r in sorted(resources, key=lambda r: (-r.bytes, r.url))[:5]]

    contributors = {
        "budget.total-bytes": top(run.resources),
        "budget.request-count": top(run.resources),
        "budget.render-blocking": blocking_urls[:5],
        "model.critical-path": blocking_urls[:5],
        "diagnostic.unsized-images": run.unsized_images[:5],
        "diagnostic.oversized-images": run.oversized_images[:5],
        "diagnostic.text-compression": [] if local else uncompressed[:5],
    }
    for rtype, cid in BYTE_TYPES.items():
        contributors[cid] = top([r for r in run.resources if r.resource_type == rtype])
    details = {"render_blocking_depth": depth, "document_bytes": doc_bytes, "render_blocking_bytes": rb_bytes}
    return {"values": values, "contributors": contributors, "details": details}


def timings(run: RunData) -> dict[str, Any]:
    return {
        "timing.fcp": run.fcp, "timing.lcp": run.lcp, "timing.cls": run.cls, "timing.tbt": tbt(run.long_tasks, run.fcp),
        "ttfb_ms": run.ttfb, "dcl_ms": run.dcl, "load_ms": run.load,
        "long_tasks": sum(1 for _, d in run.long_tasks if d > LONG_TASK_MS),
    }


def round_value(check_id: str, value: float | None) -> float | int | None:
    """Rounding before comparison: ms to integer, CLS to 3 decimals, bytes/counts exact."""
    if value is None:
        return None
    if check_id == "timing.cls":
        return round(float(value) + 0.0, 3)
    if isinstance(value, float) and math.isnan(value):
        return None
    return int(round(value))
