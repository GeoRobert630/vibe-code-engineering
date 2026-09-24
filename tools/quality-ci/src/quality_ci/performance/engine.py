"""Performance engine: Chromium performance APIs + vendored web-vitals (SHA-256 pinned), driven by Playwright/CDP.

Every run (warm-up and measured) uses a fresh browser context: no cache, cookies, storage or HTTP credentials;
service workers blocked; downloads refused; dialogs dismissed. The 4A route model applies to every request:
GET/HEAD only, target origin (+ asset origins for sub-resources), no redirects, main frame may not navigate away,
per-response and per-run byte caps, plus a per-run request cap. The page is never clicked, scrolled or typed into.

CPU is throttled via CDP (Emulation.setCPUThrottlingRate). Network throttling is NOT applied: responses fulfilled
by the route handler bypass it, so network cost is modelled (model.critical-path) instead.
Observers (web-vitals FCP/LCP/CLS/TTFB, Long Tasks, render-blocking capture) are injected as an init script before
any page script runs. After `load`, observation continues until 2 s without requests and 1 s without a long task,
capped at observation_window_ms after load.
"""

from __future__ import annotations

import hashlib
import statistics
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from ..config import origin_of
from .config import PerfConfig
from .measure import Resource, RunData

WEB_VITALS_VERSION = "6.2.2"
WEB_VITALS_SHA256 = "3ae0ee544ae45c5cd1e19d934080eaf356461a5563718fa3cef1960d26768b4e"
WEB_VITALS_PATH = Path(__file__).parent / "vendor" / "web-vitals.attribution.iife.js"
ENGINE_NAME = "chromium-performance-apis"

# Host benchmark: fixed xorshift workload, unthrottled, median of 3; index = 100000 / median_ms.
BENCHMARK_ITERATIONS = 5_000_000
# timing_reliability is LOW below this index. Calibrated 2026-09-24 as 50% of the observed ubuntu-latest median:
# median 7142.9 over 30 hosted runs (GeoRobert630/vibe-performance-test, performance-acceptance run 35958994272,
# tooling 67754e7) -> 7142.9 / 2 = 3571.45 -> 3571. Previous provisional value: 1000 (local only).
MIN_BENCHMARK = 3571
MIN_BENCHMARK_CALIBRATION = "2026-09-24: 50% of ubuntu-latest median 7142.9 (30 runs, vibe-performance-test run 35958994272)"

NET_QUIET_S = 2.0
TASK_QUIET_MS = 1000
POLL_MS = 100

_OBSERVERS = r"""
(() => {
  if (window !== window.top || window.__qperf) return;
  const s = window.__qperf = {fcp: null, lcp: null, lcpTarget: null, cls: null, ttfb: null, longTasks: [],
                              lastTaskEnd: 0, blockingScripts: [], blockingStyles: [], blockingStyleEls: []};
  // Init scripts run in a function scope: the IIFE's `var webVitals` is local here and never exposed to the page.
  const wv = (typeof webVitals !== 'undefined') ? webVitals : null;
  s.observers = !!wv;
  if (wv) {
    wv.onFCP(m => { s.fcp = m.value; }, {reportAllChanges: true});
    wv.onLCP(m => { s.lcp = m.value; s.lcpTarget = (m.attribution && m.attribution.target) || null; }, {reportAllChanges: true});
    wv.onCLS(m => { s.cls = m.value; }, {reportAllChanges: true});
    wv.onTTFB(m => { s.ttfb = m.value; });
  }
  try {
    new PerformanceObserver(list => {
      for (const e of list.getEntries()) {
        s.longTasks.push([e.startTime, e.duration]);
        s.lastTaskEnd = Math.max(s.lastTaskEnd, e.startTime + e.duration);
      }
    }).observe({type: 'longtask', buffered: true});
  } catch (e) {}
  document.addEventListener('DOMContentLoaded', () => {
    const head = document.head;
    if (!head) return;
    s.blockingScripts = [...head.querySelectorAll('script[src]')]
      .filter(e => !e.async && !e.defer && (e.type || '').toLowerCase() !== 'module').map(e => e.src);
    s.blockingStyleEls = [...head.querySelectorAll('link[rel~="stylesheet"]')]
      .filter(e => !e.disabled && (!e.media || matchMedia(e.media).matches));
    s.blockingStyles = s.blockingStyleEls.map(e => e.href);
  }, {once: true});
  s.quietMs = () => performance.now() - s.lastTaskEnd;
})();
"""

_COLLECT = r"""
() => {
  const s = window.__qperf || {};
  const nav = performance.getEntriesByType('navigation')[0] || {};
  const dpr = window.devicePixelRatio || 1;
  const label = (img) => { const src = img.currentSrc || img.src || '';
                           return src.startsWith('data:') ? 'data:' + (src.slice(5).split(/[;,]/)[0] || '') : src; };
  const unsized = [], oversized = [];
  for (const img of document.images) {
    const ar = getComputedStyle(img).aspectRatio;
    if (!(img.hasAttribute('width') && img.hasAttribute('height')) && (!ar || ar === 'auto')) unsized.push(label(img));
    const w = img.clientWidth, h = img.clientHeight;
    if (img.complete && img.naturalWidth && w && h && img.naturalWidth * img.naturalHeight > 4 * w * h * dpr * dpr)
      oversized.push(label(img));
  }
  const imports = [];
  const walk = (sheet, depth) => {
    let rules; try { rules = sheet.cssRules; } catch (e) { return; }
    for (const r of rules) {
      if (r instanceof CSSImportRule && r.styleSheet) {
        imports.push([new URL(r.href, sheet.href || location.href).href, depth]);
        walk(r.styleSheet, depth + 1);
      }
    }
  };
  for (const el of (s.blockingStyleEls || [])) if (el.sheet) walk(el.sheet, 1);
  return {fcp: s.fcp, lcp: s.lcp, lcpTarget: s.lcpTarget, cls: s.cls, ttfb: s.ttfb,
          dcl: nav.domContentLoadedEventEnd || null, load: nav.loadEventEnd || null, longTasks: s.longTasks || [],
          domNodes: document.getElementsByTagName('*').length, blockingScripts: s.blockingScripts || [],
          blockingStyles: s.blockingStyles || [], imports, unsized, oversized,
          visible: document.visibilityState, observers: !!s.observers};
}
"""

_BENCHMARK = r"""
(n) => { const t = performance.now(); let x = 0x9e3779b9 | 0;
  for (let i = 0; i < n; i++) { x ^= x << 13; x ^= x >>> 17; x ^= x << 5; }
  return [performance.now() - t, x]; }
"""


class EngineUnavailable(RuntimeError):
    pass


def load_web_vitals(path: Path = WEB_VITALS_PATH) -> str:
    try:
        data = path.read_bytes()
    except OSError as exc:
        raise EngineUnavailable(f"web-vitals not found at {path.name}") from exc
    digest = hashlib.sha256(data).hexdigest()
    if digest != WEB_VITALS_SHA256:
        raise EngineUnavailable(f"web-vitals integrity check failed (sha256 {digest[:12]}..., expected {WEB_VITALS_SHA256[:12]}...)")
    return data.decode("utf-8")


def reliability(index: float | None) -> str:
    return "HIGH" if index is not None and index >= MIN_BENCHMARK else "LOW"


@dataclass
class RunOutcome:
    status: str                    # SCANNED or a failure status
    reason: str = ""
    data: RunData | None = None
    blocked: dict[str, int] = field(default_factory=dict)
    duration_ms: int = 0
    http_status: int | None = None


class PerfEngine:
    """Context manager: one headless Chromium-family browser; every run in its own fresh context."""

    def __init__(self, cfg: PerfConfig):
        self.cfg = cfg
        self._pw = None
        self._browser = None
        self._init = load_web_vitals() + "\n" + _OBSERVERS
        self.info: dict[str, Any] = {"name": ENGINE_NAME, "web_vitals": {"version": WEB_VITALS_VERSION, "sha256": WEB_VITALS_SHA256},
                                     "browser": None, "runner": "playwright"}

    def __enter__(self) -> PerfEngine:
        try:
            from playwright.sync_api import sync_playwright
        except ImportError as exc:
            raise EngineUnavailable("Playwright is not installed (pip install 'quality-ci[browser]')") from exc
        try:
            from importlib.metadata import version
            self.info["runner"] = f"playwright {version('playwright')}"
        except Exception:  # noqa: BLE001 - informational only
            pass
        self._pw = sync_playwright().start()
        kwargs: dict[str, Any] = {"headless": True,
                                  "args": ["--disable-background-timer-throttling", "--disable-renderer-backgrounding"]}
        if self.cfg.executable_path:
            kwargs["executable_path"] = self.cfg.executable_path
        elif self.cfg.channel != "chromium":
            kwargs["channel"] = self.cfg.channel
        try:
            self._browser = self._pw.chromium.launch(**kwargs)
        except Exception as exc:  # noqa: BLE001
            self._pw.stop()
            self._pw = None
            first = str(exc).strip().splitlines()[0] if str(exc).strip() else type(exc).__name__
            raise EngineUnavailable(f"browser could not be started ({first[:200]})") from exc
        self.info["browser"] = f"{self.cfg.channel} {self._browser.version}"
        return self

    def __exit__(self, *exc: object) -> None:
        if self._browser is not None:
            self._browser.close()
        if self._pw is not None:
            self._pw.stop()

    # ------------------------------------------------------------------ host benchmark
    def benchmark(self) -> float | None:
        ctx = self._browser.new_context(service_workers="block", accept_downloads=False)
        try:
            page = ctx.new_page()
            page.goto("about:blank")
            samples = [page.evaluate(_BENCHMARK, BENCHMARK_ITERATIONS)[0] for _ in range(3)]
            ms = statistics.median(samples)
            return round(100_000 / ms, 1) if ms > 0 else None
        except Exception:  # noqa: BLE001
            return None
        finally:
            ctx.close()

    # ------------------------------------------------------------------ one run
    def run(self, url: str, timeout_s: float) -> RunOutcome:
        cfg = self.cfg
        prof = cfg.profile
        started = time.monotonic()
        deadline = started + timeout_s
        timeout_ms = max(int(timeout_s * 1000), 1000)
        allowed_assets = {cfg.origin, *cfg.allow_origins}
        blocked = {"method": 0, "origin": 0, "navigation": 0, "redirect": 0, "oversize": 0, "requests": 0}
        state: dict[str, Any] = {"bytes": 0, "oversize": False, "nav_blocked": "", "loaded": False, "count": 0,
                                 "too_many": False, "last_request": time.monotonic()}
        resources: list[Resource] = []
        ctx = self._browser.new_context(
            viewport={"width": prof.viewport[0], "height": prof.viewport[1]}, device_scale_factor=prof.dpr,
            is_mobile=prof.is_mobile, locale="en-US", timezone_id="UTC", reduced_motion="reduce", color_scheme="light",
            service_workers="block", accept_downloads=False, java_script_enabled=True, ignore_https_errors=False,
            http_credentials=None, storage_state=None,
        )
        page = ctx.new_page()
        page.set_default_timeout(timeout_ms)
        page.on("dialog", lambda d: d.dismiss())
        page.add_init_script(self._init)
        cdp = ctx.new_cdp_session(page)
        cdp.send("Emulation.setCPUThrottlingRate", {"rate": prof.cpu_throttle})

        def handle(route, request) -> None:
            state["last_request"] = time.monotonic()
            main_nav = request.is_navigation_request() and request.frame == page.main_frame
            if main_nav and (request.method != "GET" or request.url.split("#", 1)[0] != url or state["loaded"]):
                blocked["navigation"] += 1
                state["nav_blocked"] = request.url
                return route.abort("blockedbyclient")
            if request.method not in ("GET", "HEAD"):
                blocked["method"] += 1
                return route.abort("blockedbyclient")
            origin = origin_of(request.url) if request.url.startswith(("http://", "https://")) else ""
            if origin != cfg.origin and (request.is_navigation_request() or origin not in allowed_assets):
                blocked["origin"] += 1
                return route.abort("blockedbyclient")
            if state["count"] >= cfg.max_requests:
                blocked["requests"] += 1
                state["too_many"] = True
                return route.abort("blockedbyclient")
            state["count"] += 1
            try:
                resp = route.fetch(max_redirects=0, timeout=timeout_ms)
                body = resp.body()
            except Exception:  # noqa: BLE001
                return route.abort("failed")
            finally:
                state["last_request"] = time.monotonic()
            if 300 <= resp.status < 400:
                blocked["redirect"] += 1
                if main_nav:
                    state["nav_blocked"] = "redirect"
                return route.abort("blockedbyclient")
            state["bytes"] += len(body)
            if len(body) > cfg.max_page_bytes or state["bytes"] > cfg.max_page_bytes:
                blocked["oversize"] += 1
                state["oversize"] = True
                return route.abort("blockedbyclient")
            headers = {k.lower(): v for k, v in resp.headers.items()}
            resources.append(Resource(url=request.url, resource_type=request.resource_type, bytes=len(body),
                                      content_type=headers.get("content-type", ""),
                                      content_encoding=headers.get("content-encoding", ""), main_document=main_nav))
            if main_nav:
                state["loaded"] = True
            return route.fulfill(response=resp, body=body)

        page.route("**/*", handle)
        out = RunOutcome(status="ERROR")
        try:
            try:
                response = page.goto(url, wait_until="load", timeout=timeout_ms)
            except Exception as exc:  # noqa: BLE001
                out.status, out.reason = self._failure(exc, state)
                return out
            out.http_status = response.status if response else None
            if response is None or response.status >= 400:
                out.status, out.reason = "HTTP ERROR", f"HTTP {response.status if response else 'no response'}"
                return out
            load_t = time.monotonic()
            window_s = cfg.observation_window_ms / 1000
            while True:
                now = time.monotonic()
                if now >= deadline:
                    out.status, out.reason = "TIMEOUT", f"page_timeout_seconds={timeout_s:g} reached during observation"
                    return out
                if now - load_t >= window_s:
                    break
                try:
                    quiet_ms = page.evaluate("window.__qperf ? window.__qperf.quietMs() : 1e9")
                except Exception:  # noqa: BLE001
                    break
                if time.monotonic() - state["last_request"] >= NET_QUIET_S and quiet_ms >= TASK_QUIET_MS:
                    break
                page.wait_for_timeout(POLL_MS)
            raw = None
            if not state["nav_blocked"]:
                try:
                    raw = page.evaluate(_COLLECT)
                except Exception:  # noqa: BLE001 - e.g. context destroyed by a (blocked) navigation
                    raw = None
            if state["too_many"]:
                out.status, out.reason = "TOO MANY REQUESTS", f"more than max_requests={cfg.max_requests} requests in one run"
                return out
            if state["oversize"]:
                out.status, out.reason = "OVERSIZE", f"a response or the run exceeded max_page_bytes={cfg.max_page_bytes}"
                return out
            if state["nav_blocked"] or page.url.split("#", 1)[0] != url:
                out.status, out.reason = "NAVIGATION BLOCKED", "the page tried to navigate away; only the configured page is measured"
                return out
            if raw is None:
                out.status, out.reason = "ERROR", "measurements could not be collected from the page"
                return out
            out.status = "SCANNED"
            out.data = RunData(
                resources=resources, fcp=raw.get("fcp"), lcp=raw.get("lcp"), lcp_target=raw.get("lcpTarget"),
                cls=raw.get("cls"), ttfb=raw.get("ttfb"), dcl=raw.get("dcl"), load=raw.get("load"),
                long_tasks=[(float(a), float(b)) for a, b in raw.get("longTasks") or []], dom_nodes=int(raw.get("domNodes") or 0),
                blocking_scripts=list(raw.get("blockingScripts") or []), blocking_styles=list(raw.get("blockingStyles") or []),
                imports=[(str(h), int(d)) for h, d in raw.get("imports") or []],
                unsized_images=list(raw.get("unsized") or []), oversized_images=list(raw.get("oversized") or []),
            )
            return out
        finally:
            out.blocked = {k: v for k, v in blocked.items() if v}
            out.duration_ms = int((time.monotonic() - started) * 1000)
            ctx.close()

    @staticmethod
    def _failure(exc: Exception, state: dict[str, Any]) -> tuple[str, str]:
        text = str(exc)
        if state["too_many"]:
            return "TOO MANY REQUESTS", "request cap reached before load"
        if state["oversize"]:
            return "OVERSIZE", "the page exceeded max_page_bytes"
        if state["nav_blocked"] == "redirect":
            return "NAVIGATION BLOCKED", "the configured URL responded with a redirect; redirects are not followed"
        if state["nav_blocked"]:
            return "NAVIGATION BLOCKED", "navigation to a URL other than the configured page was blocked"
        if "timeout" in text.lower():
            return "TIMEOUT", "page load exceeded page_timeout_seconds"
        return "ERROR", "page could not be loaded"
