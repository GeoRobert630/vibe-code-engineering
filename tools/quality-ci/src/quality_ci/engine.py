"""Accessibility engine: axe-core (vendored, SHA-256 pinned) in headless Chromium via Playwright.

Controls applied to every page load:
* fresh browser context per page: no cookies, no storage state, no HTTP credentials, service workers blocked,
  downloads refused, dialogs dismissed, fixed viewport/locale/timezone/reduced motion (deterministic);
* every request goes through a route handler:
    - only GET/HEAD are allowed (any other method is aborted: no form submission, no destructive requests);
    - only the target origin (plus configured asset origins, sub-resources only) is allowed;
    - the main frame may navigate only to the configured page URL (redirects and script/form navigations are
      aborted and the page is reported NAVIGATION BLOCKED);
    - every response is fetched by the handler with a byte limit (per response and per page); over-limit
      responses are aborted and the page is reported OVERSIZE;
* the page is never clicked, typed into or submitted;
* axe runs with a timeout and returns only rule IDs, impacts, help/description text, help URLs, tags and CSS
  selectors - never HTML snippets or page text.
"""

from __future__ import annotations

import hashlib
import time
from pathlib import Path
from typing import Any

from .config import Config, origin_of
from .models import PAGE_OK, PageScan, RuleResult

AXE_VERSION = "4.10.3"
AXE_SHA256 = "880970c081707360e64f34cea25ff91892f5bc95675b0776925b9709dd8a68bb"
AXE_PATH = Path(__file__).parent / "vendor" / "axe.min.js"
ENGINE_NAME = "axe-core"

# Runs inside the page. Reduces axe output to metadata + selectors (no html / failureSummary / page text).
_AXE_RUN = """
async ({tags, timeoutMs}) => {
  const opts = {runOnly: {type: 'tag', values: tags}, resultTypes: ['violations', 'incomplete'],
                iframes: false, elementRef: false, selectors: true, ancestry: false, xpath: false,
                performanceTimer: false};
  const timer = new Promise((_, reject) => setTimeout(() => reject(new Error('axe-core timed out')), timeoutMs));
  const r = await Promise.race([window.axe.run(document, opts), timer]);
  const sel = (t) => Array.isArray(t) ? t.join(' >>> ') : String(t);
  const reduce = (list) => list.map(x => ({
    id: x.id, impact: x.impact || null, help: x.help || '', description: x.description || '',
    helpUrl: x.helpUrl || '', tags: x.tags || [],
    targets: (x.nodes || []).map(n => (n.target || []).map(sel).join(' >>> ')),
  }));
  const ids = (list) => list.map(x => x.id);
  return {version: window.axe.version, violations: reduce(r.violations), incomplete: reduce(r.incomplete),
          evaluated: [...ids(r.passes), ...ids(r.violations), ...ids(r.incomplete), ...ids(r.inapplicable)]};
}
"""


class EngineUnavailable(RuntimeError):
    pass


def load_axe_source(path: Path = AXE_PATH) -> str:
    try:
        data = path.read_bytes()
    except OSError as exc:
        raise EngineUnavailable(f"axe-core not found at {path.name}") from exc
    digest = hashlib.sha256(data).hexdigest()
    if digest != AXE_SHA256:
        raise EngineUnavailable(f"axe-core integrity check failed (sha256 {digest[:12]}..., expected {AXE_SHA256[:12]}...)")
    return data.decode("utf-8")


def _results(raw: list[dict[str, Any]]) -> list[RuleResult]:
    out = [RuleResult(rule_id=str(x.get("id", "")), impact=x.get("impact"), help=str(x.get("help", "")),
                      description=str(x.get("description", "")), help_url=str(x.get("helpUrl", "")),
                      tags=[str(t) for t in x.get("tags") or []], targets=[str(t) for t in x.get("targets") or []])
           for x in raw if x.get("id")]
    return sorted(out, key=lambda r: r.rule_id)


class AxeEngine:
    """Context manager: starts one headless browser, scans each page in its own fresh context."""

    name = ENGINE_NAME

    def __init__(self, cfg: Config):
        self.cfg = cfg
        self._pw = None
        self._browser = None
        self._axe = load_axe_source()
        self.info: dict[str, Any] = {"name": ENGINE_NAME, "version": AXE_VERSION, "sha256": AXE_SHA256,
                                     "tags": list(cfg.tags), "runner": "playwright", "browser": None}

    def __enter__(self) -> AxeEngine:
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
        kwargs: dict[str, Any] = {"headless": True}
        if self.cfg.executable_path:
            kwargs["executable_path"] = self.cfg.executable_path
        elif self.cfg.channel != "chromium":
            kwargs["channel"] = self.cfg.channel
        try:
            self._browser = self._pw.chromium.launch(**kwargs)
        except Exception as exc:  # noqa: BLE001 - browser missing etc.
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

    def scan(self, url: str, timeout_s: float) -> PageScan:
        cfg = self.cfg
        started = time.monotonic()
        timeout_ms = max(int(timeout_s * 1000), 1000)
        allowed_assets = {cfg.origin, *cfg.allow_origins}
        blocked = {"method": 0, "origin": 0, "navigation": 0, "redirect": 0, "oversize": 0}
        state = {"bytes": 0, "oversize": False, "nav_blocked": "", "loaded": False}
        ctx = self._browser.new_context(
            viewport={"width": 1280, "height": 800}, locale="en-US", timezone_id="UTC", reduced_motion="reduce",
            color_scheme="light", service_workers="block", accept_downloads=False, java_script_enabled=True,
            ignore_https_errors=False, http_credentials=None, storage_state=None,
        )
        page = ctx.new_page()
        page.set_default_timeout(timeout_ms)
        page.on("dialog", lambda d: d.dismiss())

        def handle(route, request) -> None:
            main_nav = request.is_navigation_request() and request.frame == page.main_frame
            if main_nav and (request.method != "GET" or request.url.split("#", 1)[0] != url or state["loaded"]):
                blocked["navigation"] += 1   # form submission, script navigation or reload away from the configured page
                state["nav_blocked"] = request.url
                return route.abort("blockedbyclient")
            if request.method not in ("GET", "HEAD"):
                blocked["method"] += 1
                return route.abort("blockedbyclient")
            origin = origin_of(request.url) if request.url.startswith(("http://", "https://")) else ""
            if origin != cfg.origin and (request.is_navigation_request() or origin not in allowed_assets):
                blocked["origin"] += 1
                return route.abort("blockedbyclient")
            try:
                resp = route.fetch(max_redirects=0, timeout=timeout_ms)
                body = resp.body()
            except Exception:  # noqa: BLE001 - network error / timeout on this resource
                return route.abort("failed")
            if 300 <= resp.status < 400:   # redirects are never followed (the follow-up would bypass these controls)
                blocked["redirect"] += 1
                if main_nav:
                    state["nav_blocked"] = "redirect"
                return route.abort("blockedbyclient")
            state["bytes"] += len(body)
            if len(body) > cfg.max_page_bytes or state["bytes"] > cfg.max_page_bytes:
                blocked["oversize"] += 1
                state["oversize"] = True
                return route.abort("blockedbyclient")
            if main_nav:
                state["loaded"] = True   # the configured document is served once; any later main-frame navigation is blocked
            return route.fulfill(response=resp, body=body)

        page.route("**/*", handle)
        result = PageScan(url=url, status="ERROR")
        try:
            try:
                response = page.goto(url, wait_until="load", timeout=timeout_ms)
            except Exception as exc:  # noqa: BLE001
                result.status, result.reason = self._load_failure(exc, state)
                return result
            result.http_status = response.status if response else None
            if state["oversize"]:
                result.status, result.reason = "OVERSIZE", f"a response exceeded max_page_bytes={cfg.max_page_bytes}"
                return result
            if response is None or response.status >= 400 or 300 <= response.status < 400:
                result.status = "HTTP ERROR" if response is None or response.status >= 400 else "NAVIGATION BLOCKED"
                result.reason = (f"HTTP {response.status if response else 'no response'}; only the configured URL is scanned"
                                 " (redirects are not followed)")
                return result
            remaining = timeout_ms - int((time.monotonic() - started) * 1000)
            if remaining <= 0:
                result.status, result.reason = "TIMEOUT", f"page_timeout_seconds={timeout_s:g} reached before analysis"
                return result
            try:
                page.evaluate(self._axe)
                raw = page.evaluate(_AXE_RUN, {"tags": list(cfg.tags), "timeoutMs": remaining})
            except Exception as exc:  # noqa: BLE001
                text = str(exc)
                if "timed out" in text.lower() or "timeout" in text.lower():
                    result.status, result.reason = "TIMEOUT", f"accessibility analysis exceeded page_timeout_seconds={timeout_s:g}"
                elif state["nav_blocked"]:
                    result.status, result.reason = "NAVIGATION BLOCKED", "the page tried to navigate away during analysis"
                else:
                    result.status, result.reason = "ERROR", "accessibility engine failed on this page"
                return result
            if page.url.split("#", 1)[0] != url:
                state["nav_blocked"] = state["nav_blocked"] or page.url
            if state["nav_blocked"] or state["oversize"]:
                result.status = "NAVIGATION BLOCKED" if state["nav_blocked"] else "OVERSIZE"
                result.reason = ("the page tried to navigate away; results may not reflect the configured page"
                                 if state["nav_blocked"] else f"a sub-resource exceeded max_page_bytes={cfg.max_page_bytes}")
                return result
            self.info["version"] = str(raw.get("version") or AXE_VERSION)
            result.status = PAGE_OK
            result.violations = _results(raw.get("violations") or [])
            result.incomplete = _results(raw.get("incomplete") or [])
            result.rules_evaluated = sorted(set(raw.get("evaluated") or []))
            return result
        finally:
            result.blocked_requests = {k: v for k, v in blocked.items() if v}
            result.duration_ms = int((time.monotonic() - started) * 1000)
            ctx.close()

    @staticmethod
    def _load_failure(exc: Exception, state: dict[str, Any]) -> tuple[str, str]:
        text = str(exc)
        if state["oversize"]:
            return "OVERSIZE", "the page exceeded max_page_bytes"
        if state["nav_blocked"] == "redirect":
            return "NAVIGATION BLOCKED", "the configured URL responded with a redirect; redirects are not followed"
        if state["nav_blocked"]:
            return "NAVIGATION BLOCKED", "navigation to a URL other than the configured page was blocked"
        if "Timeout" in text or "timeout" in text:
            return "TIMEOUT", "page load exceeded page_timeout_seconds"
        return "ERROR", "page could not be loaded"
