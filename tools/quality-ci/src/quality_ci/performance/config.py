"""Performance configuration: 4A target/page/credential rules plus profiles, runs, limits and budgets.

Example::

    target:
      base_url: http://127.0.0.1:3000
      environment: local
      production: false
    pages: ["/", "/pricing"]
    profile: mobile-lab            # mobile-lab | desktop-lab
    runs: 3                        # measured runs per page (3-7); one extra warm-up run is always discarded
    limits:
      max_pages: 10                # hard cap 25
      page_timeout_seconds: 30     # per run; hard cap 120
      total_timeout_seconds: 600   # hard cap 1800
      max_page_bytes: 5000000      # per response and per run; hard cap 20 MB
      max_requests: 300            # per run; hard cap 500
      observation_window_ms: 5000  # after load; hard cap 15000
    budgets:                       # optional overrides; every change is reported
      timing.lcp: {warn: 2000, fail: 3500}
    assets:
      allow_origins: []
    browser:
      channel: chromium            # chromium | chrome | msedge

Target, page, asset-origin, browser and credential-key rules are the 4A rules (quality_ci.config helpers, reused
read-only). Budget overrides must keep 0 < warn <= fail and fail <= 10x the default fail value; model and
diagnostic checks have no fail value.
"""

from __future__ import annotations

import json
from dataclasses import dataclass, field
from pathlib import Path
from urllib.parse import urljoin, urlsplit

from ..config import CHANNELS, CREDENTIAL_KEYS, ConfigError, _check_keys, _http_url, origin_of

HARD_MAX_PAGES = 25
HARD_PAGE_TIMEOUT = 120
HARD_TOTAL_TIMEOUT = 1800
HARD_MAX_PAGE_BYTES = 20_000_000
HARD_MAX_REQUESTS = 500
HARD_OBSERVATION_MS = 15_000
MIN_RUNS, MAX_RUNS = 3, 7
WARMUP_RUNS = 1


@dataclass(frozen=True)
class Profile:
    name: str
    viewport: tuple[int, int]
    dpr: float
    cpu_throttle: float
    model_rtt_ms: int
    model_throughput_kbps: int
    is_mobile: bool

    def to_dict(self) -> dict:
        return {"name": self.name, "viewport": {"width": self.viewport[0], "height": self.viewport[1]}, "dpr": self.dpr,
                "cpu_throttle": self.cpu_throttle, "model_rtt_ms": self.model_rtt_ms,
                "model_throughput_kbps": self.model_throughput_kbps}


PROFILES = {
    "mobile-lab": Profile("mobile-lab", (412, 823), 1.75, 4.0, 150, 1600, True),
    "desktop-lab": Profile("desktop-lab", (1350, 940), 1.0, 1.0, 40, 10_000, False),
}

# check_id -> (warn, fail); fail None = never FAIL (model / diagnostic). Values compared after rounding.
DEFAULT_BUDGETS: dict[str, tuple[float, float | None]] = {
    "timing.fcp": (1800, 3000),
    "timing.lcp": (2500, 4000),
    "timing.cls": (0.100, 0.250),
    "timing.tbt": (200, 600),
    "budget.total-bytes": (1_600_000, 4_000_000),
    "budget.script-bytes": (350_000, 1_000_000),
    "budget.stylesheet-bytes": (None, None),     # measured and reported; no default budget in the specification
    "budget.image-bytes": (1_000_000, 2_500_000),
    "budget.font-bytes": (None, None),
    "budget.document-bytes": (None, None),
    "budget.request-count": (60, 150),
    "budget.render-blocking": (2, 6),
    "budget.dom-nodes": (1_500, 3_000),
    "model.critical-path": (2000, None),
    "diagnostic.unsized-images": (0, None),
    "diagnostic.oversized-images": (0, None),
    "diagnostic.text-compression": (0, None),
}
_TOP = {"target", "pages", "profile", "runs", "limits", "budgets", "assets", "browser"}
_TARGET = {"base_url", "environment", "production", "authorized", "authorized_by"}
_LIMITS = {"max_pages", "page_timeout_seconds", "total_timeout_seconds", "max_page_bytes", "max_requests", "observation_window_ms"}


@dataclass
class PerfConfig:
    base_url: str
    environment: str
    production: bool
    pages: list[str]
    authorized: bool = False
    authorized_by: str = ""
    profile: Profile = PROFILES["mobile-lab"]
    runs: int = 3
    max_pages: int = 10
    page_timeout_seconds: float = 30.0
    total_timeout_seconds: float = 600.0
    max_page_bytes: int = 5_000_000
    max_requests: int = 300
    observation_window_ms: int = 5000
    budgets: dict[str, tuple[float | None, float | None]] = field(default_factory=lambda: dict(DEFAULT_BUDGETS))
    changed_budgets: list[str] = field(default_factory=list)
    allow_origins: list[str] = field(default_factory=list)
    channel: str = "chromium"
    executable_path: str | None = None

    @property
    def host(self) -> str:
        return urlsplit(self.base_url).hostname or ""

    @property
    def origin(self) -> str:
        return origin_of(self.base_url)


def _limit(data: dict, key: str, default, hard, kind=float, minimum=None):
    value = data.get(key, default)
    if isinstance(value, bool) or not isinstance(value, (int, float)):
        raise ConfigError(f"limits.{key} must be a number")
    value = kind(value)
    if value <= 0:
        raise ConfigError(f"limits.{key} must be positive")
    if value > hard:
        raise ConfigError(f"limits.{key}={value} exceeds the hard cap {hard}")
    return value


def _budgets(raw: object) -> tuple[dict, list[str]]:
    budgets = dict(DEFAULT_BUDGETS)
    changed: list[str] = []
    if raw is None:
        return budgets, changed
    if not isinstance(raw, dict):
        raise ConfigError("'budgets' must be a mapping of check id to {warn, fail}")
    for check_id, spec in raw.items():
        if check_id not in DEFAULT_BUDGETS:
            raise ConfigError(f"unknown budget '{check_id}'")
        if not isinstance(spec, dict) or not set(spec) <= {"warn", "fail"} or not spec:
            raise ConfigError(f"budgets.{check_id} must be a mapping with warn and/or fail")
        dwarn, dfail = DEFAULT_BUDGETS[check_id]
        warn, fail = spec.get("warn", dwarn), spec.get("fail", dfail)
        for name, v in (("warn", warn), ("fail", fail)):
            if v is not None and (isinstance(v, bool) or not isinstance(v, (int, float)) or v < 0):
                raise ConfigError(f"budgets.{check_id}.{name} must be a non-negative number")
        if check_id.startswith(("model.", "diagnostic.")) and fail is not None:
            raise ConfigError(f"budgets.{check_id}: model and diagnostic checks never FAIL (no fail value)")
        if warn is not None and fail is not None and warn > fail:
            raise ConfigError(f"budgets.{check_id}: warn must be <= fail")
        cap = 10 * (dfail if dfail is not None else (dwarn or 0))
        if cap and ((fail is not None and fail > cap) or (warn is not None and warn > cap)):
            raise ConfigError(f"budgets.{check_id} exceeds the hard cap {cap:g} (10x the default)")
        if (warn, fail) != (dwarn, dfail):
            budgets[check_id] = (warn, fail)
            changed.append(check_id)
    return budgets, sorted(changed)


def parse(data: object) -> PerfConfig:
    if not isinstance(data, dict):
        raise ConfigError("configuration must be a mapping")
    _check_keys("", data, _TOP)
    target = data.get("target")
    if not isinstance(target, dict):
        raise ConfigError("'target' section is required")
    _check_keys("target.", target, _TARGET)
    base_url = _http_url(target.get("base_url"), "target.base_url")
    env = target.get("environment")
    if not isinstance(env, str) or not env.strip():
        raise ConfigError("target.environment is required")
    production = target.get("production")
    if not isinstance(production, bool):
        raise ConfigError("target.production must be explicitly true or false")
    authorized = target.get("authorized", False)
    if not isinstance(authorized, bool):
        raise ConfigError("target.authorized must be true or false")
    authorized_by = target.get("authorized_by") or ""
    if not isinstance(authorized_by, str):
        raise ConfigError("target.authorized_by must be a string")

    pages_raw = data.get("pages")
    if not isinstance(pages_raw, list) or not pages_raw:
        raise ConfigError("'pages' must be a non-empty list of URLs or paths")
    if len(pages_raw) > HARD_MAX_PAGES:
        raise ConfigError(f"{len(pages_raw)} pages configured; the hard cap is {HARD_MAX_PAGES}")
    base_origin = origin_of(base_url)
    pages: list[str] = []
    for i, raw in enumerate(pages_raw):
        if not isinstance(raw, str) or not raw.strip():
            raise ConfigError(f"pages[{i}] must be a non-empty string")
        url = _http_url(urljoin(base_url, raw.strip()), f"pages[{i}]").split("#", 1)[0]
        if origin_of(url) != base_origin:
            raise ConfigError(f"pages[{i}] is not on the target origin; only explicitly configured same-origin pages are scanned")
        if url not in pages:
            pages.append(url)

    profile_name = data.get("profile", "mobile-lab")
    if profile_name not in PROFILES:
        raise ConfigError(f"profile must be one of {sorted(PROFILES)}")
    runs = data.get("runs", 3)
    if isinstance(runs, bool) or not isinstance(runs, int) or not MIN_RUNS <= runs <= MAX_RUNS:
        raise ConfigError(f"runs must be an integer from {MIN_RUNS} to {MAX_RUNS}")

    limits = data.get("limits") or {}
    if not isinstance(limits, dict):
        raise ConfigError("'limits' must be a mapping")
    _check_keys("limits.", limits, _LIMITS)
    budgets, changed = _budgets(data.get("budgets"))

    assets = data.get("assets") or {}
    if not isinstance(assets, dict):
        raise ConfigError("'assets' must be a mapping")
    _check_keys("assets.", assets, {"allow_origins"})
    allow = assets.get("allow_origins") or []
    if not isinstance(allow, list):
        raise ConfigError("assets.allow_origins must be a list")
    browser = data.get("browser") or {}
    if not isinstance(browser, dict):
        raise ConfigError("'browser' must be a mapping")
    _check_keys("browser.", browser, {"channel", "executable_path"})
    channel = browser.get("channel", "chromium")
    if channel not in CHANNELS:
        raise ConfigError(f"browser.channel must be one of {list(CHANNELS)}")
    exe = browser.get("executable_path")
    if exe is not None and not isinstance(exe, str):
        raise ConfigError("browser.executable_path must be a string")

    return PerfConfig(
        base_url=base_url, environment=env.strip().lower(), production=production, pages=pages,
        authorized=authorized, authorized_by=authorized_by.strip(), profile=PROFILES[profile_name], runs=runs,
        max_pages=_limit(limits, "max_pages", 10, HARD_MAX_PAGES, int),
        page_timeout_seconds=_limit(limits, "page_timeout_seconds", 30, HARD_PAGE_TIMEOUT),
        total_timeout_seconds=_limit(limits, "total_timeout_seconds", 600, HARD_TOTAL_TIMEOUT),
        max_page_bytes=_limit(limits, "max_page_bytes", 5_000_000, HARD_MAX_PAGE_BYTES, int),
        max_requests=_limit(limits, "max_requests", 300, HARD_MAX_REQUESTS, int),
        observation_window_ms=_limit(limits, "observation_window_ms", 5000, HARD_OBSERVATION_MS, int),
        budgets=budgets, changed_budgets=changed,
        allow_origins=sorted({origin_of(_http_url(o, "assets.allow_origins[]")) for o in allow}),
        channel=channel, executable_path=exe,
    )


def load(path: Path) -> PerfConfig:
    try:
        text = Path(path).read_text(encoding="utf-8")
    except OSError as exc:
        raise ConfigError(f"cannot read configuration: {exc.strerror}") from exc
    if str(path).lower().endswith(".json"):
        try:
            return parse(json.loads(text))
        except json.JSONDecodeError as exc:
            raise ConfigError(f"invalid JSON configuration: {exc.msg} (line {exc.lineno})") from exc
    import yaml

    try:
        return parse(yaml.safe_load(text))
    except yaml.YAMLError as exc:
        raise ConfigError("invalid YAML configuration") from exc


__all__ = ["CREDENTIAL_KEYS", "ConfigError", "DEFAULT_BUDGETS", "PROFILES", "PerfConfig", "Profile", "load", "parse"]
