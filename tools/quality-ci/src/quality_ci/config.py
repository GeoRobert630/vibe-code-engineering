"""Configuration: explicit target pages only, hard-capped limits, no credentials.

Example (YAML or JSON)::

    target:
      base_url: http://127.0.0.1:3000
      environment: local            # local | development | staging (and aliases, see safety.py)
      production: false             # true is always refused
      authorized: true              # required (with authorized_by) for non-local staging hosts
      authorized_by: "Jane Doe"
    pages: ["/", "/contact"]        # explicit list; nothing else is crawled
    limits:
      max_pages: 10                 # pages beyond this are not scanned (run INCOMPLETE)
      page_timeout_seconds: 30
      total_timeout_seconds: 300
      max_page_bytes: 2000000       # per response and per page total
    assets:
      allow_origins: []             # extra origins allowed for GET sub-resources (CSS, fonts); never navigated
    engine:
      tags: [wcag2a, wcag2aa, wcag21a, wcag21aa, best-practice]
    browser:
      channel: chromium             # chromium | chrome | msedge
      executable_path: null

Credential-related keys (headers, cookies, auth, login, storage state, ...) are rejected: this tool
has no credential handling and never authenticates.
"""

from __future__ import annotations

import json
from dataclasses import dataclass, field
from pathlib import Path
from urllib.parse import urljoin, urlsplit

HARD_MAX_PAGES = 25
HARD_PAGE_TIMEOUT = 120
HARD_TOTAL_TIMEOUT = 1800
HARD_MAX_PAGE_BYTES = 10_000_000
DEFAULT_TAGS = ("wcag2a", "wcag2aa", "wcag21a", "wcag21aa", "best-practice")
KNOWN_TAGS = frozenset({"wcag2a", "wcag2aa", "wcag2aaa", "wcag21a", "wcag21aa", "wcag22aa", "best-practice",
                        "section508", "EN-301-549", "ACT", "experimental"})
CHANNELS = ("chromium", "chrome", "msedge")
CREDENTIAL_KEYS = frozenset({"auth", "authentication", "credentials", "credential", "login", "password", "username",
                             "token", "headers", "header", "cookies", "cookie", "http_credentials", "storage_state",
                             "session", "bearer", "api_key"})

_TOP = {"target", "pages", "limits", "assets", "engine", "browser"}
_TARGET = {"base_url", "environment", "production", "authorized", "authorized_by"}
_LIMITS = {"max_pages", "page_timeout_seconds", "total_timeout_seconds", "max_page_bytes"}


class ConfigError(ValueError):
    pass


@dataclass
class Config:
    base_url: str
    environment: str
    production: bool
    pages: list[str]
    authorized: bool = False
    authorized_by: str = ""
    max_pages: int = 10
    page_timeout_seconds: float = 30.0
    total_timeout_seconds: float = 300.0
    max_page_bytes: int = 2_000_000
    allow_origins: list[str] = field(default_factory=list)
    tags: list[str] = field(default_factory=lambda: list(DEFAULT_TAGS))
    channel: str = "chromium"
    executable_path: str | None = None

    @property
    def host(self) -> str:
        return urlsplit(self.base_url).hostname or ""

    @property
    def origin(self) -> str:
        return origin_of(self.base_url)


def origin_of(url: str) -> str:
    p = urlsplit(url)
    port = p.port or (443 if p.scheme == "https" else 80)
    return f"{p.scheme}://{(p.hostname or '').lower()}:{port}"


def _check_keys(section: str, data: dict, allowed: set[str]) -> None:
    for k in data:
        if str(k).lower() in CREDENTIAL_KEYS:
            raise ConfigError(f"'{section}{k}' is not supported: quality-ci has no credential handling and never authenticates")
        if k not in allowed:
            raise ConfigError(f"unknown configuration key '{section}{k}'")


def _num(data: dict, key: str, default, hard, kind=float):
    value = data.get(key, default)
    if isinstance(value, bool) or not isinstance(value, (int, float)):
        raise ConfigError(f"limits.{key} must be a number")
    value = kind(value)
    if value <= 0:
        raise ConfigError(f"limits.{key} must be positive")
    if value > hard:
        raise ConfigError(f"limits.{key}={value} exceeds the hard cap {hard}")
    return value


def _http_url(value: object, what: str) -> str:
    if not isinstance(value, str) or not value.strip():
        raise ConfigError(f"{what} must be a non-empty string")
    p = urlsplit(value.strip())
    if p.scheme not in ("http", "https") or not p.hostname:
        raise ConfigError(f"{what} must be an http(s) URL")
    if p.username or p.password:
        raise ConfigError(f"{what} must not contain credentials")
    try:
        p.port
    except ValueError as exc:
        raise ConfigError(f"{what} has an invalid port") from exc
    return value.strip()


def parse(data: object) -> Config:
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
        url = _http_url(urljoin(base_url, raw.strip()), f"pages[{i}]")
        url = url.split("#", 1)[0]
        if origin_of(url) != base_origin:
            raise ConfigError(f"pages[{i}] is not on the target origin; only explicitly configured same-origin pages are scanned")
        if url not in pages:
            pages.append(url)

    limits = data.get("limits") or {}
    if not isinstance(limits, dict):
        raise ConfigError("'limits' must be a mapping")
    _check_keys("limits.", limits, _LIMITS)
    max_pages = _num(limits, "max_pages", 10, HARD_MAX_PAGES, int)
    page_timeout = _num(limits, "page_timeout_seconds", 30, HARD_PAGE_TIMEOUT)
    total_timeout = _num(limits, "total_timeout_seconds", 300, HARD_TOTAL_TIMEOUT)
    max_bytes = _num(limits, "max_page_bytes", 2_000_000, HARD_MAX_PAGE_BYTES, int)

    assets = data.get("assets") or {}
    if not isinstance(assets, dict):
        raise ConfigError("'assets' must be a mapping")
    _check_keys("assets.", assets, {"allow_origins"})
    allow = assets.get("allow_origins") or []
    if not isinstance(allow, list):
        raise ConfigError("assets.allow_origins must be a list")
    allow_origins = sorted({origin_of(_http_url(o, "assets.allow_origins[]")) for o in allow})

    engine = data.get("engine") or {}
    if not isinstance(engine, dict):
        raise ConfigError("'engine' must be a mapping")
    _check_keys("engine.", engine, {"tags", "name"})
    if engine.get("name", "axe-core") != "axe-core":
        raise ConfigError("engine.name: only 'axe-core' is supported")
    tags = engine.get("tags", list(DEFAULT_TAGS))
    if not isinstance(tags, list) or not tags or not all(isinstance(t, str) and t in KNOWN_TAGS for t in tags):
        raise ConfigError(f"engine.tags must be a non-empty list drawn from {sorted(KNOWN_TAGS)}")

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

    return Config(
        base_url=base_url, environment=env.strip().lower(), production=production, pages=pages,
        authorized=authorized, authorized_by=authorized_by.strip(), max_pages=max_pages,
        page_timeout_seconds=page_timeout, total_timeout_seconds=total_timeout, max_page_bytes=max_bytes,
        allow_origins=allow_origins, tags=sorted(dict.fromkeys(tags)), channel=channel, executable_path=exe,
    )


def load(path: Path) -> Config:
    try:
        text = Path(path).read_text(encoding="utf-8")
    except OSError as exc:
        raise ConfigError(f"cannot read configuration: {exc.strerror}") from exc
    if str(path).lower().endswith(".json"):
        try:
            return parse(json.loads(text))
        except json.JSONDecodeError as exc:
            raise ConfigError(f"invalid JSON configuration: {exc.msg} (line {exc.lineno})") from exc
    import yaml  # PyYAML, as in phase3-runtime-security

    try:
        return parse(yaml.safe_load(text))
    except yaml.YAMLError as exc:
        raise ConfigError("invalid YAML configuration") from exc
