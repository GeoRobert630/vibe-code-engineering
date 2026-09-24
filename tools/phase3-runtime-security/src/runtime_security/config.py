"""Declarative target configuration (runtime-security.yaml).

Only yaml.safe_load is used. Unknown keys are rejected so typos cannot silently
disable a safety setting. Paths are relative to the target; no other hosts can be
configured for requests (CORS origins are only sent as header values).
"""

from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path
from typing import Any
from urllib.parse import urlsplit

import re

import yaml

CHECK_NAMES = ("headers", "cookies", "cors", "redirects", "tls", "error_leakage")
MAX_CONFIG_BYTES = 128 * 1024
DEFAULT_UNTRUSTED_ORIGIN = "https://phase3-untrusted-origin.invalid"


class ConfigError(ValueError):
    pass


# --------------------------------------------------------------- authentication (plumbing only)
# Phase 3B plumbing: these settings are parsed and validated but no authentication
# request is made by this version, and the named environment variables are never read.
ENV_NAME = re.compile(r"^[A-Z_][A-Z0-9_]{0,63}$")
FIELD_NAME = re.compile(r"^[A-Za-z_][A-Za-z0-9_.\-]{0,63}$")
LOGIN_METHODS = frozenset({"POST"})
LOGOUT_METHODS = frozenset({"POST", "GET"})
PROTECTED_METHODS = frozenset({"GET", "HEAD"})
LOGIN_CONTENT_TYPES = frozenset({"application/json", "application/x-www-form-urlencoded"})


@dataclass(frozen=True)
class EndpointConfig:
    method: str
    path: str


@dataclass(frozen=True)
class LoginConfig(EndpointConfig):
    content_type: str = "application/json"
    username_field: str = "email"
    password_field: str = "password"


@dataclass(frozen=True)
class LogoutConfig(EndpointConfig):
    enabled: bool = False


@dataclass(frozen=True)
class CredentialRefs:
    """Names of environment variables only. Values are never read by this version."""

    username_env: str
    password_env: str


@dataclass(frozen=True)
class AuthConfig:
    enabled: bool
    login: LoginConfig | None
    logout: LogoutConfig | None
    protected_endpoint: EndpointConfig | None
    credentials: CredentialRefs | None


@dataclass
class Config:
    base_url: str
    environment: str
    production: bool
    authorized: bool = False
    authorized_by: str = ""
    checks: dict[str, bool] = field(default_factory=lambda: {c: True for c in CHECK_NAMES})
    paths: list[str] = field(default_factory=lambda: ["/"])
    cookie_paths: list[str] = field(default_factory=lambda: ["/"])
    allowed_origins: list[str] = field(default_factory=list)
    untrusted_origin: str = DEFAULT_UNTRUSTED_ORIGIN
    cors_paths: list[str] = field(default_factory=lambda: ["/"])
    http_url: str | None = None
    ca_file: str | None = None
    json_endpoint: str = "/"
    invalid_resource_path: str | None = None
    missing_parameter_path: str | None = None
    timeout: float = 10.0
    max_requests: int = 60
    delay_seconds: float = 0.05
    source_path: str | None = None
    authentication: AuthConfig | None = None
    zap_baseline: "ZapBaselineConfig | None" = None
    # Local JSON file with results produced by a separate, authorized test suite (never credentials).
    verification_results: str | None = None

    @property
    def scheme(self) -> str:
        return urlsplit(self.base_url).scheme

    @property
    def host(self) -> str:
        return urlsplit(self.base_url).hostname or ""


_ALLOWED = {
    "target": {"base_url", "environment", "production", "authorized", "authorized_by", "http_url", "ca_file"},
    "checks": set(CHECK_NAMES),
    "headers": {"paths"},
    "cookies": {"paths"},
    "cors": {"paths", "allowed_origins", "untrusted_origin"},
    "error_leakage": {"json_endpoint", "invalid_resource_path", "missing_parameter_path"},
    "limits": {"timeout", "max_requests", "delay_seconds"},
    "authentication": {"enabled", "login", "logout", "protected_endpoint"},
    # Only *_env names are allowed: literal username/password/token keys are rejected as unknown keys.
    "credentials": {"username_env", "password_env"},
    # Passive OWASP ZAP baseline only (zap-baseline.py). No credentials, no active scan.
    "zap_baseline": {"enabled", "image", "spider_minutes", "timeout_seconds"},
    # Imported Authentication/Session/Authorization results (a file path only; no credentials, no requests).
    "verification_results": {"path"},
}


@dataclass(frozen=True)
class ZapBaselineConfig:
    enabled: bool = False
    image: str = "zaproxy/zap-stable"
    spider_minutes: int = 1
    timeout_seconds: int = 600


def _paths(value: Any, key: str) -> list[str]:
    if not isinstance(value, list) or not value or not all(isinstance(p, str) for p in value):
        raise ConfigError(f"{key} must be a non-empty list of strings")
    for p in value:
        _check_path(p, key)
    return list(value)


def _check_path(p: str, key: str) -> str:
    # Relative paths only: requests can never be redirected to another host by config.
    if not p.startswith("/") or p.startswith("//") or "://" in p or any(c in p for c in "\r\n\t "):
        raise ConfigError(f"{key}: path {p!r} must be a relative path starting with '/'")
    return p


def parse(data: Any, source_path: str | None = None) -> Config:
    if not isinstance(data, dict):
        raise ConfigError("config must be a mapping")
    unknown = set(data) - set(_ALLOWED)
    if unknown:
        raise ConfigError("unknown top-level keys: " + ", ".join(sorted(unknown)))
    for section, allowed in _ALLOWED.items():
        if section in data:
            if not isinstance(data[section], dict):
                raise ConfigError(f"{section} must be a mapping")
            bad = set(data[section]) - allowed
            if bad:
                raise ConfigError(f"unknown keys in {section}: " + ", ".join(sorted(bad)))

    target = data.get("target")
    if not isinstance(target, dict):
        raise ConfigError("target section is required")
    base_url = target.get("base_url")
    if not isinstance(base_url, str):
        raise ConfigError("target.base_url is required")
    parts = urlsplit(base_url)
    if parts.scheme not in ("http", "https") or not parts.hostname:
        raise ConfigError("target.base_url must be an http(s) URL with a host")
    if parts.username or parts.password:
        raise ConfigError("target.base_url must not contain credentials")
    if parts.query or parts.fragment:
        raise ConfigError("target.base_url must not contain a query or fragment")
    if "production" not in target or not isinstance(target["production"], bool):
        raise ConfigError("target.production must be set explicitly to true or false")
    env = target.get("environment")
    if not isinstance(env, str) or not env.strip():
        raise ConfigError("target.environment is required (e.g. local, staging)")

    cfg = Config(
        base_url=base_url.rstrip("/"),
        environment=env.strip().lower(),
        production=target["production"],
        authorized=bool(target.get("authorized", False)),
        authorized_by=str(target.get("authorized_by", "")).strip(),
        source_path=source_path,
    )
    if "http_url" in target:
        http_url = target["http_url"]
        hp = urlsplit(str(http_url))
        if hp.scheme != "http" or hp.hostname != parts.hostname or hp.username or hp.password:
            raise ConfigError("target.http_url must be an http:// URL on the same host as base_url")
        cfg.http_url = str(http_url)
    if "ca_file" in target:
        if not Path(str(target["ca_file"])).is_file():
            raise ConfigError("target.ca_file does not exist")
        cfg.ca_file = str(target["ca_file"])

    checks = data.get("checks", {})
    for name in CHECK_NAMES:
        if name in checks:
            if not isinstance(checks[name], bool):
                raise ConfigError(f"checks.{name} must be true/false")
            cfg.checks[name] = checks[name]

    if "paths" in data.get("headers", {}):
        cfg.paths = _paths(data["headers"]["paths"], "headers.paths")
    if "paths" in data.get("cookies", {}):
        cfg.cookie_paths = _paths(data["cookies"]["paths"], "cookies.paths")
    cors = data.get("cors", {})
    if "paths" in cors:
        cfg.cors_paths = _paths(cors["paths"], "cors.paths")
    if "allowed_origins" in cors:
        origins = cors["allowed_origins"]
        if not isinstance(origins, list) or not all(isinstance(o, str) and urlsplit(o).scheme in ("http", "https") for o in origins):
            raise ConfigError("cors.allowed_origins must be a list of http(s) origins")
        cfg.allowed_origins = [o.rstrip("/") for o in origins]
    if "untrusted_origin" in cors:
        o = str(cors["untrusted_origin"])
        if urlsplit(o).scheme not in ("http", "https"):
            raise ConfigError("cors.untrusted_origin must be an http(s) origin")
        cfg.untrusted_origin = o.rstrip("/")

    err = data.get("error_leakage", {})
    if "json_endpoint" in err:
        cfg.json_endpoint = _check_path(str(err["json_endpoint"]), "error_leakage.json_endpoint")
    for key in ("invalid_resource_path", "missing_parameter_path"):
        if key in err and err[key] is not None:
            setattr(cfg, key, _check_path(str(err[key]), f"error_leakage.{key}"))

    cfg.authentication = parse_authentication(data.get("authentication"), data.get("credentials"))
    if "zap_baseline" in data:
        z = data["zap_baseline"]
        enabled = _bool(z.get("enabled", False), "zap_baseline.enabled")
        image = z.get("image", "zaproxy/zap-stable")
        if image not in ("zaproxy/zap-stable", "ghcr.io/zaproxy/zaproxy:stable"):
            raise ConfigError("zap_baseline.image must be the official zaproxy/zap-stable image")
        minutes, timeout = z.get("spider_minutes", 1), z.get("timeout_seconds", 600)
        if not isinstance(minutes, int) or isinstance(minutes, bool) or not 1 <= minutes <= 10:
            raise ConfigError("zap_baseline.spider_minutes must be an integer between 1 and 10")
        if not isinstance(timeout, int) or isinstance(timeout, bool) or not 60 <= timeout <= 3600:
            raise ConfigError("zap_baseline.timeout_seconds must be an integer between 60 and 3600")
        cfg.zap_baseline = ZapBaselineConfig(enabled, image, minutes, timeout)

    if "verification_results" in data:
        vpath = data["verification_results"].get("path")
        if not isinstance(vpath, str) or not vpath.strip() or not vpath.lower().endswith(".json"):
            raise ConfigError("verification_results.path must be a path to a .json file")
        p = Path(vpath)
        if not p.is_absolute() and source_path:
            p = Path(source_path).resolve().parent / p
        cfg.verification_results = str(p)

    limits = data.get("limits", {})
    if "timeout" in limits:
        cfg.timeout = float(limits["timeout"])
        if not 0.5 <= cfg.timeout <= 60:
            raise ConfigError("limits.timeout must be between 0.5 and 60 seconds")
    if "max_requests" in limits:
        cfg.max_requests = int(limits["max_requests"])
        if not 1 <= cfg.max_requests <= 200:
            raise ConfigError("limits.max_requests must be between 1 and 200")
    if "delay_seconds" in limits:
        cfg.delay_seconds = float(limits["delay_seconds"])
        if not 0 <= cfg.delay_seconds <= 10:
            raise ConfigError("limits.delay_seconds must be between 0 and 10")
    return cfg


def _mapping(value: Any, key: str, allowed: set[str], required: set[str]) -> dict:
    if not isinstance(value, dict):
        raise ConfigError(f"{key} must be a mapping")
    bad = set(value) - allowed
    if bad:
        raise ConfigError(f"unknown keys in {key}: " + ", ".join(sorted(bad)))
    missing = required - set(value)
    if missing:
        raise ConfigError(f"{key} is missing: " + ", ".join(sorted(missing)))
    return value


def _method(value: Any, key: str, allowed: frozenset[str]) -> str:
    if not isinstance(value, str) or value.upper() not in allowed:
        raise ConfigError(f"{key} must be one of {sorted(allowed)}")
    return value.upper()


def _bool(value: Any, key: str) -> bool:
    if not isinstance(value, bool):
        raise ConfigError(f"{key} must be true/false")
    return value


def _env_name(value: Any, key: str) -> str:
    if not isinstance(value, str) or not ENV_NAME.match(value):
        raise ConfigError(f"{key} must be an environment variable name (A-Z, 0-9, _), not a literal value")
    return value


def _field_name(value: Any, key: str) -> str:
    if not isinstance(value, str) or not FIELD_NAME.match(value):
        raise ConfigError(f"{key} must be a form/JSON field name")
    return value


def parse_authentication(auth: Any, creds: Any) -> AuthConfig | None:
    if auth is None and creds is None:
        return None
    credentials = None
    if creds is not None:
        c = _mapping(creds, "credentials", _ALLOWED["credentials"], {"username_env", "password_env"})
        credentials = CredentialRefs(_env_name(c["username_env"], "credentials.username_env"),
                                     _env_name(c["password_env"], "credentials.password_env"))
        if credentials.username_env == credentials.password_env:
            raise ConfigError("credentials.username_env and credentials.password_env must differ")
    if auth is None:
        return AuthConfig(False, None, None, None, credentials)
    a = _mapping(auth, "authentication", _ALLOWED["authentication"], set())
    enabled = _bool(a.get("enabled", False), "authentication.enabled")

    login = None
    if "login" in a:
        lg = _mapping(a["login"], "authentication.login",
                      {"method", "path", "content_type", "username_field", "password_field"},
                      {"method", "path", "username_field", "password_field"})
        ctype = lg.get("content_type", "application/json")
        if ctype not in LOGIN_CONTENT_TYPES:
            raise ConfigError(f"authentication.login.content_type must be one of {sorted(LOGIN_CONTENT_TYPES)}")
        login = LoginConfig(
            method=_method(lg["method"], "authentication.login.method", LOGIN_METHODS),
            path=_check_path(str(lg["path"]), "authentication.login.path"),
            content_type=ctype,
            username_field=_field_name(lg["username_field"], "authentication.login.username_field"),
            password_field=_field_name(lg["password_field"], "authentication.login.password_field"),
        )
    logout = None
    if "logout" in a:
        lo = _mapping(a["logout"], "authentication.logout", {"enabled", "method", "path"}, {"enabled"})
        lo_enabled = _bool(lo["enabled"], "authentication.logout.enabled")
        if lo_enabled and not {"method", "path"} <= set(lo):
            raise ConfigError("authentication.logout needs method and path when enabled")
        logout = LogoutConfig(
            method=_method(lo.get("method", "POST"), "authentication.logout.method", LOGOUT_METHODS),
            path=_check_path(str(lo.get("path", "/")), "authentication.logout.path"),
            enabled=lo_enabled,
        )
    protected = None
    if "protected_endpoint" in a:
        pe = _mapping(a["protected_endpoint"], "authentication.protected_endpoint", {"method", "path"}, {"method", "path"})
        protected = EndpointConfig(
            method=_method(pe["method"], "authentication.protected_endpoint.method", PROTECTED_METHODS),
            path=_check_path(str(pe["path"]), "authentication.protected_endpoint.path"),
        )
    if enabled and (login is None or protected is None or credentials is None):
        raise ConfigError("authentication.enabled requires login, protected_endpoint and a credentials section")
    return AuthConfig(enabled, login, logout, protected, credentials)


def load(path: Path) -> Config:
    if not path.is_file():
        raise ConfigError(f"config file not found: {path}")
    if path.stat().st_size > MAX_CONFIG_BYTES:
        raise ConfigError("config file too large")
    try:
        data = yaml.safe_load(path.read_text(encoding="utf-8"))
    except yaml.YAMLError as exc:
        raise ConfigError(f"invalid YAML: {exc.__class__.__name__}") from exc
    return parse(data, str(path))
