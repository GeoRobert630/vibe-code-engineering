"""Safety gate. Runs before any request is sent.

Policy (this slice has no override):
* production: true                      -> refused
* environment named prod/production/live -> refused
* host label prod/production/live        -> refused
* local targets (loopback, private IPs, localhost, *.localhost, *.local, *.test,
  *.internal)                            -> allowed for environments local/dev/test/staging/qa
* any other host                         -> only if environment is staging/test/qa/dev AND
                                            target.authorized: true AND target.authorized_by is set
"""

from __future__ import annotations

import ipaddress
from dataclasses import dataclass

from ..config import Config

ALLOWED_ENVIRONMENTS = frozenset({"local", "development", "dev", "test", "testing", "staging", "stage", "qa", "preview"})
FORBIDDEN_ENVIRONMENTS = frozenset({"prod", "production", "live"})
FORBIDDEN_HOST_LABELS = frozenset({"prod", "production", "live"})
LOCAL_SUFFIXES = (".localhost", ".local", ".test", ".internal")


@dataclass
class SafetyDecision:
    allowed: bool
    reason: str
    local: bool


def is_local_host(host: str) -> bool:
    host = host.strip("[]").lower()
    if host == "localhost" or host.endswith(LOCAL_SUFFIXES):
        return True
    try:
        ip = ipaddress.ip_address(host)
    except ValueError:
        return False
    return ip.is_loopback or ip.is_private or ip.is_link_local


def evaluate(cfg: Config) -> SafetyDecision:
    local = is_local_host(cfg.host)
    if cfg.production:
        return SafetyDecision(False, "target.production is true: production targets are refused by this tool", local)
    if cfg.environment in FORBIDDEN_ENVIRONMENTS:
        return SafetyDecision(False, f"environment '{cfg.environment}' is a production environment", local)
    labels = set(cfg.host.lower().replace("-", ".").split("."))
    if labels & FORBIDDEN_HOST_LABELS:
        return SafetyDecision(False, f"host '{cfg.host}' looks like a production host", local)
    if cfg.environment not in ALLOWED_ENVIRONMENTS:
        return SafetyDecision(False, f"environment '{cfg.environment}' is not one of {sorted(ALLOWED_ENVIRONMENTS)}", local)
    if local:
        return SafetyDecision(True, "local target", True)
    if cfg.environment == "local":
        return SafetyDecision(False, "environment 'local' but the host is not local", False)
    if not (cfg.authorized and cfg.authorized_by):
        return SafetyDecision(
            False,
            "remote staging targets require target.authorized: true and target.authorized_by (who approved testing)",
            False,
        )
    return SafetyDecision(True, f"remote {cfg.environment} target authorized by {cfg.authorized_by}", False)


def gate_text(cfg: Config) -> str:
    return (
        f"Target: {cfg.base_url}\n"
        f"Environment: {cfg.environment}\n"
        f"Production flag: {str(cfg.production).lower()}"
    )
