"""Area status for Authentication and Session.

No authentication or session check is implemented in this version, so both areas are
NOT VERIFIED unless (in tests) synthetic findings of those categories are present, in
which case the area is FAIL. They are never reported as PASS by this version.
"""

from __future__ import annotations

from typing import Any

from ..config import Config
from ..models import Finding
from ..zap.detect import ZapStatus, detect_zap

AUTH_CATEGORIES = {"authentication": "Authentication", "session": "Session"}
PASS, FAIL, NOT_VERIFIED, NOT_APPLICABLE = "PASS", "FAIL", "NOT VERIFIED", "NOT APPLICABLE"


def report_zap(report: Any) -> ZapStatus:
    """Detect ZAP once per report (read-only filesystem check; ZAP is never run)."""
    zap = getattr(report, "zap", None)
    if not isinstance(zap, ZapStatus):
        zap = detect_zap()
        report.zap = zap
    return zap


def auth_area_status(cfg: Config, findings: list[Finding], refused: bool, zap: ZapStatus | None = None) -> dict[str, dict[str, Any]]:
    auth = cfg.authentication
    if refused:
        reason = "safety gate refused the target; nothing was sent"
    elif auth is None:
        reason = "authentication not configured; authentication/session runtime checks are not implemented in this version"
    else:
        reason = ("authentication configured (enabled: {}), but authentication/session runtime checks are not implemented "
                  "in this version; no login, logout or authenticated request was made").format(str(auth.enabled).lower())
    if zap is not None and not refused:
        # ZAP availability is reported; authenticated ZAP testing is never run by this version.
        reason = f"{zap.reason} {reason[0].upper()}{reason[1:]}"
    out: dict[str, dict[str, Any]] = {}
    for category, label in AUTH_CATEGORIES.items():
        ids = [f.id for f in findings if f.category == category]
        out[category] = {
            "area": label,
            "status": FAIL if ids else NOT_VERIFIED,
            "reason": "synthetic/recorded findings present" if ids else reason,
            "findings": ids,
        }
    return out


def auth_config_summary(cfg: Config) -> dict[str, Any] | None:
    """Non-secret description of the configured flow (endpoints and env var *names* only)."""
    a = cfg.authentication
    if a is None:
        return None
    return {
        "enabled": a.enabled,
        "login": None if a.login is None else {"method": a.login.method, "path": a.login.path, "content_type": a.login.content_type,
                                                 "username_field": a.login.username_field, "password_field": a.login.password_field},
        "logout": None if a.logout is None else {"enabled": a.logout.enabled, "method": a.logout.method, "path": a.logout.path},
        "protected_endpoint": None if a.protected_endpoint is None else {"method": a.protected_endpoint.method, "path": a.protected_endpoint.path},
        "credential_env_names": None if a.credentials is None else [a.credentials.username_env, a.credentials.password_env],
        "credentials_read": False,
        "requests_made": 0,
    }
