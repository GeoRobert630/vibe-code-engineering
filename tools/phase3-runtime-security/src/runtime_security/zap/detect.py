"""Read-only OWASP ZAP detector.

Looks for a ZAP launcher on PATH and in common install locations. It never executes
ZAP (no version command, no JVM start), never queries or pulls Docker images, never
downloads anything and never reads credential environment variables. The version is
taken from the ``zap-<version>.jar`` file next to the launcher, if present.
"""

from __future__ import annotations

import os
import re
import shutil
from dataclasses import dataclass
from pathlib import Path
from typing import Any

PATH_COMMANDS = ("zap.sh", "zap.bat", "zap", "zaproxy")
JAR_RE = re.compile(r"^zap-(\d{1,3}\.\d{1,3}\.\d{1,3})\.jar$", re.I)
VERSION_RE = re.compile(r"^\d{1,3}\.\d{1,3}\.\d{1,3}$")
_SAFE_PATH = re.compile(r"^[^\x00-\x1f\x7f]{1,400}$")

REASON_UNAVAILABLE = "OWASP ZAP is not installed/available on this machine."
REASON_AVAILABLE_NOT_RUN = "OWASP ZAP is available but authenticated runtime testing has not been executed."


@dataclass(frozen=True)
class ZapStatus:
    available: bool
    version: str | None = None
    source: str = "unknown"          # "path", "install-location", "docker-image" or "unknown"
    location: str | None = None      # launcher path (no environment variables or credentials)

    @property
    def authentication_testing(self) -> str:
        return "available" if self.available else "not available"

    @property
    def reason(self) -> str:
        return REASON_AVAILABLE_NOT_RUN if self.available else REASON_UNAVAILABLE

    def to_dict(self) -> dict[str, Any]:
        return {
            "available": self.available,
            "version": self.version,
            "source": self.source,
            "location": self.location,
            "authentication_testing": self.authentication_testing,
            # Authenticated ZAP testing is never executed by this version (the passive
            # baseline, if enabled, is reported separately under "zap_baseline").
            "authenticated_testing_executed": False,
        }


def _install_candidates() -> list[Path]:
    """Common launcher locations. Only non-secret directory variables are consulted."""
    out: list[Path] = []
    for var in ("ProgramFiles", "ProgramFiles(x86)", "LOCALAPPDATA"):
        root = os.environ.get(var)
        if not root:
            continue
        base = Path(root)
        if var == "LOCALAPPDATA":
            base = base / "Programs"
        for sub in ("ZAP/Zed Attack Proxy", "OWASP/Zed Attack Proxy", "OWASP ZAP", "ZAP"):
            out.append(base / sub / "zap.bat")
    out += [
        Path("/Applications/ZAP.app/Contents/Java/zap.sh"),
        Path("/Applications/OWASP ZAP.app/Contents/Java/zap.sh"),
        Path("/usr/share/zaproxy/zap.sh"),
        Path("/opt/zaproxy/zap.sh"),
        Path("/opt/zap/zap.sh"),
        Path("/snap/bin/zaproxy"),
        Path("/usr/bin/zaproxy"),
        Path("/usr/local/bin/zaproxy"),
    ]
    return out


def parse_version(directory: Path) -> str | None:
    """Version from a zap-X.Y.Z.jar next to the launcher; None if absent/ambiguous."""
    try:
        names = [p.name for p in directory.iterdir() if p.is_file()]
    except OSError:
        return None
    versions = sorted({m.group(1) for n in names if (m := JAR_RE.match(n))})
    return versions[-1] if len(versions) == 1 else None


def normalize(raw: Any) -> ZapStatus:
    """Validate a detection result (e.g. from a mocked detector). Malformed input -> unavailable."""
    if isinstance(raw, ZapStatus):
        raw = raw.to_dict()
    if not isinstance(raw, dict) or not isinstance(raw.get("available"), bool):
        return ZapStatus(False)
    version = raw.get("version")
    if not (isinstance(version, str) and VERSION_RE.match(version)):
        version = None
    source = raw.get("source") if raw.get("source") in ("path", "install-location", "docker-image") else "unknown"
    location = raw.get("location")
    if not (isinstance(location, str) and _SAFE_PATH.match(location)):
        location = None
    if raw["available"] and location is None:
        return ZapStatus(False)
    return ZapStatus(raw["available"], version if raw["available"] else None, source if raw["available"] else "unknown", location if raw["available"] else None)


def detect_zap(extra_candidates: list[Path] | None = None) -> ZapStatus:
    for name in PATH_COMMANDS:
        found = shutil.which(name)
        if found and os.path.isabs(found):
            launcher = Path(found)
            return ZapStatus(True, parse_version(launcher.resolve().parent), "path", str(launcher))
    for candidate in list(extra_candidates or []) + _install_candidates():
        try:
            if candidate.is_file():
                return ZapStatus(True, parse_version(candidate.parent), "install-location", str(candidate))
        except OSError:
            continue
    return ZapStatus(False)
