"""Run the OWASP ZAP *baseline* (passive) scan in Docker.

Guarantees:
* only ``zap-baseline.py`` can be run - the builder refuses any other script
  (``zap-full-scan.py`` / ``zap-api-scan.py`` perform active scanning);
* ``--pull=never``: the image must already exist locally, nothing is downloaded;
* exactly one bind mount: the dedicated ``REPORT_DIR/zap`` output directory;
* no ``-e``/``--env`` options: no environment variables (and no credentials) are passed
  into the container; no authentication options are passed to ZAP;
* only called by the runner after the Phase 3 safety gate allowed the target;
* argument list, ``shell=False``, closed stdin, timeout, output cap; console output
  is redacted before it is written to disk.
"""

from __future__ import annotations

import os
import shutil
import subprocess
import threading
from dataclasses import dataclass, field
from pathlib import Path
from urllib.parse import urlsplit, urlunsplit

from ..utils.redaction import redact

DEFAULT_IMAGE = "zaproxy/zap-stable"
BASELINE_SCRIPT = "zap-baseline.py"
FORBIDDEN_SCRIPTS = frozenset({"zap-full-scan.py", "zap-api-scan.py"})
REPORT_NAME = "zap-report.json"
OUTPUT_NAME = "zap-output.txt"
CONTAINER_WORKDIR = "/zap/wrk"
LOOPBACK = frozenset({"127.0.0.1", "localhost", "::1"})
MAX_OUTPUT = 4 * 1024 * 1024
# Only what the docker CLI needs to find its config/daemon. Nothing credential-related.
_ENV_KEEP = frozenset({"PATH", "PATHEXT", "SYSTEMROOT", "SYSTEMDRIVE", "WINDIR", "COMSPEC", "TEMP", "TMP", "TMPDIR",
                       "HOME", "USERPROFILE", "APPDATA", "LOCALAPPDATA", "PROGRAMDATA", "PROGRAMFILES",
                       "DOCKER_HOST", "DOCKER_CONTEXT", "DOCKER_CONFIG", "DOCKER_CERT_PATH", "DOCKER_TLS_VERIFY"})


class BaselineNotAllowed(ValueError):
    pass


@dataclass
class BaselineRun:
    available: bool
    executed: bool = False
    reason: str = ""
    image: str = DEFAULT_IMAGE
    zap_target: str | None = None
    exit_code: int | None = None
    timed_out: bool = False
    command: list[str] = field(default_factory=list)
    report_path: str | None = None
    output_path: str | None = None
    console: str = ""


def container_target(base_url: str) -> str:
    """URL as seen from inside the container: loopback hosts become host.docker.internal."""
    parts = urlsplit(base_url)
    host = parts.hostname or ""
    if host in LOOPBACK:
        netloc = "host.docker.internal" + (f":{parts.port}" if parts.port else "")
        return urlunsplit((parts.scheme, netloc, parts.path or "/", "", ""))
    return urlunsplit((parts.scheme, parts.netloc, parts.path or "/", "", ""))


def build_command(docker: str, image: str, out_dir: Path, target: str, spider_minutes: int, script: str = BASELINE_SCRIPT) -> list[str]:
    if script != BASELINE_SCRIPT or script in FORBIDDEN_SCRIPTS:
        raise BaselineNotAllowed(f"only {BASELINE_SCRIPT} (passive baseline) is allowed, not {script!r}")
    t = urlsplit(target)
    if t.scheme not in ("http", "https") or not t.hostname or t.username or t.password or t.query:
        raise BaselineNotAllowed("ZAP target must be a plain http(s) URL without credentials or query")
    if not 1 <= int(spider_minutes) <= 10:
        raise BaselineNotAllowed("spider_minutes must be between 1 and 10")
    return [
        docker, "run", "--rm", "--pull=never",
        "--add-host=host.docker.internal:host-gateway",
        "-v", f"{out_dir.resolve()}:{CONTAINER_WORKDIR}:rw",
        image, BASELINE_SCRIPT,
        "-t", target,
        "-J", REPORT_NAME,
        "-m", str(int(spider_minutes)),
    ]


def _env() -> dict[str, str]:
    return {k: v for k, v in os.environ.items() if k.upper() in _ENV_KEEP}


def _run(cmd: list[str], timeout: int) -> tuple[int | None, str, bool]:
    proc = subprocess.Popen(cmd, stdin=subprocess.DEVNULL, stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
                            shell=False, env=_env())
    chunks: list[bytes] = []
    size = [0]

    def pump() -> None:
        assert proc.stdout is not None
        for chunk in iter(lambda: proc.stdout.read(65536), b""):
            if size[0] < MAX_OUTPUT:
                chunks.append(chunk[: MAX_OUTPUT - size[0]])
                size[0] += len(chunk)

    t = threading.Thread(target=pump, daemon=True)
    t.start()
    timed_out = False
    try:
        proc.wait(timeout=timeout)
    except subprocess.TimeoutExpired:
        timed_out = True
        proc.kill()
        proc.wait()
    t.join(timeout=5)
    return (None if timed_out else proc.returncode), b"".join(chunks).decode("utf-8", "replace"), timed_out


def image_available(docker: str, image: str) -> bool:
    """Local-only check (``docker image inspect``); never pulls."""
    try:
        res = subprocess.run([docker, "image", "inspect", "--format", "{{.Id}}", image], stdin=subprocess.DEVNULL,
                             capture_output=True, text=True, shell=False, timeout=30, env=_env())
    except (OSError, subprocess.TimeoutExpired):
        return False
    return res.returncode == 0 and res.stdout.strip().startswith("sha256:")


def run_baseline(base_url: str, out_dir: Path, image: str = DEFAULT_IMAGE, spider_minutes: int = 1, timeout_seconds: int = 600) -> BaselineRun:
    docker = shutil.which("docker")
    if docker is None:
        return BaselineRun(False, reason="docker is not installed/available; ZAP baseline not executed")
    if not image_available(docker, image):
        return BaselineRun(False, image=image, reason=f"Docker image {image} is not present locally (it is never pulled automatically); ZAP baseline not executed")
    out_dir.mkdir(parents=True, exist_ok=True)
    target = container_target(base_url)
    cmd = build_command(docker, image, out_dir, target, spider_minutes)
    exit_code, console, timed_out = _run(cmd, timeout_seconds)
    output_path = out_dir / OUTPUT_NAME
    output_path.write_text(redact(console), encoding="utf-8")
    report = out_dir / REPORT_NAME
    return BaselineRun(
        available=True, executed=True, image=image, zap_target=target, exit_code=exit_code, timed_out=timed_out,
        command=[Path(cmd[0]).name] + cmd[1:], report_path=str(report) if report.is_file() else None,
        output_path=str(output_path), console=redact(console),
        reason="ZAP baseline (passive) executed" if not timed_out else "ZAP baseline timed out",
    )
