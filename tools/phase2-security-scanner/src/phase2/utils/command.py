"""Allowlisted, shell-free execution of external tools.

Rules enforced here:
* only executables in ``ALLOWED_TOOLS`` can be run;
* ``shell=False`` always, arguments are passed as a list of strings;
* every run has a timeout and a cap on captured output;
* stdin is closed so a tool can never block waiting for input;
* the environment disables package-manager lifecycle scripts, Go toolchain
  downloads, Git pagers/prompts and optional Git lock files.
"""

from __future__ import annotations

import os
import shutil
import subprocess
import threading
from dataclasses import dataclass
from pathlib import Path

ALLOWED_TOOLS = frozenset({"git", "gitleaks", "npm", "pnpm", "pip-audit", "cargo-audit", "govulncheck"})
DEFAULT_TIMEOUT = 180
DEFAULT_MAX_OUTPUT = 64 * 1024 * 1024

# Git settings forced on the command line. They override repository-local config,
# which a malicious repository could use to run commands (core.fsmonitor,
# diff.external, textconv drivers, pagers).
GIT_SAFE_CONFIG = [
    "--no-pager",
    "-c", "core.fsmonitor=false",
    # SR-01: `git log` verifies commit signatures with a repo-configurable gpg.program
    # when log.showSignature is set; a crafted gpgsig header then runs that program.
    "-c", "log.showSignature=false",
    "-c", "gpg.program=",
    "-c", "gpg.ssh.program=",
    "-c", "gpg.x509.program=",
    "-c", "protocol.allow=never",
    "-c", "core.untrackedCache=false",
    "-c", "core.pager=cat",
    "-c", "diff.external=",
    "-c", "core.hooksPath=" + os.devnull,
    "-c", "color.ui=false",
]


class CommandNotAllowed(ValueError):
    pass


@dataclass
class CommandResult:
    returncode: int | None
    stdout: str
    stderr: str
    timed_out: bool = False
    truncated: bool = False
    error: str | None = None

    @property
    def ok(self) -> bool:
        return self.error is None and not self.timed_out and self.returncode is not None


_untrusted_root: Path | None = None


def set_untrusted_root(root: Path | None) -> None:
    """Directories inside the scanned project are never used to resolve executables."""
    global _untrusted_root
    _untrusted_root = root.resolve() if root is not None else None


def _inside_untrusted(path: str) -> bool:
    if _untrusted_root is None:
        return False
    try:
        Path(path).resolve().relative_to(_untrusted_root)
        return True
    except (ValueError, OSError):
        return False


def _search_path() -> str:
    """PATH without relative entries ('.', '') and without directories inside the target.

    SR-06: shutil.which on Windows/Python 3.11 searches the current directory first;
    an explicit, sanitised path plus NoDefaultCurrentDirectoryInExePath avoids that.
    """
    keep = [
        entry
        for entry in os.environ.get("PATH", "").split(os.pathsep)
        if entry and os.path.isabs(entry) and not _inside_untrusted(entry)
    ]
    return os.pathsep.join(keep)


def which(tool: str) -> str | None:
    if tool not in ALLOWED_TOOLS:
        raise CommandNotAllowed(tool)
    os.environ["NoDefaultCurrentDirectoryInExePath"] = "1"
    found = shutil.which(tool, path=_search_path())
    if found is None or not os.path.isabs(found) or _inside_untrusted(found):
        return None
    return found


# SR-02: child processes get an allowlisted environment only. Tokens such as
# NPM_TOKEN / GITHUB_TOKEN / AWS_* are dropped so a project .npmrc cannot expand
# ${NPM_TOKEN} and send it to an attacker-chosen registry during `npm audit`.
ENV_ALLOWLIST = frozenset(
    {
        "PATH", "PATHEXT", "SYSTEMROOT", "SYSTEMDRIVE", "WINDIR", "COMSPEC", "TEMP", "TMP", "TMPDIR",
        "HOME", "USERPROFILE", "HOMEDRIVE", "HOMEPATH", "APPDATA", "LOCALAPPDATA", "PROGRAMDATA",
        "PROGRAMFILES", "PROGRAMFILES(X86)", "COMMONPROGRAMFILES", "USER", "USERNAME", "LOGNAME",
        "LANG", "LC_ALL", "LC_CTYPE", "TZ", "TERM", "XDG_CACHE_HOME", "XDG_CONFIG_HOME", "XDG_DATA_HOME",
        "HTTP_PROXY", "HTTPS_PROXY", "NO_PROXY", "SSL_CERT_FILE", "SSL_CERT_DIR", "REQUESTS_CA_BUNDLE",
        "NODE_EXTRA_CA_CERTS", "GOPATH", "GOROOT", "GOCACHE", "GOMODCACHE", "GOPROXY", "GONOSUMDB",
        "GOPRIVATE", "CARGO_HOME", "RUSTUP_HOME", "NVM_DIR", "PNPM_HOME", "VIRTUAL_ENV",
    }
)


def safe_env() -> dict[str, str]:
    env = {k: v for k, v in os.environ.items() if k.upper() in ENV_ALLOWLIST}
    env.update(
        {
            "GIT_TERMINAL_PROMPT": "0",
            "GIT_PAGER": "cat",
            "PAGER": "cat",
            "GIT_OPTIONAL_LOCKS": "0",
            "GIT_ASKPASS": "",
            "SSH_ASKPASS": "",
            "npm_config_ignore_scripts": "true",
            "npm_config_ignore_pnpmfile": "true",
            "npm_config_fund": "false",
            "npm_config_update_notifier": "false",
            "npm_config_manage_package_manager_versions": "false",
            "GOTOOLCHAIN": "local",
            "GOFLAGS": "-mod=readonly",
            "CGO_ENABLED": "0",
            "COREPACK_ENABLE_NETWORK": "0",
            "COREPACK_ENABLE_STRICT": "0",
            "COREPACK_ENABLE_AUTO_PIN": "0",
            "NO_COLOR": "1",
            "CI": "true",
        }
    )
    return env


def _is_windows_batch(executable: str) -> bool:
    return os.name == "nt" and executable.lower().endswith((".cmd", ".bat"))


def run(
    tool: str,
    args: list[str],
    cwd: Path,
    timeout: int = DEFAULT_TIMEOUT,
    max_output: int = DEFAULT_MAX_OUTPUT,
) -> CommandResult:
    """Run an allowlisted tool. ``args`` must be a list of plain strings."""
    if tool not in ALLOWED_TOOLS:
        raise CommandNotAllowed(tool)
    if not all(isinstance(a, str) for a in args):
        raise CommandNotAllowed("arguments must be strings")
    executable = which(tool)
    if executable is None:
        return CommandResult(None, "", "", error=f"{tool} not found on PATH")
    if _is_windows_batch(executable):
        # cmd.exe re-parses the command line of .cmd/.bat files. Only allow
        # arguments made of characters cmd.exe does not treat specially.
        for a in args:
            if any(ch in a for ch in '&|<>^%!"`\r\n()'):
                raise CommandNotAllowed(f"unsafe argument for batch wrapper: {a!r}")
    if tool == "git":
        args = GIT_SAFE_CONFIG + args
    try:
        proc = subprocess.Popen(
            [executable, *args],
            cwd=str(cwd),
            stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            shell=False,
            env=safe_env(),
        )
    except OSError as exc:
        return CommandResult(None, "", "", error=f"failed to start {tool}: {exc.__class__.__name__}")

    out_chunks: list[bytes] = []
    err_chunks: list[bytes] = []
    state = {"out": 0, "truncated": False}

    def _pump_stdout() -> None:
        assert proc.stdout is not None
        while True:
            chunk = proc.stdout.read(65536)
            if not chunk:
                break
            if state["out"] < max_output:
                keep = chunk[: max_output - state["out"]]
                out_chunks.append(keep)
                state["out"] += len(keep)
                if len(keep) < len(chunk):
                    state["truncated"] = True
            else:
                state["truncated"] = True

    def _pump_stderr() -> None:
        assert proc.stderr is not None
        total = 0
        while True:
            chunk = proc.stderr.read(65536)
            if not chunk:
                break
            if total < 1024 * 1024:
                err_chunks.append(chunk)
                total += len(chunk)

    threads = [threading.Thread(target=_pump_stdout, daemon=True), threading.Thread(target=_pump_stderr, daemon=True)]
    for t in threads:
        t.start()
    timed_out = False
    try:
        proc.wait(timeout=timeout)
    except subprocess.TimeoutExpired:
        timed_out = True
        proc.kill()
        proc.wait()
    for t in threads:
        t.join(timeout=5)
    return CommandResult(
        returncode=None if timed_out else proc.returncode,
        stdout=b"".join(out_chunks).decode("utf-8", "replace"),
        stderr=b"".join(err_chunks).decode("utf-8", "replace"),
        timed_out=timed_out,
        truncated=state["truncated"],
    )


def tool_version(tool: str, args: list[str], cwd: Path, timeout: int = 30) -> str | None:
    res = run(tool, args, cwd=cwd, timeout=timeout, max_output=4096)
    if not res.ok or res.returncode != 0:
        return None
    text = (res.stdout or res.stderr).strip().splitlines()
    return text[0][:120] if text else None
