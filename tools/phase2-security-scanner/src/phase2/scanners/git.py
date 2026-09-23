"""Git scanner: tracked sensitive files, recent history secrets, large files,
lockfile-only dependency changes.

Only read-only Git plumbing is used (rev-parse, ls-files, check-ignore, log).
Repository-local config that could execute commands is neutralised by
``command.GIT_SAFE_CONFIG`` and ``--no-ext-diff --no-textconv``. History
contents are never written to findings: only commit hashes, paths and rule IDs.
History is never rewritten.
"""

from __future__ import annotations

import re
from collections import defaultdict
from pathlib import PurePosixPath

from ..models import Classification, Confidence, FileEntry, Finding, ScannerRun, Severity, Status, ToolStatus
from ..utils import command
from . import ScanContext, load_rules
from . import secrets as secret_scanner

NAME = "git"
LARGE_FILE = 5 * 1024 * 1024
MAX_HISTORY_OUTPUT = 48 * 1024 * 1024

ENV_NAME = re.compile(r"(^|/)\.env(\.[\w.-]+)?$|(^|/)[\w.-]+\.env$")
ENV_TEMPLATE = re.compile(r"\.(example|sample|template|dist|defaults?)$", re.I)
KEY_FILES = re.compile(r"(^|/)(id_rsa|id_dsa|id_ecdsa|id_ed25519)$|\.(pem|key|p12|pfx|jks|keystore|ppk|asc)$", re.I)
CRED_FILES = re.compile(
    r"(^|/)(\.npmrc|\.pypirc|\.netrc|_netrc|\.htpasswd|\.git-credentials|credentials(\.json)?|service[-_]?account[\w.-]*\.json|"
    r"\.dockercfg|\.docker/config\.json|terraform\.tfstate(\.backup)?|[\w.-]+\.tfvars|\.aws/credentials|secrets?\.(ya?ml|json|toml))$",
    re.I,
)
LOCK_TO_MANIFEST = {
    "package-lock.json": "package.json", "pnpm-lock.yaml": "package.json", "yarn.lock": "package.json",
    "poetry.lock": "pyproject.toml", "uv.lock": "pyproject.toml", "Cargo.lock": "Cargo.toml", "go.sum": "go.mod",
}


def _git(ctx: ScanContext, args: list[str], max_output: int = command.DEFAULT_MAX_OUTPUT) -> command.CommandResult:
    return command.run("git", args, cwd=ctx.root, timeout=ctx.tool_timeout, max_output=max_output)


def repo_info(ctx: ScanContext) -> str | None:
    """Return the repository top-level path, or None if not a usable Git repository."""
    if "git_toplevel" in ctx.cache:
        return ctx.cache["git_toplevel"]
    top = None
    reason = ""
    if command.which("git") is None:
        reason = "git not installed"
    else:
        res = _git(ctx, ["rev-parse", "--show-toplevel"], max_output=65536)
        if res.ok and res.returncode == 0 and res.stdout.strip():
            top = res.stdout.strip()
        else:
            reason = "dubious ownership (safe.directory)" if "dubious ownership" in res.stderr else "not a Git repository"
    ctx.cache["git_toplevel"] = top
    ctx.cache["git_reason"] = reason
    return top


def tracked_files(ctx: ScanContext) -> set[str]:
    if "git_tracked" not in ctx.cache:
        res = _git(ctx, ["-c", "core.quotePath=false", "ls-files", "-z"])
        ctx.cache["git_tracked"] = set(filter(None, res.stdout.split("\x00"))) if res.ok and res.returncode == 0 else set()
    return ctx.cache["git_tracked"]


def is_tracked(ctx: ScanContext, rel: str) -> bool:
    return rel in tracked_files(ctx)


def is_ignored(ctx: ScanContext, rel: str) -> bool | None:
    res = _git(ctx, ["check-ignore", "-q", "--no-index", "--", rel], max_output=4096)
    if not res.ok:
        return None
    if res.returncode == 0:
        return True
    if res.returncode == 1:
        return False
    return None


def _file_finding(rel: str, title: str, severity: Severity, description: str, rule_id: str, evidence: str, confidence: Confidence = Confidence.HIGH) -> Finding:
    return Finding(
        scanner=NAME, category="secret-exposure", severity=severity, confidence=confidence, title=title,
        description=description, file=rel, evidence=evidence,
        impact="Everyone with repository access (and every clone/fork/CI cache) has a copy, including in history.",
        recommendation=(
            "Remove the file from the index (`git rm --cached <file>`), add it to .gitignore, and rotate any credentials it "
            "contains. If it was ever pushed, plan a history cleanup (git filter-repo / BFG) with the repository owner - "
            "this scanner never rewrites history."
        ),
        validation="`git ls-files <file>` returns nothing and the rotated credential is the only valid one.",
        cwe="CWE-538", owasp="A05:2021-Security Misconfiguration", source=[f"git:{rule_id}"],
        classification=Classification.CONFIRMED, rule_id=rule_id, dedup_key=rule_id,
    )


def check_tracked(ctx: ScanContext, run: ScannerRun) -> None:
    by_rel = ctx.files_by_rel
    for rel in sorted(tracked_files(ctx)):
        if ENV_NAME.search(rel) and not ENV_TEMPLATE.search(rel):
            run.findings.append(_file_finding(rel, "Environment file tracked in Git", Severity.HIGH,
                                              "An environment file is committed to the repository.", "git-tracked-env", "Tracked by Git: yes"))
        elif KEY_FILES.search(rel):
            entry = by_rel.get(rel)
            text = ctx.text(entry) if entry else None
            if rel.lower().endswith((".pem", ".key", ".asc")) and text is not None and "PRIVATE KEY" not in text:
                continue  # certificate / public key only
            run.findings.append(_file_finding(rel, "Private key or keystore tracked in Git", Severity.HIGH,
                                              "A private key or keystore file is committed.", "git-tracked-key", "Tracked by Git: yes (key/keystore filename)"))
        elif CRED_FILES.search(rel):
            entry = by_rel.get(rel)
            text = (ctx.text(entry) if entry else None) or ""
            name = PurePosixPath(rel).name.lower()
            if name == ".npmrc" and "_authtoken" not in text.lower() and "_password" not in text.lower():
                continue
            if name.endswith(".json") and "service" in name and "private_key" not in text:
                continue
            run.findings.append(_file_finding(rel, "Credential or state file tracked in Git", Severity.MEDIUM,
                                              "A file type that commonly contains credentials is committed.", "git-tracked-credential-file",
                                              "Tracked by Git: yes (credential/state filename)", Confidence.MEDIUM))
        entry = by_rel.get(rel)
        size = entry.size if entry else None
        if size is None:
            try:
                size = (ctx.root / rel).lstat().st_size
            except OSError:
                size = 0
        if size > LARGE_FILE:
            run.findings.append(
                Finding(
                    scanner=NAME, category="repository-hygiene", severity=Severity.LOW, confidence=Confidence.HIGH,
                    title="Large file tracked in Git", description=f"Tracked file is {size // (1024 * 1024)} MiB.",
                    file=rel, evidence=f"size={size} bytes",
                    impact="Large blobs are often database dumps, archives or build artifacts that may contain sensitive data.",
                    recommendation="Confirm the file is intended; move artifacts/dumps out of Git (or to Git LFS) and check contents for data.",
                    validation="Review the file contents and origin.", cwe="CWE-538", source=["git:large-file"],
                    status=Status.REQUIRES_REVIEW, classification=Classification.INFORMATIONAL,
                    rule_id="git-large-file", dedup_key="git-large-file",
                )
            )


def check_history(ctx: ScanContext, run: ScannerRun) -> None:
    if ctx.git_history_depth <= 0:
        run.limitations.append("Git history scan disabled (depth 0).")
        return
    rules = load_rules("secret-patterns.yaml", ctx.rules_dir)
    res = _git(
        ctx,
        ["-c", "core.quotePath=false", "log", f"--max-count={int(ctx.git_history_depth)}", "--relative", "-p",
         "--unified=0", "--no-ext-diff", "--no-textconv", "--no-color", "--no-show-signature", "--diff-filter=AM",
         "--format=%x00commit %H", "--", "."],
        max_output=MAX_HISTORY_OUTPUT,
    )
    if not res.ok or res.returncode != 0:
        if "does not have any commits" in res.stderr:
            return
        raise RuntimeError("git log failed" + (" (timeout)" if res.timed_out else ""))
    if res.truncated:
        run.limitations.append("Git history output exceeded the size cap; older commits in the window were not fully scanned.")

    added: dict[tuple[str, str], list[str]] = defaultdict(list)
    commit, path = None, None
    for line in res.stdout.split("\n"):
        if line.startswith("\x00commit "):
            commit, path = line[8:].strip(), None
        elif line.startswith("+++ "):
            target = line[4:]
            path = target[2:] if target.startswith("b/") else None
        elif line.startswith("+") and commit and path:
            added[(commit, path)].append(line[1:])

    hits: dict[tuple[str, str], dict] = {}
    for (commit, path), lines in added.items():
        name = PurePosixPath(path).name.lower()
        if name in secret_scanner.SKIP_FILES or name.endswith(secret_scanner.SKIP_SUFFIXES):
            continue
        fake = FileEntry(rel=path, path=ctx.root / path, size=0)
        for f in secret_scanner.scan_text(fake, "\n".join(lines), rules, scanner=NAME):
            if f.severity in (Severity.INFORMATIONAL,) or f.confidence == Confidence.LOW:
                continue
            key = (path, f.dedup_key)
            h = hits.setdefault(key, {"commits": [], "severity": f.severity, "rule": f.rule_id, "title": f.title})
            if commit[:10] not in h["commits"]:
                h["commits"].append(commit[:10])

    for (path, kind), h in sorted(hits.items()):
        entry = ctx.files_by_rel.get(path)
        still_present = False
        if entry is not None:
            current = ctx.text(entry) or ""
            still_present = any(f.dedup_key == kind for f in secret_scanner.scan_text(entry, current, rules))
        run.findings.append(
            Finding(
                scanner=NAME, category="secret-history", severity=h["severity"], confidence=Confidence.MEDIUM,
                title="Potential secret exposure in Git history",
                description=f"A value matching '{h['title']}' was added to {path} in recent history.",
                file=path,
                evidence=f"Rule {h['rule']} matched in {len(h['commits'])} commit(s): {', '.join(h['commits'][:5])}. Value redacted.",
                impact="Removing a secret from the current files does not remove it from Git history, clones, forks or CI caches.",
                recommendation=(
                    "Assume the credential is compromised: revoke/rotate it first. Then, with the repository owner's approval, "
                    "consider history cleanup (git filter-repo/BFG) and force-push coordination. This scanner does not rewrite history."
                ),
                validation="Confirm the old credential is rejected by the provider; re-run the history scan.",
                cwe="CWE-798", owasp="A07:2021-Identification and Authentication Failures", source=[f"git-history:{h['rule']}"],
                classification=Classification.POTENTIAL, rule_id=f"git-history:{h['rule']}", dedup_key=f"history:{kind}",
                notes=["Still present in the working tree." if still_present else "Not found in the current working tree (history only)."],
            )
        )


def check_lockfile_changes(ctx: ScanContext, run: ScannerRun) -> None:
    res = _git(ctx, ["-c", "core.quotePath=false", "log", "--max-count=50", "--relative", "--name-only", "--no-renames", "--no-show-signature", "--format=%x00%H", "--", "."])
    if not res.ok or res.returncode != 0:
        return
    suspicious: list[str] = []
    for block in res.stdout.split("\x00")[1:]:
        lines = [l for l in block.strip().split("\n") if l]
        if not lines:
            continue
        sha, files = lines[0], set(lines[1:])
        for f in files:
            p = PurePosixPath(f)
            manifest = LOCK_TO_MANIFEST.get(p.name)
            if manifest and str(p.with_name(manifest)).replace("\\", "/") not in files:
                suspicious.append(f"{sha[:10]} ({f})")
    if suspicious:
        run.findings.append(
            Finding(
                scanner=NAME, category="dependency", severity=Severity.INFORMATIONAL, confidence=Confidence.MEDIUM,
                title="Lockfile changed without manifest change",
                description="Recent commits modified a lockfile without touching its manifest. This is normal for dependency updates but is also how unexpected dependency swaps slip in.",
                file=None, evidence="Commits: " + "; ".join(suspicious[:10]),
                impact="Unreviewed transitive dependency changes can introduce vulnerable or malicious packages.",
                recommendation="Review lockfile diffs for new packages, changed 'resolved' URLs and integrity hashes.",
                validation="Inspect each listed commit's lockfile diff.", source=["git:lockfile-changes"],
                status=Status.REQUIRES_REVIEW, classification=Classification.INFORMATIONAL,
                rule_id="git-lockfile-only-change", dedup_key="git-lockfile-only-change",
                owasp="A08:2021-Software and Data Integrity Failures",
            )
        )


def scan(ctx: ScanContext) -> ScannerRun:
    run = ScannerRun(NAME)
    status = ToolStatus("git", available=command.which("git") is not None)
    run.tools.append(status)
    if not status.available:
        status.detail = "not installed"
        run.limitations.append("git not installed: tracked-file and history checks skipped.")
        return run
    status.version = command.tool_version("git", ["--version"], ctx.root)
    top = repo_info(ctx)
    if top is None:
        status.detail = ctx.cache.get("git_reason", "not a Git repository")
        run.limitations.append(f"Git checks skipped: {status.detail}.")
        return run
    status.used = True
    status.detail = f"repository detected; history depth {ctx.git_history_depth} commits"
    check_tracked(ctx, run)
    try:
        check_history(ctx, run)
    except RuntimeError as exc:
        status.failed = True
        status.detail += f"; history scan failed: {exc}"
    check_lockfile_changes(ctx, run)
    run.limitations.append(
        f"Git history scan covers the most recent {ctx.git_history_depth} commits reachable from HEAD only "
        "(not other branches, stashes, or unreachable objects). Large blobs in history are not measured."
    )
    return run
