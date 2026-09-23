"""Pipeline: discovery -> scanners -> normalize -> dedup -> baseline -> summary.

Each scanner runs in isolation; an exception in one scanner is recorded as a
tool failure (exit code 3 unless blocking findings exist) and the remaining
scanners still run.
"""

from __future__ import annotations

import re
import time
import traceback
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Callable

import yaml

from . import TOOL_NAME, __version__
from .baseline import manager as baseline_manager
from .discovery import discover
from .models import Classification, Confidence, Finding, ScannerRun, Severity, Status, Technology, ToolStatus
from .scanners import ScanContext, configuration, dangerous_code, dependencies, git, secrets
from .severity import (
    conf_rank, count_by_severity, exit_code, is_blocking, rank, release_status, sort_key,
)
from .utils.filesystem import DEFAULT_EXCLUDED_DIRS, DEFAULT_MAX_FILE_SIZE, walk_project
from .scanners import load_rules
from .utils import command
from .utils.redaction import sanitize_evidence, strip_control

SCANNERS: list[tuple[str, str, Callable[[ScanContext], ScannerRun]]] = [
    ("secrets", "Secret scan", secrets.scan),
    ("dangerous_code", "Dangerous-code scan", dangerous_code.scan),
    ("dependencies", "Dependency scan", dependencies.scan),
    ("configuration", "Configuration scan", configuration.scan),
    ("git", "Git scan", git.scan),
]
INLINE_IGNORE = re.compile(r"phase2[:-]ignore\b")
MAX_CONFIG_BYTES = 256 * 1024

GLOBAL_LIMITATIONS = [
    "Static analysis only: no application code, tests, build or install scripts from the target are executed.",
    "No findings does NOT mean the application is secure. Authentication, authorization/IDOR, business logic, "
    "rate limiting and runtime headers require manual review and staging tests (see skills/06-security/*).",
    "Pattern-based findings can be false positives or miss obfuscated/multi-line constructs; verify before acting.",
]


@dataclass
class ScanOptions:
    project: Path
    use_external_tools: bool = True
    baseline_path: Path | None = None
    update_baseline: bool = False
    min_severity: Severity = Severity.INFORMATIONAL
    config_path: Path | None = None
    output_dir: Path | None = None
    verbose: bool = False
    git_history_depth: int = 100
    progress: Callable[[str], None] | None = None


@dataclass
class ScanReport:
    project: dict[str, Any]
    technologies: list[Technology]
    tools: list[ToolStatus]
    scanners: list[dict[str, Any]]
    findings: list[Finding]
    baseline: dict[str, Any] | None
    limitations: list[str]
    configuration: dict[str, Any]
    tool_failure: bool
    generated_at: str = field(default_factory=lambda: datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"))

    @property
    def counts(self) -> dict[str, int]:
        return count_by_severity(self.findings)

    @property
    def blocking(self) -> list[Finding]:
        return [f for f in self.findings if is_blocking(f)]

    @property
    def release_status(self) -> str:
        return release_status(self.findings, self.tool_failure)

    @property
    def exit_code(self) -> int:
        return exit_code(self.findings, self.tool_failure)


class ConfigError(ValueError):
    pass


def load_config(path: Path | None) -> dict[str, Any]:
    """Optional YAML config. Must be passed explicitly; never auto-loaded from the target."""
    if path is None:
        return {}
    if not path.is_file():
        raise ConfigError(f"config file not found: {path}")
    if path.stat().st_size > MAX_CONFIG_BYTES:
        raise ConfigError("config file too large")
    try:
        data = yaml.safe_load(path.read_text(encoding="utf-8")) or {}
    except yaml.YAMLError as exc:
        raise ConfigError(f"invalid YAML in config: {exc.__class__.__name__}") from exc
    if not isinstance(data, dict):
        raise ConfigError("config must be a mapping")
    allowed = {"exclude_dirs", "include_default_excludes", "exclude_paths", "include_build_output", "max_file_size",
               "git_history_depth", "tool_timeout", "disabled_scanners"}
    unknown = set(data) - allowed
    if unknown:
        raise ConfigError("unknown config keys: " + ", ".join(sorted(unknown)))
    for key in ("exclude_dirs", "exclude_paths", "disabled_scanners"):
        if key in data and not (isinstance(data[key], list) and all(isinstance(x, str) for x in data[key])):
            raise ConfigError(f"{key} must be a list of strings")
    for key in ("max_file_size", "git_history_depth", "tool_timeout"):
        if key in data and (not isinstance(data[key], int) or isinstance(data[key], bool) or data[key] < 0):
            raise ConfigError(f"{key} must be a non-negative integer")
    for key in ("include_build_output", "include_default_excludes"):
        if key in data and not isinstance(data[key], bool):
            raise ConfigError(f"{key} must be true/false")
    bad = set(data.get("disabled_scanners", [])) - {s[0] for s in SCANNERS}
    if bad:
        raise ConfigError("unknown scanners in disabled_scanners: " + ", ".join(sorted(bad)))
    return data


# ------------------------------------------------------------------ normalization


_SECRET_RULES: list | None = None


def mask_with_secret_rules(text: str) -> str:
    """Defense in depth (SR-10): mask anything any secret rule matches."""
    global _SECRET_RULES
    if _SECRET_RULES is None:
        _SECRET_RULES = load_rules("secret-patterns.yaml")
    for rule in _SECRET_RULES:
        group = int(rule.get("secret_group", 1))
        spans = [m.span(group) for m in rule["compiled"].finditer(text)]
        for start, end in sorted(spans, reverse=True):
            if start >= 0 and end > start:
                text = text[:start] + "<redacted>" + text[end:]
    return text


def normalize(f: Finding, project_name: str) -> Finding:
    f.project = project_name
    if f.file is not None:
        f.file = strip_control(f.file.replace("\\", "/"))
        while f.file.startswith("./"):
            f.file = f.file[2:]
    if f.line is not None and (not isinstance(f.line, int) or f.line < 1):
        f.line = None
    if f.column is not None and (not isinstance(f.column, int) or f.column < 1):
        f.column = None
    f.severity = Severity(f.severity)
    f.confidence = Confidence(f.confidence)
    f.status = Status(f.status)
    f.classification = Classification(f.classification)
    f.evidence = sanitize_evidence(mask_with_secret_rules(f.evidence[:1000]), 300)
    f.title = strip_control(f.title)[:200]
    f.source = sorted({strip_control(s)[:120] for s in f.source}) or [f.scanner]
    f.notes = [sanitize_evidence(n, 300) for n in f.notes]
    f.context = sanitize_evidence(mask_with_secret_rules(f.context[:1000]), 200)
    return f


def apply_inline_ignores(findings: list[Finding], ctx: ScanContext) -> None:
    for f in findings:
        if f.file is None or f.line is None:
            continue
        entry = ctx.files_by_rel.get(f.file)
        if entry is None:
            continue
        lines = (ctx.text(entry) or "").splitlines()
        if not 0 < f.line <= len(lines) or not INLINE_IGNORE.search(lines[f.line - 1]):
            continue
        if f.severity in (Severity.CRITICAL, Severity.HIGH):
            # SR-03: the author of a change must not be able to silence blocking-level
            # findings in the same change. Use a reviewed baseline instead.
            f.notes.append("Inline phase2:ignore comment present, but CRITICAL/HIGH findings cannot be suppressed inline; use a reviewed baseline.")
            continue
        f.status = Status.IGNORED
        f.notes.append("Suppressed by inline phase2:ignore comment (reviewers should verify the justification).")


def deduplicate(findings: list[Finding]) -> list[Finding]:
    """Merge findings with the same (category, file, line, dedup key). Keep every source."""
    merged: dict[str, Finding] = {}
    order: list[str] = []
    for f in findings:
        f.compute_ids()
        existing = merged.get(f.id)
        if existing is None:
            merged[f.id] = f
            order.append(f.id)
            continue
        if rank(f.severity) > rank(existing.severity):
            existing.severity = f.severity
        if conf_rank(f.confidence) > conf_rank(existing.confidence):
            existing.confidence = f.confidence
        if f.status == Status.OPEN and existing.status == Status.REQUIRES_REVIEW:
            existing.status = Status.OPEN
        existing.source = sorted(set(existing.source) | set(f.source))
        if f.scanner != existing.scanner and f.scanner not in existing.tags:
            existing.tags.append(f"also:{f.scanner}")
        for n in f.notes:
            if n not in existing.notes:
                existing.notes.append(n)
    return [merged[i] for i in order]


# ------------------------------------------------------------------ pipeline


def run_scan(opts: ScanOptions) -> ScanReport:
    progress = opts.progress or (lambda _msg: None)
    root = opts.project.resolve()
    if not root.is_dir():
        raise ConfigError(f"project path is not a directory: {opts.project}")
    cfg = load_config(opts.config_path)
    excluded = set(DEFAULT_EXCLUDED_DIRS) if cfg.get("include_default_excludes", True) else set()
    excluded |= set(cfg.get("exclude_dirs", []))
    max_size = int(cfg.get("max_file_size", DEFAULT_MAX_FILE_SIZE))
    depth = int(cfg.get("git_history_depth", opts.git_history_depth))
    disabled = set(cfg.get("disabled_scanners", []))
    total = len(SCANNERS) + 1

    progress(f"[1/{total}] Project discovery")
    walk = walk_project(
        root, excluded_dirs=excluded, exclude_globs=list(cfg.get("exclude_paths", [])),
        include_build_output=bool(cfg.get("include_build_output", False)), max_file_size=max_size,
    )
    # SR-04: the output directory is NOT excluded (a project could contain a directory
    # with the same name). Generated reports contain only redacted evidence.
    command.set_untrusted_root(root)
    ctx = ScanContext(
        root=root, files=walk.files, use_external_tools=opts.use_external_tools, git_history_depth=depth,
        tool_timeout=int(cfg.get("tool_timeout", 180)), max_file_size=max_size, verbose=opts.verbose,
    )
    ctx.technologies = discover(ctx)

    limitations = list(GLOBAL_LIMITATIONS)
    if walk.skipped_large:
        limitations.append(f"{len(walk.skipped_large)} file(s) larger than {max_size} bytes were not scanned (e.g. {', '.join(walk.skipped_large[:3])}).")
    if walk.skipped_symlinks:
        limitations.append(f"{len(walk.skipped_symlinks)} symlink(s) were not followed.")
    if walk.truncated:
        limitations.append("File limit reached; the scan is incomplete.")
    if not cfg.get("include_build_output", False):
        limitations.append("Build output directories (dist, build, .next, out, ...) were excluded; client bundles were not inspected for secrets.")
    if cfg.get("exclude_paths") or cfg.get("exclude_dirs"):
        limitations.append("Custom exclusions from the config file were applied: " + ", ".join(cfg.get("exclude_dirs", []) + cfg.get("exclude_paths", [])))
    if not cfg.get("include_default_excludes", True):
        limitations.append("Default directory exclusions were disabled by configuration.")

    findings: list[Finding] = []
    tools: list[ToolStatus] = []
    scanner_meta: list[dict[str, Any]] = []
    tool_failure = False
    for i, (name, label, fn) in enumerate(SCANNERS, start=2):
        progress(f"[{i}/{total}] {label}")
        if name in disabled:
            scanner_meta.append({"name": name, "status": "disabled", "findings": 0, "duration_seconds": 0.0, "errors": []})
            limitations.append(f"Scanner '{name}' was disabled by configuration.")
            continue
        started = time.monotonic()
        try:
            result = fn(ctx)
        except Exception as exc:  # noqa: BLE001 - a crashing scanner must not abort the audit
            result = ScannerRun(name, errors=[f"{exc.__class__.__name__}: {sanitize_evidence(str(exc), 200)}"])
            if opts.verbose:
                result.errors.append(sanitize_evidence(traceback.format_exc(limit=3), 400))
        result.duration_seconds = round(time.monotonic() - started, 3)
        tool_failure = tool_failure or result.failed
        findings.extend(result.findings)
        tools.extend(result.tools)
        for lim in result.limitations:
            if lim not in limitations:
                limitations.append(lim)
        scanner_meta.append(
            {
                "name": name,
                "status": "failed" if result.failed else "completed",
                "findings": len(result.findings),
                "duration_seconds": result.duration_seconds,
                "errors": result.errors + [f"{t.name}: {t.detail}" for t in result.tools if t.failed],
            }
        )

    project_name = root.name
    findings = [normalize(f, project_name) for f in findings]
    apply_inline_ignores(findings, ctx)
    findings = deduplicate(findings)

    baseline_info = None
    if opts.baseline_path is not None:
        entries = baseline_manager.load(opts.baseline_path)
        result = baseline_manager.apply(findings, entries, str(opts.baseline_path))
        if opts.update_baseline:
            written, skipped = baseline_manager.write(opts.baseline_path, findings, entries)
            result_dict = result.to_dict() | {"updated": True, "written": written, "critical_not_baselined": skipped}
        else:
            result_dict = result.to_dict() | {"updated": False}
        baseline_info = result_dict

    findings.sort(key=sort_key)
    return ScanReport(
        project={"name": project_name, "path": str(root), "files_scanned": len(walk.files),
                 "git_repository": ctx.cache.get("git_toplevel") is not None},
        technologies=ctx.technologies,
        tools=tools,
        scanners=scanner_meta,
        findings=findings,
        baseline=baseline_info,
        limitations=limitations,
        configuration={
            "external_tools": opts.use_external_tools, "config_file": str(opts.config_path) if opts.config_path else None,
            "min_report_severity": opts.min_severity.value, "git_history_depth": depth, "max_file_size": max_size,
            "include_build_output": bool(cfg.get("include_build_output", False)),
        },
        tool_failure=tool_failure,
    )


def reported_findings(report: ScanReport, min_severity: Severity) -> list[Finding]:
    """Findings shown in reports. Filtering never affects counts, status or exit code."""
    return [f for f in report.findings if rank(f.severity) >= rank(min_severity)]


def tool_info() -> dict[str, str]:
    return {"name": TOOL_NAME, "version": __version__}
