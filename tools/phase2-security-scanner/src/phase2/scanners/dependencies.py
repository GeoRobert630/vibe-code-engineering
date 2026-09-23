"""Dependency and supply-chain scanner (skills/06-security/11-dependency-supply-chain).

Local analysis (always):
  * manifest/lockfile presence and consistency (npm, pnpm, yarn, poetry, uv)
  * non-registry and insecure dependency sources
  * install/lifecycle scripts in package.json and packages flagged hasInstallScript
  * imported-but-undeclared JS packages (phantom / possibly hallucinated deps)
  * risky pip options (--extra-index-url, --trusted-host, http index)

External audit tools (only when installed and allowed):
  npm audit, pnpm audit, pip-audit, cargo-audit, govulncheck

Vulnerability data comes *only* from those tools. This module never invents
CVEs, advisories, affected ranges or fixed versions.
"""

from __future__ import annotations

import json
import re
import tomllib
from collections import defaultdict
from pathlib import Path, PurePosixPath
from typing import Any

import yaml

from ..discovery import normalize_py_name, pyproject_dependency_names, python_requirement_names
from ..models import Classification, Confidence, FileEntry, Finding, ScannerRun, Severity, Status, ToolStatus
from ..utils import command
from ..utils.redaction import sanitize_evidence
from . import ScanContext, load_json_file

NAME = "dependencies"
OWASP_VULN = "A06:2021-Vulnerable and Outdated Components"
OWASP_INTEGRITY = "A08:2021-Software and Data Integrity Failures"
MAX_LOCKFILE = 30 * 1024 * 1024

NODE_LOCKS = ("package-lock.json", "npm-shrinkwrap.json", "pnpm-lock.yaml", "yarn.lock")
PY_LOCKS = ("poetry.lock", "uv.lock", "pdm.lock", "pipfile.lock")
TRUSTED_REGISTRIES = ("https://registry.npmjs.org/", "https://registry.yarnpkg.com/")
INSTALL_HOOKS = ("preinstall", "install", "postinstall", "prepare", "prepublish", "preprepare", "postprepare")
SUSPICIOUS_SCRIPT = re.compile(
    r"\b(?:curl|wget|Invoke-WebRequest|iwr|powershell|bash\s+-c|sh\s+-c|node\s+-e|python\s+-c|eval|base64|nc\s|netcat)\b|https?://|\|\s*(?:ba)?sh\b",
    re.I,
)
NON_REGISTRY_SPEC = re.compile(r"^(?:git\+|git:|github:|gitlab:|bitbucket:|https?:|file:|link:|[\w.-]+/[\w.-]+(?:#.*)?$)")
SEVERITY_MAP = {
    "critical": Severity.CRITICAL,
    "high": Severity.HIGH,
    "moderate": Severity.MEDIUM,
    "medium": Severity.MEDIUM,
    "low": Severity.LOW,
    "info": Severity.INFORMATIONAL,
}
NODE_BUILTINS = frozenset(
    "assert async_hooks buffer child_process cluster console constants crypto dgram diagnostics_channel dns domain "
    "events fs http http2 https inspector module net os path perf_hooks process punycode querystring readline repl "
    "stream string_decoder sys timers tls trace_events tty url util v8 vm wasi worker_threads zlib test".split()
)
JS_IMPORT = re.compile(
    r"""(?:\bfrom\s+|\bimport\s+|\brequire\s*\(\s*|\bimport\s*\(\s*)(['"])([^'"\s]+)\1"""
)
JS_SOURCE_EXT = frozenset({".js", ".jsx", ".ts", ".tsx", ".mjs", ".cjs"})
_SAFE_FILENAME = re.compile(r"^[A-Za-z0-9._-]+$")


def _finding(**kw: Any) -> Finding:
    kw.setdefault("scanner", NAME)
    kw.setdefault("category", "dependency")
    kw.setdefault("source", ["internal:dependencies"])
    kw.setdefault("owasp", OWASP_INTEGRITY)
    return Finding(**kw)


def _parent(rel: str) -> str:
    parent = PurePosixPath(rel).parent.as_posix()
    return "" if parent == "." else parent


def _join(directory: str, name: str) -> str:
    return f"{directory}/{name}" if directory else name


# ================================================================ Node


def package_json_deps(pkg: dict) -> dict[str, str]:
    deps: dict[str, str] = {}
    for key in ("dependencies", "devDependencies", "optionalDependencies", "peerDependencies"):
        section = pkg.get(key)
        if isinstance(section, dict):
            deps.update({str(k): str(v) for k, v in section.items()})
    return deps


def _lock_root_names(lock: dict) -> set[str] | None:
    packages = lock.get("packages")
    if isinstance(packages, dict):
        names = set()
        root = packages.get("", {})
        if isinstance(root, dict):
            for key in ("dependencies", "devDependencies", "optionalDependencies", "peerDependencies"):
                if isinstance(root.get(key), dict):
                    names.update(root[key])
        for path in packages:
            if path.startswith("node_modules/") and "/node_modules/" not in path[len("node_modules/"):]:
                names.add(path[len("node_modules/"):])
        return names
    deps = lock.get("dependencies")
    if isinstance(deps, dict):
        return set(deps)
    return None


def _yarn_lock_names(text: str) -> set[str]:
    names = set()
    for line in text.splitlines():
        if not line or line[0] in " #":
            continue
        for spec in line.rstrip(":").split(","):
            spec = spec.strip().strip('"')
            if not spec:
                continue
            at = spec.rfind("@")
            name = spec[:at] if at > 0 else spec
            names.add(name)
    return names


def _pnpm_lock_names(data: Any) -> set[str] | None:
    if not isinstance(data, dict):
        return None
    names: set[str] = set()
    importers = data.get("importers")
    sections = []
    if isinstance(importers, dict) and isinstance(importers.get("."), dict):
        sections.append(importers["."])
    sections.append(data)
    for sec in sections:
        for key in ("dependencies", "devDependencies", "optionalDependencies"):
            if isinstance(sec.get(key), dict):
                names.update(sec[key])
    return names


def check_node_project(ctx: ScanContext, pkg_entry: FileEntry, run: ScannerRun, workspace_names: set[str], ancestor_deps: set[str]) -> None:
    pkg = load_json_file(ctx, pkg_entry)
    directory = _parent(pkg_entry.rel)
    if not isinstance(pkg, dict):
        run.findings.append(
            _finding(
                severity=Severity.LOW, confidence=Confidence.HIGH, title="package.json could not be parsed",
                description="The manifest is not valid JSON, so dependency analysis was skipped for it.",
                file=pkg_entry.rel, evidence="JSON parse failed", recommendation="Fix the manifest syntax.",
                validation="Run `npm pkg get name` in that directory.", status=Status.REQUIRES_REVIEW,
                classification=Classification.INFORMATIONAL, rule_id="dep-manifest-invalid",
            )
        )
        return
    deps = package_json_deps(pkg)
    present = {name: ctx.files_by_rel.get(_join(directory, name)) for name in NODE_LOCKS}
    locks = {name: e for name, e in present.items() if e is not None}
    is_workspace_member = bool(ancestor_deps) or any(
        ctx.files_by_rel.get(_join(p, lock)) for p in _ancestors(directory) for lock in NODE_LOCKS
    )

    if deps and not locks and not is_workspace_member:
        run.findings.append(
            _finding(
                severity=Severity.LOW, confidence=Confidence.HIGH, title="No Node.js lockfile",
                description="package.json declares dependencies but no package-lock.json, pnpm-lock.yaml or yarn.lock was found.",
                file=pkg_entry.rel, evidence=f"{len(deps)} declared dependencies, no lockfile",
                impact="Installs are not reproducible; a compromised or unexpected new version can be pulled silently.",
                recommendation="Commit a lockfile and install with `npm ci` / `pnpm install --frozen-lockfile` in CI.",
                validation="Confirm CI fails when the lockfile is out of date.",
                classification=Classification.CONFIRMED, rule_id="dep-no-lockfile",
            )
        )
    if len(locks) > 1:
        run.findings.append(
            _finding(
                severity=Severity.LOW, confidence=Confidence.HIGH, title="Multiple Node.js lockfiles",
                description="More than one package manager lockfile exists; they can resolve different versions.",
                file=pkg_entry.rel, evidence="Lockfiles: " + ", ".join(sorted(locks)),
                recommendation="Keep exactly one lockfile for the package manager actually used in CI.",
                validation="Verify CI uses the same package manager as the retained lockfile.",
                classification=Classification.CONFIRMED, rule_id="dep-multiple-lockfiles",
            )
        )

    # ---- declared specs
    odd_sources = [f"{n}@{v}" for n, v in deps.items() if NON_REGISTRY_SPEC.match(v) and not v.startswith("workspace:")]
    if odd_sources:
        run.findings.append(
            _finding(
                severity=Severity.MEDIUM, confidence=Confidence.MEDIUM, title="Dependencies installed from non-registry sources",
                description="Git, URL, GitHub shorthand or local file dependencies bypass registry integrity metadata and review.",
                file=pkg_entry.rel, evidence=sanitize_evidence("; ".join(odd_sources[:10])),
                impact="The code fetched can change without a version bump and is not covered by registry advisories.",
                recommendation="Prefer published registry versions, or pin git dependencies to a full commit SHA.",
                validation="Check each listed source and confirm it is pinned and trusted.",
                status=Status.REQUIRES_REVIEW, rule_id="dep-non-registry-source",
            )
        )
    loose = [n for n, v in deps.items() if v.strip() in ("*", "latest", "", "x")]
    if loose:
        run.findings.append(
            _finding(
                severity=Severity.LOW, confidence=Confidence.HIGH, title="Unbounded dependency versions",
                description="Dependencies using '*', 'latest' or an empty range accept any future version.",
                file=pkg_entry.rel, evidence=", ".join(loose[:15]),
                recommendation="Use explicit semver ranges and rely on the lockfile.",
                validation="Re-run after pinning.", classification=Classification.CONFIRMED, rule_id="dep-unbounded-version",
            )
        )

    # ---- lifecycle scripts
    scripts = pkg.get("scripts") if isinstance(pkg.get("scripts"), dict) else {}
    for hook in INSTALL_HOOKS:
        body = scripts.get(hook)
        if not isinstance(body, str):
            continue
        suspicious = bool(SUSPICIOUS_SCRIPT.search(body))
        run.findings.append(
            _finding(
                severity=Severity.MEDIUM if suspicious else Severity.INFORMATIONAL,
                confidence=Confidence.MEDIUM if suspicious else Confidence.HIGH,
                title=f"Install lifecycle script '{hook}'" + (" downloads or evaluates code" if suspicious else ""),
                description="Lifecycle scripts run automatically on install for anyone installing this package.",
                file=pkg_entry.rel, evidence=sanitize_evidence(f"scripts.{hook}: {body}", 160),
                impact="A malicious or compromised install script runs with the installing user's privileges (developer laptops, CI).",
                recommendation="Review the script; avoid network downloads/eval in install hooks; run installs with --ignore-scripts where possible.",
                validation="Run `npm install --ignore-scripts` and confirm the project still builds.",
                status=Status.REQUIRES_REVIEW,
                classification=Classification.POTENTIAL if suspicious else Classification.INFORMATIONAL,
                rule_id="dep-install-script",
            )
        )

    # ---- lockfile consistency
    if "package-lock.json" in locks or "npm-shrinkwrap.json" in locks:
        entry = locks.get("package-lock.json") or locks["npm-shrinkwrap.json"]
        lock = load_json_file(ctx, entry) if entry.size <= MAX_LOCKFILE else None
        if not isinstance(lock, dict):
            run.limitations.append(f"{entry.rel}: could not be parsed (invalid JSON or larger than size limit).")
        else:
            _check_lock_sync(run, pkg_entry, entry, deps, _lock_root_names(lock))
            _check_package_lock_details(run, entry, lock)
    if "pnpm-lock.yaml" in locks:
        entry = locks["pnpm-lock.yaml"]
        text = ctx.text(entry)
        data = None
        if text is not None:
            try:
                data = yaml.safe_load(text)
            except (yaml.YAMLError, RecursionError):
                data = None
        names = _pnpm_lock_names(data)
        if names is None:
            run.limitations.append(f"{entry.rel}: could not be parsed.")
        else:
            _check_lock_sync(run, pkg_entry, entry, deps, names)
    if "yarn.lock" in locks:
        entry = locks["yarn.lock"]
        _check_lock_sync(run, pkg_entry, entry, deps, _yarn_lock_names(ctx.text(entry) or ""))

    # ---- imported but undeclared
    declared = set(deps) | ancestor_deps | workspace_names | {str(pkg.get("name", ""))}
    _check_undeclared_imports(ctx, run, pkg_entry, directory, declared)


def _ancestors(directory: str) -> list[str]:
    if not directory:
        return []
    parts = directory.split("/")
    return ["/".join(parts[:i]) for i in range(len(parts) - 1, -1, -1)]


def _check_lock_sync(run: ScannerRun, pkg_entry: FileEntry, lock_entry: FileEntry, deps: dict[str, str], lock_names: set[str] | None) -> None:
    if lock_names is None:
        return
    missing = sorted(n for n, v in deps.items() if n not in lock_names and not v.startswith(("workspace:", "link:", "file:")))
    if missing:
        run.findings.append(
            _finding(
                severity=Severity.MEDIUM, confidence=Confidence.HIGH, title="Lockfile out of sync with package.json",
                description=f"Dependencies declared in {pkg_entry.rel} are missing from {lock_entry.rel}.",
                file=lock_entry.rel, evidence="Missing from lockfile: " + ", ".join(missing[:15]),
                impact="CI installs may resolve unreviewed versions, or frozen installs fail; the audit result may not reflect what is deployed.",
                recommendation="Regenerate the lockfile with the project's package manager and review the diff.",
                validation="`npm ci` / `pnpm install --frozen-lockfile` / `yarn install --immutable` succeeds.",
                classification=Classification.CONFIRMED, rule_id="dep-lockfile-out-of-sync",
            )
        )


def _check_package_lock_details(run: ScannerRun, entry: FileEntry, lock: dict) -> None:
    packages = lock.get("packages")
    if not isinstance(packages, dict):
        return
    insecure, foreign, scripts, no_integrity = [], [], [], []
    for path, meta in packages.items():
        if not path or not isinstance(meta, dict) or meta.get("link"):
            continue
        name = path.rsplit("node_modules/", 1)[-1]
        resolved = meta.get("resolved")
        if isinstance(resolved, str):
            if resolved.startswith("http://"):
                insecure.append(name)
            elif not resolved.startswith(TRUSTED_REGISTRIES):
                foreign.append(name)
            elif not meta.get("integrity"):
                no_integrity.append(name)
        if meta.get("hasInstallScript"):
            scripts.append(name)
    if insecure:
        run.findings.append(
            _finding(
                severity=Severity.HIGH, confidence=Confidence.HIGH, title="Dependencies resolved over plain HTTP",
                description="Lockfile entries download packages over unencrypted HTTP.",
                file=entry.rel, evidence="Packages: " + ", ".join(sorted(set(insecure))[:15]),
                impact="A network attacker can substitute package contents during install (code execution in CI/production builds).",
                recommendation="Use an HTTPS registry and regenerate the lockfile.",
                validation="grep the lockfile for 'http://' after regeneration.", classification=Classification.CONFIRMED,
                rule_id="dep-insecure-resolved",
            )
        )
    if foreign:
        run.findings.append(
            _finding(
                severity=Severity.LOW, confidence=Confidence.MEDIUM, title="Dependencies resolved from non-default sources",
                description="Some packages resolve from a source other than the public npm registry (private registry, git or tarball URL).",
                file=entry.rel, evidence="Packages: " + ", ".join(sorted(set(foreign))[:15]),
                impact="Legitimate for private registries; otherwise may indicate dependency confusion or an unreviewed source.",
                recommendation="Confirm each source is an approved registry or a pinned, trusted repository.",
                validation="Review the 'resolved' URLs in the lockfile.", status=Status.REQUIRES_REVIEW,
                rule_id="dep-foreign-resolved",
            )
        )
    if no_integrity:
        run.findings.append(
            _finding(
                severity=Severity.LOW, confidence=Confidence.MEDIUM, title="Lockfile entries without integrity hashes",
                description="Registry packages lack an 'integrity' field, so tampering is not detected at install time.",
                file=entry.rel, evidence="Packages: " + ", ".join(sorted(set(no_integrity))[:15]),
                recommendation="Regenerate the lockfile with a current npm version.",
                validation="Every registry entry has an integrity value.", rule_id="dep-missing-integrity",
            )
        )
    if scripts:
        run.findings.append(
            _finding(
                severity=Severity.INFORMATIONAL, confidence=Confidence.HIGH, title="Installed packages with install scripts",
                description="These packages run lifecycle scripts during installation.",
                file=entry.rel, evidence=f"{len(set(scripts))} packages: " + ", ".join(sorted(set(scripts))[:20]),
                impact="Install scripts are a common supply-chain attack vector.",
                recommendation="Review why each package needs install scripts; consider `--ignore-scripts` with an allowlist.",
                validation="Build succeeds with scripts disabled except for allowlisted packages.",
                status=Status.REQUIRES_REVIEW, classification=Classification.INFORMATIONAL, rule_id="dep-transitive-install-scripts",
            )
        )


def _import_package_name(spec: str) -> str | None:
    if spec.startswith((".", "/", "~", "#", "node:", "@/", "$", "virtual:", "http:", "https:", "data:")) or "\\" in spec:
        return None
    parts = spec.split("/")
    if spec.startswith("@"):
        return "/".join(parts[:2]) if len(parts) >= 2 else None
    return parts[0]


def _tsconfig_aliases(ctx: ScanContext, directory: str) -> list[str]:
    prefixes: list[str] = []
    for name in ("tsconfig.json", "jsconfig.json"):
        entry = ctx.files_by_rel.get(_join(directory, name))
        if entry is None:
            continue
        text = ctx.text(entry) or ""
        # tsconfig allows comments; pull alias keys with a regex instead of strict JSON.
        block = re.search(r'"paths"\s*:\s*\{(.*?)\}\s*[,}]', text, re.S)
        if block:
            prefixes.extend(k.rstrip("*").rstrip("/") for k in re.findall(r'"([^"]+)"\s*:', block.group(1)))
    return [p for p in prefixes if p]


def _check_undeclared_imports(ctx: ScanContext, run: ScannerRun, pkg_entry: FileEntry, directory: str, declared: set[str]) -> None:
    aliases = _tsconfig_aliases(ctx, directory)
    prefix = directory + "/" if directory else ""
    undeclared: dict[str, str] = {}
    for entry in ctx.files:
        if entry.suffix not in JS_SOURCE_EXT or entry.build_output or not entry.rel.startswith(prefix):
            continue
        # Skip files that belong to a nested package.json.
        sub = entry.rel[len(prefix):]
        if any(ctx.files_by_rel.get(_join(prefix + "/".join(sub.split("/")[:i]), "package.json")) for i in range(1, sub.count("/") + 1)):
            continue
        for m in JS_IMPORT.finditer(ctx.text(entry) or ""):
            spec = m.group(2)
            if any(spec == a or spec.startswith(a + "/") for a in aliases):
                continue
            name = _import_package_name(spec)
            if not name or name in NODE_BUILTINS or name in declared or name.startswith("@types/"):
                continue
            if not re.fullmatch(r"(?:@[a-z0-9][\w.-]*/)?[a-z0-9][\w.-]*", name):
                continue
            undeclared.setdefault(name, entry.rel)
    if undeclared:
        items = sorted(undeclared.items())
        run.findings.append(
            _finding(
                severity=Severity.LOW, confidence=Confidence.MEDIUM, title="Imported packages not declared in package.json",
                description="Source files import packages that are not declared as dependencies (phantom dependencies).",
                file=pkg_entry.rel,
                evidence=sanitize_evidence("; ".join(f"{n} (first seen in {f})" for n, f in items[:10])),
                impact="Undeclared packages resolve from whatever happens to be installed, and names suggested by AI tools may not exist or may be squatted.",
                recommendation="Verify each package name on the official registry before adding it explicitly to package.json.",
                validation="Install in a clean checkout with a frozen lockfile and run the build.",
                status=Status.REQUIRES_REVIEW, rule_id="dep-undeclared-import",
            )
        )


# ================================================================ Python


def check_python(ctx: ScanContext, run: ScannerRun) -> None:
    for entry in ctx.files:
        name = entry.name.lower()
        if entry.build_output:
            continue
        if name.startswith("requirements") and name.endswith(".txt"):
            _check_requirements(ctx, run, entry)
        elif name == "pyproject.toml":
            _check_pyproject(ctx, run, entry)


def _check_requirements(ctx: ScanContext, run: ScannerRun, entry: FileEntry) -> None:
    text = ctx.text(entry) or ""
    unpinned, urls = [], []
    for lineno, raw in enumerate(text.splitlines(), start=1):
        line = raw.split(" #", 1)[0].strip()
        if not line or line.startswith("#"):
            continue
        low = line.lower()
        if low.startswith("--extra-index-url"):
            run.findings.append(
                _finding(
                    severity=Severity.MEDIUM, confidence=Confidence.HIGH, title="pip --extra-index-url enables dependency confusion",
                    description="pip picks the highest version across all indexes, so a public package with an internal name can win.",
                    file=entry.rel, line=lineno, evidence=sanitize_evidence(line),
                    impact="An attacker publishing a same-named package on PyPI can get code executed at install time.",
                    recommendation="Use a single --index-url that proxies PyPI, or pin with --require-hashes.",
                    validation="Confirm internal package names are reserved on PyPI or resolution is restricted.",
                    classification=Classification.CONFIRMED, rule_id="dep-pip-extra-index",
                )
            )
        elif low.startswith(("--index-url", "-i ")) and "http://" in low:
            run.findings.append(
                _finding(
                    severity=Severity.MEDIUM, confidence=Confidence.HIGH, title="pip index over plain HTTP",
                    description="Packages are downloaded over an unencrypted connection.", file=entry.rel, line=lineno,
                    evidence=sanitize_evidence(line), recommendation="Use HTTPS.", validation="Re-run after change.",
                    classification=Classification.CONFIRMED, rule_id="dep-pip-http-index",
                )
            )
        elif low.startswith("--trusted-host"):
            run.findings.append(
                _finding(
                    severity=Severity.LOW, confidence=Confidence.HIGH, title="pip --trusted-host disables TLS verification",
                    description="TLS certificate checks are skipped for this host.", file=entry.rel, line=lineno,
                    evidence=sanitize_evidence(line), recommendation="Fix the certificate chain instead.",
                    validation="Remove the option and confirm installs work.", classification=Classification.CONFIRMED,
                    rule_id="dep-pip-trusted-host",
                )
            )
        elif line.startswith("-"):
            continue
        elif "://" in line or line.startswith(("git+", "file:")):
            urls.append(sanitize_evidence(line, 80))
        elif "==" not in line and "@" not in line:
            unpinned.append(line.split(";")[0].strip()[:60])
    if unpinned:
        run.findings.append(
            _finding(
                severity=Severity.LOW, confidence=Confidence.HIGH, title="Unpinned Python requirements",
                description="Requirements without exact pins resolve to whatever version is newest at install time.",
                file=entry.rel, evidence=f"{len(unpinned)} unpinned: " + ", ".join(unpinned[:12]),
                impact="Builds are not reproducible and pip-audit cannot audit them offline.",
                recommendation="Pin exact versions (pip-compile / uv pip compile) ideally with --require-hashes.",
                validation="pip install --require-hashes -r succeeds.", classification=Classification.CONFIRMED,
                rule_id="dep-python-unpinned",
            )
        )
    if urls:
        run.findings.append(
            _finding(
                severity=Severity.LOW, confidence=Confidence.MEDIUM, title="Python requirements from direct URLs/VCS",
                description="Some requirements install from URLs or VCS instead of the package index.",
                file=entry.rel, evidence="; ".join(urls[:5]), recommendation="Pin VCS requirements to a commit hash and verify the source.",
                validation="Review each source.", status=Status.REQUIRES_REVIEW, rule_id="dep-python-direct-url",
            )
        )


def _check_pyproject(ctx: ScanContext, run: ScannerRun, entry: FileEntry) -> None:
    try:
        data = tomllib.loads(ctx.text(entry) or "")
    except (tomllib.TOMLDecodeError, ValueError, RecursionError):
        run.limitations.append(f"{entry.rel}: could not be parsed as TOML.")
        return
    names = set(pyproject_dependency_names(data))
    directory = _parent(entry.rel)
    for lock_name in ("poetry.lock", "uv.lock"):
        lock_entry = ctx.files_by_rel.get(_join(directory, lock_name))
        if lock_entry is None:
            continue
        try:
            lock = tomllib.loads(ctx.text(lock_entry) or "")
        except (tomllib.TOMLDecodeError, ValueError, RecursionError):
            run.limitations.append(f"{lock_entry.rel}: could not be parsed as TOML.")
            continue
        locked = {normalize_py_name(str(p.get("name", ""))) for p in lock.get("package", []) if isinstance(p, dict)}
        project_name = normalize_py_name(str((data.get("project") or {}).get("name", "")))
        missing = sorted(n for n in names if n not in locked and n != project_name)
        if missing:
            run.findings.append(
                _finding(
                    severity=Severity.MEDIUM, confidence=Confidence.HIGH, title="Lockfile out of sync with pyproject.toml",
                    description=f"Dependencies declared in {entry.rel} are missing from {lock_entry.rel}.",
                    file=lock_entry.rel, evidence="Missing from lockfile: " + ", ".join(missing[:15]),
                    recommendation=f"Regenerate {lock_name} and review the diff.",
                    validation="`poetry check --lock` / `uv lock --check` passes.",
                    classification=Classification.CONFIRMED, rule_id="dep-lockfile-out-of-sync",
                )
            )


# ================================================================ Rust / Go (local)


def check_rust_go(ctx: ScanContext, run: ScannerRun) -> None:
    for entry in ctx.files:
        directory = _parent(entry.rel)
        if entry.name == "Cargo.toml" and not ctx.files_by_rel.get(_join(directory, "Cargo.lock")):
            if not any(ctx.files_by_rel.get(_join(p, "Cargo.lock")) for p in _ancestors(directory)):
                run.findings.append(
                    _finding(
                        severity=Severity.INFORMATIONAL, confidence=Confidence.HIGH, title="Cargo.lock not present",
                        description="Without Cargo.lock, cargo-audit cannot check resolved versions (acceptable for libraries).",
                        file=entry.rel, evidence="Cargo.toml without Cargo.lock",
                        recommendation="Commit Cargo.lock for binaries/applications.", validation="cargo audit runs.",
                        classification=Classification.INFORMATIONAL, rule_id="dep-no-cargo-lock",
                    )
                )
        elif entry.name == "go.mod":
            text = ctx.text(entry) or ""
            if re.search(r"^\s*require\b", text, re.M) and not ctx.files_by_rel.get(_join(directory, "go.sum")):
                run.findings.append(
                    _finding(
                        severity=Severity.LOW, confidence=Confidence.HIGH, title="go.sum missing",
                        description="go.mod declares requirements but go.sum (checksums) is not present.",
                        file=entry.rel, evidence="go.mod has require directives; no go.sum",
                        recommendation="Commit go.sum so module checksums are verified.", validation="go mod verify passes.",
                        classification=Classification.CONFIRMED, rule_id="dep-no-go-sum",
                    )
                )


# ================================================================ external tools


class _Tools:
    def __init__(self, ctx: ScanContext, run: ScannerRun) -> None:
        self.ctx, self.run = ctx, run
        self.status: dict[str, ToolStatus] = {}

    def get(self, name: str, executable: str, version_args: list[str]) -> ToolStatus | None:
        """Return the status if the tool can be used, else None (status recorded either way)."""
        if name not in self.status:
            available = command.which(executable) is not None
            st = ToolStatus(name, available=available)
            if available and version_args:
                st.version = command.tool_version(executable, version_args, self.ctx.root)
                if st.version is None and name == "cargo-audit":
                    st.available = False
            if not st.available:
                st.detail = "not installed"
                self.run.limitations.append(f"{name} not installed: known-vulnerability check for this ecosystem was not performed.")
            elif not self.ctx.use_external_tools:
                st.detail = "disabled by --no-external-tools"
                self.run.limitations.append(f"{name} skipped (--no-external-tools): no known-vulnerability data for this ecosystem.")
            self.status[name] = st
            self.run.tools.append(st)
        st = self.status[name]
        return st if st.available and self.ctx.use_external_tools else None

    def fail(self, st: ToolStatus, where: str, why: str) -> None:
        st.failed = True
        st.detail = (st.detail + "; " if st.detail else "") + f"{where}: {why}"


def _vuln_finding(tool: str, file: str, package: str, severity: Severity, title: str, evidence: str, fixed: str | None, cwe: str | None, ident: str, notes: list[str] | None = None) -> Finding:
    rec = f"Upgrade {package} to a fixed version ({fixed}) reported by {tool}." if fixed else f"Check {tool} output for a fixed version; if none exists, assess exploitability and mitigate."
    return Finding(
        scanner=NAME, category="vulnerable-dependency", severity=severity, confidence=Confidence.HIGH,
        title=f"Vulnerable dependency: {package}", description=f"{tool} reports: {title}",
        file=file, evidence=sanitize_evidence(evidence, 300),
        impact="Known vulnerability in a dependency; exploitability depends on how the package is used.",
        recommendation=rec, validation=f"Re-run {tool} after upgrading and confirm the advisory no longer appears.",
        cwe=cwe, owasp=OWASP_VULN, source=[f"{tool}"], status=Status.OPEN,
        classification=Classification.CONFIRMED, rule_id=f"{tool}:{ident}", dedup_key=f"vuln:{package}",
        notes=notes or [],
    )


def parse_npm_audit(data: Any, file: str) -> list[Finding]:
    if not isinstance(data, dict) or "error" in data:
        raise ValueError("npm audit returned an error object")
    vulns = data.get("vulnerabilities")
    if not isinstance(vulns, dict):
        raise ValueError("npm audit JSON has no 'vulnerabilities' mapping (npm < 7?)")
    out = []
    for name, v in sorted(vulns.items()):
        if not isinstance(v, dict):
            continue
        sev = SEVERITY_MAP.get(str(v.get("severity", "")).lower(), Severity.MEDIUM)
        advisories = [a for a in v.get("via", []) if isinstance(a, dict)]
        via_pkgs = [a for a in v.get("via", []) if isinstance(a, str)]
        titles = [f"{a.get('title', 'advisory')} ({a.get('url', 'no url')})" for a in advisories]
        cwes = sorted({c for a in advisories for c in (a.get("cwe") or []) if isinstance(c, str)})
        fix = v.get("fixAvailable")
        fixed = None
        if isinstance(fix, dict) and fix.get("name") and fix.get("version"):
            fixed = f"{fix['name']}@{fix['version']}"
        evidence = f"{name} {v.get('range', '')}: " + ("; ".join(titles) if titles else "vulnerable via " + ", ".join(via_pkgs))
        notes = [] if v.get("isDirect") else ["Transitive dependency."]
        if fix is False:
            notes.append("npm reports no fix available.")
        elif fix is True:
            notes.append("npm reports a fix is available within the declared range (npm audit fix); review the lockfile diff.")
        out.append(_vuln_finding("npm-audit", file, name, sev, titles[0] if titles else "vulnerable via " + ", ".join(via_pkgs), evidence, fixed, cwes[0] if cwes else None, name, notes))
    return out


def parse_pnpm_audit(data: Any, file: str) -> list[Finding]:
    if not isinstance(data, dict) or "error" in data:
        raise ValueError("pnpm audit returned an error object")
    advisories = data.get("advisories")
    if not isinstance(advisories, dict):
        raise ValueError("pnpm audit JSON has no 'advisories' mapping")
    grouped: dict[str, list[dict]] = defaultdict(list)
    for adv in advisories.values():
        if isinstance(adv, dict) and adv.get("module_name"):
            grouped[str(adv["module_name"])].append(adv)
    out = []
    for name, advs in sorted(grouped.items()):
        worst = min((SEVERITY_MAP.get(str(a.get("severity", "")).lower(), Severity.MEDIUM) for a in advs), key=lambda s: ["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFORMATIONAL"].index(s.value))
        titles = [f"{a.get('title', 'advisory')} ({a.get('url', 'no url')})" for a in advs]
        patched = [str(a.get("patched_versions")) for a in advs if a.get("patched_versions") and a.get("patched_versions") != "<0.0.0"]
        cwes = [c for a in advs for c in (a.get("cwe") if isinstance(a.get("cwe"), list) else [a.get("cwe")]) if isinstance(c, str)]
        out.append(_vuln_finding("pnpm-audit", file, name, worst, titles[0], f"{name} {advs[0].get('vulnerable_versions', '')}: " + "; ".join(titles), ", ".join(patched) or None, cwes[0] if cwes else None, name))
    return out


def parse_pip_audit(data: Any, file: str) -> list[Finding]:
    deps = data.get("dependencies") if isinstance(data, dict) else data
    if not isinstance(deps, list):
        raise ValueError("unexpected pip-audit JSON")
    out = []
    for dep in deps:
        if not isinstance(dep, dict):
            continue
        for v in dep.get("vulns") or []:
            if not isinstance(v, dict):
                continue
            ident = str(v.get("id", "unknown"))
            aliases = [a for a in v.get("aliases") or [] if isinstance(a, str)]
            fixed = ", ".join(v.get("fix_versions") or []) or None
            f = _vuln_finding(
                "pip-audit", file, f"{dep.get('name')}", Severity.MEDIUM,
                f"{ident} affects {dep.get('name')} {dep.get('version')}",
                f"{dep.get('name')}=={dep.get('version')}: {ident}" + (f" (aliases: {', '.join(aliases[:4])})" if aliases else ""),
                fixed, None, ident,
                ["pip-audit does not report severity; MEDIUM is a placeholder pending review of the advisory."],
            )
            f.status = Status.REQUIRES_REVIEW
            out.append(f)
    return out


def parse_cargo_audit(data: Any, file: str) -> list[Finding]:
    if not isinstance(data, dict):
        raise ValueError("unexpected cargo-audit JSON")
    out = []
    for item in ((data.get("vulnerabilities") or {}).get("list") or []):
        adv = item.get("advisory") or {}
        pkg = item.get("package") or {}
        patched = ", ".join((item.get("versions") or {}).get("patched") or []) or None
        f = _vuln_finding(
            "cargo-audit", file, str(pkg.get("name")), Severity.MEDIUM, str(adv.get("title", "advisory")),
            f"{pkg.get('name')} {pkg.get('version')}: {adv.get('id')} {adv.get('title', '')} ({adv.get('url') or 'no url'})",
            patched, None, str(adv.get("id")),
            ["cargo-audit JSON does not always include a severity; MEDIUM is a placeholder pending review."],
        )
        f.status = Status.REQUIRES_REVIEW
        out.append(f)
    for kind, items in ((data.get("warnings") or {}).items() if isinstance(data.get("warnings"), dict) else []):
        for item in items or []:
            adv = (item or {}).get("advisory") or {}
            pkg = (item or {}).get("package") or {}
            out.append(
                Finding(
                    scanner=NAME, category="dependency", severity=Severity.LOW, confidence=Confidence.HIGH,
                    title=f"Crate warning ({kind}): {pkg.get('name')}", description=str(adv.get("title", kind)),
                    file=file, evidence=sanitize_evidence(f"{pkg.get('name')} {pkg.get('version')}: {adv.get('id', kind)}"),
                    recommendation="Review whether the crate should be replaced.", validation="Re-run cargo audit.",
                    source=["cargo-audit"], status=Status.REQUIRES_REVIEW, rule_id=f"cargo-audit:{kind}",
                    dedup_key=f"crate-warning:{pkg.get('name')}:{kind}", owasp=OWASP_VULN,
                )
            )
    return out


def parse_govulncheck(text: str, file: str) -> list[Finding]:
    decoder = json.JSONDecoder()
    idx, osv, called = 0, {}, {}
    text = text.strip()
    while idx < len(text):
        while idx < len(text) and text[idx].isspace():
            idx += 1
        if idx >= len(text):
            break
        obj, idx = decoder.raw_decode(text, idx)
        if "osv" in obj and isinstance(obj["osv"], dict):
            osv[obj["osv"].get("id")] = obj["osv"]
        elif "finding" in obj and isinstance(obj["finding"], dict):
            fnd = obj["finding"]
            trace = fnd.get("trace") or []
            reachable = bool(trace and isinstance(trace[0], dict) and trace[0].get("function"))
            key = fnd.get("osv")
            called[key] = called.get(key, False) or reachable
            called.setdefault(f"{key}#module", (trace[0].get("module") if trace and isinstance(trace[0], dict) else "unknown"))
    out = []
    for key in sorted(k for k in called if not str(k).endswith("#module")):
        entry = osv.get(key, {})
        module = called.get(f"{key}#module", "unknown")
        reachable = called[key]
        f = _vuln_finding(
            "govulncheck", file, str(module), Severity.HIGH if reachable else Severity.LOW,
            str(entry.get("summary", key)), f"{module}: {key} {entry.get('summary', '')}", None, None, str(key),
            ["Vulnerable symbol is reachable from this module's code." if reachable else "Module imported but vulnerable symbol not reached; severity is a triage placeholder."],
        )
        f.confidence = Confidence.HIGH if reachable else Confidence.MEDIUM
        out.append(f)
    return out


def _run_json_tool(tools: _Tools, st: ToolStatus, executable: str, args: list[str], cwd: Path, where: str, parser, ok_codes: tuple[int, ...]) -> None:
    res = command.run(executable, args, cwd=cwd, timeout=tools.ctx.tool_timeout)
    st.used = True
    if res.timed_out:
        tools.fail(st, where, "timed out")
        return
    if not res.ok or res.returncode not in ok_codes:
        tools.fail(st, where, f"exit code {res.returncode}")
        return
    try:
        data = res.stdout if parser is parse_govulncheck else json.loads(res.stdout)
        tools.run.findings.extend(parser(data, where))
        st.detail = (st.detail + "; " if st.detail else "") + f"ran in {where or '.'}"
    except (ValueError, KeyError, TypeError, AttributeError) as exc:
        tools.fail(st, where, f"unparseable output ({exc.__class__.__name__})")


_PINNED_LINE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]*(\[[^\]]*\])?==[^\s;@]+(\s*;[^#]*)?(\s+--hash=\S+)*$")


def requirements_fully_pinned(text: str) -> bool:
    """SR-12: only plain `name==version` lines (optional extras/markers/hashes) qualify.

    Includes (-r/-c), editables (-e), index options and URL/VCS requirements make the
    file ineligible, so pip-audit is never asked to resolve or build anything.
    """
    lines = [l.split(" #", 1)[0].strip() for l in text.splitlines()]
    lines = [l for l in lines if l and not l.startswith("#")]
    return bool(lines) and all(_PINNED_LINE.match(l) for l in lines)


def run_external(ctx: ScanContext, run: ScannerRun) -> None:
    tools = _Tools(ctx, run)
    for entry in ctx.files:
        if entry.build_output:
            continue
        directory = _parent(entry.rel)
        cwd = ctx.root / directory if directory else ctx.root
        name = entry.name
        if name in ("package-lock.json", "npm-shrinkwrap.json"):
            st = tools.get("npm-audit", "npm", ["--version"])
            if st:
                _run_json_tool(tools, st, "npm", ["audit", "--json", "--package-lock-only", "--ignore-scripts"], cwd, entry.rel, parse_npm_audit, (0, 1))
        elif name == "pnpm-lock.yaml":
            st = tools.get("pnpm-audit", "pnpm", ["--version"])
            if st:
                _run_json_tool(tools, st, "pnpm", ["audit", "--json", "--ignore-pnpmfile"], cwd, entry.rel, parse_pnpm_audit, (0, 1))
        elif name == "yarn.lock" and "yarn-audit" not in tools.status:
            tools.status["yarn-audit"] = ToolStatus("yarn-audit", available=False, detail="yarn is not in the tool allowlist")
            run.tools.append(tools.status["yarn-audit"])
            run.limitations.append("yarn.lock present: yarn audit is not run by this scanner; run it separately.")
        elif name.lower().startswith("requirements") and name.lower().endswith(".txt"):
            st = tools.get("pip-audit", "pip-audit", ["--version"])
            if not st:
                continue
            reqs = python_requirement_names(ctx.text(entry) or "")
            text = ctx.text(entry) or ""
            pinned = requirements_fully_pinned(text)
            if not reqs:
                continue
            if not pinned or not _SAFE_FILENAME.match(name):
                st.detail = (st.detail + "; " if st.detail else "") + f"{entry.rel}: skipped (not fully pinned; auditing would require installing packages)"
                run.limitations.append(f"pip-audit skipped for {entry.rel}: requirements are not fully pinned and resolving them would execute package builds.")
                continue
            _run_json_tool(tools, st, "pip-audit", ["-r", name, "--disable-pip", "--no-deps", "--format", "json", "--progress-spinner", "off"], cwd, entry.rel, parse_pip_audit, (0, 1))
        elif name == "Cargo.lock":
            # Run the cargo-audit binary directly: `cargo audit` can be redirected by an
            # [alias] in the project's .cargo/config.toml to arbitrary cargo commands.
            st = tools.get("cargo-audit", "cargo-audit", ["audit", "--version"])
            if st:
                _run_json_tool(tools, st, "cargo-audit", ["audit", "--json"], cwd, entry.rel, parse_cargo_audit, (0, 1))
        elif name == "go.mod":
            st = tools.get("govulncheck", "govulncheck", ["-version"])
            if st:
                _run_json_tool(tools, st, "govulncheck", ["-json", "./..."], cwd, entry.rel, parse_govulncheck, (0, 3))
    if ctx.has_tech("Python"):
        tools.get("pip-audit", "pip-audit", ["--version"])
    if ctx.has_tech("Python") and not any(f.name.lower().startswith("requirements") for f in ctx.files):
        run.limitations.append("Python project without requirements*.txt: pip-audit is only run on pinned requirements files (pyproject/poetry/uv locks are checked for consistency only).")


def scan(ctx: ScanContext) -> ScannerRun:
    run = ScannerRun(NAME)
    manifests = [f for f in ctx.files if f.name == "package.json" and not f.build_output]
    workspace_names = set()
    deps_by_dir: dict[str, set[str]] = {}
    for m in manifests:
        pkg = load_json_file(ctx, m)
        if isinstance(pkg, dict):
            if isinstance(pkg.get("name"), str):
                workspace_names.add(pkg["name"])
            deps_by_dir[_parent(m.rel)] = set(package_json_deps(pkg))
    for m in manifests:
        directory = _parent(m.rel)
        ancestor_deps: set[str] = set()
        for a in _ancestors(directory):
            ancestor_deps |= deps_by_dir.get(a, set())
        check_node_project(ctx, m, run, workspace_names, ancestor_deps)
    check_python(ctx, run)
    check_rust_go(ctx, run)
    run_external(ctx, run)
    run.limitations.append(
        "Known-vulnerability data comes only from external audit tools. Missing tools mean missing CVE coverage; "
        "this scanner never infers vulnerabilities from package names or versions on its own."
    )
    return run
