"""Secret scanner: internal rule engine plus optional Gitleaks.

The internal engine always runs. When Gitleaks is installed (and external tools
are allowed) it also runs; results are merged by the orchestrator's dedup step.
Matched secret values are used only in memory for placeholder/entropy/JWT checks
and are never written to a Finding.
"""

from __future__ import annotations

import base64
import binascii
import json
import os
import re
import tempfile
import time
from pathlib import Path
from typing import Any

from ..models import Classification, Confidence, FileEntry, Finding, ScannerRun, Severity, ToolStatus
from ..utils import command
from ..utils.filesystem import is_test_path, iter_lines
from ..utils.redaction import looks_like_placeholder, shannon_entropy
from . import ScanContext, load_rules

NAME = "secrets"

SKIP_FILES = frozenset(
    {
        "package-lock.json", "npm-shrinkwrap.json", "yarn.lock", "pnpm-lock.yaml", "poetry.lock",
        "uv.lock", "cargo.lock", "go.sum", "composer.lock", "gemfile.lock", "pipfile.lock",
    }
)
SKIP_SUFFIXES = (".map", ".svg", ".min.css", ".lock", ".sum", ".png", ".jpg", ".jpeg", ".gif", ".ico", ".woff", ".woff2", ".pdf")
LOCAL_HOSTS = frozenset(
    {"localhost", "127.0.0.1", "0.0.0.0", "::1", "db", "database", "postgres", "postgresql", "mysql", "mariadb", "redis", "mongo", "mongodb", "host.docker.internal", "rabbitmq"}
)
GENERIC_KINDS = frozenset({"credential-assignment", "generic-high-entropy"})

KIND_TEXT = {
    "private-key": ("Private key material is stored in the repository.", "Anyone with repository access can impersonate the key owner (TLS, SSH, signing)."),
    "aws": ("An AWS access key ID pattern was found.", "Combined with its secret key this grants the IAM principal's AWS permissions."),
    "aws-secret": ("An AWS secret access key pattern was found.", "Grants the IAM principal's permissions; can lead to cloud account compromise."),
    "supabase-service-role": ("A Supabase service-role credential was found.", "Service-role keys bypass Row Level Security and give full database access."),
}
DEFAULT_TEXT = ("A value matching a credential pattern was found.", "If real, anyone with access to this file can use the credential.")


def _is_env_file(entry: FileEntry) -> bool:
    name = entry.name.lower()
    return name.startswith(".env") or name.endswith(".env") or name in ("env", ".envrc")


def _is_yaml(entry: FileEntry) -> bool:
    return entry.suffix in (".yml", ".yaml")


def should_scan(entry: FileEntry) -> bool:
    name = entry.name.lower()
    return name not in SKIP_FILES and not name.endswith(SKIP_SUFFIXES)


def _b64url_json(segment: str) -> dict[str, Any] | None:
    try:
        padded = segment + "=" * (-len(segment) % 4)
        data = json.loads(base64.urlsafe_b64decode(padded.encode("ascii")))
        return data if isinstance(data, dict) else None
    except (ValueError, binascii.Error, UnicodeDecodeError, RecursionError):
        return None


def _level(value: str) -> Confidence:
    return Confidence(value)


def _classify(rule: dict[str, Any], match: re.Match, line: str) -> dict[str, Any] | None:
    """Return overrides for the finding, or None when the match should be discarded."""
    group = int(rule.get("secret_group", 1))
    value = match.group(group) or ""
    out: dict[str, Any] = {
        "severity": Severity(rule["severity"]),
        "confidence": _level(rule["confidence"]),
        "title": rule["title"],
        "kind": rule["kind"],
        "notes": [],
        "classification": Classification.POTENTIAL,
    }
    check = rule.get("check")
    if check in ("assignment", "generic", "db_url") and looks_like_placeholder(value):
        return None
    if check == "assignment":
        low = value.lower()
        if low.startswith(("process.env", "os.environ", "import.meta.env", "env(", "getenv")) or value.startswith(("$", "%", "@")):
            return None
        if re.fullmatch(r"[a-z_.-]+", value):
            out["confidence"] = Confidence.LOW
            out["notes"].append("Value looks like a word/identifier; may be a field name rather than a credential.")
    if "min_entropy" in rule and shannon_entropy(value) < float(rule["min_entropy"]):
        if check == "generic":
            return None
        out["confidence"] = Confidence.LOW
        out["notes"].append("Low-entropy value; may be a placeholder or test value.")
    if check == "db_url":
        host = (match.group(4) or "").lower()
        if host in LOCAL_HOSTS or host.endswith(".local"):
            out["severity"] = Severity.LOW
            out["confidence"] = Confidence.LOW
            out["notes"].append("Host looks local/containerised; likely development credentials.")
    if check == "jwt":
        parts = value.split(".")
        payload = _b64url_json(parts[1]) if len(parts) == 3 else None
        header = _b64url_json(parts[0]) if len(parts) == 3 else None
        if payload is None or header is None:
            out["confidence"] = Confidence.LOW
            out["notes"].append("Token segments do not decode as JSON; may not be a JWT.")
        else:
            role = str(payload.get("role", "")).lower()
            if role == "service_role":
                out.update(
                    severity=Severity.CRITICAL,
                    confidence=Confidence.HIGH,
                    title="Supabase service-role key (JWT)",
                    kind="supabase-service-role",
                )
            elif role == "anon":
                out.update(severity=Severity.INFORMATIONAL, confidence=Confidence.HIGH, title="Supabase anon key (public by design)")
                out["classification"] = Classification.INFORMATIONAL
                out["notes"].append("Anon keys are meant to be public; security depends on Row Level Security policies.")
            exp = payload.get("exp")
            if isinstance(exp, (int, float)) and exp < time.time():
                out["notes"].append("Token 'exp' claim is in the past.")
    return out


def scan_text(entry: FileEntry, text: str, rules: list[dict[str, Any]], scanner: str = NAME) -> list[Finding]:
    findings: list[Finding] = []
    is_env, is_yaml = _is_env_file(entry), _is_yaml(entry)
    test_ctx = is_test_path(entry.rel)
    in_private_key = False
    all_lines = text.splitlines()
    for lineno, line in iter_lines(text):
        if in_private_key:
            if "-----END" in line:
                in_private_key = False
            continue
        taken: list[tuple[int, int]] = []
        for rule in rules:
            scope = rule.get("files")
            if (scope == "env" and not is_env) or (scope == "yaml" and not is_yaml):
                continue
            for match in rule["compiled"].finditer(line):
                group = int(rule.get("secret_group", 1))
                span = match.span(group)
                if any(span[0] < e and s < span[1] for s, e in taken):
                    continue
                result = _classify(rule, match, line)
                if result is None:
                    continue
                taken.append(span)
                if rule["id"] == "private-key":
                    in_private_key = "-----END" not in line[match.end():]
                    if _private_key_body_len(all_lines, lineno - 1, line[match.end():]) < 100:
                        result["severity"], result["confidence"] = Severity.MEDIUM, Confidence.LOW
                        result["notes"].append("PEM header without a plausible key body (fewer than 100 base64 characters); likely a sample or fragment.")
                if test_ctx:
                    result["confidence"] = Confidence.LOW
                    result["notes"].append("Located in test/fixture/example path; verify it is not a real credential.")
                description, impact = KIND_TEXT.get(result["kind"], DEFAULT_TEXT)
                if is_env:
                    description += " The value is in an environment file."
                label = result["title"]
                findings.append(
                    Finding(
                        scanner=scanner,
                        category="secret",
                        severity=result["severity"],
                        confidence=result["confidence"],
                        title=result["title"],
                        description=description,
                        file=entry.rel,
                        line=lineno,
                        column=span[0] + 1,
                        evidence=f"Potential {label} detected (rule {rule['id']}, value length {span[1] - span[0]}). Value redacted.",
                        impact=impact,
                        recommendation=(
                            "Treat the credential as compromised if it is real: revoke/rotate it with the provider, "
                            "move it to a server-side secret store or untracked environment variable, and check "
                            "provider logs for misuse. Replace committed values with placeholders."
                        ),
                        validation=(
                            "Confirm with the owner whether the value is live (without pasting it anywhere). "
                            "After rotation, re-run this scanner and verify the old credential is rejected by the provider."
                        ),
                        cwe=rule.get("cwe", "CWE-798"),
                        owasp="A07:2021-Identification and Authentication Failures",
                        source=[f"internal:{rule['id']}"],
                        classification=result["classification"],
                        rule_id=rule["id"],
                        dedup_key="secret:" + result["kind"],
                        context=_context_without_secret(line, span),
                        notes=result["notes"],
                        tags=["test-context"] if test_ctx else [],
                    )
                )
    return findings


def _private_key_body_len(lines: list[str], start: int, rest_of_line: str) -> int:
    """Count base64 characters between BEGIN and END (bounded look-ahead)."""
    body = rest_of_line.split("-----END", 1)[0]
    if "-----END" not in rest_of_line:
        for nxt in lines[start + 1:start + 200]:
            if "-----END" in nxt:
                body += nxt.split("-----END", 1)[0]
                break
            body += nxt
    return len(re.findall(r"[A-Za-z0-9+/=]", body))


def _context_without_secret(line: str, span: tuple[int, int]) -> str:
    masked = line[: span[0]] + "<S>" + line[span[1]:]
    return re.sub(r"\s+", " ", masked).strip()[:200]


# ---------------------------------------------------------------- gitleaks

GITLEAKS_KIND = [
    ("private-key", "private-key"),
    ("aws", "aws"),
    ("github", "github-token"),
    ("stripe", "stripe-secret"),
    ("openai", "openai-key"),
    ("anthropic", "anthropic-key"),
    ("slack", "slack-token"),
    ("gcp-api-key", "google-api-key"),
    ("jwt", "jwt"),
    ("generic", "credential-assignment"),
]


def parse_gitleaks_report(data: Any, root: Path, walked: set[str]) -> list[Finding]:
    findings: list[Finding] = []
    if not isinstance(data, list):
        raise ValueError("unexpected gitleaks report format")
    root_resolved = root.resolve()
    for item in data:
        if not isinstance(item, dict):
            continue
        raw_file = str(item.get("File", ""))
        try:
            p = Path(raw_file)
            rel = (p if p.is_absolute() else (root_resolved / p)).resolve().relative_to(root_resolved).as_posix()
        except (ValueError, OSError):
            continue
        if rel not in walked:
            continue  # excluded directory or outside project
        rule_id = re.sub(r"[^A-Za-z0-9_.-]", "", str(item.get("RuleID", "unknown")))[:80]
        kind = next((k for needle, k in GITLEAKS_KIND if needle in rule_id.lower()), "gitleaks-" + rule_id)
        line = item.get("StartLine")
        findings.append(
            Finding(
                scanner=NAME,
                category="secret",
                severity=Severity.CRITICAL if kind in ("private-key", "aws-secret", "stripe-secret") else Severity.HIGH,
                confidence=Confidence.MEDIUM,
                title=f"Potential secret ({rule_id})",
                description="Gitleaks reported a potential secret.",
                file=rel,
                line=line if isinstance(line, int) and line > 0 else None,
                column=item.get("StartColumn") if isinstance(item.get("StartColumn"), int) else None,
                evidence=f"Gitleaks rule '{rule_id}' matched. Value redacted.",
                impact=DEFAULT_TEXT[1],
                recommendation="Verify whether the credential is real; if so revoke/rotate it and remove it from the codebase.",
                validation="Re-run gitleaks and this scanner after remediation.",
                cwe="CWE-798",
                owasp="A07:2021-Identification and Authentication Failures",
                source=[f"gitleaks:{rule_id}"],
                rule_id=f"gitleaks:{rule_id}",
                dedup_key="secret:" + kind,
            )
        )
    return findings


def run_gitleaks(ctx: ScanContext, run: ScannerRun) -> None:
    status = ToolStatus("gitleaks", available=command.which("gitleaks") is not None)
    run.tools.append(status)
    if not status.available:
        status.detail = "not installed; internal secret rules used"
        run.limitations.append("Gitleaks not installed: secret detection relies on the internal rule set only.")
        return
    if not ctx.use_external_tools:
        status.detail = "disabled by --no-external-tools"
        return
    status.version = command.tool_version("gitleaks", ["version"], ctx.root)
    fd, report_path = tempfile.mkstemp(prefix="phase2-gitleaks-", suffix=".json")
    os.close(fd)
    try:
        res = command.run(
            "gitleaks",
            ["detect", "--no-git", "--source", ".", "--redact", "--no-banner", "--exit-code", "0",
             "--report-format", "json", "--report-path", report_path, "--log-level", "error"],
            cwd=ctx.root,
            timeout=ctx.tool_timeout,
        )
        status.used = True
        if not res.ok or res.returncode not in (0, 1):
            status.failed = True
            status.detail = "timed out" if res.timed_out else f"exit code {res.returncode}"
            return
        with open(report_path, encoding="utf-8", errors="replace") as fh:
            data = json.load(fh)
        walked = {f.rel for f in ctx.files}
        run.findings.extend(parse_gitleaks_report(data, ctx.root, walked))
        status.detail = "ran on working tree (--no-git)"
    except (OSError, ValueError) as exc:
        status.failed = True
        status.detail = f"could not parse report: {exc.__class__.__name__}"
    finally:
        try:
            os.unlink(report_path)
        except OSError:
            pass


def scan(ctx: ScanContext) -> ScannerRun:
    run = ScannerRun(NAME)
    rules = load_rules("secret-patterns.yaml", ctx.rules_dir)
    for entry in ctx.files:
        if not should_scan(entry):
            continue
        text = ctx.text(entry)
        if text is None:
            continue
        run.findings.extend(scan_text(entry, text, rules))
    run_gitleaks(ctx, run)
    run.limitations.append(
        "Secret findings are pattern matches. The scanner never validates credentials against providers, "
        "so 'confirmed' secret status requires human verification."
    )
    return run
