"""Dangerous-code scanner (JS/TS and Python).

Line-based pattern matching plus a lightweight taint heuristic: if an untrusted
input source (request body/query/params, argv, input(), location, ...) appears
on the same line, the finding is OPEN with HIGH confidence; if it appears in the
preceding window of lines, OPEN with MEDIUM confidence. Otherwise the finding is
REQUIRES_REVIEW because static context is insufficient. This is a heuristic,
not data-flow analysis.
"""

from __future__ import annotations

import re
from typing import Any

from ..models import Classification, Confidence, FileEntry, Finding, ScannerRun, Severity, Status
from ..severity import rank
from ..utils.filesystem import in_string_literal, is_test_path, iter_lines, python_multiline_string_lines
from ..utils.redaction import sanitize_evidence
from . import ScanContext, load_rules

NAME = "dangerous_code"
TAINT_WINDOW = 12

JS_EXT = frozenset({".js", ".jsx", ".ts", ".tsx", ".mjs", ".cjs", ".vue", ".svelte"})
PY_EXT = frozenset({".py"})

TAINT_JS = re.compile(
    r"\breq\.(?:body|query|params|headers|cookies|url|originalUrl|path|files?)\b"
    r"|\brequest\.(?:body|query|params|headers|nextUrl|url|json\(|formData\(|text\()"
    r"|\b(?:searchParams|useSearchParams|useParams|formData)\b"
    r"|\b(?:window\.)?location\.(?:search|hash|href|pathname)\b"
    r"|\bdocument\.(?:cookie|referrer|URL)\b"
    r"|\b(?:event|e|evt|msg)\.data\b|\bprocess\.argv\b|\bctx\.(?:request|query|params)\b"
    r"|\bparams\.\w+|\bquery\.\w+|\bbody\.\w+|\buserInput\b|\binput\.value\b|\.value\b(?=\s*[;)+,])"
)
TAINT_PY = re.compile(
    r"\brequest\.(?:args|form|json|get_json|data|values|files|cookies|headers|GET|POST|body|query_params|path_params|FILES|COOKIES|META)\b"
    r"|\bsys\.argv\b|(?<![\w.])input\s*\(|\bflask\.request\b|\bQuery\s*\(|\bForm\s*\(|\bBody\s*\("
    r"|\buser_input\b|\bpayload\b|\bparams\[|\bkwargs\["
)
SANITIZER = re.compile(r"DOMPurify\.sanitize|sanitizeHtml|sanitize\(|xss\(|escapeHtml|bleach\.clean|html\.escape|markupsafe\.escape", re.I)
COMMENT_JS = re.compile(r"^\s*(?://|/\*|\*)")
COMMENT_PY = re.compile(r"^\s*#")
LITERAL_ARG = re.compile(r"""^\s*(?:(?P<q>['"])(?:(?!(?P=q)).)*(?P=q)|`[^`$]*`)\s*[,)]""")
LITERAL_ASSIGN = re.compile(r"""^\s*(?:(?P<q>['"])(?:(?!(?P=q)).)*(?P=q)|`[^`$]*`)\s*;?\s*$""")


def language_of(entry: FileEntry) -> str | None:
    if entry.suffix in JS_EXT:
        return "js"
    if entry.suffix in PY_EXT:
        return "py"
    return None


def _literal_only(line: str, match: re.Match) -> bool:
    rest = line[match.end():]
    if match.group(0).rstrip().endswith("="):
        return bool(LITERAL_ASSIGN.match(rest))
    return bool(LITERAL_ARG.match(rest))


def scan_text(entry: FileEntry, text: str, rules: list[dict[str, Any]]) -> list[Finding]:
    lang = language_of(entry)
    if lang is None:
        return []
    applicable = [r for r in rules if lang in r.get("languages", [])]
    applicable = [r for r in applicable if not r.get("requires_file") or re.search(r["requires_file"], text)]
    if not applicable:
        return []
    taint_re = TAINT_JS if lang == "js" else TAINT_PY
    comment_re = COMMENT_JS if lang == "js" else COMMENT_PY
    lines = list(iter_lines(text))
    test_ctx = is_test_path(entry.rel)
    findings: list[Finding] = []
    in_multiline = python_multiline_string_lines(text) if lang == "py" else set()
    for idx, (lineno, line) in enumerate(lines):
        if comment_re.match(line) or lineno in in_multiline:
            continue
        seen_categories: set[str] = set()
        for rule in applicable:
            match = rule["compiled"].search(line)
            if not match or rule["category"] in seen_categories or in_string_literal(line, match.start()):
                continue
            same_line_taint = bool(taint_re.search(line))
            window = " ".join(l for _, l in lines[max(0, idx - TAINT_WINDOW):idx])
            near_taint = bool(taint_re.search(window))
            if rule.get("requires_taint"):
                # Noisy generic APIs (spawn, path.join, open, dynamic import) are only
                # reported when untrusted input is visible on the same line.
                if not same_line_taint:
                    continue
                near_taint = False
            seen_categories.add(rule["category"])
            notes: list[str] = []
            if same_line_taint:
                severity = Severity(rule["tainted_severity"])
                confidence, status = Confidence.HIGH, Status.OPEN
                classification = Classification.POTENTIAL
                notes.append("Untrusted-input source appears on the same line.")
            elif near_taint:
                severity = Severity(rule["tainted_severity"])
                confidence, status = Confidence.MEDIUM, Status.OPEN
                classification = Classification.POTENTIAL
                notes.append(f"Untrusted-input source appears within the previous {TAINT_WINDOW} lines; data flow not proven.")
            else:
                severity = Severity(rule["severity"])
                confidence, status = Confidence.LOW, Status.REQUIRES_REVIEW
                classification = Classification.REQUIRES_RUNTIME_VERIFICATION
                notes.append("No untrusted-input source visible nearby; review where the data comes from.")
            if rule.get("literal_downgrade") and _literal_only(line, match):
                severity, confidence, status = Severity.INFORMATIONAL, Confidence.HIGH, Status.REQUIRES_REVIEW
                classification = Classification.INFORMATIONAL
                notes = ["Argument is a string literal only; low risk but consider removing the dangerous API."]
            if rule.get("sanitizer_downgrade") and SANITIZER.search(line):
                if rank(severity) > rank(Severity.LOW):
                    severity = Severity.LOW
                status = Status.REQUIRES_REVIEW
                notes.append("A sanitiser call appears on the same line; verify its configuration.")
            if test_ctx:
                # SR-07: path names are attacker-controlled, so they lower confidence only;
                # CRITICAL findings still block.
                confidence = Confidence.LOW
                notes.append("Located in test/fixture/example code; confidence lowered, severity kept.")
            findings.append(
                Finding(
                    scanner=NAME,
                    category=rule["category"],
                    severity=severity,
                    confidence=confidence,
                    title=rule["title"],
                    description=f"{rule['title']} detected in {lang.upper()} code.",
                    file=entry.rel,
                    line=lineno,
                    column=match.start() + 1,
                    evidence=sanitize_evidence(line.strip(), 200),
                    impact=rule.get("impact", ""),
                    recommendation=rule.get("recommendation", ""),
                    validation=rule.get("validation", ""),
                    cwe=rule.get("cwe"),
                    owasp=rule.get("owasp"),
                    source=[f"internal:{rule['id']}"],
                    status=status,
                    classification=classification,
                    rule_id=rule["id"],
                    dedup_key=rule["id"],
                    context=re.sub(r"\s+", " ", sanitize_evidence(line.strip(), 200)),
                    notes=notes,
                    tags=["test-context"] if test_ctx else [],
                )
            )
    return findings


def scan(ctx: ScanContext) -> ScannerRun:
    run = ScannerRun(NAME)
    rules = load_rules("dangerous-patterns.yaml", ctx.rules_dir)
    for entry in ctx.files:
        if entry.build_output or language_of(entry) is None:
            continue
        text = ctx.text(entry)
        if text is None:
            continue
        run.findings.extend(scan_text(entry, text, rules))
    run.limitations.append(
        "Dangerous-code detection is line-based pattern matching with a proximity taint heuristic; it does not "
        "perform inter-procedural data-flow analysis. Multi-line calls, aliased imports and framework-specific "
        "sanitisation may be missed or misjudged. Languages covered: JavaScript/TypeScript and Python only."
    )
    return run
