# phase2-security-scanner

The executable engine behind `skills/06-security/17-security-audit/SKILL.md`.
It runs the automatable part of that skill's audit ("scan source/config",
"inspect dependencies", "inspect infrastructure") and writes an evidence-based report
that follows the finding format and release gate in `MASTER-SKILL.md`.

It is a **read-only static scanner**. It does not replace the manual parts of the
audit (authentication, authorization/IDOR, business logic, runtime validation in staging).

```
Target project
  -> Project discovery -> Secret scan -> Dangerous-code scan -> Dependency scan
  -> Configuration scan -> Git scan
  -> Normalize -> Deduplicate -> Baseline -> security-report.json / .md -> exit code
```

## Installation

Requires Python 3.11+. The only runtime dependency is PyYAML (used only through `yaml.safe_load`).

```bash
cd tools/phase2-security-scanner
python -m pip install -e ".[dev]"      # editable install + pytest
```

Without installing, from this directory:

```bash
PYTHONPATH=src python -m phase2.cli --project .
```

## Usage

```bash
python -m phase2.cli --project .
phase2-scan ../../my-app --format both
python -m phase2.cli --project ../../my-app --output reports --format both --verbose
```

| Option | Meaning |
|---|---|
| `--project PATH` / positional `PATH` | Directory to scan |
| `--output DIR` | Where `security-report.json` / `security-report.md` are written (default `./reports`) |
| `--format json\|markdown\|both` | Report formats (default `both`) |
| `--baseline PATH` | Apply an accepted-findings baseline (`security-baseline.json`) |
| `--update-baseline` | Write the current non-critical findings to `--baseline PATH` (explicit only) |
| `--severity LEVEL` | Minimum severity *shown* in reports. Counts, release status and exit code always use all findings |
| `--config FILE` | Optional YAML config (see `examples/security-config.yaml`). Never auto-loaded from the target |
| `--git-history-depth N` | Recent commits scanned for secrets (default 100, `0` disables) |
| `--no-external-tools` | Run only the internal scanners (no gitleaks / npm / pnpm / pip-audit / cargo-audit / govulncheck) |
| `--verbose` | Print each finding and scanner errors to the console |

Console output:

```
[1/6] Project discovery
[2/6] Secret scan
[3/6] Dangerous-code scan
[4/6] Dependency scan
[5/6] Configuration scan
[6/6] Git scan

Critical: 1
High: 3
Medium: 2
Low: 1
Informational: 0
Blocking: 4

Report: /abs/path/reports/security-report.json
Report: /abs/path/reports/security-report.md
Status: NOT READY
```

## Exit codes

Deterministic; the first matching rule wins.

| Code | Meaning |
|---|---|
| `2` | At least one **blocking** finding: an active (OPEN / REQUIRES_REVIEW) CRITICAL finding, or an active HIGH finding with MEDIUM or HIGH confidence |
| `3` | Scanner or external-tool failure (crash, timeout, unparseable output), invalid config/baseline, or CLI usage error |
| `1` | Non-blocking active findings (MEDIUM, LOW, or HIGH with LOW confidence) |
| `0` | No active findings above INFORMATIONAL |

Usage errors exit `3` on purpose: argparse's default `2` would be indistinguishable from "blocking findings".
A tool that is simply *not installed* is not a failure; it is recorded under Scanner Availability and Limitations.

## Release status

| Status | When |
|---|---|
| `NOT READY` | Any blocking finding, or any scanner/tool failure (the audit is incomplete) |
| `READY WITH DOCUMENTED RISKS` | Non-blocking active findings or baselined findings remain |
| `READY` | No active findings above INFORMATIONAL. **This is not proof of security**; see Limitations |

## What each scanner does

**Project discovery** – evidence-based detection of Next.js, React, Node.js, Express, Django, FastAPI, Flask,
Supabase, Firebase, PostgreSQL, MySQL, Prisma, Docker, Terraform, AWS, Vercel, Python, Rust, Go. Each detection
lists its evidence. An AWS SDK dependency alone is reported only as `AWS (SDK only)` with LOW confidence.

**Secrets** (`rules/secret-patterns.yaml`) – private keys (with key-body plausibility check), AWS key IDs and
secret keys, GitHub tokens, Stripe live/test keys, OpenAI/Anthropic-style keys, Slack tokens, Google API keys,
Supabase secret keys and service-role JWTs (JWT payload decoded in memory; anon keys are INFORMATIONAL),
database URLs with credentials (local hosts downgraded), bearer tokens, credential assignments in code,
`.env` and YAML, keyword-scoped high-entropy strings. Placeholders (`changeme`, `your-...`, `${VAR}`,
`process.env.X` ...) are ignored. Lockfiles and binaries are skipped. If `gitleaks` is installed it also
runs (`gitleaks detect --no-git --redact`) and its results are merged with the internal ones.

**Dangerous code** (`rules/dangerous-patterns.yaml`) – JS/TS: `eval`, `new Function`, string timers, `vm`,
`child_process.exec/execSync`, spawn with `shell: true`, `dangerouslySetInnerHTML`, `innerHTML/outerHTML`,
`insertAdjacentHTML`, `document.write`, SQL via template literals/concatenation, `$queryRawUnsafe`,
dynamic `require/import`, request-controlled file paths. Python: `eval`, `exec`, `os.system/popen`,
`subprocess` (`shell=True` separately), `pickle/marshal`, unsafe `yaml.load`, SQL via f-string/`%`/`format`,
dynamic imports, `render_template_string`, `mark_safe`, request-controlled file paths.
A proximity taint heuristic decides status:

| Evidence | Severity | Confidence | Status |
|---|---|---|---|
| untrusted input (req.query, request.args, location.hash, sys.argv, ...) on the same line | rule's `tainted_severity` | HIGH | OPEN |
| untrusted input within the previous 12 lines | `tainted_severity` | MEDIUM | OPEN |
| no visible source | rule's base severity | LOW | REQUIRES_REVIEW |
| string-literal argument only | INFORMATIONAL | HIGH | REQUIRES_REVIEW |

Matches inside closed string literals, Python docstrings and comment lines are skipped. Findings in test/fixture/example paths keep their severity but get LOW confidence (path names are attacker-controlled, so a CRITICAL there still blocks).

**Dependencies** – see "Supported ecosystems" below. Local checks: missing/multiple lockfiles, lockfile out of
sync with the manifest (npm, pnpm, yarn, poetry, uv), non-registry and plain-HTTP sources, missing integrity,
install lifecycle scripts (suspicious ones flagged MEDIUM), transitive packages with install scripts,
imported-but-undeclared JS packages, `--extra-index-url` / `--trusted-host` / HTTP index in requirements.
**CVE data comes only from external tools; the scanner never invents CVEs, advisories or fixed versions.**

**Configuration** – Django `DEBUG`/`ALLOWED_HOSTS`/cookie flags, Flask `debug=True`, CORS wildcards and
reflected origins, cookie `secure/httpOnly: false`, `SameSite=None`, public-prefixed env vars
(`NEXT_PUBLIC_`, `VITE_`, `REACT_APP_`, ...) whose *name or value* indicates a secret (anon/publishable keys
and URLs are not flagged), debug/dev mode in production env files, identical secrets across environments
(compared by hash), `.env` files not ignored by Git, service-role keys in client components, Dockerfile
`curl | sh`, `ADD <url>`, secrets in `ENV/ARG`, root user, Compose/Kubernetes `privileged`, Docker socket
mounts, dangerous capabilities, host networking, database/admin ports published on all interfaces, Terraform
public ACLs / publicly accessible DBs / `0.0.0.0/0` / disabled encryption, open Firebase rules, Supabase
`disable row level security` / `using (true)`, GitHub Actions script injection and `pull_request_target`
checkouts.

**Git** – tracked `.env` files, private keys/keystores, credential/state files (`.npmrc` with tokens,
`terraform.tfstate`, service-account JSON, ...), large tracked files, secrets added in the most recent N
commits (reported as *"Potential secret exposure in Git history"* with commit hashes only), lockfile-only
commits. History is never rewritten.

## Supported ecosystems and external tools

| Ecosystem | Files | External tool (optional) | How it is run |
|---|---|---|---|
| Node (npm) | `package.json`, `package-lock.json`, `npm-shrinkwrap.json` | `npm audit` | `npm audit --json --package-lock-only --ignore-scripts` |
| Node (pnpm) | `pnpm-lock.yaml` | `pnpm audit` | `pnpm audit --json --ignore-pnpmfile` |
| Node (yarn) | `yarn.lock` | – | local consistency checks only |
| Python | `requirements*.txt`, `pyproject.toml`, `poetry.lock`, `uv.lock` | `pip-audit` | `pip-audit -r <file> --disable-pip --no-deps --format json`, only for fully pinned files |
| Rust | `Cargo.toml`, `Cargo.lock` | `cargo-audit` | `cargo-audit audit --json` (binary called directly, not via `cargo`) |
| Go | `go.mod`, `go.sum` | `govulncheck` | `govulncheck -json ./...` with `GOTOOLCHAIN=local CGO_ENABLED=0` |
| Secrets | all text files | `gitleaks` | `gitleaks detect --no-git --redact --source .` |

Missing tools are reported as unavailable (not as failures) and listed in Limitations.

## Security guarantees (what the scanner will and will not do)

- **Read-only.** The only files written are the reports in `--output` and, with `--update-baseline`, the baseline file.
  The output directory is *not* excluded from the scan (a project could contain a directory of the same name);
  generated reports hold only redacted evidence.
- **No project code is executed.** No install, build, test or lifecycle scripts. Package managers run with
  `npm_config_ignore_scripts=true` and `--ignore-scripts` / `--ignore-pnpmfile`; pip-audit runs with
  `--disable-pip --no-deps` (it never installs or builds packages); `cargo-audit` is invoked directly so a
  project `.cargo/config.toml` `[alias]` cannot redirect it; Go runs with `GOTOOLCHAIN=local` and `CGO_ENABLED=0`;
  Corepack downloads are disabled.
- **Minimal child environment**: tools receive an allowlisted environment (PATH, HOME, temp dirs, proxy/CA and
  toolchain variables). Tokens such as `NPM_TOKEN`, `GITHUB_TOKEN` or `AWS_*` are not passed, so a project `.npmrc`
  cannot expand them and send them to an attacker-chosen registry.
- **Executable resolution** ignores relative `PATH` entries, the current directory and any directory inside the
  scanned project, so a committed `git.bat`/`npm.cmd` is never run.
- **Allowlisted subprocesses only**: `git, gitleaks, npm, pnpm, pip-audit, cargo-audit, govulncheck`, always with
  `shell=False`, an argument list, closed stdin, a timeout and an output cap. Project paths are passed as the
  working directory, never interpolated into a command string. `.cmd/.bat` wrappers on Windows reject arguments
  containing cmd.exe metacharacters.
- **Git hardening**: every git call is prefixed with `-c core.fsmonitor=false -c core.pager=cat -c diff.external=
  -c core.hooksPath=<null> -c log.showSignature=false -c gpg.program=` (plus `--no-pager`), and history reads use
  `--no-ext-diff --no-textconv --no-show-signature`, so repository-local config cannot run commands. Tests plant a
  malicious `core.fsmonitor` and a malicious `gpg.program` + signed commit and assert nothing executes.
- **Secrets are never output.** Evidence describes the match (rule, length) and every evidence string is passed
  through a redaction filter. Tests assert fixture secrets never appear in JSON or Markdown.
- **No network changes, deployments, credential rotation, database access or history rewriting.**
  External audit tools do contact their advisory databases/registries.
- **Bounded input**: files > 2 MiB skipped (configurable), lines capped at 4000 chars before regex matching,
  symlinks never followed, file count capped, lockfiles capped at 30 MiB, config 256 KiB, baseline 10 MiB.
- **Report injection**: Markdown escapes all project-derived text (paths, evidence, tool output) and strips control
  characters in console output.

## Finding schema

Every scanner returns the same structure (`src/phase2/models.py`); JSON adds `blocking`.

| Field | Notes |
|---|---|
| `id` | Deterministic: `P2-` + sha256(category, file, line, dedup key)[:12] |
| `fingerprint` | sha256(category, file, dedup key, secret-free line context) – survives line moves; used by baselines |
| `scanner`, `source` | Originating scanner; `source` lists every rule/tool that reported it after dedup |
| `category` | e.g. `secret`, `secret-history`, `secret-exposure`, `command-injection`, `sql-injection`, `xss`, `dependency`, `vulnerable-dependency`, `cors`, `cookie`, `container`, `cloud`, `ci-cd` |
| `severity` | `CRITICAL`, `HIGH`, `MEDIUM`, `LOW`, `INFORMATIONAL` |
| `confidence` | `HIGH`, `MEDIUM`, `LOW` |
| `classification` | `CONFIRMED`, `POTENTIAL`, `REQUIRES_RUNTIME_VERIFICATION`, `INFORMATIONAL` |
| `status` | `OPEN`, `REQUIRES_REVIEW`, `BASELINED`, `IGNORED`, `FIXED` (stale baseline entries) |
| `title`, `description`, `impact`, `recommendation`, `validation` | Human text |
| `project`, `file`, `line`, `column` | POSIX-style path relative to the project root |
| `evidence` | Redacted, ≤ 300 chars |
| `cwe`, `owasp` | Where applicable |
| `rule_id`, `notes`, `tags`, `context` | Rule identifier, reasoning notes, e.g. `test-context` |

Duplicates (same category + file + line + dedup key, e.g. internal secret rule and gitleaks) are merged:
highest severity/confidence wins and all sources are kept.

## Baseline

```bash
# accept current non-critical findings (explicit; review the file before committing it)
phase2-scan . --baseline security-baseline.json --update-baseline
# later runs
phase2-scan . --baseline security-baseline.json
```

- Matching findings become `BASELINED` (not blocking, still listed in the report).
- New findings stay `OPEN`.
- **CRITICAL findings are never baselined**, neither when writing nor when applying.
- A finding whose severity increased since it was baselined is kept active.
- Entries no longer detected are listed as `FIXED` (stale).
- Each entry has a `reason` field; replace the placeholder with the justification.
- Protect the baseline (and any `--config`) with CODEOWNERS: whoever can edit it can hide non-critical findings.

Inline suppression: a `phase2:ignore` comment on the flagged line sets the status to `IGNORED` (listed in the
report). It only works for MEDIUM and lower: CRITICAL/HIGH findings need a reviewed baseline entry, so the author
of a change cannot silence a blocking finding in the same change.

## CI usage

For SARIF output and a policy-based CI gate across Phase 2, Phase 3 and AI-review findings, see
`tools/security-ci/` (`security-ci sarif`, `security-ci gate`) and its example workflow
`tools/security-ci/examples/github-actions-security-ci.yml`. It reads `security-report.json`; this scanner's exit
codes are unchanged. SARIF does not change verification status and is not proof of security.


See `examples/github-actions-security.yml`: checkout the project to `project/` and the scanner to `scanner/`,
install Python and the scanner, scan only `project/`, upload `security-reports/` as an artifact, fail the job when
the exit code is `>= 2` (blocking findings or tool failure). Use `>= 1` to also fail on non-blocking findings.
Do not take `--config` or `--baseline` from the pull request being scanned without review, and do not exclude
paths inside the scanned tree in CI (path names are attacker-controlled).

## Examples

```bash
# scan this repository, excluding the scanner's own deliberately vulnerable fixtures (this repo only)
python -m phase2.cli --project ../.. --config examples/security-config.yaml

# only show High+ in reports (exit code still reflects everything)
phase2-scan ../../my-app --severity high

# offline / hermetic run
phase2-scan ../../my-app --no-external-tools --git-history-depth 0
```

## Tests

```bash
python -m pytest            # from tools/phase2-security-scanner
```

Fixtures in `tests/fixtures/` (`vulnerable-node`, `vulnerable-python`, `safe-project`) contain deliberately
insecure code and **fake** credentials (they contain `FAKE`). Scanning this repository without the example
config therefore reports them. Token formats that trigger push protection (GitHub, Stripe live) are assembled
at runtime in `tests/conftest.py` instead of being committed.

## Limitations

- Static, line-based analysis. No inter-procedural data flow; multi-line calls, aliased imports and
  triple-quoted strings can cause misses or false positives. JS/TS and Python only for dangerous-code rules.
- Secret findings are pattern matches; the scanner never validates a credential with its provider.
- Vulnerability (CVE) coverage exists only for ecosystems whose audit tool is installed; yarn is not audited;
  pip-audit is skipped for unpinned requirements and for pyproject-only projects.
- `pip-audit` and `cargo-audit` do not report severities; their findings default to MEDIUM / REQUIRES_REVIEW.
  govulncheck severity is derived from reachability (HIGH if the vulnerable symbol is called).
- Git history: only the last N commits reachable from HEAD; other branches, stashes and unreachable objects
  are not scanned; historical large blobs are not measured. Repositories failing Git's `safe.directory` check are skipped.
- Build output (`dist`, `.next`, ...) is excluded unless `include_build_output: true`.
- Client/server classification for Next.js files is heuristic (`'use client'`, paths).
- Authentication, authorization/IDOR, business logic, rate limiting, security headers and runtime behaviour
  are out of scope and must be covered by the other `06-security` skills and staging tests.
- Deliberate obfuscation (e.g. `window['ev'+'al']`, string splitting) defeats static pattern matching.
- Default directory exclusions (`vendor`, `dist`, `build`, ...) are path-name based; an attacker can place code there.
  Use `include_default_excludes: false` / `include_build_output: true` for adversarial reviews.
- **An empty report does not mean the application is secure.**

## Scanner self-review

`SECURITY-REVIEW.md` records the security review of the scanner itself (findings SR-01 ... SR-16) and how each
confirmed issue was fixed; `tests/test_security_hardening.py` holds the regression tests.

## Layout

```
src/phase2/cli.py            argument parsing, console output, exit code
src/phase2/orchestrator.py   pipeline, config, normalization, dedup, baseline application
src/phase2/discovery.py      technology detection
src/phase2/scanners/         secrets, dangerous_code, dependencies, configuration, git
src/phase2/reporting/        json_report, markdown_report
src/phase2/baseline/         baseline load/apply/write
src/phase2/utils/            command (allowlisted subprocess), filesystem (bounded walk), redaction
rules/                       secret-patterns.yaml, dangerous-patterns.yaml
```
