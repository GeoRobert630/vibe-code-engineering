# Security review of phase2-security-scanner (self-audit)

Second-pass review of the scanner itself, performed after the first implementation
and self-scan. Scope: command injection, path traversal, subprocess use, arbitrary
command execution, secret leakage, malicious repository content, parsing, YAML,
resource exhaustion, symlinks, report injection, baseline manipulation, CI exit-code
bypass, dependency risk.

Findings were recorded here **before** any fix was applied. The "Resolution" column
was filled in afterwards.

| ID | Severity | Status of evidence | Finding | Resolution |
|---|---|---|---|---|
| SR-01 | CRITICAL | Reproduced | **Arbitrary command execution from a malicious repository.** A repository-local `log.showSignature=true` plus `gpg.program=<script>` and a commit carrying a `gpgsig` header makes `git log` (history scan) execute the script. Reproduced: running the scanner on such a repo created a marker file. | Fixed. Every git call now adds `--no-pager -c log.showSignature=false -c gpg.program= -c gpg.ssh.program= -c gpg.x509.program= -c protocol.allow=never`; `git log` also gets `--no-show-signature`. Regression test `test_sr01_*` plants the malicious config + signed commit, proves the control executes, and asserts the scanner does not. Mutation-checked: removing the defences makes the test fail. |
| SR-02 | HIGH | Confirmed by design (npm expands `${VAR}` in `.npmrc`); not replayed against a live registry | **Secret exfiltration through inherited environment.** Child tools received the full environment (`NPM_TOKEN`, `GITHUB_TOKEN`, `AWS_*` ...). A project `.npmrc` can set `registry=` to an attacker host and `//host/:_authToken=${NPM_TOKEN}`, so `npm audit` / `pnpm audit` would send the CI token to the attacker. | Fixed. `command.safe_env()` passes an allowlisted environment only (PATH, HOME, temp, proxy/CA, toolchain dirs). Test `test_sr02_*`. |
| SR-03 | HIGH | Confirmed (code path) | **CI bypass via inline suppression.** A `phase2:ignore` comment added by the same PR marks HIGH findings (e.g. tainted `eval`) IGNORED, so they no longer block. | Fixed. Inline `phase2:ignore` only applies to MEDIUM and below; CRITICAL/HIGH need a reviewed baseline. Test `test_sr03_*`. |
| SR-04 | HIGH | Confirmed (code path) | **CI bypass via output directory exclusion.** The `--output` directory (default `./reports`, relative to cwd) is excluded from the walk. Running `phase2-scan .` from the project root skips the project's own `reports/` directory, where an attacker can place code or secrets. | Fixed. The output directory is no longer excluded; generated reports contain only redacted evidence and produced no findings when re-scanned (verified). Test `test_sr04_*`. |
| SR-05 | MEDIUM | Confirmed (example files) | **CI example excludes attacker-controllable paths.** The workflow checked the scanner out inside the scanned workspace and passed a config excluding `.phase2-scanner/*` and `tools/phase2-security-scanner/tests/fixtures/*`; a PR can create those paths to hide content. | Fixed. CI example checks out `project/` and `scanner/` separately, scans only `project/`, uses no config; the example config is marked as this-repository-only. |
| SR-06 | MEDIUM | Documented Python 3.11 behaviour; not reproducible on 3.13 (tested) | **Executable planting via `shutil.which`.** On Windows, Python 3.11's `shutil.which` searches the current directory before `PATH`. With cwd = project root (typical in CI), a committed `git.bat`/`npm.cmd` would be executed. | Fixed. Executables are resolved against a sanitised PATH (absolute entries only, nothing inside the scanned project) with `NoDefaultCurrentDirectoryInExePath=1`; results inside the project are rejected. Tests `test_sr06_*`. |
| SR-07 | MEDIUM | Confirmed (code path) | **Blocking findings hidden by path naming.** Dangerous-code findings under `tests/`, `fixtures/`, `examples/`, ... were downgraded one severity level *and* to LOW confidence, turning a tainted CRITICAL into a non-blocking HIGH. | Fixed. Test/fixture paths now lower confidence only; severity is kept, so CRITICAL still blocks. |
| SR-08 | MEDIUM | Reproduced (benchmark) | **Regex CPU exhaustion.** `secret-assignment-yaml` and `cfg-cap-add-dangerous` start with `^\s*-?\s*`, which is quadratic on long whitespace lines: 0.21 s for one 4000-char line, i.e. minutes for a crafted 2 MiB file. All other rules measured < 10 ms on adversarial inputs. | Fixed. Both patterns rewritten to `^\s*(?:-\s*)?`; all rules now < 50 ms on adversarial 4000-char lines (tests `test_sr08_*`). |
| SR-09 | LOW | Reproduced | **Windows junctions are traversed.** `os.walk(followlinks=False)` descends into directory junctions. Files outside the root are dropped by the `is_within` check (no leak), but silently, and cyclic junctions waste work. | Fixed. Directories that are symlinks, junctions (`Path.is_junction`) or resolve outside the root are skipped and listed; files resolving outside are listed too. Test `test_junctions_and_symlinks_outside_root_not_followed` uses a symlink, or a real junction where symlinks are unavailable. |
| SR-10 | LOW | Confirmed (code path) | **Residual secret exposure in report fields.** (a) Dockerfile rule evidence is the raw line; `ENV API_TOKEN value` (space form) is not masked by the generic redactor. (b) The `context` field (used for fingerprints) was emitted in JSON; with two secrets on one line only the matched one was masked. | Fixed. Dockerfile ENV/ARG evidence shows only the variable name; `context` is no longer emitted; all evidence/context is additionally masked with every secret rule before sanitising. Test `test_sr10_*`. |
| SR-11 | LOW | Confirmed (code path) | **Parser recursion crash.** Deeply nested YAML (pnpm-lock) / TOML raise `RecursionError`, which was not caught; the dependency scanner aborts (fails closed with exit 3, but loses its other results). | Fixed. `RecursionError` caught for YAML/TOML parsing (JSON already was). Test `test_sr11_*`. |
| SR-12 | LOW | Confirmed (code path) | **pip-audit pin check too loose.** Lines starting with `-` (`-e`, `-r`, `-c`) and direct-URL requirements were ignored by the "fully pinned" check, so such files were passed to pip-audit (`--disable-pip` prevents builds; result is a tool failure, not execution). | Fixed. `requirements_fully_pinned()` accepts only plain `name==version` lines (extras/markers/hashes allowed). Test `test_sr12_*`. |
| SR-13 | LOW | By design of pnpm ≥ 9.7 | **pnpm self-switching.** `packageManager` in `package.json` can make pnpm download and run another pnpm version (official registry package, not arbitrary code). | Fixed. `npm_config_manage_package_manager_versions=false` in the child environment. |
| SR-14 | INFO | Accepted limitation | **Heuristic evasion.** The string-literal skip can be abused (unbalanced quote / regex literal before a call) to hide a match. Static pattern scanners cannot resist deliberate obfuscation (`window['ev'+'al']`). | Mitigated. The string-literal skip now requires the quote to close later on the same line; deliberate obfuscation remains a documented limitation. |
| SR-15 | INFO | Accepted limitation | **Trusted inputs.** `--baseline` and `--config` can hide non-critical findings; they are never auto-loaded from the target and are listed in the report. Protect them with CODEOWNERS. | Accepted; documented in README (CODEOWNERS, never take config/baseline from the PR under test). |
| SR-16 | INFO | Accepted | Audit tools talking to an attacker-chosen registry can return misleading advisory text; it is parsed as data and escaped in Markdown. | Accepted; documented. |

Checked with no issue found:

- **Command injection**: every subprocess uses an argument list with `shell=False`; the only non-constant arguments are
  a Git pathspec after `--`, a regex-validated requirements filename, an integer and a temp-file path. `.cmd/.bat`
  wrappers reject cmd.exe metacharacters.
- **Path traversal**: report/baseline paths come only from the CLI; gitleaks paths are resolved and required to be
  inside the root; project paths are never joined from untrusted absolute input.
- **YAML**: only `yaml.safe_load` is used; rule files are trusted; target YAML is size-capped.
- **Report injection**: Markdown escapes `[ ] ( ) ! | * _ \` # ~` and converts `< > &` to entities; control characters
  are stripped from Markdown and console output; JSON is produced by `json.dumps`.
- **Exit codes**: argparse errors and internal exceptions exit 3, never 0/1/2; `--severity` filters only the report.
- **Dependencies**: one runtime dependency (PyYAML ≥ 6, safe loader only).

Also changed during the review: `.vscode/` and `.idea/` removed from default exclusions (editor task/settings files
can hold secrets or auto-run tasks).

Found by the self-scan (before this review) and fixed: rule text inside Python docstrings and string literals was
reported as code (e.g. `app.run(debug=True)` in a description), a PEM header without a key body was CRITICAL, the
`py-sql-fstring` rule matched `write_text(f"...")`. Each has a regression test.
