# quality-ci

Quality CI for the vibe-code-engineering pipeline. **Phase 4A: accessibility.**

Runs the established accessibility engine **axe-core 4.10.3** (Deque; vendored, SHA-256 pinned, MPL-2.0) in
headless Chromium via Playwright against **explicitly configured** local/development/staging pages, and writes
JSON (source of truth), Markdown and optional SARIF 2.1.0 reports plus an explicit quality gate. It does not invent
accessibility rules; it reports exactly what axe-core evaluated.

```
Quality CI
    ↓
Accessibility            quality-ci a11y   -> accessibility-report.json / .md
    ↓
JSON / Markdown
    ↓
SARIF                    quality-ci sarif  -> accessibility.sarif   (quality category, not security)
    ↓
Quality gate             quality-ci gate   -> exit 0 pass / 1 fail / 3 error
```

- **Separate from Security CI.** Findings use the `Q-A11Y-*` namespace; security findings use `P2-*`, `RT-*`, `AI-*`.
  Accessibility findings never become security findings (no `security-severity` in SARIF, separate SARIF category,
  separate gate). This tool does not import or change Phase 2, Phase 3, ZAP or security-ci.
- **Not proof of compliance.** A clean scan is not proof of full WCAG compliance or of complete accessibility.
  Automated rules cover a subset of WCAG; manual testing is still required.

## Usage

```bash
cd tools/quality-ci && python -m pip install -e ".[browser,dev]"
python -m playwright install chromium        # or use an installed browser: browser.channel: chrome | msedge

quality-ci a11y  --config quality-ci.yaml --output reports [--format json|markdown|both] [--sarif reports/a11y.sarif]
quality-ci sarif --report reports/accessibility-report.json --sarif reports/a11y.sarif [--anchor path/in/repo]
quality-ci gate  --report reports/accessibility-report.json [--fail-on release|critical|high|medium|low] \
                 [--allow-incomplete] [--require-configured]
```

`quality-ci a11y` without `--config` writes a **NOT CONFIGURED** report and scans nothing.

## Configuration

```yaml
target:
  base_url: http://127.0.0.1:3000
  environment: local          # local | development | staging (and dev/test/qa/preview aliases)
  production: false           # must be explicit; true is always refused
  # authorized: true          # required with authorized_by for non-local staging hosts
  # authorized_by: "QA lead"
pages: ["/", "/contact"]      # the only pages loaded; same origin as base_url
limits:                       # defaults; hard caps in brackets
  max_pages: 10               # [25]  pages beyond this are NOT SCANNED (run INCOMPLETE)
  page_timeout_seconds: 30    # [120]
  total_timeout_seconds: 300  # [1800]
  max_page_bytes: 2000000     # [10 MB] per response and per page total
assets:
  allow_origins: []           # extra origins for GET sub-resources (CSS/fonts); never navigated
engine:
  tags: [wcag2a, wcag2aa, wcag21a, wcag21aa, best-practice]
browser:
  channel: chromium           # chromium | chrome | msedge
```

Unknown keys and credential-related keys (`headers`, `cookies`, `auth`, `password`, `token`, `storage_state`,
`http_credentials`, ...) are rejected. URLs with embedded credentials are rejected.

## Safety controls

| Control | Behaviour |
|---|---|
| Targets | local/development/staging only; `production: true`, prod/production/live environments or host labels refused (same policy as phase3-runtime-security, no override); remote staging needs `authorized` + `authorized_by` |
| Pages | only the configured list; no crawling; page count, per-page and total time, and byte limits all hard-capped |
| Requests | every request is routed: only GET/HEAD; only the target origin (+ asset origins for sub-resources); redirects are not followed; the main frame cannot navigate away (form submissions and script navigations are aborted) |
| Interaction | none: no clicks, typing or form submission; dialogs dismissed; downloads refused; service workers blocked |
| Credentials | none: fresh browser context per page, no cookies/storage state/HTTP credentials; environment variables are not read |
| Determinism | fixed viewport 1280x800, locale en-US, timezone UTC, reduced motion; pinned engine; sorted output; IDs are hashes of the rule |
| Output | only rule metadata, page URLs (query values removed) and CSS selectors (sensitive attribute values removed); never HTML snippets or page text; all strings redacted |

A page that is blocked, redirected, too large or too slow is reported (`NAVIGATION BLOCKED`, `OVERSIZE`, `TIMEOUT`,
`HTTP ERROR`, `ERROR`) and the run is **INCOMPLETE**; it is never silently passed.

## What is checked

Whatever axe-core evaluates for the configured tags (89 rules with the default tags in the fixture runs), for example:
document language (`html-has-lang`, `html-lang-valid`, `valid-lang`), page title (`document-title`), form labels
(`label`, `select-name`), image alternative text (`image-alt`, `input-image-alt`, `role-img-alt`), heading structure
(`heading-order`, `page-has-heading-one`, `empty-heading`), link and button names (`link-name`, `button-name`),
colour contrast (`color-contrast`, where computable), keyboard/focus issues detectable statically (`tabindex`,
`scrollable-region-focusable`, `aria-hidden-focus`, `nested-interactive`, `skip-link`), landmarks/ARIA (`region`,
`landmark-*`, `aria-*`). The report's `rules_evaluated` lists the exact rules that ran; nothing else is claimed.

## Findings

One finding per axe rule (grouped across nodes and pages): `id` (`Q-A11Y-<10 hex>`, deterministic), `rule_id` /
`engine_rule`, `title`, `description`, `impact` (axe: critical/serious/moderate/minor) and `severity`
(CRITICAL/HIGH/MEDIUM/LOW), `url` + `urls`, `selector` (representative) + per-page `selectors` (up to 5),
`occurrence_count`, `help`, `help_url`, `wcag` tags, `source` (`axe-core <version>`), `blocking` (CRITICAL/HIGH).
Rules axe could not decide are **needs-review** results: `INFORMATIONAL`, status `NEEDS_REVIEW`, separate IDs; they
never fail the gate. Different rules are never merged.

## Reports

JSON (`accessibility-report.json`): `run` (status COMPLETE/INCOMPLETE/REFUSED/NOT CONFIGURED, verdict
PASS/FAIL/INCOMPLETE/NOT CONFIGURED/NOT VERIFIED, reasons, timestamps, exit code), `target`, `engine`,
`pages_tested`, `rules_evaluated`, `summary`, `findings`, `limitations`, `notice`.
Markdown: `## Accessibility`, `## Findings`, `## Pages Tested`, `## Limitations`.

## Quality gate

| `--fail-on` | Fails when |
|---|---|
| `release` (default) | any active finding marked `blocking` (axe impact critical/serious) |
| `critical` | any active CRITICAL |
| `high` | any active CRITICAL or HIGH |
| `medium` | also active MEDIUM |
| `low` | also active LOW |

Outcomes are distinguished: **active finding** (fails at/above the policy), **informational** (needs-review, never
fails), **scan incomplete** (INCOMPLETE/REFUSED fails unless `--allow-incomplete`), **not configured** (passes with an
explicit "accessibility NOT VERIFIED" note unless `--require-configured`). Exit codes: gate 0/1/3;
`a11y` 0 no active findings, 1 non-blocking findings, 2 blocking findings, 3 refused/incomplete/config error.

## SARIF

One run (`quality-ci-accessibility`, automation id `vibe-code-engineering/quality/accessibility/`), ruleId
`a11y/<axe rule>`, level error/warning/note from severity, `kind: review` for needs-review results, logical locations
for page URL + representative selector, optional `--anchor` physical location, `partialFingerprints.findingId/v1`,
redacted strings, deterministic output. No `security-severity`: platforms show these as quality results.

## Tests

`python -m pytest` - browser tests (GOOD/BAD/FIXED fixtures in `fixtures/`, served locally) are skipped when
Playwright or a Chromium-family browser is unavailable.

---

# Phase 4B: Performance (lab)

`quality-ci-perf` measures explicitly configured local/development/staging pages in headless Chromium and gates on
performance budgets. It shares the 4A safety gate, route model, credential rules and redaction; findings use the
separate `Q-PERF-*` namespace. **Lab data only**: not field data, not proof of real-user performance.

```bash
quality-ci-perf perf  --config quality-perf.yaml --output reports [--sarif reports/performance.sarif]
quality-ci-perf sarif --report reports/performance-report.json --sarif reports/performance.sarif
quality-ci-perf gate  --report reports/performance-report.json [--fail-on release|critical|high|medium|low] \
                      [--allow-incomplete] [--require-configured]
```

**Engine.** Chromium performance APIs plus vendored web-vitals 6.2.2 (`web-vitals.attribution.iife.js`, SHA-256
`3ae0ee54...8b4e`, Apache-2.0, verified before every run). CPU is throttled via CDP; network throttling is not applied
(responses pass through the safety route handler), so network cost is modelled (`model.critical-path`).

**Checks.** Deterministic: `budget.total-bytes`, `budget.script-bytes`, `budget.stylesheet-bytes`, `budget.image-bytes`,
`budget.font-bytes`, `budget.document-bytes`, `budget.request-count`, `budget.render-blocking` (sync head scripts,
matching head stylesheets, CSS `@import` chains read from the CSSOM), `budget.dom-nodes`, `model.critical-path`.
Timing (median of runs): `timing.fcp`, `timing.lcp`, `timing.cls`, `timing.tbt` (FCP to end of observation; not
Lighthouse TBT). Diagnostics: unsized images, oversized images, text compression (not applicable on `local`).
Recorded only: TTFB, DOMContentLoaded, load event, long-task count. INP is not measured.

**Profiles.** `mobile-lab` (412x823, DPR 1.75, CPU 4x, model 150 ms / 1.6 Mbit/s; default) and `desktop-lab`
(1350x940, DPR 1, CPU 1x, model 40 ms / 10 Mbit/s).

**Default budgets (WARN > / FAIL >).** FCP 1800/3000 ms, LCP 2500/4000 ms, CLS 0.100/0.250, TBT 200/600 ms, total bytes
1.6 MB/4 MB, script bytes 350 KB/1 MB, image bytes 1 MB/2.5 MB, requests 60/150, render-blocking 2/6, DOM nodes
1,500/3,000, critical path 2000 ms (WARN only), diagnostics > 0 (LOW, never FAIL). Stylesheet/font/document bytes are
measured and reported without a default budget. Overrides (`budgets:`) are allowed up to 10x the default and are
always listed in the report.

**Aggregation.** One discarded warm-up run plus 3-7 measured runs per page, each in a fresh browser context, strictly
sequential, never retried. Equality passes. Timing FAIL needs a strict majority of runs above `fail` (floor(N/2)+1:
2 of 3, 3 of 5); coefficient of variation > 0.35 makes a WARN/FAIL timing check `unstable` WARN; deterministic values
must match across runs (otherwise `nondeterministic`, maximum used).

**Host benchmark.** A fixed xorshift workload (5,000,000 iterations, unthrottled, median of 3) gives
`benchmark_index = 100000 / ms`. Below `MIN_BENCHMARK`, `timing_reliability` is LOW and timing FAILs are capped at WARN;
deterministic checks are never capped. `MIN_BENCHMARK = 1000` is **provisional (2026-09-24, local measurements
only)**; it must be re-calibrated to 50% of the observed ubuntu-latest median before release.

**Severity.** FAIL -> HIGH (blocking); WARN -> MEDIUM; diagnostic -> LOW; NOT MEASURED / nondeterministic -> INFORMATIONAL
(needs review). CRITICAL is never used. SARIF: driver `quality-ci-performance`, ruleId `perf/<check_id>`, no
`security-severity`, upload category `...-quality-performance`.

**Limits.** pages 10 (cap 25), measured runs 3 (3-7), page timeout 30 s (cap 120), total 600 s (cap 1800), bytes per
response/run 5 MB (cap 20 MB), requests per run 300 (cap 500), observation window 5000 ms (cap 15000). Not a load test.

**Fixtures** (`fixtures/performance/`): GOOD -> PASS; SLOW -> FAIL (`timing.tbt`, `timing.cls`, `budget.dom-nodes`;
WARN `budget.render-blocking`, `budget.script-bytes`, `model.critical-path`; LOW unsized image); FIXED -> PASS.
SLOW fails on `budget.dom-nodes` even when timing is capped on a slow host.

**Tests.** `python -m pytest` (browser tests skip without Playwright/Chromium). Repeatability (20x each fixture, no
retries): `python -m pytest -m repeat tests/performance/test_repeat.py`.
