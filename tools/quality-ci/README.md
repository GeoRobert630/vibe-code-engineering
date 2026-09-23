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
