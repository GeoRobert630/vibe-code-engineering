# Adopting Vibe-Code Engineering

This is the single guide for adding the complete system to a project. It covers which file to copy, the released
versions it pins, every configuration setting, what each gate means and what is (and is not) verified.
See also [TROUBLESHOOTING.md](TROUBLESHOOTING.md), [UPGRADING.md](UPGRADING.md) and the starter project in
[`templates/adopter-project/`](../templates/adopter-project/).

## 1. The canonical workflow

Adopt the system with **one file**:

| | |
|---|---|
| File to copy | `tools/engineering-ci/examples/github-actions-engineering-ci.yml` |
| Copy it from | release tag `engineering-ci-v1.2` (commit `70d52f8`) |
| Put it at | `.github/workflows/engineering-ci.yml` in your project, unchanged |

```bash
mkdir -p .github/workflows
curl -fsSL https://raw.githubusercontent.com/GeoRobert630/vibe-code-engineering/engineering-ci-v1.2/tools/engineering-ci/examples/github-actions-engineering-ci.yml \
  -o .github/workflows/engineering-ci.yml
```

The workflow checks out the released tools itself; you do not install anything or combine the per-tool example
workflows (`tools/*/examples/`). Those examples run one tool on its own and are not needed for adoption.

It runs on **push to `master`**, on **pull requests** and on **manual dispatch** (`workflow_dispatch`). If your default
branch is not `master`, change only the `branches:` line under `push:`. With no configuration at all it already runs the
Security gate on the repository and enforces the result; accessibility and performance are reported NOT CONFIGURED
until a quality target is set.

Nothing needs a secret, token, password or cookie. Configuration is done with repository **variables**
(Settings > Secrets and variables > Actions > Variables). The workflow needs the permissions it declares:
`contents: read`, `actions: read`, `security-events: write` (for SARIF upload to code scanning).

## 2. How it works

```
security job (Security CI)       quality job (Accessibility)        performance job (Performance)
Phase 2 static scan              quality-ci a11y     (if target)    quality-ci-perf perf  (if target)
Phase 3 runtime   (if target)    quality-ci sarif / gate            quality-ci-perf sarif / gate
security-ci sarif / gate
        \                                  |                                  /
         engineering job: engineering-summary.json + final enforcement (needs all three, always runs)
```

- **Security** - Phase 2 static scan of the repository (secrets, dangerous code, dependencies, configuration, Git
  history); Phase 3 runtime defensive checks only when `RUNTIME_TARGET_URL` is set (headers, cookies, CORS, HTTP to
  HTTPS, TLS, error leakage; optional passive ZAP baseline); then `security-ci` exports SARIF and applies the gate.
  Findings: `P2-*`, `RT-*`, `AI-*`.
- **Accessibility** - axe-core in headless Chrome against the configured pages; `quality-ci` gate. Findings `Q-A11Y-*`.
- **Performance** - lab budgets (bytes, requests, render-blocking resources, DOM size, modelled critical path) and lab
  timings (FCP, LCP, CLS, TBT) of the configured pages under a fixed emulation profile; `quality-ci-perf` gate.
  Findings `Q-PERF-*`.
- **Final Engineering enforcement** - the `engineering` job reads the three gate results, writes
  `engineering-summary.json` and fails the run when any gate fails (or a gate job never reached its gate).

The three jobs run independently: a failure in one never stops the others from producing their reports. Each uploads
its own report artifact (`security-reports<suffix>`, `quality-reports<suffix>`, `performance-reports<suffix>`,
`engineering-reports<suffix>`) and its own SARIF under its own code-scanning category (see section 6).

## 3. Released versions

This is the authoritative list of released components.

| Component | Release tag | Commit | Pinned in the canonical workflow as |
|---|---|---|---|
| Security baseline (Phase 2, Phase 3, security-ci) | `security-baseline-v1` | `bd71c46f1584063254dfc0b668fcff2ba0ea26d0` | `SECURITY_TOOLING_REF` |
| Quality CI accessibility | `quality-ci-v1.1` | `fa816aad46fb46f3dade2173b53da5d920177e21` | `QUALITY_TOOLING_REF` |
| Quality CI performance | `quality-ci-v1.2` | `c6b82c0739f0342a3ac6b2952532e86343985e1f` | `PERFORMANCE_TOOLING_REF` |
| Engineering CI (the canonical workflow) | `engineering-ci-v1.2` | `70d52f8` | the file you copy |

`v1.0.0` (commit `33fe2d4`) is the top-level release that contains exactly these components; it is historical and is
never moved.

**Why pins.** The workflow checks out the tools at exact commit SHAs, not a branch, so a change in the toolkit can never
change your CI result - or run code nobody reviewed - until you deliberately update a pin.

**Updating a pin.** Replace your copy of the workflow with the file from a newer `engineering-ci-*` release tag; its
`env:` block carries the matching `SECURITY_TOOLING_REF`, `QUALITY_TOOLING_REF` and `PERFORMANCE_TOOLING_REF`. Do not
edit individual SHAs to a branch or an untagged commit. See [UPGRADING.md](UPGRADING.md).

## 4. Configuration reference

All settings are optional. The workflow reads exactly these repository variables and reusable-workflow inputs.

### Security

| Variable | Default | Valid values | Purpose and effect on the gate |
|---|---|---|---|
| `RUNTIME_TARGET_URL` | *(unset)* | `http(s)` URL of a local/development/staging deployment | Enables Phase 3 runtime checks. Unset: Phase 3 is not run (runtime `NOT RUN`), Authentication/Session/Authorization stay NOT VERIFIED, the gate uses Phase 2 only. |
| `RUNTIME_ENVIRONMENT` | `staging` | `local`, `development`, `dev`, `test`, `testing`, `staging`, `stage`, `qa`, `preview` | Declared environment of the runtime target. `prod`/`production`/`live` (and production-looking hosts) are always refused. |
| `RUNTIME_AUTHORIZED_BY` | *(unset)* | name of the person who approved testing | Required for a non-local runtime target; without it the safety gate refuses the target and Security is INCOMPLETE (gate FAIL). Not needed for local/private hosts. |
| `ENABLE_ZAP_BASELINE` | `false` | `true` or anything else (= off) | Adds the passive OWASP ZAP baseline to Phase 3 (only with a runtime target). The `zaproxy/zap-stable` image must already exist on the runner; it is never pulled. If it is absent the baseline is reported "not executed" and the gate is unaffected. |
| `SECURITY_GATE_POLICY` | `release` | `release`, `critical`, `high`, `medium`, `low` | `release`: fail on blocking findings (active CRITICAL, or active HIGH with MEDIUM/HIGH confidence). `critical`: any active CRITICAL. `high`: any active CRITICAL/HIGH. `medium`/`low`: also MEDIUM/LOW. An incomplete or refused scan fails the gate under every policy. |

### Accessibility and performance (shared target)

| Variable | Default | Valid values | Purpose and effect on the gate |
|---|---|---|---|
| `QUALITY_TARGET_URL` | *(unset)* | `http(s)` URL of a local/development/staging deployment | The site both quality jobs load. Unset: accessibility and performance are NOT CONFIGURED (their gates pass and report NOT CONFIGURED - nothing was checked). |
| `QUALITY_ENVIRONMENT` | `staging` | same values as `RUNTIME_ENVIRONMENT` | Declared environment of the quality target; production is always refused. |
| `QUALITY_AUTHORIZED_BY` | *(unset)* | name of the person who approved testing | Required for a non-local quality target; without it both quality scans are refused (INCOMPLETE, gate FAIL). |
| `QUALITY_PAGES` | `/` | space-separated paths on the target, e.g. `/ /pricing /contact` | Pages loaded by both quality jobs; nothing else is crawled. More than 10 pages: the extra pages are not scanned and the result is INCOMPLETE. More than 25: configuration error (INCOMPLETE). |

### Accessibility

| Variable | Default | Valid values | Purpose and effect on the gate |
|---|---|---|---|
| `QUALITY_GATE_POLICY` | `release` | `release`, `critical`, `high`, `medium`, `low` | `release`: fail on blocking violations (axe impact critical/serious). `critical`/`high`/`medium`/`low`: fail at or above that severity (critical=CRITICAL, serious=HIGH, moderate=MEDIUM, minor=LOW). Needs-review items never fail. INCOMPLETE fails under every policy. |

### Performance

| Variable | Default | Valid values | Purpose and effect on the gate |
|---|---|---|---|
| `PERF_PROFILE` | `mobile-lab` | `mobile-lab`, `desktop-lab` | Emulation profile. `mobile-lab`: 412x823, DPR 1.75, CPU 4x, modelled 150 ms RTT / 1.6 Mbit/s. `desktop-lab`: 1350x940, DPR 1, CPU 1x, modelled 40 ms / 10 Mbit/s. Any other value is a configuration error (INCOMPLETE). |
| `PERF_GATE_POLICY` | `release` | `release`, `critical`, `high`, `medium`, `low` | `release`/`high`: fail on any budget or timing FAIL (HIGH). `medium`: also on WARN. `low`: also on diagnostics (LOW). `critical`: performance findings never fail it (performance uses no CRITICAL severity); only INCOMPLETE fails. |

### Reusable-workflow inputs (`workflow_call` only)

These apply only when another workflow in your repository calls `engineering-ci.yml` with `uses:`. Push, pull-request
and manual runs use the defaults.

| Input | Default | Valid values | Purpose |
|---|---|---|---|
| `project_path` | `.` | directory inside the repository | What the security scan checks and where `quality_site_dir` is resolved. |
| `quality_site_dir` | *(empty)* | directory under `project_path` | Serves that static directory on `127.0.0.1` inside the quality jobs (environment `local`) and scans it; overrides `QUALITY_TARGET_URL`. |
| `quality_pages` | *(empty)* | space-separated paths | Overrides `QUALITY_PAGES` for this call. |
| `artifact_suffix` | *(empty)* | text appended to names, e.g. `-docs` | Makes artifact names and code-scanning categories unique. **Required to be distinct** for every call of the workflow within one run; otherwise the calls overwrite each other's categories. |
| `enforce` | `true` | `true`, `false` | `false` only reports the combined result (the `engineering` job does not fail). Push, pull-request and manual runs always enforce. There is no repository variable for this. |

Example caller for a static site kept in the repository:

```yaml
# .github/workflows/site-quality.yml
name: site-quality
on: [workflow_dispatch]
permissions: {actions: read, contents: read, security-events: write}
jobs:
  site:
    uses: ./.github/workflows/engineering-ci.yml
    with: {quality_site_dir: site, quality_pages: "/", artifact_suffix: -site}
```

## 5. What the gates mean

| Gate | Status values | Gate result |
|---|---|---|
| Security | PASS, FAIL (policy violation), INCOMPLETE (scan incomplete/refused, or could not be evaluated) | PASS/FAIL from `security-ci gate` |
| Accessibility | PASS, FAIL, INCOMPLETE, NOT CONFIGURED | PASS/FAIL from `quality-ci gate` |
| Performance | PASS, FAIL, INCOMPLETE, NOT CONFIGURED | PASS/FAIL from `quality-ci-perf gate` |
| Final enforcement | PASS / FAIL | FAIL when any gate result is FAIL |

- A gate job that never reached its gate (tool error, cancellation) is INCOMPLETE and counts as FAIL.
- NOT CONFIGURED means no quality target was set: the gate passes, and the status says nothing was checked.
- NOT VERIFIED is a coverage status (Authentication, Session, Authorization), never a finding and never a pass.
- `engineering-summary.json` lists each gate's status, gate result, report and SARIF paths, the Phase 3 runtime status,
  the performance timing reliability, the three coverage statuses, the overall result and whether it was enforced. It
  contains no findings; findings stay in each tool's own report and SARIF.

## 6. SARIF and code scanning

Three SARIF files are uploaded, each under its own category:

| Gate | Category | Finding IDs |
|---|---|---|
| Security | `vibe-code-engineering-security<artifact_suffix>` | `P2-*`, `RT-*`, `AI-*` |
| Accessibility | `vibe-code-engineering-quality-accessibility<artifact_suffix>` | `Q-A11Y-*` (no `security-severity`) |
| Performance | `vibe-code-engineering-quality-performance<artifact_suffix>` | `Q-PERF-*` (no `security-severity`) |

The tools stamp their SARIF with a fixed `runs[].automationDetails.id`, which `upload-sarif` keeps. The workflow
therefore uploads a copy whose `automationDetails.id` is the category above plus `/`, changing nothing else; the report
artifacts keep the tools' original SARIF.

## 7. Verification boundaries

**Verified** (when configured and the gate passes):
- static security scanning of the repository (Phase 2);
- runtime defensive checks that actually executed against the configured local/development/staging target
  (Phase 3A; passive ZAP baseline only if enabled and executed);
- the accessibility rules axe-core evaluates on the configured pages;
- performance budgets and lab timings of the configured pages under the chosen profile;
- the Engineering CI orchestration: independent gates, fail-closed incomplete handling, final enforcement;
- SARIF separation: one file and one code-scanning category per gate and per `artifact_suffix`.

**Not verified:**
- **Authentication** - NOT VERIFIED (Phase 3B reports status only).
- **Session** - NOT VERIFIED.
- **Authorization, IDOR/BOLA and tenant isolation** - NOT VERIFIED (Phase 3C reports status only).
- No credentials are used and no authenticated or authorization requests are made. These areas remain for
  source-code review until runtime checks exist.

**Performance does not claim:**
- to be a load, stress or capacity test - it loads each configured page one at a time;
- scalability testing;
- field or real-user performance measurement - it is lab data under fixed emulation, cold cache, one host;
- equivalence with Lighthouse scores or Lighthouse TBT (TBT here ends at the observation window).

Accessibility automation covers a subset of WCAG; a passing scan is not proof of WCAG compliance. A passing security
gate is not proof of security. A combined PASS means only that the three gates passed for what was configured.
