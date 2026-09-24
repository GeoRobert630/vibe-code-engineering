# Adopter project template

A minimal starting point for a project that adopts Vibe-Code Engineering. Full guide:
[docs/ADOPTION.md](../../docs/ADOPTION.md).

| File | What it is |
|---|---|
| `.github/workflows/engineering-ci.yml` | The canonical workflow, byte-identical to `tools/engineering-ci/examples/github-actions-engineering-ci.yml` at release tag `engineering-ci-v1.2` (`70d52f8`). Keep it unchanged (except the `push` branch name if your default branch is not `master`). |
| `.github/workflows/site-quality.yml` | Optional. Runs the canonical workflow on the static site in `site/` (manual trigger only). |
| `site/index.html` | Optional. A small accessible page for `site-quality.yml`; replace with your site or delete. |

## Steps

1. Copy `.github/workflows/engineering-ci.yml` into your repository (or download it from the release tag - see
   ADOPTION.md section 1).
2. Push. The Security gate runs on every push to `master`, every pull request and on manual dispatch, and the final
   Engineering result is enforced. Accessibility and Performance report NOT CONFIGURED until step 3.
3. Give the quality gates something to check - one of:
   - set the repository variable `QUALITY_TARGET_URL` to a local/development/staging deployment (plus
     `QUALITY_ENVIRONMENT`, `QUALITY_AUTHORIZED_BY` for non-local hosts, and `QUALITY_PAGES`), or
   - keep `site-quality.yml` and `site/` and run `site-quality` manually for a static site in the repository.
4. Optionally set `RUNTIME_TARGET_URL` (plus `RUNTIME_ENVIRONMENT`, `RUNTIME_AUTHORIZED_BY`) to add the unauthenticated
   Phase 3 runtime checks to the Security gate.

All settings are repository variables (never secrets); defaults and valid values are listed in ADOPTION.md section 4.

## What to expect

- Three independent gates (Security, Accessibility, Performance) and one final enforcement result in the
  `engineering` job and `engineering-summary.json`.
- Three SARIF files in code scanning, one category each.
- Authentication, Session and Authorization are always reported NOT VERIFIED; no credentials are used.
- Performance is a lab budget check of the configured pages, not a load test or real-user measurement.
