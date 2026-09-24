# Upgrading

Releases are immutable tags. Upgrading means replacing your copy of the canonical workflow with the copy from a newer
`engineering-ci-*` release tag - never pointing a pin at a branch. Current versions: see
[ADOPTION.md, section 3](ADOPTION.md#3-released-versions).

`v1.0.0` (commit `33fe2d4`) is the historical top-level release. It is never moved or modified; later work happens on
new commits and new tags.

## engineering-ci-v1.1 to engineering-ci-v1.2

Replace `.github/workflows/engineering-ci.yml` with the file from tag `engineering-ci-v1.2`:

```bash
curl -fsSL https://raw.githubusercontent.com/GeoRobert630/vibe-code-engineering/engineering-ci-v1.2/tools/engineering-ci/examples/github-actions-engineering-ci.yml \
  -o .github/workflows/engineering-ci.yml
```

What changes:
- Each SARIF upload now uses a copy whose `runs[].automationDetails.id` is the per-gate category
  (`vibe-code-engineering-security<artifact_suffix>/`, `...-quality-accessibility<artifact_suffix>/`,
  `...-quality-performance<artifact_suffix>/`). With v1.1 the tools' own ids (`vibe-code-engineering/phase2/`,
  `vibe-code-engineering/quality/accessibility/`, `vibe-code-engineering/quality/performance/`) were used, so analyses of
  the same tool for one commit replaced each other.
- After upgrading, new analyses appear under the per-gate categories; the old tool-family categories receive no new
  uploads.

What does not change: the tool pins (`bd71c46`, `fa816aa`, `c6b82c0`), all repository variables and inputs, the gates,
their policies, the finding namespaces, the report artifacts (they keep the tools' original SARIF) and enforcement.

## quality-ci-v1.1 to quality-ci-v1.2

`quality-ci-v1.2` adds Quality CI performance (`quality-ci-perf`, `Q-PERF-*`) with its hosted-calibrated
`MIN_BENCHMARK`. The accessibility code is unchanged between the two releases.

- **Using the canonical workflow:** nothing to do. Engineering CI already pins accessibility at `quality-ci-v1.1`
  (`QUALITY_TOOLING_REF`) and performance at `quality-ci-v1.2` (`PERFORMANCE_TOOLING_REF`); upgrading Engineering CI is
  how both are updated.
- **Using the standalone Quality CI example workflows:** pin the quality tooling checkout to `c6b82c0`
  (`quality-ci-v1.2`) to get `quality-ci-perf`; `quality-ci` accessibility behaves as in v1.1. Moving to the canonical
  workflow instead is recommended.

## Older tags

`engineering-ci-v1` (security and accessibility gates only) and `quality-ci-v1` are kept unchanged for history.
Moving from `engineering-ci-v1` means taking the current Engineering CI file, which adds the performance job and the
`PERF_PROFILE` / `PERF_GATE_POLICY` variables. `QUALITY_TARGET_URL`, `QUALITY_ENVIRONMENT`, `QUALITY_AUTHORIZED_BY`
and `QUALITY_PAGES` then drive the performance job as well as accessibility; the other variables are unchanged.
