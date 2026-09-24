"""Adoption documentation and template consistency.

Checks the adoption guide, README and adopter template against the canonical workflow and the released tools' own
constants (policies, profiles, environments, MIN_BENCHMARK), so the documented configuration can never drift from what
the workflow actually consumes. Documentation only: no scanner runs here.
"""

from __future__ import annotations

import re
import shutil
import subprocess
import sys
from pathlib import Path

import pytest
import yaml

REPO = Path(__file__).resolve().parents[3]
CANONICAL = REPO / "tools" / "engineering-ci" / "examples" / "github-actions-engineering-ci.yml"
ADOPTION = REPO / "docs" / "ADOPTION.md"
TROUBLESHOOTING = REPO / "docs" / "TROUBLESHOOTING.md"
UPGRADING = REPO / "docs" / "UPGRADING.md"
README = REPO / "README.md"
TEMPLATE = REPO / "templates" / "adopter-project"

RELEASES = {  # tag: full commit (as pinned by the canonical workflow; Engineering CI is the file itself)
    "security-baseline-v1": "bd71c46f1584063254dfc0b668fcff2ba0ea26d0",
    "quality-ci-v1.1": "fa816aad46fb46f3dade2173b53da5d920177e21",
    "quality-ci-v1.2": "c6b82c0739f0342a3ac6b2952532e86343985e1f",
}
ENGINEERING_TAG, ENGINEERING_COMMIT = "engineering-ci-v1.2", "70d52f8"
PIN_VARS = {"SECURITY_TOOLING_REF": "security-baseline-v1", "QUALITY_TOOLING_REF": "quality-ci-v1.1",
            "PERFORMANCE_TOOLING_REF": "quality-ci-v1.2"}


def text(p: Path) -> str:
    return p.read_text(encoding="utf-8")


@pytest.fixture(scope="module")
def wf():
    return yaml.safe_load(text(CANONICAL))


@pytest.fixture(scope="module")
def adoption():
    return text(ADOPTION)


def doc_rows(md: str, heading: str) -> dict[str, list[str]]:
    """Rows of the first table after `heading`, keyed by the backticked first cell."""
    section = md.split(heading, 1)[1]
    rows = {}
    for line in section.splitlines()[1:]:
        if line.startswith("#"):
            break
        m = re.match(r"\|\s*`([A-Za-z_]+)`\s*\|(.*)\|\s*$", line)
        if m:
            rows[m.group(1)] = [c.strip() for c in m.group(2).split("|")]
    return rows


def all_var_rows(md: str) -> dict[str, list[str]]:
    rows = {}
    for heading in ("### Security", "### Accessibility and performance (shared target)", "### Accessibility\n",
                    "### Performance\n"):
        rows.update(doc_rows(md, heading))
    return rows


# ------------------------------------------------------------------ canonical workflow references and pins

def test_adoption_names_one_canonical_file_and_release(adoption):
    assert "tools/engineering-ci/examples/github-actions-engineering-ci.yml" in adoption
    assert f"`{ENGINEERING_TAG}` (commit `{ENGINEERING_COMMIT}`)" in adoption
    url = ("https://raw.githubusercontent.com/GeoRobert630/vibe-code-engineering/"
           f"{ENGINEERING_TAG}/tools/engineering-ci/examples/github-actions-engineering-ci.yml")
    assert url in adoption and url in text(UPGRADING)


def test_single_authoritative_version_table(adoption):
    table = adoption.split("## 3. Released versions", 1)[1].split("\n## ", 1)[0]
    for tag, sha in RELEASES.items():
        assert f"| `{tag}` | `{sha}` |" in table, tag
    assert f"| `{ENGINEERING_TAG}` | `{ENGINEERING_COMMIT}` |" in table
    assert "`v1.0.0`" in table and "33fe2d4" in table and "never moved" in table
    # README and the engineering README link to it instead of repeating a release table
    readme = text(README)
    assert "docs/ADOPTION.md" in readme and "| `security-baseline-v1` |" not in readme
    assert "docs/ADOPTION.md#3-released-versions" in text(REPO / "tools" / "engineering-ci" / "README.md")


def test_workflow_pins_match_the_table(wf):
    for var, tag in PIN_VARS.items():
        assert wf["env"][var] == RELEASES[tag], var


def test_tags_point_to_documented_commits():
    git = shutil.which("git")
    if git is None:
        pytest.skip("git not available")
    for tag, sha in {**RELEASES, ENGINEERING_TAG: ENGINEERING_COMMIT, "v1.0.0": "33fe2d4"}.items():
        res = subprocess.run([git, "rev-parse", f"{tag}^{{commit}}"], cwd=REPO, capture_output=True, text=True)
        if res.returncode != 0:
            pytest.skip(f"tag {tag} not available in this checkout")
        assert res.stdout.strip().startswith(sha), tag


# ------------------------------------------------------------------ configuration reference

def workflow_vars(wf_text: str) -> dict[str, str | None]:
    found: dict[str, str | None] = {}
    for m in re.finditer(r"vars\.([A-Z_]+)(?:\s*\|\|\s*'([^']*)')?", wf_text):
        found[m.group(1)] = m.group(2) if m.group(2) is not None else found.get(m.group(1))
    return found


def test_every_consumed_variable_documented_with_its_default(adoption):
    consumed = workflow_vars(text(CANONICAL))
    rows = all_var_rows(adoption)
    assert set(rows) == set(consumed), set(rows) ^ set(consumed)
    for var, default in consumed.items():
        doc_default = rows[var][0]
        if default:
            assert f"`{default}`" in doc_default, (var, doc_default)
        else:
            assert "unset" in doc_default, (var, doc_default)


def test_every_input_documented_with_its_default(adoption, wf):
    inputs = wf[True]["workflow_call"]["inputs"]
    rows = doc_rows(adoption, "### Reusable-workflow inputs")
    assert set(rows) == set(inputs)
    for name, spec in inputs.items():
        default = str(spec["default"]).lower() if isinstance(spec["default"], bool) else spec["default"]
        cell = rows[name][0]
        assert (f"`{default}`" in cell) if default else ("empty" in cell), (name, cell)
    assert "There is no repository variable for this" in rows["enforce"][-1]
    assert "distinct" in rows["artifact_suffix"][-1]


def _import_tools():
    for sub in ("security-ci", "quality-ci", "phase3-runtime-security"):
        path = str(REPO / "tools" / sub / "src")
        if path not in sys.path:
            sys.path.insert(0, path)


def test_documented_valid_values_match_the_tools(adoption):
    _import_tools()
    from quality_ci.gate import POLICIES as A11Y_POLICIES
    from quality_ci.performance.config import PROFILES
    from quality_ci.performance.gate import POLICIES as PERF_POLICIES
    from quality_ci.safety import ALLOWED_ENVIRONMENTS as QUALITY_ENVS
    from runtime_security.utils.safety import ALLOWED_ENVIRONMENTS as RUNTIME_ENVS
    from security_ci.gate import POLICIES as SEC_POLICIES

    rows = all_var_rows(adoption)

    def values(var):
        return set(re.findall(r"`([^`]+)`", rows[var][1]))

    assert values("SECURITY_GATE_POLICY") == set(SEC_POLICIES)
    assert values("QUALITY_GATE_POLICY") == set(A11Y_POLICIES)
    assert values("PERF_GATE_POLICY") == set(PERF_POLICIES)
    assert values("PERF_PROFILE") == set(PROFILES)
    assert values("RUNTIME_ENVIRONMENT") == set(RUNTIME_ENVS) == set(QUALITY_ENVS)
    assert "same values as `RUNTIME_ENVIRONMENT`" in rows["QUALITY_ENVIRONMENT"][1]


def test_troubleshooting_benchmark_matches_engine():
    _import_tools()
    from quality_ci.performance.engine import MIN_BENCHMARK

    assert f"`MIN_BENCHMARK` ({MIN_BENCHMARK}," in text(TROUBLESHOOTING)


# ------------------------------------------------------------------ verification boundaries and wording

def test_verification_boundaries_stated(adoption):
    sec = adoption.split("## 7. Verification boundaries", 1)[1]
    for area in ("**Authentication** - NOT VERIFIED", "**Session** - NOT VERIFIED",
                 "**Authorization, IDOR/BOLA and tenant isolation** - NOT VERIFIED"):
        assert area in sec
    for claim in ("load, stress or capacity test", "scalability testing", "field or real-user performance measurement",
                  "equivalence with Lighthouse"):
        assert claim in sec, claim
    readme = text(README)
    assert "Authentication, Session and Authorization (IDOR/BOLA, tenant isolation) are NOT VERIFIED" in readme
    assert "not a load, stress, capacity or scalability test" in readme


def test_no_stale_or_unreleased_wording():
    files = [README, ADOPTION, TROUBLESHOOTING, UPGRADING, TEMPLATE / "README.md",
             REPO / "tools" / "engineering-ci" / "README.md"]
    for f in files:
        low = text(f).lower()
        for bad in ("two-gate", "two gate", "unreleased", "not yet released", "before release"):
            assert bad not in low, (f.name, bad)


# ------------------------------------------------------------------ adopter template

def test_template_workflow_is_the_canonical_file():
    copy = TEMPLATE / ".github" / "workflows" / "engineering-ci.yml"
    assert text(copy).replace("\r\n", "\n") == text(CANONICAL).replace("\r\n", "\n")


def test_template_site_caller_uses_canonical_inputs(wf):
    caller = yaml.safe_load(text(TEMPLATE / ".github" / "workflows" / "site-quality.yml"))
    assert set(caller[True]) == {"workflow_dispatch"}                  # never duplicates push / pull_request runs
    job = caller["jobs"]["site"]
    assert job["uses"] == "./.github/workflows/engineering-ci.yml"
    assert set(job["with"]) <= set(wf[True]["workflow_call"]["inputs"])
    assert job["with"]["artifact_suffix"] and job["with"]["quality_site_dir"] == "site"
    assert caller["permissions"] == wf["permissions"]
    assert (TEMPLATE / "site" / "index.html").is_file()


def test_template_is_minimal_without_failure_fixtures():
    files = [p for p in TEMPLATE.rglob("*") if p.is_file()]
    names = {p.relative_to(TEMPLATE).as_posix() for p in files}
    assert names == {"README.md", ".github/workflows/engineering-ci.yml", ".github/workflows/site-quality.yml",
                     "site/index.html"}
    page = text(TEMPLATE / "site" / "index.html")
    assert '<html lang="en">' in page and "<title>" in page and "<main>" in page
    for f in files:
        assert "INTENTIONALLY" not in text(f).upper()                     # no failure fixtures
