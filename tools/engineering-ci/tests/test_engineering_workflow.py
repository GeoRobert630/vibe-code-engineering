"""Engineering CI example workflow: orchestration policy checks and the workflow's own result-combination scripts.

The scripts are extracted from the workflow file and executed as-is, so these tests check the shipped workflow,
not a copy. Security/quality gates are stubbed: no scanner runs here and no finding is created.
"""

from __future__ import annotations

import json
import os
import re
import shutil
import subprocess
import sys
from pathlib import Path

import pytest
import yaml

ROOT = Path(__file__).resolve().parents[1]
WORKFLOW = ROOT / "examples" / "github-actions-engineering-ci.yml"
SECURITY_EXAMPLE = ROOT.parent / "security-ci" / "examples" / "github-actions-security-ci.yml"
QUALITY_EXAMPLE = ROOT.parent / "quality-ci" / "examples" / "github-actions-quality-ci.yml"
SECURITY_PIN = "bd71c46f1584063254dfc0b668fcff2ba0ea26d0"   # security-baseline-v1
QUALITY_PIN = "fa816aad46fb46f3dade2173b53da5d920177e21"    # quality-ci-v1.1
ALLOWED_VARS = {"RUNTIME_TARGET_URL", "RUNTIME_ENVIRONMENT", "RUNTIME_AUTHORIZED_BY", "ENABLE_ZAP_BASELINE",
                "SECURITY_GATE_POLICY", "QUALITY_TARGET_URL", "QUALITY_ENVIRONMENT", "QUALITY_AUTHORIZED_BY",
                "QUALITY_PAGES", "QUALITY_GATE_POLICY"}
BASH = shutil.which("bash")


@pytest.fixture(scope="module")
def wf():
    return yaml.safe_load(WORKFLOW.read_text(encoding="utf-8"))


@pytest.fixture(scope="module")
def text():
    return WORKFLOW.read_text(encoding="utf-8")


def step(wf, job, name):
    return next(s for s in wf["jobs"][job]["steps"] if s.get("name") == name)


def test_triggers(wf):
    on = wf[True]
    assert on["push"]["branches"] == ["master"] and "pull_request" in on and "workflow_dispatch" in on
    assert set(on["workflow_call"]["inputs"]) == {"project_path", "quality_site_dir", "quality_pages", "artifact_suffix", "enforce"}


def test_minimum_permissions(wf):
    assert wf["permissions"] == {"actions": "read", "contents": "read", "security-events": "write"}
    for job in wf["jobs"].values():
        assert "permissions" not in job


def test_pinned_public_tooling_without_credentials(wf, text):
    assert wf["env"] == {"SECURITY_TOOLING_REF": SECURITY_PIN, "QUALITY_TOOLING_REF": QUALITY_PIN}
    checkouts = [s for j in wf["jobs"].values() for s in j["steps"] if str(s.get("uses", "")).startswith("actions/checkout")]
    assert len(checkouts) == 4 and all(s["with"]["persist-credentials"] is False for s in checkouts)
    tooling = {s["with"]["path"]: s["with"] for s in checkouts if "repository" in s["with"]}
    assert tooling["security-tooling"]["repository"] == tooling["quality-tooling"]["repository"] == "GeoRobert630/vibe-code-engineering"
    assert tooling["security-tooling"]["ref"] == "${{ env.SECURITY_TOOLING_REF }}"
    assert tooling["quality-tooling"]["ref"] == "${{ env.QUALITY_TOOLING_REF }}"
    assert "secrets." not in text and "token:" not in text.lower()
    for word in ("password", "api_key", "apikey", "bearer", "cookie:"):
        assert word not in text.lower().replace("passwords", ""), word
    assert set(re.findall(r"vars\.([A-Z_]+)", text)) <= ALLOWED_VARS


def test_security_job_reuses_existing_tools(wf):
    runs = "\n".join(s.get("run", "") for s in wf["jobs"]["security"]["steps"])
    for cmd in ("phase2-scan", "runtime-security --config", "security-ci sarif", "security-ci gate"):
        assert cmd in runs
    assert "if [ -z \"$RUNTIME_TARGET_URL\" ]" in runs and "NOT VERIFIED" in runs


def test_zap_optional_passive_no_pull(wf, text):
    assert wf["jobs"]["security"]["env"]["ENABLE_ZAP_BASELINE"] == "${{ vars.ENABLE_ZAP_BASELINE || 'false' }}"
    for forbidden in ("docker pull", "zap-full-scan", "zap-api-scan", "--pull=always"):
        assert forbidden not in text


def test_quality_job_uses_existing_browser_setup(wf, text):
    runs = "\n".join(s.get("run", "") for s in wf["jobs"]["quality"]["steps"])
    for cmd in ("quality-ci a11y", "quality-ci sarif", "quality-ci gate"):
        assert cmd in runs
    assert '"channel": "chrome"' in runs and "playwright install" not in text   # no browser download


def test_reports_and_sarif_kept_separate(wf):
    sec = step(wf, "security", "Upload security reports")["with"]
    qual = step(wf, "quality", "Upload quality reports")["with"]
    eng = step(wf, "engineering", "Upload engineering summary")["with"]
    assert (sec["path"], qual["path"], eng["path"]) == ("security-reports/", "quality-reports/", "engineering-reports/")
    assert len({sec["name"], qual["name"], eng["name"]}) == 3
    s = step(wf, "security", "Upload security SARIF")["with"]
    q = step(wf, "quality", "Upload quality SARIF")["with"]
    assert s["sarif_file"] == "security-reports/security.sarif" and q["sarif_file"] == "quality-reports/accessibility.sarif"
    assert s["category"].startswith("vibe-code-engineering-security") and q["category"].startswith("vibe-code-engineering-quality-accessibility")
    for job in ("security", "quality"):
        up = step(wf, job, f"Upload {job} SARIF")
        assert up["uses"] == "github/codeql-action/upload-sarif@v4"
        assert up["if"] == "${{ !cancelled() && steps.sarif.outputs.created == 'true' }}"


def test_combined_job_depends_on_both_and_always_runs(wf):
    eng = wf["jobs"]["engineering"]
    assert eng["needs"] == ["security", "quality"] and eng["if"] == "${{ always() }}"
    enforce = step(wf, "engineering", "Enforce combined result")["env"]["ENFORCE"]
    assert enforce == "${{ format('{0}', inputs.enforce) == 'false' && 'false' || 'true' }}"   # null (push) -> enforce


def test_existing_example_workflows_untouched():
    # Behaviour of the standalone examples is unchanged: same tools, same gates.
    sec = SECURITY_EXAMPLE.read_text(encoding="utf-8")
    qual = QUALITY_EXAMPLE.read_text(encoding="utf-8")
    assert "security-ci gate $ARGS --fail-on \"$SECURITY_GATE_POLICY\"" in sec
    assert "quality-ci gate --report quality-reports/accessibility-report.json --fail-on \"$QUALITY_GATE_POLICY\"" in qual


# ------------------------------------------------------------------ combined result script

def combine_script(wf) -> str:
    run = step(wf, "engineering", "Combined result")["run"]
    return run.split("<<'PY'\n", 1)[1].rsplit("\nPY", 1)[0]


def combine(wf, tmp_path, **env):
    out = tmp_path / "out.txt"
    out.write_text("")
    base = {k: v for k, v in os.environ.items() if not k.startswith(("SECURITY_", "QUALITY_"))}
    base.update(GITHUB_OUTPUT=str(out), GITHUB_STEP_SUMMARY=str(tmp_path / "summary.md"), SUFFIX="")
    base.update(env)
    (tmp_path / "engineering-reports").mkdir(exist_ok=True)
    subprocess.run([sys.executable, "-c", combine_script(wf)], cwd=tmp_path, env=base, check=True, capture_output=True, text=True)
    summary = json.loads((tmp_path / "engineering-reports" / "engineering-summary.json").read_text())
    outputs = dict(line.split("=", 1) for line in out.read_text().splitlines())
    return summary, outputs


def job(prefix, status, gate, code, result="success"):
    return {f"{prefix}_STATUS": status, f"{prefix}_GATE": gate, f"{prefix}_GATE_EXIT": str(code), f"{prefix}_JOB": result}


def _keys(obj) -> set:
    if isinstance(obj, dict):
        return set(obj) | {k for v in obj.values() for k in _keys(v)}
    return set()


NV = {"AUTHENTICATION": "NOT VERIFIED", "SESSION": "NOT VERIFIED", "AUTHORIZATION": "NOT VERIFIED", "SECURITY_RUNTIME": "NOT RUN"}


@pytest.mark.parametrize("sec,qual,overall", [
    (("PASS", "PASS", 0), ("PASS", "PASS", 0), "PASS"),                       # A clean
    (("FAIL", "FAIL", 1), ("PASS", "PASS", 0), "FAIL"),                       # B security failure
    (("PASS", "PASS", 0), ("FAIL", "FAIL", 1), "FAIL"),                       # C quality failure
    (("FAIL", "FAIL", 1), ("FAIL", "FAIL", 1), "FAIL"),                       # D both
    (("INCOMPLETE", "FAIL", 1), ("PASS", "PASS", 0), "FAIL"),                 # security incomplete
    (("PASS", "PASS", 0), ("INCOMPLETE", "FAIL", 1), "FAIL"),                 # quality incomplete
    (("PASS", "PASS", 0), ("NOT CONFIGURED", "PASS", 0), "PASS"),             # quality not configured: existing gate passes
])
def test_combined_matrix(wf, tmp_path, sec, qual, overall):
    s, o = combine(wf, tmp_path, **NV, **job("SECURITY", *sec), **job("QUALITY", *qual))
    assert s["overall"] == o["overall"] == overall
    assert (s["security"]["status"], s["security"]["gate_result"]) == sec[:2]
    assert (s["quality"]["status"], s["quality"]["gate_result"]) == qual[:2]
    assert s["security"]["report_path"] == "security-reports/phase2/security-report.json"
    assert s["security"]["sarif_path"] == "security-reports/security.sarif"
    assert s["quality"]["report_path"] == "quality-reports/accessibility-report.json"
    assert s["quality"]["sarif_path"] == "quality-reports/accessibility.sarif"
    assert s["verification"] == {"authentication": "NOT VERIFIED", "session": "NOT VERIFIED", "authorization": "NOT VERIFIED"}
    assert not _keys(s) & {"findings", "id", "rule_id"}                    # no findings invented or copied
    assert "Q-A11Y-" not in json.dumps(s["security"]) and "P2-" not in json.dumps(s["quality"])


def test_job_that_never_reached_its_gate_is_incomplete_not_pass(wf, tmp_path):
    s, _ = combine(wf, tmp_path, **NV, SECURITY_JOB="failure", **job("QUALITY", "PASS", "PASS", 0))
    assert s["security"] == {**s["security"], "status": "INCOMPLETE", "gate_result": "FAIL", "job_result": "failure"}
    assert s["overall"] == "FAIL"
    s2, _ = combine(wf, tmp_path, **job("SECURITY", "PASS", "PASS", 0), QUALITY_JOB="cancelled")
    assert s2["quality"]["status"] == "INCOMPLETE" and s2["overall"] == "FAIL"


def test_not_verified_statuses_are_exposed_not_findings(wf, tmp_path):
    s, o = combine(wf, tmp_path, **job("SECURITY", "PASS", "PASS", 0), **job("QUALITY", "PASS", "PASS", 0))
    assert s["verification"] == {"authentication": "NOT VERIFIED", "session": "NOT VERIFIED", "authorization": "NOT VERIFIED"}
    assert s["security"]["runtime"] == "NOT RUN" and "runtime_report_path" not in s["security"]
    assert o["authentication"] == o["session"] == o["authorization"] == "NOT VERIFIED"
    assert "every verification area is complete" in s["notice"]
    md = (tmp_path / "summary.md").read_text()
    assert "Authentication: NOT VERIFIED" in md and "Phase 3 runtime: NOT RUN" in md


def test_statuses_copied_verbatim_when_reported(wf, tmp_path):
    s, _ = combine(wf, tmp_path, **job("SECURITY", "PASS", "PASS", 0), **job("QUALITY", "PASS", "PASS", 0),
                   AUTHENTICATION="NOT VERIFIED", SESSION="NOT VERIFIED", AUTHORIZATION="NOT VERIFIED", SECURITY_RUNTIME="EXECUTED")
    assert s["security"]["runtime_report_path"] == "security-reports/phase3/runtime-security-report.json"


# ------------------------------------------------------------------ gate classification scripts (stubbed gates)

def _stub(tmp_path: Path, name: str, body: str) -> Path:
    bin_dir = tmp_path / "bin"
    bin_dir.mkdir(exist_ok=True)
    p = bin_dir / name
    p.write_text("#!/usr/bin/env bash\n" + body, encoding="utf-8", newline="\n")
    p.chmod(0o755)
    return bin_dir


def run_gate_step(wf, tmp_path, job_name, stub_name, stub_body, extra_env=None):
    bin_dir = _stub(tmp_path, stub_name, stub_body)
    out = tmp_path / "gh_output"
    out.write_text("")
    env = dict(os.environ, GITHUB_OUTPUT=str(out), SECURITY_GATE_POLICY="release", QUALITY_GATE_POLICY="release",
               PHASE3_RAN="false", PHASE3_EXIT="", MSYS2_ENV_CONV_EXCL="*")
    env["PATH"] = str(bin_dir) + os.pathsep + env["PATH"]
    env.update(extra_env or {})
    script = step(wf, job_name, "Security gate" if job_name == "security" else "Quality gate")["run"]
    res = subprocess.run([BASH, "-e", "-c", script], cwd=tmp_path, env=env, capture_output=True, text=True)
    assert res.returncode == 0, res.stderr
    return dict(line.strip().split("=", 1) for line in out.read_text().splitlines() if "=" in line)


SEC_TEXT = "printf 'Security CI gate - policy: release\\nAuthentication: NOT VERIFIED\\nAuthorization: NOT VERIFIED\\nSession: NOT VERIFIED\\n'\n"


@pytest.mark.skipif(BASH is None, reason="bash not available")
@pytest.mark.parametrize("strict,lenient,status,gate", [
    (0, 0, "PASS", "PASS"),
    (1, 1, "FAIL", "FAIL"),          # violations regardless of incompleteness
    (1, 0, "INCOMPLETE", "FAIL"),    # fails only because the scan was incomplete
    (3, 3, "INCOMPLETE", "FAIL"),    # gate could not evaluate (missing report)
])
def test_security_gate_classification(wf, tmp_path, strict, lenient, status, gate):
    body = SEC_TEXT + f'case " $* " in *" --allow-incomplete "*) exit {lenient};; esac\nexit {strict}\n'
    o = run_gate_step(wf, tmp_path, "security", "security-ci", body)
    assert (o["status"], o["gate_result"], o["gate_exit_code"]) == (status, gate, str(strict))
    assert (o["authentication"], o["session"], o["authorization"]) == ("NOT VERIFIED",) * 3
    assert o["runtime"] == "NOT RUN"


@pytest.mark.skipif(BASH is None, reason="bash not available")
@pytest.mark.parametrize("ran,exit_code,runtime", [("true", "0", "EXECUTED"), ("true", "2", "EXECUTED"), ("true", "3", "INCOMPLETE")])
def test_security_runtime_status(wf, tmp_path, ran, exit_code, runtime):
    o = run_gate_step(wf, tmp_path, "security", "security-ci", SEC_TEXT + "exit 0\n", {"PHASE3_RAN": ran, "PHASE3_EXIT": exit_code})
    assert o["runtime"] == runtime


@pytest.mark.skipif(BASH is None, reason="bash not available")
def test_security_missing_status_lines_default_to_not_verified(wf, tmp_path):
    o = run_gate_step(wf, tmp_path, "security", "security-ci", "echo 'Result: PASS'\nexit 0\n")
    assert (o["authentication"], o["session"], o["authorization"]) == ("NOT VERIFIED",) * 3


@pytest.mark.skipif(BASH is None, reason="bash not available")
@pytest.mark.parametrize("outcome,code,status,gate", [
    ("PASS", 0, "PASS", "PASS"), ("FAIL", 1, "FAIL", "FAIL"), ("INCOMPLETE", 1, "INCOMPLETE", "FAIL"),
    ("NOT CONFIGURED", 0, "NOT CONFIGURED", "PASS"), (None, 3, "INCOMPLETE", "FAIL"),
])
def test_quality_gate_classification(wf, tmp_path, outcome, code, status, gate):
    body = (f"echo 'Outcome: {outcome}'\n" if outcome else "echo 'quality-ci: error: cannot read accessibility report' >&2\n") + f"exit {code}\n"
    o = run_gate_step(wf, tmp_path, "quality", "quality-ci", body)
    assert (o["status"], o["gate_result"], o["gate_exit_code"]) == (status, gate, str(code))
