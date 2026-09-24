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
PERFORMANCE_PIN = "c6b82c0739f0342a3ac6b2952532e86343985e1f"  # quality-ci-v1.2
ALLOWED_VARS = {"RUNTIME_TARGET_URL", "RUNTIME_ENVIRONMENT", "RUNTIME_AUTHORIZED_BY", "ENABLE_ZAP_BASELINE",
                "SECURITY_GATE_POLICY", "QUALITY_TARGET_URL", "QUALITY_ENVIRONMENT", "QUALITY_AUTHORIZED_BY",
                "QUALITY_PAGES", "QUALITY_GATE_POLICY", "PERF_PROFILE", "PERF_GATE_POLICY"}


def _is_wsl_launcher(path: str) -> bool:
    """WindowsApps\\bash.exe and System32\\bash.exe are WSL launchers, not a usable bash for these scripts."""
    p = path.replace("/", "\\").lower()
    return "\\microsoft\\windowsapps\\" in p or p.endswith(("\\system32\\bash.exe", "\\sysnative\\bash.exe"))


def find_bash(os_name: str = os.name, which=shutil.which, exists=os.path.isfile, environ=os.environ) -> str | None:
    """Bash used to execute the workflow's run: scripts in tests.

    Windows: Git for Windows Bash (Git\\bin\\bash.exe preferred, then Git\\usr\\bin\\bash.exe) under Program Files,
    then a bash on PATH only if it is not a WSL launcher. Never WSL. Elsewhere: bash on PATH. None -> tests skip.
    """
    if os_name != "nt":
        return which("bash")
    roots = []
    for var in ("ProgramFiles", "ProgramW6432"):
        if environ.get(var) and environ[var] not in roots:
            roots.append(environ[var])
    if r"C:\Program Files" not in roots:
        roots.append(r"C:\Program Files")
    for root in roots:
        for rel in (r"Git\bin\bash.exe", r"Git\usr\bin\bash.exe"):
            candidate = os.path.join(root, rel)
            if exists(candidate):
                return candidate
    found = which("bash")
    return found if found and not _is_wsl_launcher(found) else None


BASH = find_bash()


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
    assert wf["env"] == {"SECURITY_TOOLING_REF": SECURITY_PIN, "QUALITY_TOOLING_REF": QUALITY_PIN,
                         "PERFORMANCE_TOOLING_REF": PERFORMANCE_PIN}
    checkouts = [s for j in wf["jobs"].values() for s in j["steps"] if str(s.get("uses", "")).startswith("actions/checkout")]
    assert len(checkouts) == 6 and all(s["with"]["persist-credentials"] is False for s in checkouts)
    tooling = {s["with"]["path"]: s["with"] for s in checkouts if "repository" in s["with"]}
    assert tooling["security-tooling"]["repository"] == tooling["quality-tooling"]["repository"] == "GeoRobert630/vibe-code-engineering"
    assert tooling["security-tooling"]["ref"] == "${{ env.SECURITY_TOOLING_REF }}"
    assert tooling["quality-tooling"]["ref"] == "${{ env.QUALITY_TOOLING_REF }}"
    assert tooling["performance-tooling"]["repository"] == "GeoRobert630/vibe-code-engineering"
    assert tooling["performance-tooling"]["ref"] == "${{ env.PERFORMANCE_TOOLING_REF }}"
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
    assert s["sarif_file"] == "sarif-upload/security.sarif" and q["sarif_file"] == "sarif-upload/accessibility.sarif"
    assert s["category"].startswith("vibe-code-engineering-security") and q["category"].startswith("vibe-code-engineering-quality-accessibility")
    for job in ("security", "quality"):
        up = step(wf, job, f"Upload {job} SARIF")
        assert up["uses"] == "github/codeql-action/upload-sarif@v4"
        assert up["if"] == "${{ !cancelled() && steps.sarif_upload.outputs.ready == 'true' }}"


def test_combined_job_depends_on_all_three_and_always_runs(wf):
    eng = wf["jobs"]["engineering"]
    assert eng["needs"] == ["security", "quality", "performance"] and eng["if"] == "${{ always() }}"
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
    base = {k: v for k, v in os.environ.items() if not k.startswith(("SECURITY_", "QUALITY_", "PERFORMANCE_", "ENFORCE"))}
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


PERF_PASS = {"PERFORMANCE_STATUS": "PASS", "PERFORMANCE_GATE": "PASS", "PERFORMANCE_GATE_EXIT": "0", "PERFORMANCE_JOB": "success"}
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
    # pre-existing security x accessibility matrix, unchanged; performance passes so it cannot affect the result
    s, o = combine(wf, tmp_path, **NV, **job("SECURITY", *sec), **job("QUALITY", *qual), **PERF_PASS)
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
    script = step(wf, job_name, {"security": "Security gate", "quality": "Quality gate",
                                 "performance": "Performance gate"}[job_name])["run"]
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


# ------------------------------------------------------------------ performance integration (third independent gate)

# Fingerprints of each job WITHOUT its SARIF upload boundary (the "Prepare ... SARIF for upload" and "Upload ... SARIF"
# steps): security / quality as released in engineering-ci-v1 (752c3bd), performance and engineering as released in
# engineering-ci-v1.1 (62461a6). Everything that scans, gates, reports or enforces is byte-for-byte the release.
SECURITY_JOB_SHA256 = "98479ef2f76b50e83ba17e20e8895deefb1b9e74ca6d39a11a05eb523c6721b7"
QUALITY_JOB_SHA256 = "b84208bbd8f2dd460b6b0e15d48bebf26ae08800675dfd00b7d32eeca730dfcf"
PERFORMANCE_JOB_SHA256 = "af0b112cea4a5191c91adf97ed6fcb5a9181f98f18b8655b84daad08f00c4d29"
ENGINEERING_JOB_SHA256 = "8d076a2a3e948d7c78f38cfce8ca8f954c3de6ad439bc1780e322214926c4950"


def _fingerprint(job_def: dict, without: tuple = ()) -> str:
    import hashlib

    j = dict(job_def)
    j["steps"] = [s for s in job_def["steps"] if not any(s.get("name", "").startswith(w) for w in without)]
    return hashlib.sha256(json.dumps(j, sort_keys=True).encode()).hexdigest()


def perf(status, gate, code, result="success", reliability="HIGH"):
    return {**job("PERFORMANCE", status, gate, code, result), "PERFORMANCE_RELIABILITY": reliability}


def test_existing_jobs_unchanged_apart_from_sarif_upload_boundary(wf):
    # scanning, gating, reporting and enforcement are exactly the released definitions (steps, env, pins, outputs)
    for job, sha in (("security", SECURITY_JOB_SHA256), ("quality", QUALITY_JOB_SHA256),
                     ("performance", PERFORMANCE_JOB_SHA256)):
        assert _fingerprint(wf["jobs"][job], (f"Prepare {job} SARIF", f"Upload {job} SARIF")) == sha, job
    assert _fingerprint(wf["jobs"]["engineering"]) == ENGINEERING_JOB_SHA256


def test_performance_job_reuses_existing_tool_and_gate(wf, text):
    pj = wf["jobs"]["performance"]
    runs = "\n".join(s.get("run", "") for s in pj["steps"])
    for cmd in ("quality-ci-perf perf", "quality-ci-perf sarif", "quality-ci-perf gate", '--fail-on "$PERF_GATE_POLICY"'):
        assert cmd in runs, cmd
    assert pj["env"]["PERF_GATE_POLICY"] == "${{ vars.PERF_GATE_POLICY || 'release' }}"
    assert pj["env"]["PERF_PROFILE"] == "${{ vars.PERF_PROFILE || 'mobile-lab' }}"
    assert '"channel": "chrome"' in runs and "playwright install" not in text          # no browser download
    assert '"production": False' in runs and "performance NOT CONFIGURED" in runs
    assert "needs" not in pj                                                             # independent of security/quality
    for word in ("median", "majority", "benchmark", "budget", "tbt", "lcp"):              # no reimplemented measurement
        assert word not in runs.lower(), word


def test_three_separate_sarif_outputs_and_categories(wf):
    uploads = {j: step(wf, j, f"Upload {j} SARIF")["with"] for j in ("security", "quality", "performance")}
    files = {w["sarif_file"] for w in uploads.values()}
    cats = [w["category"] for w in uploads.values()]
    assert files == {"sarif-upload/security.sarif", "sarif-upload/accessibility.sarif", "sarif-upload/performance.sarif"}
    assert cats[2] == "vibe-code-engineering-quality-performance${{ env.SUFFIX }}" and len(set(cats)) == 3
    up = step(wf, "performance", "Upload performance SARIF")
    assert up["uses"] == "github/codeql-action/upload-sarif@v4"
    assert up["if"] == "${{ !cancelled() && steps.sarif_upload.outputs.ready == 'true' }}"
    rep = step(wf, "performance", "Upload performance reports")
    assert rep["with"]["path"] == "performance-reports/" and rep["if"] == "always()"
    names = {step(wf, j, f"Upload {n} reports")["with"]["name"] for j, n in
             (("security", "security"), ("quality", "quality"), ("performance", "performance"))}
    assert len(names) == 3


@pytest.mark.parametrize("sec,acc,prf,overall", [
    (("PASS", "PASS", 0), ("PASS", "PASS", 0), ("PASS", "PASS", 0), "PASS"),                 # all gates pass
    (("PASS", "PASS", 0), ("PASS", "PASS", 0), ("FAIL", "FAIL", 1), "FAIL"),                 # performance blocking failure
    (("PASS", "PASS", 0), ("PASS", "PASS", 0), ("INCOMPLETE", "FAIL", 1), "FAIL"),           # performance incomplete
    (("PASS", "PASS", 0), ("PASS", "PASS", 0), ("NOT CONFIGURED", "PASS", 0), "PASS"),       # not configured: gate passes
    (("FAIL", "FAIL", 1), ("PASS", "PASS", 0), ("FAIL", "FAIL", 1), "FAIL"),                 # security + performance
    (("PASS", "PASS", 0), ("FAIL", "FAIL", 1), ("FAIL", "FAIL", 1), "FAIL"),                 # accessibility + performance
    (("FAIL", "FAIL", 1), ("FAIL", "FAIL", 1), ("FAIL", "FAIL", 1), "FAIL"),                 # all three
    (("INCOMPLETE", "FAIL", 1), ("PASS", "PASS", 0), ("PASS", "PASS", 0), "FAIL"),           # security incomplete only
])
def test_three_gate_matrix(wf, tmp_path, sec, acc, prf, overall):
    s, o = combine(wf, tmp_path, **NV, **job("SECURITY", *sec), **job("QUALITY", *acc), **perf(*prf))
    assert s["overall"] == o["overall"] == overall
    assert (s["performance"]["status"], s["performance"]["gate_result"]) == prf[:2]
    assert (o["performance_status"], o["performance_gate"]) == prf[:2]
    assert (s["security"]["status"], s["quality"]["status"]) == (sec[0], acc[0])
    assert s["performance"]["report_path"] == "performance-reports/performance-report.json"
    assert s["performance"]["sarif_path"] == "performance-reports/performance.sarif"
    assert s["performance"]["gate_exit_code"] == prf[2] and s["performance"]["timing_reliability"] == "HIGH"
    md = (tmp_path / "summary.md").read_text()
    assert f"Security: {sec[0]}" in md and f"Accessibility: {acc[0]}" in md and f"Performance: {prf[0]}" in md
    assert f"Final enforcement: {overall}" in md


def test_performance_job_never_reached_gate_is_incomplete(wf, tmp_path):
    for result in ("failure", "cancelled", "skipped"):
        s, _ = combine(wf, tmp_path, **NV, **job("SECURITY", "PASS", "PASS", 0), **job("QUALITY", "PASS", "PASS", 0),
                       PERFORMANCE_JOB=result)
        assert s["performance"]["status"] == "INCOMPLETE" and s["performance"]["gate_result"] == "FAIL"
        assert s["performance"]["job_result"] == result and s["overall"] == "FAIL"


def test_performance_failure_does_not_change_security_or_accessibility(wf, tmp_path):
    s, _ = combine(wf, tmp_path, **NV, **job("SECURITY", "PASS", "PASS", 0), **job("QUALITY", "PASS", "PASS", 0),
                   **perf("FAIL", "FAIL", 1))
    assert s["security"]["status"] == "PASS" and s["quality"]["status"] == "PASS" and s["overall"] == "FAIL"
    assert s["verification"] == {"authentication": "NOT VERIFIED", "session": "NOT VERIFIED", "authorization": "NOT VERIFIED"}


def test_not_verified_never_becomes_a_finding_with_performance(wf, tmp_path):
    s, o = combine(wf, tmp_path, **NV, **job("SECURITY", "PASS", "PASS", 0), **job("QUALITY", "NOT CONFIGURED", "PASS", 0),
                   **perf("NOT CONFIGURED", "PASS", 0, reliability="n/a"))
    assert s["overall"] == "PASS" and s["performance"]["status"] == "NOT CONFIGURED"
    assert s["verification"] == {"authentication": "NOT VERIFIED", "session": "NOT VERIFIED", "authorization": "NOT VERIFIED"}
    assert o["authentication"] == o["session"] == o["authorization"] == "NOT VERIFIED"
    assert not _keys(s) & {"findings", "id", "rule_id", "check_id"}
    body = json.dumps({k: v for k, v in s.items() if k != "notice"})
    for ns in ("Q-PERF-", "Q-A11Y-", "P2-", "RT-"):
        assert ns not in body, ns
    assert "Q-PERF-*" in s["notice"] and "Q-A11Y-*" in s["notice"]


@pytest.mark.parametrize("enforce_env,overall,exit_code", [("true", "FAIL", 1), ("false", "FAIL", 0), ("true", "PASS", 0),
                                                          ("false", "PASS", 0)])
def test_enforce_step(wf, tmp_path, enforce_env, overall, exit_code):
    if BASH is None:
        pytest.skip("bash not available")
    script = step(wf, "engineering", "Enforce combined result")["run"]
    res = subprocess.run([BASH, "-e", "-c", script], cwd=tmp_path, env=dict(os.environ, OVERALL=overall, ENFORCE=enforce_env),
                         capture_output=True, text=True)
    assert res.returncode == exit_code
    if enforce_env == "false" and overall == "FAIL":
        assert "not enforced: enforce=false" in res.stdout


def test_enforce_false_reported_in_summary(wf, tmp_path):
    s, _ = combine(wf, tmp_path, **NV, **job("SECURITY", "PASS", "PASS", 0), **job("QUALITY", "PASS", "PASS", 0),
                   **perf("FAIL", "FAIL", 1), ENFORCE="false")
    assert s["overall"] == "FAIL" and s["enforced"] is False
    assert "Final enforcement: FAIL (not enforced: enforce=false)" in (tmp_path / "summary.md").read_text()
    s2, _ = combine(wf, tmp_path, **NV, **job("SECURITY", "PASS", "PASS", 0), **job("QUALITY", "PASS", "PASS", 0),
                    **perf("PASS", "PASS", 0))
    assert s2["enforced"] is True                                                          # default: enforced


def test_combined_env_and_reusable_outputs(wf):
    env = step(wf, "engineering", "Combined result")["env"]
    assert env["ENFORCE"] == "${{ format('{0}', inputs.enforce) == 'false' && 'false' || 'true' }}"
    assert env["PERFORMANCE_JOB"] == "${{ needs.performance.result }}"
    assert step(wf, "engineering", "Enforce combined result")["env"]["ENFORCE"] == env["ENFORCE"]
    outs = wf[True]["workflow_call"]["outputs"]
    assert {"performance_status", "performance_gate"} <= set(outs)
    assert {"overall", "security_status", "security_gate", "quality_status", "quality_gate",
            "authentication", "session", "authorization"} <= set(outs)                    # existing outputs kept


@pytest.mark.skipif(BASH is None, reason="bash not available")
@pytest.mark.parametrize("outcome,code,status,gate", [
    ("PASS", 0, "PASS", "PASS"), ("FAIL", 1, "FAIL", "FAIL"), ("INCOMPLETE", 1, "INCOMPLETE", "FAIL"),
    ("NOT CONFIGURED", 0, "NOT CONFIGURED", "PASS"), (None, 3, "INCOMPLETE", "FAIL"),
])
def test_performance_gate_classification(wf, tmp_path, outcome, code, status, gate):
    body = ((f"echo 'Timing reliability: LOW'\necho 'Outcome: {outcome}'\n" if outcome else
             "echo 'quality-ci-perf: error: cannot read performance report' >&2\n") + f"exit {code}\n")
    o = run_gate_step(wf, tmp_path, "performance", "quality-ci-perf", body, {"PERF_GATE_POLICY": "release"})
    assert (o["status"], o["gate_result"], o["gate_exit_code"]) == (status, gate, str(code))
    assert o["timing_reliability"] == ("LOW" if outcome else "n/a")


def test_performance_gate_uses_tool_exit_code_not_own_policy(wf):
    run = step(wf, "performance", "Performance gate")["run"]
    assert 'gate_result=$([ "$code" = "0" ] && echo PASS || echo FAIL)' in run
    assert "severity" not in run.lower() and "blocking" not in run.lower()


# ------------------------------------------------------------------ bash discovery for the tests themselves

WINDOWSAPPS_SHIM = r"C:\Users\someone\AppData\Local\Microsoft\WindowsApps\bash.exe"
GIT_BIN = r"C:\Program Files\Git\bin\bash.exe"
GIT_USR = r"C:\Program Files\Git\usr\bin\bash.exe"
WIN_ENV = {"ProgramFiles": r"C:\Program Files"}


def test_windowsapps_shim_not_selected_when_git_bash_installed():
    chosen = find_bash("nt", which=lambda _: WINDOWSAPPS_SHIM, exists=lambda p: p in (GIT_BIN, GIT_USR), environ=WIN_ENV)
    assert chosen == GIT_BIN


def test_git_usr_bin_bash_used_when_bin_missing():
    assert find_bash("nt", which=lambda _: WINDOWSAPPS_SHIM, exists=lambda p: p == GIT_USR, environ=WIN_ENV) == GIT_USR


@pytest.mark.parametrize("launcher", [WINDOWSAPPS_SHIM, r"C:\Windows\System32\bash.exe", "C:/Windows/System32/bash.exe"])
def test_wsl_launchers_rejected_skip_preserved(launcher):
    # only a WSL launcher available: no usable bash, the bash-dependent tests skip instead of invoking WSL
    assert find_bash("nt", which=lambda _: launcher, exists=lambda p: False, environ=WIN_ENV) is None


def test_other_git_bash_on_path_accepted_and_non_windows_unchanged():
    other = r"D:\Tools\Git\bin\bash.exe"
    assert find_bash("nt", which=lambda _: other, exists=lambda p: False, environ=WIN_ENV) == other
    assert find_bash("nt", which=lambda _: None, exists=lambda p: False, environ=WIN_ENV) is None
    assert find_bash("posix", which=lambda _: "/usr/bin/bash", exists=lambda p: False, environ={}) == "/usr/bin/bash"
    assert find_bash("posix", which=lambda _: None, exists=lambda p: True, environ={}) is None


def test_selected_bash_on_this_machine_is_not_a_wsl_launcher():
    assert BASH is None or not _is_wsl_launcher(BASH)


# ------------------------------------------------------------------ SARIF upload boundary (unique code-scanning categories)

TOOLS = ROOT.parent
GATES = {  # job: (prepare step, original SARIF, upload copy, category base)
    "security": ("Prepare security SARIF for upload (unique code-scanning category)", "security-reports/security.sarif",
                 "sarif-upload/security.sarif", "vibe-code-engineering-security"),
    "quality": ("Prepare quality SARIF for upload (unique code-scanning category)", "quality-reports/accessibility.sarif",
                "sarif-upload/accessibility.sarif", "vibe-code-engineering-quality-accessibility"),
    "performance": ("Prepare performance SARIF for upload (unique code-scanning category)",
                    "performance-reports/performance.sarif", "sarif-upload/performance.sarif",
                    "vibe-code-engineering-quality-performance"),
}
TOOL_AUTOMATION_IDS = {"security": {"vibe-code-engineering/phase2/", "vibe-code-engineering/phase3/"},
                       "quality": {"vibe-code-engineering/quality/accessibility/"},
                       "performance": {"vibe-code-engineering/quality/performance/"}}
NAMESPACES = {"security": ("P2-", "RT-", "AI-"), "quality": ("Q-A11Y-",), "performance": ("Q-PERF-",)}


def _tool_sarif(gate: str) -> dict:
    """SARIF produced by the real, unmodified tool code (read-only import of the toolkit sources)."""
    if gate == "security":
        sys.path.insert(0, str(TOOLS / "security-ci" / "src"))
        from security_ci.inputs import load_all
        from security_ci.sarif import build

        fx = TOOLS / "security-ci" / "tests" / "fixtures"
        return build(load_all(fx / "phase2-report.json", fx / "phase3-report.json", None))
    sys.path.insert(0, str(TOOLS / "quality-ci" / "src"))
    page = {"url": "http://127.0.0.1:8000/", "occurrences": 1, "selectors": ["img"], "value": 3217, "runs": [3217],
            "status": "FAIL", "contributors": [], "unstable": False, "capped_by_host": False}
    if gate == "quality":
        from quality_ci.sarif import build as a11y_build

        return a11y_build({"run": {"status": "COMPLETE", "verdict": "FAIL"}, "findings": [{
            "id": "Q-A11Y-0123456789", "kind": "violation", "rule_id": "image-alt", "title": "Images must have alt text",
            "description": "d", "impact": "critical", "severity": "CRITICAL", "status": "OPEN", "blocking": True,
            "source": "axe-core 4.10.3", "help": "h", "help_url": "", "wcag": ["wcag2a"], "occurrence_count": 1,
            "pages": [page]}]})
    from quality_ci.performance.sarif import build as perf_build

    return perf_build({"run": {"status": "COMPLETE", "verdict": "FAIL"}, "host": {"timing_reliability": "HIGH"},
                       "engine": {"web_vitals": {"version": "6.2.2"}}, "findings": [{
                           "id": "Q-PERF-0123456789", "check_id": "budget.dom-nodes", "kind": "budget", "title": "DOM too large",
                           "help": "h", "severity": "HIGH", "status": "OPEN", "blocking": True, "unit": "count",
                           "threshold": {"warn": 1500, "fail": 3000}, "source": "quality-ci performance 0.1.0",
                           "notes": [], "pages": [page]}]})


def _ids(doc: dict) -> list[str]:
    return [r["properties"]["findingId"] for run in doc["runs"] for r in run["results"]]


def _without_automation(doc: dict) -> dict:
    d = json.loads(json.dumps(doc))
    for run in d["runs"]:
        run.pop("automationDetails", None)
    return d


def run_prepare(wf, tmp_path: Path, gate: str, suffix: str, original: dict | None = None):
    """Execute the workflow's exact 'Prepare ... SARIF for upload' step (bash + python), as GitHub would."""
    name, src, dst, base = GATES[gate]
    st = step(wf, gate, name)
    work = tmp_path / f"{gate}{suffix or '-none'}"
    (work / src).parent.mkdir(parents=True, exist_ok=True)
    if original is not None:
        (work / src).write_text(json.dumps(original, indent=2) + "\n", encoding="utf-8")
    out = work / "gh_output"
    out.write_text("")
    env = dict(os.environ, GITHUB_OUTPUT=str(out), MSYS2_ENV_CONV_EXCL="*")
    env["PATH"] = os.path.dirname(sys.executable) + os.pathsep + env["PATH"]      # `python` as setup-python provides
    for k, v in st["env"].items():
        env[k] = v.replace("${{ env.SUFFIX }}", suffix)
    res = subprocess.run([BASH, "-e", "-c", st["run"]], cwd=work, env=env, capture_output=True, text=True)
    return res, work, out.read_text()


@pytest.mark.parametrize("gate", list(GATES))
def test_tool_automation_ids_are_fixed_so_uploads_would_collide(gate):
    # The released tools stamp a fixed runs[].automationDetails.id; upload-sarif keeps an existing id and ignores its
    # `category` input, so every case of the same gate would land in ONE code-scanning category (the reported bug).
    a, b = _tool_sarif(gate), _tool_sarif(gate)
    ids_a = {run.get("automationDetails", {}).get("id") for run in a["runs"]}
    assert ids_a <= TOOL_AUTOMATION_IDS[gate] and ids_a
    assert ids_a == {run.get("automationDetails", {}).get("id") for run in b["runs"]}     # identical for every case


@pytest.mark.skipif(BASH is None, reason="bash not available")
@pytest.mark.parametrize("gate", list(GATES))
@pytest.mark.parametrize("suffix", ["", "-clean", "-slow"])
def test_prepare_step_rewrites_only_the_upload_copy(wf, tmp_path, gate, suffix):
    import hashlib

    original = _tool_sarif(gate)
    res, work, gh_out = run_prepare(wf, tmp_path, gate, suffix, original)
    assert res.returncode == 0, res.stderr
    assert "ready=true" in gh_out
    _, src, dst, base = GATES[gate]
    before = (work / src).read_bytes()
    copy = json.loads((work / dst).read_text(encoding="utf-8"))
    expected_id = f"{base}{suffix}/"
    assert {run["automationDetails"]["id"] for run in copy["runs"]} == {expected_id}   # every run rewritten
    assert len(copy["runs"]) == len(original["runs"])
    assert _without_automation(copy) == _without_automation(original)                  # nothing else changed
    assert hashlib.sha256((work / src).read_bytes()).digest() == hashlib.sha256(before).digest()
    assert json.loads((work / src).read_text(encoding="utf-8")) == original             # original SARIF untouched
    assert {run.get("automationDetails", {}).get("id") for run in original["runs"]} <= TOOL_AUTOMATION_IDS[gate]
    ids = _ids(copy)
    assert ids == _ids(original) and all(i.startswith(NAMESPACES[gate]) for i in ids)   # namespaces unchanged
    if gate != "security":
        assert "security-severity" not in json.dumps(copy)                             # quality stays non-security


@pytest.mark.skipif(BASH is None, reason="bash not available")
def test_categories_distinct_across_gates_and_cases_and_stable(wf, tmp_path):
    suffixes = ["-clean", "-vulnerable", "-inaccessible", "-slow", "-all-fail", "-clean-enforced", ""]
    seen = {}
    for gate in GATES:
        original = _tool_sarif(gate)
        for sfx in suffixes:
            res, work, _ = run_prepare(wf, tmp_path, gate, sfx, original)
            assert res.returncode == 0, res.stderr
            doc = json.loads((work / GATES[gate][2]).read_text(encoding="utf-8"))
            (auto_id,) = {run["automationDetails"]["id"] for run in doc["runs"]}
            seen[(gate, sfx)] = auto_id
            # the upload step's `category` input is the same value (without the trailing slash)
            assert step(wf, gate, f"Upload {gate} SARIF")["with"]["category"].replace("${{ env.SUFFIX }}", sfx) + "/" == auto_id
    assert len(set(seen.values())) == len(seen) == 3 * len(suffixes)                  # all analyses distinct
    for gate in GATES:                                                                 # stable: same input, same id
        res, work, _ = run_prepare(wf, tmp_path / "again", gate, "-clean", _tool_sarif(gate))
        doc = json.loads((work / GATES[gate][2]).read_text(encoding="utf-8"))
        assert {run["automationDetails"]["id"] for run in doc["runs"]} == {seen[(gate, "-clean")]}


@pytest.mark.skipif(BASH is None, reason="bash not available")
def test_prepare_step_fails_closed_without_sarif(wf, tmp_path):
    res, work, gh_out = run_prepare(wf, tmp_path, "performance", "-x", original=None)
    assert res.returncode != 0 and "ready=true" not in gh_out                           # upload then skipped
    assert not (work / GATES["performance"][2]).exists()


def test_upload_boundary_wiring(wf):
    for gate, (prep_name, src, dst, base) in GATES.items():
        steps = [s.get("name", "") for s in wf["jobs"][gate]["steps"]]
        prep, up = step(wf, gate, prep_name), step(wf, gate, f"Upload {gate} SARIF")
        assert prep["id"] == "sarif_upload" and prep["if"] == "${{ !cancelled() && steps.sarif.outputs.created == 'true' }}"
        assert prep["env"] == {"SARIF_IN": src, "SARIF_OUT": dst, "SARIF_CATEGORY": base + "${{ env.SUFFIX }}"}
        assert up["with"] == {"sarif_file": dst, "category": base + "${{ env.SUFFIX }}"}
        assert up["if"] == "${{ !cancelled() && steps.sarif_upload.outputs.ready == 'true' }}"
        assert steps.index(prep_name) == steps.index(f"Upload {gate} SARIF") - 1         # prepared right before upload
        gate_step = {"security": "Security gate", "quality": "Quality gate", "performance": "Performance gate"}[gate]
        assert steps.index(gate_step) < steps.index(prep_name)                            # gate result recorded first
        reports = next(s for s in wf["jobs"][gate]["steps"] if s.get("name", "").startswith("Upload") and
                       s.get("name", "").endswith("reports"))
        assert not dst.startswith(reports["with"]["path"])                                # artifact keeps the original
        assert src.startswith(reports["with"]["path"])
