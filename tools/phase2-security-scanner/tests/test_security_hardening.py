"""Regression tests for the scanner self-review (SECURITY-REVIEW.md, SR-xx)."""

import os
import stat
import sys
import time

import pytest
from conftest import git, make_ctx, requires_git, write

from phase2.models import Severity, Status
from phase2.orchestrator import ScanOptions, run_scan
from phase2.scanners import configuration, dependencies, load_rules
from phase2.scanners import git as git_scanner
from phase2.utils import command


@requires_git
def test_sr01_signature_verification_program_not_executed(tmp_path, tmp_path_factory):
    repo = tmp_path / "repo"
    repo.mkdir()
    git(repo, "init", "-q")
    write(repo, "a.txt", "a\n")
    git(repo, "add", "a.txt")
    git(repo, "commit", "-q", "-m", "init")
    tree = git(repo, "rev-parse", "HEAD^{tree}").strip()
    commit = (
        f"tree {tree}\nauthor x <x@x> 1700000000 +0000\ncommitter x <x@x> 1700000000 +0000\n"
        "gpgsig -----BEGIN PGP SIGNATURE-----\n \n FAKE\n -----END PGP SIGNATURE-----\n\nsigned\n"
    )
    (repo / "c.txt").write_bytes(commit.encode())  # bytes: no CRLF translation on Windows
    sha = git(repo, "hash-object", "-t", "commit", "-w", "c.txt").strip()
    (repo / "c.txt").unlink()
    git(repo, "update-ref", "HEAD", sha)
    marker = tmp_path_factory.mktemp("m") / "pwned.txt"
    script = repo / ".git" / "evil.sh"
    script.write_text(f"#!/bin/sh\necho pwned > '{marker.as_posix()}'\n", encoding="utf-8")
    script.chmod(script.stat().st_mode | stat.S_IEXEC)
    git(repo, "config", "log.showSignature", "true")
    git(repo, "config", "gpg.program", script.as_posix())
    # Control: plain `git log` runs the configured program.
    git(repo, "log", "-n", "1")
    if not marker.exists():
        pytest.skip("gpg.program not executed by this git build; control failed")
    marker.unlink()
    git_scanner.scan(make_ctx(repo))
    assert not marker.exists()


def test_sr02_child_environment_drops_tokens(monkeypatch):
    monkeypatch.setenv("NPM_TOKEN", "FAKE-npm-token")
    monkeypatch.setenv("GITHUB_TOKEN", "FAKE-gh-token")
    monkeypatch.setenv("AWS_SECRET_ACCESS_KEY", "FAKE-aws")
    env = command.safe_env()
    assert "NPM_TOKEN" not in env and "GITHUB_TOKEN" not in env and "AWS_SECRET_ACCESS_KEY" not in env
    assert env["npm_config_ignore_scripts"] == "true"
    assert any(k.upper() == "PATH" for k in env)


def test_sr03_inline_ignore_cannot_silence_high(tmp_path):
    write(tmp_path, "app.py", 'x = eval(request.args["q"])  # phase2:ignore\nDEBUG = True  # phase2:ignore\n')
    report = run_scan(ScanOptions(project=tmp_path, use_external_tools=False))
    ev = next(f for f in report.findings if f.rule_id == "py-eval")
    dbg = next(f for f in report.findings if f.rule_id == "cfg-django-debug")
    assert ev.status == Status.OPEN and report.exit_code == 2
    assert dbg.status == Status.IGNORED


def test_sr04_output_directory_inside_project_is_still_scanned(tmp_path):
    write(tmp_path, "reports/evil.py", 'eval(request.args["q"])\n')
    report = run_scan(ScanOptions(project=tmp_path, use_external_tools=False, output_dir=tmp_path / "reports"))
    assert any(f.file == "reports/evil.py" for f in report.findings)


def test_sr06_executables_inside_project_are_not_resolved(tmp_path, monkeypatch):
    bindir = tmp_path / "bin"
    bindir.mkdir()
    name = "gitleaks.bat" if os.name == "nt" else "gitleaks"
    exe = bindir / name
    exe.write_text("@echo pwned\n" if os.name == "nt" else "#!/bin/sh\necho pwned\n")
    exe.chmod(exe.stat().st_mode | stat.S_IEXEC)
    monkeypatch.setenv("PATH", str(bindir) + os.pathsep + os.environ.get("PATH", ""))
    monkeypatch.chdir(bindir)
    try:
        command.set_untrusted_root(tmp_path)
        found = command.which("gitleaks")
        assert found is None or not os.path.realpath(found).startswith(os.path.realpath(str(tmp_path)))
    finally:
        command.set_untrusted_root(None)


def test_sr06_relative_path_entries_ignored(monkeypatch):
    monkeypatch.setenv("PATH", "." + os.pathsep + "" + os.pathsep + os.path.dirname(sys.executable))
    assert "." not in command._search_path().split(os.pathsep)


@pytest.mark.parametrize("rule_file", ["secret-patterns.yaml", "dangerous-patterns.yaml"])
def test_sr08_rules_are_fast_on_adversarial_lines(rule_file):
    payloads = [" " * 4000, "a" * 4000, ("'SELECT a FROM " * 300)[:4000], "password=" * 400, "\t- " * 1300]
    for rule in load_rules(rule_file):
        for p in payloads:
            start = time.perf_counter()
            list(rule["compiled"].finditer(p))
            assert time.perf_counter() - start < 0.05, rule["id"]


def test_sr08_configuration_rules_are_fast():
    rules = configuration.PY_RULES + configuration.JS_RULES + configuration.DOCKERFILE_RULES + configuration.COMPOSE_K8S_RULES
    for rule in rules:
        start = time.perf_counter()
        list(rule.regex.finditer(" " * 4000))
        assert time.perf_counter() - start < 0.05, rule.id


def test_sr10_dockerfile_env_value_not_in_evidence(tmp_path):
    write(tmp_path, "Dockerfile", "FROM alpine\nENV API_TOKEN FakeTok3nValue9876\nUSER app\n")
    report = run_scan(ScanOptions(project=tmp_path, use_external_tools=False))
    f = next(f for f in report.findings if f.rule_id == "cfg-docker-secret-env")
    assert "FakeTok3nValue9876" not in f.evidence and "API_TOKEN" in f.evidence
    assert "context" not in f.to_dict()


def test_sr11_deeply_nested_lockfile_does_not_crash(tmp_path):
    write(tmp_path, "package.json", '{"dependencies": {"a": "1"}}')
    write(tmp_path, "pnpm-lock.yaml", "a: " + "[" * 5000 + "]" * 5000 + "\n")
    run = dependencies.scan(make_ctx(tmp_path))
    assert not run.errors


def test_sr12_pip_audit_only_for_plain_pins():
    assert dependencies.requirements_fully_pinned("flask==3.0.0\nrequests[socks]==2.32.0 ; python_version>'3.8'\n")
    assert not dependencies.requirements_fully_pinned("-e .\nflask==3.0.0\n")
    assert not dependencies.requirements_fully_pinned("-r other.txt\n")
    assert not dependencies.requirements_fully_pinned("pkg @ https://example.invalid/pkg.tgz\n")
    assert not dependencies.requirements_fully_pinned("flask>=3\n")


def test_junctions_and_symlinks_outside_root_not_followed(tmp_path):
    outside = tmp_path / "outside"
    outside.mkdir()
    write(outside, "leak.py", 'token = "FAKEFAKEFAKEFAKEFAKE1234"\n')
    root = tmp_path / "root"
    root.mkdir()
    write(root, "ok.py", "x = 1\n")
    try:
        os.symlink(outside, root / "link", target_is_directory=True)
    except (OSError, NotImplementedError):
        if os.name != "nt":
            pytest.skip("symlinks unavailable")
        import subprocess

        res = subprocess.run(["cmd", "/c", "mklink", "/J", str(root / "link"), str(outside)], capture_output=True, shell=False)
        if res.returncode != 0:
            pytest.skip("cannot create junction")
    ctx = make_ctx(root)
    assert [f.rel for f in ctx.files] == ["ok.py"]


def test_severity_filter_and_ignored_not_blocking():
    from phase2.models import Confidence, Finding
    from phase2.severity import is_blocking

    f = Finding(scanner="s", category="c", severity=Severity.MEDIUM, confidence=Confidence.HIGH, title="t", description="d", status=Status.IGNORED)
    assert not is_blocking(f)
