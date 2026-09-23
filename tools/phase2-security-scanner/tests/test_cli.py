import json
import os
import subprocess
import sys
from pathlib import Path

from conftest import FIXTURES, write

from phase2 import cli

SRC = Path(__file__).resolve().parent.parent / "src"


def run_cli(tmp_path, *args):
    out = tmp_path / "out"
    code = cli.main([*args, "--output", str(out), "--no-external-tools"])
    return code, out


def test_vulnerable_exit_2_and_reports(tmp_path, capsys):
    code, out = run_cli(tmp_path, "--project", str(FIXTURES / "vulnerable-node"), "--format", "both")
    assert code == 2
    assert (out / "security-report.json").exists() and (out / "security-report.md").exists()
    text = capsys.readouterr().out
    for line in ("[1/6] Project discovery", "[2/6] Secret scan", "[3/6] Dangerous-code scan", "[4/6] Dependency scan",
                 "[5/6] Configuration scan", "[6/6] Git scan", "Critical:", "High:", "Medium:", "Low:", "Informational:",
                 "Status: NOT READY"):
        assert line in text


def test_safe_project_exit_0(tmp_path, capsys):
    code, out = run_cli(tmp_path, str(FIXTURES / "safe-project"), "--format", "json")
    assert code == 0
    assert (out / "security-report.json").exists() and not (out / "security-report.md").exists()
    assert "Status: READY" in capsys.readouterr().out


def test_non_blocking_exit_1(tmp_path):
    proj = tmp_path / "p"
    write(proj, "requirements.txt", "flask\n")
    code, _ = run_cli(tmp_path, str(proj))
    assert code == 1


def test_usage_errors_exit_3(tmp_path):
    assert cli.main([]) == 3
    assert cli.main([str(tmp_path / "missing"), "--output", str(tmp_path / "o")]) == 3
    assert cli.main([str(tmp_path), "--update-baseline"]) == 3
    try:
        cli.main(["--format", "xml", str(tmp_path)])
    except SystemExit as exc:
        assert exc.code == 3
    else:
        raise AssertionError("argparse error should exit")


def test_bad_config_exit_3(tmp_path):
    cfg = tmp_path / "c.yaml"
    cfg.write_text("unknown_key: 1\n")
    assert cli.main([str(FIXTURES / "safe-project"), "--config", str(cfg), "--output", str(tmp_path / "o")]) == 3


def test_config_excludes_paths(tmp_path):
    cfg = tmp_path / "c.yaml"
    cfg.write_text("exclude_paths:\n  - 'public/*'\n  - '*.js'\n  - '.env'\n  - 'docker-compose.yml'\n  - 'Dockerfile'\n  - 'package*.json'\n")
    code = cli.main([str(FIXTURES / "vulnerable-node"), "--config", str(cfg), "--output", str(tmp_path / "o"), "--no-external-tools"])
    data = json.loads((tmp_path / "o" / "security-report.json").read_text())
    assert data["findings"] == [] and code == 0
    assert any("Custom exclusions" in lim for lim in data["limitations"])


def test_module_invocation_subprocess(tmp_path):
    env = dict(os.environ, PYTHONPATH=str(SRC))
    res = subprocess.run(
        [sys.executable, "-m", "phase2.cli", "--project", str(FIXTURES / "vulnerable-python"), "--output", str(tmp_path / "o"),
         "--no-external-tools", "--severity", "high"],
        capture_output=True, text=True, env=env, shell=False, timeout=120,
    )
    assert res.returncode == 2, res.stderr
    data = json.loads((tmp_path / "o" / "security-report.json").read_text())
    assert all(f["severity"] in ("CRITICAL", "HIGH") for f in data["findings"])


def test_scan_is_read_only(tmp_path):
    import shutil

    proj = tmp_path / "copy"
    shutil.copytree(FIXTURES / "vulnerable-node", proj)
    before = {p: p.read_bytes() for p in proj.rglob("*") if p.is_file()}
    cli.main([str(proj), "--output", str(tmp_path / "o"), "--no-external-tools"])
    after = {p: p.read_bytes() for p in proj.rglob("*") if p.is_file()}
    assert before == after
