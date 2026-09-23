from __future__ import annotations

import shutil
import subprocess
from pathlib import Path

import pytest

from phase2.discovery import discover
from phase2.models import Finding
from phase2.orchestrator import ScanOptions, run_scan
from phase2.scanners import ScanContext
from phase2.utils.filesystem import walk_project

FIXTURES = Path(__file__).parent / "fixtures"

# Built at runtime so no complete token-shaped literal is committed to the repo
# (avoids tripping push protection / other secret scanners on this test file).
FAKE_GITHUB_TOKEN = "gh" + "p_" + "FAKE0fake1FAKE2fake3FAKE4fake5FAKE6f"
FAKE_STRIPE_LIVE = "sk_" + "live_" + "FAKEfake0000FAKEfake1111FAKE"
FAKE_AWS_ID = "AKIA" + "FAKEFAKEFAKE0000"


def make_ctx(root: Path, use_external_tools: bool = False) -> ScanContext:
    walk = walk_project(root)
    ctx = ScanContext(root=root.resolve(), files=walk.files, use_external_tools=use_external_tools, git_history_depth=50)
    ctx.technologies = discover(ctx)
    return ctx


def scan_fixture(name: str, **kw):
    return run_scan(ScanOptions(project=FIXTURES / name, use_external_tools=False, **kw))


def titles(findings: list[Finding]) -> set[str]:
    return {f.title for f in findings}


def by_rule(findings: list[Finding], rule_id: str) -> list[Finding]:
    return [f for f in findings if f.rule_id == rule_id or rule_id in f.source or f"internal:{rule_id}" in f.source]


def write(root: Path, rel: str, content: str) -> Path:
    path = root / rel
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(content, encoding="utf-8")
    return path


def git(root: Path, *args: str) -> str:
    res = subprocess.run(
        ["git", "-c", "user.name=phase2-test", "-c", "user.email=test@example.invalid", "-c", "commit.gpgsign=false", *args],
        cwd=root, capture_output=True, text=True, check=True, shell=False,
    )
    return res.stdout


requires_git = pytest.mark.skipif(shutil.which("git") is None, reason="git not installed")


@pytest.fixture(scope="session")
def vulnerable_node_report():
    return scan_fixture("vulnerable-node")


@pytest.fixture(scope="session")
def vulnerable_python_report():
    return scan_fixture("vulnerable-python")


@pytest.fixture(scope="session")
def safe_report():
    return scan_fixture("safe-project")
