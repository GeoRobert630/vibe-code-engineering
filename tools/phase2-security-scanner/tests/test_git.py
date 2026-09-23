import pytest
from conftest import FAKE_AWS_ID, git, make_ctx, requires_git, write

from phase2.scanners import git as git_scanner

pytestmark = requires_git


@pytest.fixture()
def repo(tmp_path):
    git(tmp_path, "init", "-q")
    write(tmp_path, "README.md", "hello\n")
    write(tmp_path, ".env", "DB_PASSWORD=FakeTrackedPassw0rd1\n")
    write(tmp_path, "deploy/id_rsa", "-----BEGIN OPENSSH PRIVATE KEY-----\nFAKE\n-----END OPENSSH PRIVATE KEY-----\n")
    write(tmp_path, "cert.pem", "-----BEGIN CERTIFICATE-----\nFAKE\n-----END CERTIFICATE-----\n")
    write(tmp_path, "config.js", f'const id = "{FAKE_AWS_ID}";\n')
    write(tmp_path, "package.json", '{"dependencies": {"a": "1"}}\n')
    write(tmp_path, "package-lock.json", '{"lockfileVersion": 3}\n')
    git(tmp_path, "add", "-A")
    git(tmp_path, "commit", "-q", "-m", "initial")
    # remove the secret from the working tree: it must still be found in history
    write(tmp_path, "config.js", "const id = process.env.AWS_ACCESS_KEY_ID;\n")
    write(tmp_path, "package-lock.json", '{"lockfileVersion": 3, "x": 1}\n')
    git(tmp_path, "commit", "-q", "-am", "remove key; bump lock")
    return tmp_path


def test_tracked_sensitive_files(repo):
    run = git_scanner.scan(make_ctx(repo))
    ids = {(f.rule_id, f.file) for f in run.findings}
    assert ("git-tracked-env", ".env") in ids
    assert ("git-tracked-key", "deploy/id_rsa") in ids
    assert not any(f.file == "cert.pem" for f in run.findings)


def test_history_secret_reported_without_value(repo):
    run = git_scanner.scan(make_ctx(repo))
    hist = [f for f in run.findings if f.category == "secret-history"]
    assert any(f.file == "config.js" and f.title == "Potential secret exposure in Git history" for f in hist)
    h = next(f for f in hist if f.file == "config.js")
    assert FAKE_AWS_ID not in h.evidence and FAKE_AWS_ID not in " ".join(h.notes)
    assert "history only" in " ".join(h.notes)
    assert "rotate" in h.recommendation.lower()


def test_lockfile_only_change_flagged(repo):
    run = git_scanner.scan(make_ctx(repo))
    f = next(f for f in run.findings if f.rule_id == "git-lockfile-only-change")
    assert "package-lock.json" in f.evidence


def test_not_a_repo(tmp_path):
    write(tmp_path, "a.txt", "x\n")
    run = git_scanner.scan(make_ctx(tmp_path))
    assert run.findings == [] and not run.failed
    assert any("Git checks skipped" in lim for lim in run.limitations)


def test_scan_does_not_modify_repo(repo):
    before = git(repo, "status", "--porcelain")
    head = git(repo, "rev-parse", "HEAD")
    git_scanner.scan(make_ctx(repo))
    assert git(repo, "status", "--porcelain") == before
    assert git(repo, "rev-parse", "HEAD") == head


def test_malicious_fsmonitor_config_not_executed(repo, tmp_path_factory):
    marker = tmp_path_factory.mktemp("m") / "pwned.txt"
    # A repository-local fsmonitor hook would run on commands that read the index.
    git(repo, "config", "core.fsmonitor", f"echo pwned > '{marker.as_posix()}'")
    # Control: a plain `git ls-files` executes the hook on this platform.
    git(repo, "ls-files")
    if not marker.exists():
        pytest.skip("fsmonitor hook not executed by this git build; control failed")
    marker.unlink()
    git_scanner.scan(make_ctx(repo))
    assert not marker.exists()
