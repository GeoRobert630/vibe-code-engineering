import json

import pytest
from conftest import make_ctx, write

from phase2.models import Severity, Status
from phase2.scanners import dependencies


def rule_ids(findings):
    return {f.rule_id for f in findings}


def test_node_fixture(vulnerable_node_report):
    ids = rule_ids(vulnerable_node_report.findings)
    assert {"dep-lockfile-out-of-sync", "dep-install-script", "dep-non-registry-source", "dep-insecure-resolved", "dep-undeclared-import"} <= ids
    sync = next(f for f in vulnerable_node_report.findings if f.rule_id == "dep-lockfile-out-of-sync")
    assert "pg" in sync.evidence
    undeclared = next(f for f in vulnerable_node_report.findings if f.rule_id == "dep-undeclared-import")
    assert "cors" in undeclared.evidence and "child_process" not in undeclared.evidence


def test_python_fixture(vulnerable_python_report):
    ids = rule_ids(vulnerable_python_report.findings)
    assert {"dep-pip-extra-index", "dep-python-unpinned"} <= ids


def test_safe_project_has_no_dependency_findings(safe_report):
    assert not [f for f in safe_report.findings if f.scanner == "dependencies"]


def test_no_lockfile_and_multiple_lockfiles(tmp_path):
    write(tmp_path, "a/package.json", '{"dependencies": {"x": "1.0.0"}}')
    write(tmp_path, "b/package.json", '{"dependencies": {"x": "1.0.0"}}')
    write(tmp_path, "b/yarn.lock", '"x@1.0.0":\n  version "1.0.0"\n')
    write(tmp_path, "b/package-lock.json", json.dumps({"lockfileVersion": 3, "packages": {"": {"dependencies": {"x": "1.0.0"}}, "node_modules/x": {"resolved": "https://registry.npmjs.org/x/-/x-1.0.0.tgz", "integrity": "sha512-a"}}}))
    run = dependencies.scan(make_ctx(tmp_path))
    by = {(f.rule_id, f.file) for f in run.findings}
    assert ("dep-no-lockfile", "a/package.json") in by
    assert ("dep-multiple-lockfiles", "b/package.json") in by
    assert not any(f.rule_id == "dep-lockfile-out-of-sync" for f in run.findings)


def test_yarn_and_pnpm_lock_sync(tmp_path):
    write(tmp_path, "y/package.json", '{"dependencies": {"left": "^1.0.0", "@scope/right": "^2.0.0"}}')
    write(tmp_path, "y/yarn.lock", '"left@^1.0.0":\n  version "1.0.0"\n')
    write(tmp_path, "p/package.json", '{"dependencies": {"a": "1.0.0", "b": "1.0.0"}}')
    write(tmp_path, "p/pnpm-lock.yaml", "lockfileVersion: '9.0'\nimporters:\n  .:\n    dependencies:\n      a:\n        specifier: 1.0.0\n        version: 1.0.0\n")
    run = dependencies.scan(make_ctx(tmp_path))
    sync = {f.file: f.evidence for f in run.findings if f.rule_id == "dep-lockfile-out-of-sync"}
    assert "@scope/right" in sync["y/yarn.lock"]
    assert "b" in sync["p/pnpm-lock.yaml"]


def test_poetry_lock_sync(tmp_path):
    write(tmp_path, "pyproject.toml", '[tool.poetry]\nname = "app"\n[tool.poetry.dependencies]\npython = "^3.11"\nrequests = "^2"\nDjango = "^5"\n')
    write(tmp_path, "poetry.lock", '[[package]]\nname = "requests"\nversion = "2.32.0"\n')
    run = dependencies.scan(make_ctx(tmp_path))
    f = next(f for f in run.findings if f.rule_id == "dep-lockfile-out-of-sync")
    assert "django" in f.evidence and "requests" not in f.evidence


def test_benign_install_script_informational(tmp_path):
    write(tmp_path, "package.json", '{"scripts": {"prepare": "husky install"}}')
    run = dependencies.scan(make_ctx(tmp_path))
    f = next(f for f in run.findings if f.rule_id == "dep-install-script")
    assert f.severity == Severity.INFORMATIONAL


def test_tsconfig_alias_not_reported_as_undeclared(tmp_path):
    write(tmp_path, "package.json", '{"dependencies": {"react": "18"}}')
    write(tmp_path, "package-lock.json", json.dumps({"lockfileVersion": 3, "packages": {"": {"dependencies": {"react": "18"}}, "node_modules/react": {"resolved": "https://registry.npmjs.org/react/-/react-18.tgz", "integrity": "sha512-a"}}}))
    write(tmp_path, "tsconfig.json", '{\n  // comment\n  "compilerOptions": {"paths": {"@components/*": ["src/components/*"]}}\n}\n')
    write(tmp_path, "src/a.tsx", 'import React from "react";\nimport B from "@components/b";\nimport fs from "node:fs";\nimport x from "./x";\n')
    run = dependencies.scan(make_ctx(tmp_path))
    assert not any(f.rule_id == "dep-undeclared-import" for f in run.findings)


def test_npm_audit_parser():
    data = {
        "auditReportVersion": 2,
        "vulnerabilities": {
            "lodash": {
                "name": "lodash", "severity": "high", "isDirect": True, "range": "<4.17.21",
                "via": [{"source": 1, "title": "Prototype Pollution", "url": "https://github.com/advisories/GHSA-x", "cwe": ["CWE-1321"]}],
                "fixAvailable": {"name": "lodash", "version": "4.17.21"},
            },
            "wrapper": {"name": "wrapper", "severity": "moderate", "via": ["lodash"], "fixAvailable": False},
        },
    }
    found = {f.title: f for f in dependencies.parse_npm_audit(data, "package-lock.json")}
    lodash = found["Vulnerable dependency: lodash"]
    assert lodash.severity == Severity.HIGH and "4.17.21" in lodash.recommendation and lodash.cwe == "CWE-1321"
    assert found["Vulnerable dependency: wrapper"].severity == Severity.MEDIUM
    with pytest.raises(ValueError):
        dependencies.parse_npm_audit({"error": {"code": "ENOLOCK"}}, "x")


def test_pnpm_pip_cargo_govulncheck_parsers():
    pnpm = {"advisories": {"1": {"module_name": "minimist", "severity": "critical", "title": "Proto", "url": "u", "vulnerable_versions": "<1.2.6", "patched_versions": ">=1.2.6"}}}
    f = dependencies.parse_pnpm_audit(pnpm, "pnpm-lock.yaml")[0]
    assert f.severity == Severity.CRITICAL and ">=1.2.6" in f.recommendation

    pip = {"dependencies": [{"name": "pyyaml", "version": "5.3", "vulns": [{"id": "PYSEC-2020-1", "fix_versions": ["5.4"], "aliases": ["CVE-2020-14343"]}]}]}
    f = dependencies.parse_pip_audit(pip, "requirements.txt")[0]
    assert f.status == Status.REQUIRES_REVIEW and "CVE-2020-14343" in f.evidence and "5.4" in f.recommendation

    cargo = {"vulnerabilities": {"list": [{"advisory": {"id": "RUSTSEC-2020-1", "title": "t", "url": "u"}, "package": {"name": "c", "version": "1"}, "versions": {"patched": [">=2"]}}]}, "warnings": {}}
    assert dependencies.parse_cargo_audit(cargo, "Cargo.lock")[0].rule_id == "cargo-audit:RUSTSEC-2020-1"

    stream = '{"osv": {"id": "GO-2024-1", "summary": "bad"}}\n{"finding": {"osv": "GO-2024-1", "trace": [{"module": "example.com/m", "function": "F"}]}}\n'
    f = dependencies.parse_govulncheck(stream, "go.mod")[0]
    assert f.severity == Severity.HIGH and "example.com/m" in f.title


def test_missing_tools_do_not_crash(tmp_path, monkeypatch):
    from phase2.utils import command

    monkeypatch.setattr(command, "which", lambda tool: None)
    write(tmp_path, "package.json", '{"dependencies": {"a": "1"}}')
    write(tmp_path, "package-lock.json", json.dumps({"lockfileVersion": 3, "packages": {"": {"dependencies": {"a": "1"}}}}))
    write(tmp_path, "go.mod", "module x\n\nrequire example.com/y v1.0.0\n")
    run = dependencies.scan(make_ctx(tmp_path, use_external_tools=True))
    assert not run.failed
    names = {t.name: t for t in run.tools}
    assert names["npm-audit"].available is False and names["govulncheck"].available is False
    assert any(f.rule_id == "dep-no-go-sum" for f in run.findings)


def test_tool_failure_is_recorded(tmp_path, monkeypatch):
    from phase2.utils import command

    write(tmp_path, "package.json", '{"dependencies": {"a": "1"}}')
    write(tmp_path, "package-lock.json", json.dumps({"lockfileVersion": 3, "packages": {"": {"dependencies": {"a": "1"}}}}))
    monkeypatch.setattr(command, "which", lambda tool: "/usr/bin/" + tool)
    monkeypatch.setattr(command, "tool_version", lambda *a, **k: "1.0")
    monkeypatch.setattr(command, "run", lambda *a, **k: command.CommandResult(1, "not json", ""))
    run = dependencies.scan(make_ctx(tmp_path, use_external_tools=True))
    assert run.failed
    assert [t for t in run.tools if t.name == "npm-audit"][0].failed
