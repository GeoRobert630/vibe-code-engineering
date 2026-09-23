from phase2.models import Confidence, FileEntry, Severity, Status
from phase2.scanners import dangerous_code, load_rules

RULES = load_rules("dangerous-patterns.yaml")


def scan_str(text: str, rel: str):
    return dangerous_code.scan_text(FileEntry(rel=rel, path=None, size=len(text)), text, RULES)  # type: ignore[arg-type]


def rule_ids(findings):
    return {f.rule_id for f in findings}


def test_node_fixture(vulnerable_node_report):
    ids = rule_ids(vulnerable_node_report.findings)
    assert {"js-eval", "js-child-process-exec", "js-sql-template", "js-inner-html", "js-document-write"} <= ids
    ev = next(f for f in vulnerable_node_report.findings if f.rule_id == "js-eval")
    assert ev.severity == Severity.CRITICAL and ev.confidence == Confidence.HIGH and ev.status == Status.OPEN


def test_python_fixture(vulnerable_python_report):
    ids = rule_ids(vulnerable_python_report.findings)
    assert {"py-eval", "py-os-system", "py-subprocess-shell", "py-pickle", "py-yaml-load", "py-sql-fstring"} <= ids


def test_untainted_usage_requires_review():
    found = scan_str("def run(expr):\n    return eval(expr)\n", "lib/calc.py")
    assert len(found) == 1
    f = found[0]
    assert f.status == Status.REQUIRES_REVIEW and f.severity == Severity.MEDIUM and f.confidence == Confidence.LOW


def test_literal_argument_is_informational():
    found = scan_str('eval("1 + 1")\n', "lib/x.py")
    assert found[0].severity == Severity.INFORMATIONAL


def test_false_positives_not_reported():
    js = "\n".join(
        [
            "const m = /a(b)/.exec(str);",
            "const r = regex.exec(input);",
            "model.evaluate();",
            "// eval(req.query.x) in a comment",
            'el.textContent = name;',
        ]
    )
    assert scan_str(js, "src/a.js") == []
    py = "\n".join(["model.eval()", "# os.system(request.args['x'])", "yaml.safe_load(data)", "yaml.load(data, Loader=yaml.SafeLoader)"])
    assert scan_str(py, "src/a.py") == []


def test_exec_requires_child_process_import():
    assert scan_str("exec(cmd);\n", "src/a.js") == []
    found = scan_str("const { exec } = require('child_process');\nexec(cmd);\n", "src/a.js")
    assert rule_ids(found) == {"js-child-process-exec"}


def test_subprocess_list_without_shell_is_informational():
    found = scan_str('subprocess.run(["git", "status"], check=True)\n', "src/a.py")
    assert found and all(f.severity == Severity.INFORMATIONAL for f in found)


def test_shell_true_preferred_over_generic_subprocess():
    found = scan_str('subprocess.run(cmd, shell=True)\n', "src/a.py")
    assert rule_ids(found) == {"py-subprocess-shell"}


def test_sanitizer_downgrades_xss():
    found = scan_str("el.innerHTML = DOMPurify.sanitize(location.hash);\n", "src/a.js")
    assert found[0].severity == Severity.LOW and found[0].status == Status.REQUIRES_REVIEW


def test_test_files_lower_confidence_but_keep_severity():
    # SR-07: path names are attacker-controlled; severity is kept so CRITICAL still blocks.
    found = scan_str("eval(req.query.x);\n", "tests/unit/a.test.js")
    assert found[0].severity == Severity.CRITICAL and found[0].confidence == Confidence.LOW
    assert "test-context" in found[0].tags


def test_path_traversal_needs_same_line_taint():
    assert scan_str("const p = path.join(base, name);\n", "src/a.js") == []
    found = scan_str("res.sendFile(path.join(__dirname, req.params.file));\n", "src/a.js")
    assert found and found[0].category == "path-traversal" and found[0].severity == Severity.HIGH


def test_secret_in_dangerous_line_is_redacted():
    line = 'eval("x"); const password = "S3cretPassw0rd!ZZ";\n'
    found = scan_str(line, "src/a.js")
    assert all("S3cretPassw0rd!ZZ" not in f.evidence for f in found)


def test_matches_inside_string_literals_are_skipped():
    assert scan_str('msg = "never call eval(user_input) here"\n', "src/a.py") == []
    assert scan_str("const doc = 'use exec(cmd) carefully';\nconst cp = require('child_process');\n", "src/a.js") == []


def test_python_docstring_continuation_lines_skipped():
    text = 'def f():\n    """Doc.\n\n    Never do eval(request.args["x"]) here.\n    """\n    return eval(request.args["y"])\n'
    found = scan_str(text, "src/a.py")
    assert [f.line for f in found] == [6]


def test_write_text_fstring_is_not_sql():
    assert scan_str('path.write_text(f"#!/bin/sh\necho {x}")\n', "src/a.py") == []
    assert {f.rule_id for f in scan_str('db.execute(sa.text(f"SELECT * FROM t WHERE id={uid}"))\n', "src/a.py")} == {"py-sql-fstring"}
