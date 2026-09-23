import json

from conftest import FAKE_AWS_ID, FAKE_GITHUB_TOKEN, FAKE_STRIPE_LIVE, make_ctx, write

from phase2.models import Confidence, FileEntry, Severity
from phase2.reporting import json_report, markdown_report
from phase2.scanners import load_rules, secrets
from phase2.utils.redaction import redact_text, sanitize_evidence, shannon_entropy

RULES = load_rules("secret-patterns.yaml")


def scan_str(text: str, rel: str = "src/app.js"):
    return secrets.scan_text(FileEntry(rel=rel, path=None, size=len(text)), text, RULES)  # type: ignore[arg-type]


def test_detects_fixture_secrets(vulnerable_node_report):
    secret_findings = [f for f in vulnerable_node_report.findings if f.category == "secret"]
    rules = {f.rule_id for f in secret_findings}
    assert {"aws-access-key-id", "aws-secret-access-key", "database-url-credentials", "jwt"} <= rules
    jwt = next(f for f in secret_findings if f.rule_id == "jwt")
    assert jwt.title == "Supabase service-role key (JWT)"
    assert jwt.severity == Severity.CRITICAL


def test_detects_common_token_formats():
    text = "\n".join(
        [
            f'const gh = "{FAKE_GITHUB_TOKEN}";',
            f'const stripe = "{FAKE_STRIPE_LIVE}";',
            "-----BEGIN RSA PRIVATE KEY-----",
            "MIIEFAKEFAKEFAKEFAKEFAKEFAKEFAKEFAKEFAKEFAKEFAKEFAKEFAKEFAKEFAKE",
            "-----END RSA PRIVATE KEY-----",
            'headers: { Authorization: "Bearer FAKEab12cd34ef56gh78ij90kl12mn34op" }',
            'const key = "sk-proj-FAKEfake0123456789abcdefFAKEfake0123";',
        ]
    )
    found = {f.rule_id: f for f in scan_str(text)}
    assert {"github-token", "stripe-live-secret-key", "private-key", "bearer-token", "openai-api-key"} <= set(found)
    assert found["stripe-live-secret-key"].severity == Severity.CRITICAL
    assert found["private-key"].line == 3
    # key body lines are not re-reported as generic high-entropy strings
    assert not any(f.line == 4 for f in scan_str(text))


def test_env_file_rules_only_apply_to_env_files():
    line = "SERVICE_API_TOKEN=Zx81Kq09PlmN4rT7\n"
    assert any(f.rule_id == "secret-assignment-env" for f in scan_str(line, ".env.production"))
    assert not any(f.rule_id == "secret-assignment-env" for f in scan_str(line, "notes.txt"))


def test_placeholders_and_references_are_ignored():
    text = "\n".join(
        [
            'password = "changeme"',
            'api_key = "your-api-key-here"',
            'const token = process.env.GITHUB_TOKEN;',
            'DATABASE_URL = "postgres://user:${DB_PASSWORD}@db:5432/app"',
            'secret: "<REPLACE_ME>"',
        ]
    )
    assert scan_str(text, "config/settings.py") == []


def test_local_database_url_is_low_severity():
    found = scan_str('url = "postgres://postgres:Sup3rLocal99@localhost:5432/dev"')
    db = [f for f in found if f.rule_id == "database-url-credentials"]
    assert db and db[0].severity == Severity.LOW and db[0].confidence == Confidence.LOW


def test_anon_jwt_is_informational():
    import base64

    def seg(d):
        return base64.urlsafe_b64encode(json.dumps(d).encode()).decode().rstrip("=")

    token = seg({"alg": "HS256"}) + "." + seg({"role": "anon", "iss": "supabase"}) + ".FAKEsigFAKEsigFAKEsig"
    found = [f for f in scan_str(f'const anon = "{token}";') if f.rule_id == "jwt"]
    assert found[0].severity == Severity.INFORMATIONAL


def test_word_like_password_gets_low_confidence():
    found = scan_str('password_field = "user_password_input"')
    assert all(f.confidence == Confidence.LOW for f in found)


def test_secret_never_in_evidence_or_reports(tmp_path, vulnerable_node_report):
    secret_values = [
        "fakeFAKEfake0000SECRETsecret1111NOTREAL0",
        "FakeProdPassw0rd99",
        "FakePassw0rd-Fixture7",
        "AKIAFAKEFAKEFAKE0000",
        "FAKEsignatureFAKEsignatureFAKE00",
    ]
    blob = json.dumps(json_report.build(vulnerable_node_report)) + markdown_report.render(vulnerable_node_report)
    for value in secret_values:
        assert value not in blob, value


def test_redaction_helpers():
    raw = f"aws={FAKE_AWS_ID} gh={FAKE_GITHUB_TOKEN} url=postgres://u:hunter2secret@h/db password='S3cretPassw0rd!'"
    out = redact_text(raw)
    for value in (FAKE_AWS_ID, FAKE_GITHUB_TOKEN, "hunter2secret", "S3cretPassw0rd!"):
        assert value not in out
    assert "\n" not in sanitize_evidence("a\nb\x1b[31m")
    assert len(sanitize_evidence("x" * 1000)) <= 240
    assert shannon_entropy("aaaa") == 0.0


def test_gitleaks_report_parsing(tmp_path):
    write(tmp_path, "src/app.js", "x\n")
    data = [
        {"RuleID": "aws-access-token", "File": "src/app.js", "StartLine": 1, "StartColumn": 3, "Secret": "REDACTED", "Match": "REDACTED"},
        {"RuleID": "generic-api-key", "File": "node_modules/x/index.js", "StartLine": 2},
        {"RuleID": "github-pat", "File": "../outside.txt", "StartLine": 1},
    ]
    findings = secrets.parse_gitleaks_report(data, tmp_path, {"src/app.js"})
    assert len(findings) == 1
    f = findings[0]
    assert f.dedup_key == "secret:aws" and f.file == "src/app.js" and "REDACTED" not in f.evidence


def test_scanner_records_gitleaks_unavailable(tmp_path, monkeypatch):
    from phase2.utils import command

    monkeypatch.setattr(command, "which", lambda tool: None)
    write(tmp_path, "a.txt", "nothing\n")
    run = secrets.scan(make_ctx(tmp_path, use_external_tools=True))
    gl = [t for t in run.tools if t.name == "gitleaks"][0]
    assert gl.available is False and not gl.failed
    assert any("Gitleaks not installed" in lim for lim in run.limitations)


def test_private_key_header_without_body_is_downgraded():
    found = [f for f in scan_str("-----BEGIN PRIVATE KEY-----\nFAKE\n-----END PRIVATE KEY-----\n", "keys/a.pem") if f.rule_id == "private-key"]
    assert found[0].severity == Severity.MEDIUM and found[0].confidence == Confidence.LOW
    body = "\n".join(["MIIE" + "A" * 60 + "b" * 4] * 5)
    full = [f for f in scan_str(f"-----BEGIN PRIVATE KEY-----\n{body}\n-----END PRIVATE KEY-----\n", "keys/a.pem") if f.rule_id == "private-key"]
    assert full[0].severity == Severity.CRITICAL and full[0].confidence == Confidence.HIGH


def test_secrets_in_test_paths_keep_severity_but_low_confidence():
    found = [f for f in scan_str(f'const k = "{FAKE_GITHUB_TOKEN}";', "tests/unit/a.test.js") if f.rule_id == "github-token"]
    assert found[0].severity == Severity.HIGH and found[0].confidence == Confidence.LOW and "test-context" in found[0].tags
