from conftest import make_ctx, write

from phase2.models import Confidence, Severity
from phase2.scanners import configuration


def rule_ids(findings):
    return {f.rule_id for f in findings}


def test_node_fixture(vulnerable_node_report):
    ids = rule_ids(vulnerable_node_report.findings)
    assert {
        "cfg-cors-wildcard-js", "cfg-cookie-insecure-js", "cfg-privileged-container", "cfg-docker-socket",
        "cfg-exposed-port", "cfg-docker-curl-pipe-sh", "cfg-docker-root", "cfg-public-env-secret", "cfg-env-not-ignored",
    } <= ids
    pub = next(f for f in vulnerable_node_report.findings if f.rule_id == "cfg-public-env-secret")
    assert pub.severity == Severity.CRITICAL  # value is a service-role JWT
    assert "eyJ" not in pub.evidence


def test_python_fixture(vulnerable_python_report):
    ids = rule_ids(vulnerable_python_report.findings)
    assert {"cfg-django-debug", "cfg-django-allowed-hosts", "cfg-flask-debug", "cfg-django-cookie-insecure", "cfg-cors-allow-all-django"} <= ids


def test_public_env_context(tmp_path):
    write(tmp_path, ".gitignore", ".env*\n")
    write(
        tmp_path, ".env.local",
        "NEXT_PUBLIC_SUPABASE_URL=https://abc.supabase.co\n"
        "NEXT_PUBLIC_SUPABASE_ANON_KEY=eyJhbGciOiJIUzI1NiJ9.eyJyb2xlIjoiYW5vbiJ9.c2lnbmF0dXJl\n"
        "NEXT_PUBLIC_STRIPE_PUBLISHABLE_KEY=pk_test_FAKE123456\n"
        "NEXT_PUBLIC_ANALYTICS_ID=G-123\n"
        "NEXT_PUBLIC_STRIPE_SECRET_KEY=FAKEvalue12345678\n",
    )
    run = configuration.scan(make_ctx(tmp_path))
    pub = [f for f in run.findings if f.rule_id == "cfg-public-env-secret"]
    assert len(pub) == 1 and pub[0].line == 5 and pub[0].severity == Severity.HIGH


def test_env_reuse_across_environments(tmp_path):
    write(tmp_path, ".gitignore", ".env*\n")
    write(tmp_path, ".env.production", "DB_PASSWORD=SameFakeValue123\nNODE_ENV=development\n")
    write(tmp_path, ".env.development", "DB_PASSWORD=SameFakeValue123\n")
    run = configuration.scan(make_ctx(tmp_path))
    ids = rule_ids(run.findings)
    assert {"cfg-env-reuse", "cfg-env-dev-in-prod"} <= ids
    reuse = next(f for f in run.findings if f.rule_id == "cfg-env-reuse")
    assert "SameFakeValue123" not in reuse.evidence


def test_env_ignored_via_gitignore_text(tmp_path):
    write(tmp_path, ".gitignore", ".env\n")
    write(tmp_path, ".env", "A=1\n")
    write(tmp_path, ".env.example", "A=\n")
    run = configuration.scan(make_ctx(tmp_path))
    assert "cfg-env-not-ignored" not in rule_ids(run.findings)


def test_service_role_in_client_component(tmp_path):
    write(tmp_path, "app/admin/page.tsx", "'use client'\nconst k = process.env.SUPABASE_SERVICE_ROLE_KEY;\n")
    write(tmp_path, "app/api/admin/route.ts", "const k = process.env.SUPABASE_SERVICE_ROLE_KEY;\n")
    run = configuration.scan(make_ctx(tmp_path))
    hits = [f for f in run.findings if f.rule_id == "cfg-service-role-client"]
    assert [f.file for f in hits] == ["app/admin/page.tsx"]
    assert hits[0].confidence == Confidence.HIGH


def test_compose_loopback_port_not_flagged(tmp_path):
    write(tmp_path, "docker-compose.yml", 'services:\n  db:\n    image: postgres\n    ports:\n      - "127.0.0.1:5432:5432"\n      - "8080:80"\n')
    run = configuration.scan(make_ctx(tmp_path))
    assert "cfg-exposed-port" not in rule_ids(run.findings)


def test_github_actions_injection(tmp_path):
    write(
        tmp_path, ".github/workflows/ci.yml",
        "on: issues\njobs:\n  a:\n    runs-on: ubuntu-latest\n    steps:\n      - run: |\n          echo \"${{ github.event.issue.title }}\"\n      - run: echo ok\n        env:\n          T: ${{ github.event.issue.title }}\n",
    )
    run = configuration.scan(make_ctx(tmp_path))
    hits = [f for f in run.findings if f.rule_id == "cfg-gha-injection"]
    assert len(hits) == 1 and hits[0].line == 7


def test_terraform_and_firebase(tmp_path):
    write(tmp_path, "main.tf", 'resource "aws_db_instance" "x" {\n  publicly_accessible = true\n}\nresource "aws_s3_bucket_acl" "b" {\n  acl = "public-read"\n}\n')
    write(tmp_path, "firestore.rules", "service cloud.firestore {\n  match /{d=**} {\n    allow read, write: if true;\n  }\n}\n")
    run = configuration.scan(make_ctx(tmp_path))
    assert {"cfg-tf-publicly-accessible", "cfg-tf-public-acl", "cfg-firebase-open-rules"} <= rule_ids(run.findings)


def test_safe_project_clean(safe_report):
    assert not [f for f in safe_report.findings if f.scanner == "configuration"]
