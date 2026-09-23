from conftest import FIXTURES, make_ctx, write

from phase2.models import Confidence


def names(ctx):
    return {t.name: t for t in ctx.technologies}


def test_node_fixture_technologies():
    techs = names(make_ctx(FIXTURES / "vulnerable-node"))
    assert {"Node.js", "Express", "PostgreSQL", "Docker"} <= set(techs)
    assert techs["Express"].confidence == Confidence.HIGH
    assert any("express" in e for e in techs["Express"].evidence)


def test_python_fixture_technologies():
    techs = names(make_ctx(FIXTURES / "vulnerable-python"))
    assert {"Python", "Flask", "Django", "PostgreSQL"} <= set(techs)


def test_package_json_alone_is_only_node(tmp_path):
    write(tmp_path, "package.json", '{"name": "x", "dependencies": {"lodash": "^4.17.21"}}')
    techs = names(make_ctx(tmp_path))
    assert set(techs) == {"Node.js"}


def test_next_react_supabase_vercel(tmp_path):
    write(tmp_path, "package.json", '{"dependencies": {"next": "14.0.0", "react": "18.2.0", "@supabase/supabase-js": "2.0.0"}}')
    write(tmp_path, "next.config.mjs", "export default {}\n")
    write(tmp_path, "vercel.json", "{}\n")
    techs = names(make_ctx(tmp_path))
    assert {"Next.js", "React", "Supabase", "Vercel", "Node.js"} <= set(techs)


def test_aws_sdk_alone_is_not_aws(tmp_path):
    write(tmp_path, "package.json", '{"dependencies": {"@aws-sdk/client-s3": "3.0.0"}}')
    techs = names(make_ctx(tmp_path))
    assert "AWS" not in techs
    assert techs["AWS (SDK only)"].confidence == Confidence.LOW
    assert "does not prove" in techs["AWS (SDK only)"].evidence[0]


def test_terraform_aws_provider_is_strong_evidence(tmp_path):
    write(tmp_path, "main.tf", 'provider "aws" {\n  region = "eu-west-1"\n}\n')
    techs = names(make_ctx(tmp_path))
    assert techs["AWS"].confidence == Confidence.HIGH
    assert "Terraform" in techs


def test_fastapi_and_firebase(tmp_path):
    write(tmp_path, "pyproject.toml", '[project]\nname = "x"\ndependencies = ["fastapi>=0.110", "firebase-admin"]\n')
    write(tmp_path, "firebase.json", "{}\n")
    techs = names(make_ctx(tmp_path))
    assert {"FastAPI", "Firebase", "Python"} <= set(techs)


def test_excluded_dirs_not_walked(tmp_path):
    write(tmp_path, "node_modules/evil/package.json", '{"dependencies": {"next": "1"}}')
    write(tmp_path, "src/index.js", "console.log(1)\n")
    ctx = make_ctx(tmp_path)
    assert all(not f.rel.startswith("node_modules/") for f in ctx.files)
    assert "Next.js" not in names(ctx)
