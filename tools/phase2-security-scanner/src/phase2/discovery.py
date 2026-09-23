"""Evidence-based technology discovery.

Every detection records *why* it was made. Weak signals (e.g. only an AWS SDK
dependency) are recorded with LOW confidence and explicitly described as not
proving the technology is used for deployment.
"""

from __future__ import annotations

import re
import tomllib

from .models import Confidence, Technology
from .scanners import ScanContext, load_json_file

_CONF_ORDER = {Confidence.LOW: 0, Confidence.MEDIUM: 1, Confidence.HIGH: 2}


class _Detector:
    def __init__(self) -> None:
        self.techs: dict[str, Technology] = {}

    def add(self, name: str, confidence: Confidence, evidence: str) -> None:
        tech = self.techs.get(name)
        if tech is None:
            self.techs[name] = Technology(name, confidence, [evidence])
            return
        if _CONF_ORDER[confidence] > _CONF_ORDER[tech.confidence]:
            tech.confidence = confidence
        if evidence not in tech.evidence and len(tech.evidence) < 8:
            tech.evidence.append(evidence)


NODE_DEPS = {
    "next": ("Next.js", Confidence.HIGH),
    "react": ("React", Confidence.HIGH),
    "react-dom": ("React", Confidence.HIGH),
    "express": ("Express", Confidence.HIGH),
    "@supabase/supabase-js": ("Supabase", Confidence.HIGH),
    "@supabase/ssr": ("Supabase", Confidence.HIGH),
    "firebase": ("Firebase", Confidence.HIGH),
    "firebase-admin": ("Firebase", Confidence.HIGH),
    "pg": ("PostgreSQL", Confidence.MEDIUM),
    "postgres": ("PostgreSQL", Confidence.MEDIUM),
    "@prisma/client": ("Prisma", Confidence.HIGH),
    "mysql": ("MySQL", Confidence.MEDIUM),
    "mysql2": ("MySQL", Confidence.MEDIUM),
    "vercel": ("Vercel", Confidence.LOW),
}
PY_DEPS = {
    "django": ("Django", Confidence.HIGH),
    "fastapi": ("FastAPI", Confidence.HIGH),
    "flask": ("Flask", Confidence.HIGH),
    "supabase": ("Supabase", Confidence.HIGH),
    "firebase-admin": ("Firebase", Confidence.HIGH),
    "psycopg": ("PostgreSQL", Confidence.MEDIUM),
    "psycopg2": ("PostgreSQL", Confidence.MEDIUM),
    "psycopg2-binary": ("PostgreSQL", Confidence.MEDIUM),
    "asyncpg": ("PostgreSQL", Confidence.MEDIUM),
    "mysqlclient": ("MySQL", Confidence.MEDIUM),
    "pymysql": ("MySQL", Confidence.MEDIUM),
    "mysql-connector-python": ("MySQL", Confidence.MEDIUM),
}
AWS_SDK_NODE = re.compile(r"^(aws-sdk|@aws-sdk/.+)$")
AWS_SDK_PY = {"boto3", "botocore", "aiobotocore"}
_REQ_NAME = re.compile(r"^\s*([A-Za-z0-9][A-Za-z0-9._-]*)")
_PY_IMPORT = {
    "Flask": re.compile(r"^\s*from\s+flask\s+import|^\s*import\s+flask\b", re.M),
    "FastAPI": re.compile(r"^\s*from\s+fastapi\s+import|^\s*import\s+fastapi\b", re.M),
    "Django": re.compile(r"^\s*from\s+django[.\s]|^\s*import\s+django\b", re.M),
}


def normalize_py_name(name: str) -> str:
    return re.sub(r"[-_.]+", "-", name).lower()


def python_requirement_names(text: str) -> list[str]:
    names = []
    for line in text.splitlines():
        line = line.split("#", 1)[0].strip()
        if not line or line.startswith("-"):
            continue
        m = _REQ_NAME.match(line)
        if m:
            names.append(normalize_py_name(m.group(1)))
    return names


def pyproject_dependency_names(data: dict) -> list[str]:
    names: list[str] = []
    project = data.get("project") if isinstance(data.get("project"), dict) else {}
    deps = list(project.get("dependencies") or [])
    for group in (project.get("optional-dependencies") or {}).values():
        if isinstance(group, list):
            deps.extend(group)
    for dep in deps:
        if isinstance(dep, str):
            m = _REQ_NAME.match(dep)
            if m:
                names.append(normalize_py_name(m.group(1)))
    poetry = ((data.get("tool") or {}).get("poetry") or {}) if isinstance(data.get("tool"), dict) else {}
    for key in ("dependencies", "dev-dependencies"):
        section = poetry.get(key)
        if isinstance(section, dict):
            names.extend(normalize_py_name(n) for n in section if n.lower() != "python")
    for group in (poetry.get("group") or {}).values():
        if isinstance(group, dict) and isinstance(group.get("dependencies"), dict):
            names.extend(normalize_py_name(n) for n in group["dependencies"] if n.lower() != "python")
    return names


def discover(ctx: ScanContext) -> list[Technology]:
    d = _Detector()
    aws_sdk_seen: list[str] = []

    for entry in ctx.files:
        name = entry.name.lower()
        rel = entry.rel
        if entry.build_output:
            continue
        if name == "package.json":
            d.add("Node.js", Confidence.HIGH, f"{rel} present")
            pkg = load_json_file(ctx, entry)
            if isinstance(pkg, dict):
                deps: dict = {}
                for key in ("dependencies", "devDependencies", "peerDependencies", "optionalDependencies"):
                    if isinstance(pkg.get(key), dict):
                        deps.update(pkg[key])
                for dep in deps:
                    if dep in NODE_DEPS:
                        tech, conf = NODE_DEPS[dep]
                        d.add(tech, conf, f"{rel} declares dependency '{dep}'")
                    elif AWS_SDK_NODE.match(dep):
                        aws_sdk_seen.append(f"{rel} declares '{dep}'")
        elif name.startswith("next.config.") and name.endswith((".js", ".mjs", ".ts", ".cjs")):
            d.add("Next.js", Confidence.HIGH, f"{rel} present")
        elif name in ("requirements.txt",) or (name.startswith("requirements") and name.endswith(".txt")):
            d.add("Python", Confidence.HIGH, f"{rel} present")
            for dep in python_requirement_names(ctx.text(entry) or ""):
                if dep in PY_DEPS:
                    tech, conf = PY_DEPS[dep]
                    d.add(tech, conf, f"{rel} lists '{dep}'")
                elif dep in AWS_SDK_PY:
                    aws_sdk_seen.append(f"{rel} lists '{dep}'")
        elif name == "pyproject.toml":
            d.add("Python", Confidence.HIGH, f"{rel} present")
            try:
                data = tomllib.loads(ctx.text(entry) or "")
            except (tomllib.TOMLDecodeError, ValueError, RecursionError):
                data = {}
            for dep in pyproject_dependency_names(data):
                if dep in PY_DEPS:
                    tech, conf = PY_DEPS[dep]
                    d.add(tech, conf, f"{rel} declares '{dep}'")
                elif dep in AWS_SDK_PY:
                    aws_sdk_seen.append(f"{rel} declares '{dep}'")
        elif name == "manage.py":
            text = ctx.text(entry) or ""
            if "django" in text.lower():
                d.add("Django", Confidence.HIGH, f"{rel} references Django")
        elif name == "settings.py":
            text = ctx.text(entry) or ""
            if "INSTALLED_APPS" in text:
                d.add("Django", Confidence.HIGH, f"{rel} defines INSTALLED_APPS")
        elif entry.suffix == ".py":
            text = ctx.text(entry) or ""
            for tech, pattern in _PY_IMPORT.items():
                if pattern.search(text):
                    d.add(tech, Confidence.MEDIUM, f"{rel} imports {tech.lower()}")
        elif name == "cargo.toml":
            d.add("Rust", Confidence.HIGH, f"{rel} present")
        elif name == "go.mod":
            d.add("Go", Confidence.HIGH, f"{rel} present")
        elif name == "dockerfile" or name.endswith(".dockerfile") or name.startswith("dockerfile."):
            d.add("Docker", Confidence.HIGH, f"{rel} present")
            text = (ctx.text(entry) or "").lower()
            if re.search(r"^\s*from\s+(\S*/)?postgres", text, re.M):
                d.add("PostgreSQL", Confidence.MEDIUM, f"{rel} uses a postgres base image")
            if re.search(r"^\s*from\s+(\S*/)?(mysql|mariadb)", text, re.M):
                d.add("MySQL", Confidence.MEDIUM, f"{rel} uses a mysql/mariadb base image")
        elif re.fullmatch(r"(docker-)?compose(\.[\w-]+)?\.ya?ml", name):
            d.add("Docker", Confidence.HIGH, f"{rel} present")
            text = (ctx.text(entry) or "").lower()
            if re.search(r"image:\s*['\"]?(\S*/)?postgres", text):
                d.add("PostgreSQL", Confidence.HIGH, f"{rel} runs a postgres image")
            if re.search(r"image:\s*['\"]?(\S*/)?(mysql|mariadb)", text):
                d.add("MySQL", Confidence.HIGH, f"{rel} runs a mysql/mariadb image")
        elif entry.suffix == ".tf":
            d.add("Terraform", Confidence.HIGH, f"{rel} present")
            text = ctx.text(entry) or ""
            if re.search(r'provider\s+"aws"', text) or re.search(r'resource\s+"aws_', text):
                d.add("AWS", Confidence.HIGH, f"{rel} configures the Terraform AWS provider/resources")
        elif name in ("vercel.json",):
            d.add("Vercel", Confidence.HIGH, f"{rel} present")
        elif rel.startswith(".vercel/") and name == "project.json":
            d.add("Vercel", Confidence.HIGH, f"{rel} present")
        elif name in ("firebase.json", ".firebaserc", "firestore.rules", "storage.rules", "database.rules.json"):
            d.add("Firebase", Confidence.HIGH, f"{rel} present")
        elif rel.startswith("supabase/") and name in ("config.toml", "seed.sql"):
            d.add("Supabase", Confidence.HIGH, f"{rel} present")
        elif name in ("cdk.json", "samconfig.toml", "amplify.yml"):
            d.add("AWS", Confidence.HIGH, f"{rel} present (AWS deployment tooling)")
        elif name in ("serverless.yml", "serverless.yaml", "template.yaml", "template.yml"):
            text = ctx.text(entry) or ""
            if re.search(r"provider:\s*\n\s*name:\s*aws", text) or "AWS::" in text:
                d.add("AWS", Confidence.HIGH, f"{rel} defines AWS resources")

    if aws_sdk_seen and "AWS" not in d.techs:
        d.add(
            "AWS (SDK only)",
            Confidence.LOW,
            "AWS SDK dependency found (" + "; ".join(aws_sdk_seen[:3]) + "). An SDK alone does not prove AWS hosting.",
        )
    order = {Confidence.HIGH: 0, Confidence.MEDIUM: 1, Confidence.LOW: 2}
    return sorted(d.techs.values(), key=lambda t: (order[t.confidence], t.name))
