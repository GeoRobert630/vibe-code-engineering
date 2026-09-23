"""Configuration scanner.

Covers debug/dev settings, browser-exposed secrets (NEXT_PUBLIC_/VITE_/...),
CORS, cookies, service-role keys in client code, Docker/Compose/Kubernetes
privileges and exposed ports, Terraform public exposure, Firebase rules,
GitHub Actions script injection, .env ignore status and environment separation.

Context matters: public-prefixed variables are only flagged when their *name*
or *value* indicates a secret; anon/publishable keys and URLs are expected to
be public.
"""

from __future__ import annotations

import fnmatch
import hashlib
import re
from collections import defaultdict
from dataclasses import dataclass

from ..models import Classification, Confidence, FileEntry, Finding, ScannerRun, Severity, Status
from ..utils.filesystem import in_string_literal, is_test_path, iter_lines, python_multiline_string_lines
from ..utils.redaction import looks_like_placeholder, sanitize_evidence
from . import ScanContext
from . import git as git_scanner
from . import secrets as secret_scanner

NAME = "configuration"

PUBLIC_PREFIXES = ("NEXT_PUBLIC_", "VITE_", "REACT_APP_", "EXPO_PUBLIC_", "PUBLIC_", "NUXT_PUBLIC_", "GATSBY_")
SECRET_NAME = re.compile(r"SECRET|SERVICE_ROLE|SERVICE_KEY|PRIVATE|PASSWORD|PASSWD|DATABASE_URL|DB_URL|DB_PASS|SK_LIVE|STRIPE_SECRET|ADMIN_KEY|ACCESS_KEY_SECRET|_TOKEN$|API_SECRET")
PUBLIC_SAFE_NAME = re.compile(r"ANON_KEY|PUBLISHABLE|PUBLIC_KEY$|_URL$|SITE_KEY|MEASUREMENT_ID|APP_ID|PROJECT_ID|DSN$|CLIENT_ID")
SECRET_VALUE = re.compile(r"(?:sk|rk)_live_[A-Za-z0-9]{10,}|sb_secret_|-----BEGIN [A-Z ]*PRIVATE KEY|(?:postgres(?:ql)?|mysql|mongodb(?:\+srv)?)://[^:\s]+:[^@\s]+@")
ENV_LINE = re.compile(r"^\s*(?:export\s+)?([A-Za-z_][A-Za-z0-9_]*)\s*=\s*(.*)$")
FRONTEND_EXT = frozenset({".jsx", ".tsx", ".vue", ".svelte", ".astro"})
SERVER_HINT = re.compile(r"(^|/)(api|server|backend|functions|supabase/functions|scripts|lib/server|app/.+/route\.[jt]s|pages/api)(/|$)|route\.[jt]s$|\.server\.[jt]sx?$|middleware\.[jt]s$")
DANGEROUS_PORTS = {
    "22": "SSH", "23": "Telnet", "2375": "Docker API (unauthenticated)", "2376": "Docker API", "3306": "MySQL",
    "5432": "PostgreSQL", "6379": "Redis", "27017": "MongoDB", "9200": "Elasticsearch", "11211": "Memcached",
    "5984": "CouchDB", "8500": "Consul", "2379": "etcd", "1433": "MSSQL",
}
GHA_INJECTION = re.compile(
    r"\$\{\{\s*github\.(?:event\.(?:issue\.(?:title|body)|pull_request\.(?:title|body|head\.ref|head\.label)|comment\.body|review\.body|review_comment\.body|head_commit\.(?:message|author\.(?:name|email))|commits\[\d*\]\.(?:message|author\.(?:name|email))|pages\[\d*\]\.page_name|workflow_run\.head_branch)|head_ref)\s*\}\}"
)


@dataclass
class _Rule:
    id: str
    title: str
    regex: re.Pattern
    severity: Severity
    confidence: Confidence
    category: str
    description: str
    impact: str
    recommendation: str
    validation: str
    cwe: str | None = None
    owasp: str | None = None
    classification: Classification = Classification.POTENTIAL
    status: Status = Status.OPEN


def _r(id, title, regex, severity, confidence, category, description, impact, recommendation, validation, cwe=None, owasp="A05:2021-Security Misconfiguration", classification=Classification.POTENTIAL, status=Status.OPEN, flags=0):
    return _Rule(id, title, re.compile(regex, flags), severity, confidence, category, description, impact, recommendation, validation, cwe, owasp, classification, status)


CORS_REC = "Restrict allowed origins to an explicit allowlist; never combine a wildcard/reflected origin with credentials."
COOKIE_REC = "Set Secure, HttpOnly and SameSite=Lax/Strict on session and CSRF cookies in production."

PY_RULES = [
    _r("cfg-django-debug", "Django DEBUG enabled", r"^\s*DEBUG\s*=\s*True\b", Severity.MEDIUM, Confidence.MEDIUM, "configuration",
       "DEBUG = True in a Django settings module.", "Debug pages leak settings, source and stack traces.",
       "Read DEBUG from the environment and default to False.", "Request a missing URL in staging and confirm no debug page appears.", "CWE-489"),
    _r("cfg-django-allowed-hosts", "Django ALLOWED_HOSTS wildcard", r"^\s*ALLOWED_HOSTS\s*=\s*\[\s*['\"]\*['\"]\s*\]", Severity.MEDIUM, Confidence.HIGH, "configuration",
       "ALLOWED_HOSTS accepts any Host header.", "Enables host-header poisoning (password-reset links, cache poisoning).",
       "List the real hostnames.", "Send a request with a forged Host header and expect HTTP 400.", "CWE-644"),
    _r("cfg-flask-debug", "Flask debug mode enabled", r"\.run\s*\([^)]*debug\s*=\s*True", Severity.HIGH, Confidence.MEDIUM, "configuration",
       "app.run(debug=True) enables the Werkzeug interactive debugger.", "The Werkzeug debugger allows arbitrary code execution if reachable.",
       "Never enable debug outside local development; read it from the environment.", "Confirm production starts without debug.", "CWE-489"),
    _r("cfg-cors-allow-all-django", "CORS allows all origins (django-cors-headers)", r"^\s*CORS_(?:ORIGIN_ALLOW_ALL|ALLOW_ALL_ORIGINS)\s*=\s*True", Severity.MEDIUM, Confidence.HIGH, "cors",
       "Every origin may make cross-origin requests.", "Any website can read API responses for users (worse with credentials).", CORS_REC,
       "Send a request with Origin: https://evil.example and check the response headers.", "CWE-942"),
    _r("cfg-cors-fastapi-wildcard", "CORS wildcard origin (Starlette/FastAPI)", r"allow_origins\s*=\s*\[\s*['\"]\*['\"]\s*\]", Severity.MEDIUM, Confidence.HIGH, "cors",
       "CORSMiddleware allows every origin.", "Any website can call the API from a browser.", CORS_REC,
       "Send a request with a foreign Origin and check Access-Control-Allow-Origin.", "CWE-942"),
    _r("cfg-django-cookie-insecure", "Insecure Django cookie setting", r"^\s*(?:SESSION|CSRF)_COOKIE_(?:SECURE|HTTPONLY)\s*=\s*False", Severity.MEDIUM, Confidence.MEDIUM, "cookie",
       "A session/CSRF cookie protection flag is disabled.", "Cookies can be sent over HTTP or read by JavaScript (session theft).", COOKIE_REC,
       "Inspect Set-Cookie headers in staging.", "CWE-614", "A07:2021-Identification and Authentication Failures"),
]
JS_RULES = [
    _r("cfg-cors-wildcard-js", "CORS wildcard origin", r"""(?:origin\s*:\s*['"]\*['"]|Access-Control-Allow-Origin['"]?\s*[,:]\s*['"]\*['"])""", Severity.MEDIUM, Confidence.HIGH, "cors",
       "CORS is configured to allow any origin.", "Any website can read responses from a browser context.", CORS_REC,
       "Send a request with Origin: https://evil.example and inspect the response.", "CWE-942"),
    _r("cfg-cors-reflect-credentials", "CORS reflects any origin with credentials", r"origin\s*:\s*(?:true|\(\s*origin\s*,\s*(?:cb|callback)\s*\)\s*=>\s*(?:cb|callback)\s*\(\s*null\s*,\s*true)", Severity.HIGH, Confidence.MEDIUM, "cors",
       "The CORS origin option reflects the request origin.", "Combined with credentials, any site can perform authenticated reads.", CORS_REC,
       "Send a credentialed request from a foreign origin and check Access-Control-Allow-Credentials.", "CWE-942"),
    _r("cfg-cors-default", "cors() middleware with default (allow-all) options", r"\bapp\.use\(\s*cors\(\s*\)\s*\)", Severity.MEDIUM, Confidence.HIGH, "cors",
       "The cors package defaults to Access-Control-Allow-Origin: *.", "Any website can call the API from a browser.", CORS_REC,
       "Check response headers for a foreign Origin.", "CWE-942"),
    _r("cfg-cookie-insecure-js", "Cookie set without Secure/HttpOnly", r"\b(?:secure|httpOnly)\s*:\s*false\b", Severity.MEDIUM, Confidence.MEDIUM, "cookie",
       "A cookie option disables Secure or HttpOnly.", "Session cookies may leak over HTTP or to injected scripts.", COOKIE_REC,
       "Inspect Set-Cookie headers in staging.", "CWE-614", "A07:2021-Identification and Authentication Failures"),
    _r("cfg-cookie-samesite-none", "Cookie SameSite=None", r"""sameSite\s*:\s*['"]none['"]""", Severity.LOW, Confidence.MEDIUM, "cookie",
       "SameSite=None sends the cookie on cross-site requests.", "Increases CSRF exposure; requires Secure.", COOKIE_REC,
       "Confirm CSRF protection exists for state-changing routes.", "CWE-1275", flags=re.I),
    _r("cfg-next-source-maps", "Production browser source maps enabled", r"productionBrowserSourceMaps\s*:\s*true", Severity.LOW, Confidence.HIGH, "configuration",
       "Next.js publishes source maps for client bundles.", "Exposes original source, comments and internal endpoints.",
       "Disable or upload source maps privately to your error tracker.", "Check that *.map files are not served in production.", "CWE-540",
       classification=Classification.CONFIRMED),
]
DOCKERFILE_RULES = [
    _r("cfg-docker-curl-pipe-sh", "Remote script piped to a shell in Dockerfile", r"(?:curl|wget)[^|\n]*\|\s*(?:ba|z)?sh\b", Severity.MEDIUM, Confidence.HIGH, "container",
       "The image build downloads and executes a remote script without verification.", "A compromised download host injects code into the image.",
       "Download, verify a checksum/signature, then execute.", "Confirm the checksum is pinned.", "CWE-494", "A08:2021-Software and Data Integrity Failures"),
    _r("cfg-docker-add-url", "ADD from remote URL", r"^\s*ADD\s+https?://", Severity.LOW, Confidence.HIGH, "container",
       "ADD fetches remote content without integrity verification.", "Tampered content enters the image.", "Use curl with checksum verification, or ADD --checksum.",
       "Confirm integrity verification.", "CWE-494", "A08:2021-Software and Data Integrity Failures", flags=re.I),
    _r("cfg-docker-expose-ssh", "SSH port exposed by image", r"^\s*EXPOSE\s+(?:.*\s)?22(?:/tcp)?\b", Severity.MEDIUM, Confidence.HIGH, "container",
       "The image exposes port 22.", "SSH in application containers widens the attack surface.", "Remove SSH from application images; use orchestration exec tooling.",
       "Rebuild and confirm port 22 is not exposed.", "CWE-1188", flags=re.I),
    _r("cfg-docker-secret-env", "Secret-looking value baked into image (ENV/ARG)", r"^\s*(?:ENV|ARG)\s+[A-Za-z0-9_]*(?:PASSWORD|SECRET|TOKEN|API_KEY|PRIVATE_KEY)[A-Za-z0-9_]*\s*[= ]\s*['\"]?[^\s'\"$]{6,}", Severity.HIGH, Confidence.MEDIUM, "secret",
       "A credential is set with ENV/ARG, which persists in image layers/history.", "Anyone who can pull the image can read the value.",
       "Use BuildKit secrets (--mount=type=secret) or runtime environment injection.", "Run `docker history --no-trunc` on the image and confirm no secret appears.", "CWE-538", flags=re.I),
]
COMPOSE_K8S_RULES = [
    _r("cfg-privileged-container", "Privileged container", r"^\s*privileged\s*:\s*true\b", Severity.HIGH, Confidence.HIGH, "container",
       "The container runs privileged.", "A compromised process can escape to the host.", "Remove privileged mode and grant only specific capabilities if required.",
       "Inspect the running container (docker inspect / kubectl get pod -o yaml).", "CWE-250", classification=Classification.CONFIRMED),
    _r("cfg-docker-socket", "Docker socket mounted into container", r"/var/run/docker\.sock", Severity.HIGH, Confidence.HIGH, "container",
       "The Docker socket is mounted.", "Equivalent to root on the host for anyone controlling the container.", "Remove the socket mount; use a restricted API proxy if unavoidable.",
       "Confirm the mount is absent.", "CWE-250", classification=Classification.CONFIRMED),
    _r("cfg-cap-add-dangerous", "Dangerous Linux capability added", r"^\s*(?:-\s*)?['\"]?(?:SYS_ADMIN|ALL|NET_ADMIN|SYS_PTRACE|SYS_MODULE)['\"]?\s*$", Severity.HIGH, Confidence.MEDIUM, "container",
       "A powerful capability is granted.", "Enables container escape or host network manipulation.", "Drop all capabilities and add back only what is required.",
       "Review cap_add / securityContext.capabilities.", "CWE-250"),
    _r("cfg-host-network", "Host networking enabled", r"^\s*(?:network_mode\s*:\s*['\"]?host|hostNetwork\s*:\s*true|hostPID\s*:\s*true|pid\s*:\s*['\"]?host)", Severity.MEDIUM, Confidence.HIGH, "container",
       "The container shares the host network/PID namespace.", "Removes network isolation; local host services become reachable.", "Use bridge networking and explicit port mappings.",
       "Inspect the running configuration.", "CWE-668"),
    _r("cfg-k8s-privilege-escalation", "allowPrivilegeEscalation enabled / root user", r"^\s*(?:allowPrivilegeEscalation\s*:\s*true|runAsUser\s*:\s*0\b|runAsNonRoot\s*:\s*false)", Severity.MEDIUM, Confidence.HIGH, "container",
       "The pod security context allows root or privilege escalation.", "Increases impact of a container compromise.", "Set runAsNonRoot: true and allowPrivilegeEscalation: false.",
       "kubectl get pod -o yaml and check securityContext.", "CWE-250"),
]
TF_RULES = [
    _r("cfg-tf-public-acl", "Public S3 ACL", r"""acl\s*=\s*["']public-read(?:-write)?["']""", Severity.HIGH, Confidence.HIGH, "cloud",
       "A bucket ACL grants public access.", "Objects may be readable (or writable) by anyone.", "Use private ACLs and S3 Block Public Access.",
       "Check the bucket's public access settings in a non-production account.", "CWE-732", classification=Classification.CONFIRMED),
    _r("cfg-tf-publicly-accessible", "Database publicly accessible", r"publicly_accessible\s*=\s*true", Severity.HIGH, Confidence.HIGH, "cloud",
       "A managed database has a public endpoint.", "The database is reachable from the internet (brute force, exploitation).", "Set publicly_accessible = false and use private networking.",
       "Confirm the endpoint does not resolve to a public IP.", "CWE-668", classification=Classification.CONFIRMED),
    _r("cfg-tf-open-ingress", "Security group open to the internet", r"""cidr_blocks\s*=\s*\[\s*["']0\.0\.0\.0/0["']""", Severity.MEDIUM, Confidence.MEDIUM, "cloud",
       "A rule allows 0.0.0.0/0.", "Fine for public HTTP(S); dangerous for SSH/DB/admin ports.", "Restrict source ranges to known networks for non-public ports.",
       "Review which port this rule applies to.", "CWE-284", status=Status.REQUIRES_REVIEW),
    _r("cfg-tf-unencrypted", "Encryption disabled", r"(?:encrypted|storage_encrypted)\s*=\s*false", Severity.MEDIUM, Confidence.HIGH, "cloud",
       "Storage encryption is explicitly disabled.", "Data at rest is not encrypted.", "Enable encryption (ideally with a customer-managed key).",
       "Check resource settings after apply in a non-production account.", "CWE-311", classification=Classification.CONFIRMED),
]
FIREBASE_RULES = [
    _r("cfg-firebase-open-rules", "Firebase security rules allow open access", r"allow\s+(?:read|write|read\s*,\s*write|write\s*,\s*read)\s*(?::\s*if\s+true\s*;|;)", Severity.HIGH, Confidence.HIGH, "authorization",
       "Firestore/Storage rules allow access without conditions.", "Anyone can read/write the affected data.", "Require request.auth and ownership checks in rules.",
       "Use the Firebase emulator rules tests to confirm unauthenticated access is denied.", "CWE-284", "A01:2021-Broken Access Control", Classification.CONFIRMED),
    _r("cfg-firebase-rtdb-open", "Realtime Database rules allow public access", r"""["']\.(?:read|write)["']\s*:\s*(?:true|["']true["'])""", Severity.HIGH, Confidence.HIGH, "authorization",
       "Realtime Database rules grant public access.", "Anyone can read/write the database path.", "Require auth != null and per-user conditions.",
       "Run rules unit tests with an unauthenticated client.", "CWE-284", "A01:2021-Broken Access Control", Classification.CONFIRMED),
]
SQL_RULES = [
    _r("cfg-supabase-rls-disabled", "Row Level Security disabled", r"disable\s+row\s+level\s+security", Severity.HIGH, Confidence.MEDIUM, "authorization",
       "A migration disables RLS on a table.", "With Supabase/PostgREST, tables without RLS are readable/writable with the anon key.", "Enable RLS and add explicit policies.",
       "Query the table with the anon key and confirm access is denied.", "CWE-284", "A01:2021-Broken Access Control", flags=re.I),
    _r("cfg-supabase-policy-true", "RLS policy with unconditional USING (true)", r"using\s*\(\s*true\s*\)", Severity.MEDIUM, Confidence.MEDIUM, "authorization",
       "A policy allows every row.", "May expose all rows to any authenticated or anonymous user.", "Scope policies to auth.uid() / tenant columns.",
       "Test with two different users and confirm isolation.", "CWE-284", "A01:2021-Broken Access Control", status=Status.REQUIRES_REVIEW, flags=re.I),
]


def _mk(rule: _Rule, entry: FileEntry, lineno: int | None, evidence: str, test_ctx: bool = False, **overrides) -> Finding:
    f = Finding(
        scanner=NAME, category=rule.category, severity=rule.severity, confidence=rule.confidence, title=rule.title,
        description=rule.description, file=entry.rel, line=lineno, evidence=sanitize_evidence(evidence, 200),
        impact=rule.impact, recommendation=rule.recommendation, validation=rule.validation, cwe=rule.cwe,
        owasp=rule.owasp, source=[f"internal:{rule.id}"], status=rule.status, classification=rule.classification,
        rule_id=rule.id, dedup_key=rule.id, context=sanitize_evidence(evidence, 200),
    )
    for k, v in overrides.items():
        setattr(f, k, v)
    if test_ctx:
        f.confidence = Confidence.LOW
        f.tags.append("test-context")
        f.notes.append("Located in test/fixture/example path.")
    return f


def _apply_rules(rules: list[_Rule], entry: FileEntry, text: str, run: ScannerRun, comment: str | None, code: bool = False) -> None:
    test_ctx = is_test_path(entry.rel)
    skip_lines = python_multiline_string_lines(text) if code and entry.suffix == ".py" else set()
    for lineno, line in iter_lines(text):
        stripped = line.lstrip()
        if (comment and stripped.startswith(comment)) or lineno in skip_lines:
            continue
        for rule in rules:
            m = rule.regex.search(line)
            if m and code and in_string_literal(line, m.start()):
                continue
            if m:
                evidence = line.strip()
                if rule.id == "cfg-docker-secret-env":
                    name = re.match(r"\s*(?:ENV|ARG)\s+([A-Za-z0-9_]+)", line, re.I)
                    evidence = f"{name.group(1) if name else 'variable'} set with a literal value (redacted)"
                f = _mk(rule, entry, lineno, evidence, test_ctx)
                if rule.id == "cfg-django-debug" and re.search(r"(dev|local|test)", entry.name, re.I):
                    f.severity, f.confidence = Severity.LOW, Confidence.LOW
                    f.notes.append("Settings file name suggests a development-only module.")
                run.findings.append(f)


# ------------------------------------------------------------------ env files


def is_env_file(entry: FileEntry) -> bool:
    n = entry.name.lower()
    return n == ".env" or n.startswith(".env.") or n.endswith(".env")


def is_env_template(entry: FileEntry) -> bool:
    return bool(re.search(r"\.(example|sample|template|dist|defaults?)$", entry.name.lower()))


def env_kind(entry: FileEntry) -> str:
    n = entry.name.lower()
    if "prod" in n:
        return "production"
    if "stag" in n:
        return "staging"
    if "dev" in n or "local" in n:
        return "development"
    if "test" in n:
        return "test"
    return "default"


def parse_env(text: str) -> list[tuple[int, str, str]]:
    out = []
    for lineno, line in iter_lines(text):
        if line.lstrip().startswith("#"):
            continue
        m = ENV_LINE.match(line)
        if m:
            value = m.group(2).strip()
            if len(value) >= 2 and value[0] == value[-1] and value[0] in "'\"":
                value = value[1:-1]
            else:
                value = value.split(" #", 1)[0].strip()
            out.append((lineno, m.group(1), value))
    return out


def _is_service_role_jwt(value: str) -> bool:
    parts = value.split(".")
    if len(parts) != 3 or not value.startswith("eyJ"):
        return False
    payload = secret_scanner._b64url_json(parts[1])
    return bool(payload) and str(payload.get("role", "")).lower() == "service_role"


def check_env_files(ctx: ScanContext, run: ScannerRun) -> None:
    env_entries = [e for e in ctx.files if is_env_file(e) and not e.build_output]
    values_by_key: dict[str, dict[str, tuple[str, FileEntry, int]]] = defaultdict(dict)
    for entry in env_entries:
        text = ctx.text(entry) or ""
        template = is_env_template(entry)
        kind = env_kind(entry)
        for lineno, key, value in parse_env(text):
            upper = key.upper()
            if upper.startswith(PUBLIC_PREFIXES) and value and not looks_like_placeholder(value):
                name_secret = bool(SECRET_NAME.search(upper)) and not PUBLIC_SAFE_NAME.search(upper)
                value_secret = bool(SECRET_VALUE.search(value)) or _is_service_role_jwt(value)
                if name_secret or value_secret:
                    run.findings.append(
                        Finding(
                            scanner=NAME, category="secret-exposure",
                            severity=Severity.CRITICAL if value_secret else Severity.HIGH,
                            confidence=Confidence.HIGH if value_secret else Confidence.MEDIUM,
                            title="Secret exposed to the browser via public env prefix",
                            description=f"{key} uses a public prefix; bundlers inline these values into client JavaScript.",
                            file=entry.rel, line=lineno, evidence=f"{key} is set (value redacted, {len(value)} chars)",
                            impact="Every visitor can extract the value from the JavaScript bundle.",
                            recommendation="Rename without the public prefix, use it only in server code, and rotate the value if it was ever deployed.",
                            validation="Build the app and search the client bundle (.next/static, dist/assets) for the variable's value.",
                            cwe="CWE-200", owasp="A01:2021-Broken Access Control", source=["internal:cfg-public-env-secret"],
                            classification=Classification.POTENTIAL, rule_id="cfg-public-env-secret",
                            dedup_key="cfg-public-env-secret", context=key,
                        )
                    )
            if upper in ("DEBUG", "APP_DEBUG", "FLASK_DEBUG", "DJANGO_DEBUG") and value.lower() in ("1", "true", "yes", "on") and kind in ("production", "staging", "default") and not template:
                run.findings.append(
                    Finding(
                        scanner=NAME, category="configuration", severity=Severity.MEDIUM if kind != "default" else Severity.LOW,
                        confidence=Confidence.MEDIUM, title="Debug mode enabled in environment file",
                        description=f"{key} is enabled in {entry.rel} ({kind} environment).",
                        file=entry.rel, line=lineno, evidence=f"{key}={value[:10]}",
                        impact="Debug modes expose stack traces, configuration and sometimes interactive consoles.",
                        recommendation="Disable debug in production/staging environment configuration.",
                        validation="Trigger an error in staging and confirm a generic error page.",
                        cwe="CWE-489", owasp="A05:2021-Security Misconfiguration", source=["internal:cfg-env-debug"],
                        rule_id="cfg-env-debug", dedup_key="cfg-env-debug", context=key,
                    )
                )
            if upper in ("NODE_ENV", "APP_ENV", "ENVIRONMENT", "RAILS_ENV", "FLASK_ENV") and kind == "production" and value.lower() in ("development", "dev", "local", "test"):
                run.findings.append(
                    Finding(
                        scanner=NAME, category="configuration", severity=Severity.MEDIUM, confidence=Confidence.HIGH,
                        title="Development mode configured in production environment file",
                        description=f"{key}={value} in {entry.rel}.", file=entry.rel, line=lineno, evidence=f"{key}={value[:20]}",
                        impact="Development mode disables production hardening (error detail, caching, security defaults).",
                        recommendation="Set production mode in production configuration.",
                        validation="Check the deployed runtime's environment.", cwe="CWE-489",
                        owasp="A05:2021-Security Misconfiguration", source=["internal:cfg-env-dev-in-prod"],
                        classification=Classification.CONFIRMED, rule_id="cfg-env-dev-in-prod", dedup_key="cfg-env-dev-in-prod", context=key,
                    )
                )
            if not template and value and not looks_like_placeholder(value) and len(value) >= 8 and SECRET_NAME.search(upper):
                digest = hashlib.sha256(value.encode()).hexdigest()
                values_by_key[upper][kind] = (digest, entry, lineno)
    # Weak environment separation: same secret value in production and another environment.
    for key, per_env in sorted(values_by_key.items()):
        if "production" not in per_env:
            continue
        prod_digest, prod_entry, prod_line = per_env["production"]
        others = [k for k, (d, _, _) in per_env.items() if k != "production" and d == prod_digest]
        if others:
            run.findings.append(
                Finding(
                    scanner=NAME, category="environment-separation", severity=Severity.HIGH, confidence=Confidence.HIGH,
                    title="Same secret reused across environments",
                    description=f"{key} has an identical value in production and {', '.join(sorted(others))} environment files.",
                    file=prod_entry.rel, line=prod_line, evidence=f"{key}: identical value (compared by hash, not shown)",
                    impact="Compromise of a lower environment (or a developer laptop) yields production access.",
                    recommendation="Use distinct credentials per environment and rotate the production value.",
                    validation="Confirm each environment's credential is different and scoped to that environment.",
                    cwe="CWE-653", owasp="A05:2021-Security Misconfiguration", source=["internal:cfg-env-reuse"],
                    classification=Classification.CONFIRMED, rule_id="cfg-env-reuse", dedup_key="cfg-env-reuse", context=key,
                )
            )
    _check_env_ignored(ctx, run, [e for e in env_entries if not is_env_template(e)])


def _gitignore_patterns(ctx: ScanContext) -> list[str]:
    entry = ctx.files_by_rel.get(".gitignore")
    if entry is None:
        return []
    pats = []
    for line in (ctx.text(entry) or "").splitlines():
        line = line.strip()
        if line and not line.startswith(("#", "!")):
            pats.append(line.lstrip("/").rstrip("/"))
    return pats


def _check_env_ignored(ctx: ScanContext, run: ScannerRun, env_entries: list[FileEntry]) -> None:
    if not env_entries:
        return
    repo = git_scanner.repo_info(ctx)
    for entry in env_entries:
        if repo is not None:
            ignored = git_scanner.is_ignored(ctx, entry.rel)
            if ignored is None:
                continue
            if ignored or git_scanner.is_tracked(ctx, entry.rel):
                continue  # tracked env files are reported by the Git scanner
        else:
            pats = _gitignore_patterns(ctx)
            if any(fnmatch.fnmatch(entry.name, p) or fnmatch.fnmatch(entry.rel, p) for p in pats):
                continue
        run.findings.append(
            Finding(
                scanner=NAME, category="secret-exposure", severity=Severity.MEDIUM, confidence=Confidence.HIGH,
                title="Environment file not ignored by Git",
                description=f"{entry.rel} is not matched by .gitignore and could be committed.",
                file=entry.rel, evidence="No matching .gitignore rule" + ("" if repo else " (no Git repository; checked .gitignore text)"),
                impact="Secrets in the file are one `git add .` away from the repository history.",
                recommendation="Add `.env*` (with `!.env.example`) to .gitignore.",
                validation="`git check-ignore -v <file>` prints the matching rule.",
                cwe="CWE-538", owasp="A05:2021-Security Misconfiguration", source=["internal:cfg-env-not-ignored"],
                classification=Classification.CONFIRMED, rule_id="cfg-env-not-ignored", dedup_key="cfg-env-not-ignored",
            )
        )


# ------------------------------------------------------------------ client code


def _is_client_file(entry: FileEntry, text: str) -> tuple[bool, Confidence]:
    rel = entry.rel
    if SERVER_HINT.search(rel):
        return False, Confidence.LOW
    head = text[:300]
    if re.search(r"""^\s*['"]use client['"]""", head, re.M):
        return True, Confidence.HIGH
    if re.search(r"""^\s*['"]use server['"]""", head, re.M) or "server-only" in head:
        return False, Confidence.LOW
    if entry.suffix in FRONTEND_EXT or re.search(r"(^|/)(components|hooks|public|client|frontend|src/pages|app)(/|$)", rel):
        return True, Confidence.MEDIUM
    return False, Confidence.LOW


def check_client_code(ctx: ScanContext, run: ScannerRun) -> None:
    for entry in ctx.files:
        if entry.suffix not in (".js", ".jsx", ".ts", ".tsx", ".vue", ".svelte", ".mjs", ".astro") or entry.build_output:
            continue
        text = ctx.text(entry) or ""
        if not re.search(r"service_role|SERVICE_ROLE|serviceRole|NEXT_PUBLIC_\w*(?:SECRET|PASSWORD|DATABASE_URL)", text):
            continue
        client, conf = _is_client_file(entry, text)
        if not client:
            continue
        test_ctx = is_test_path(entry.rel)
        for lineno, line in iter_lines(text):
            if re.search(r"service_role|SERVICE_ROLE|serviceRole", line):
                title, rid = "Supabase service-role key referenced in client-side code", "cfg-service-role-client"
            elif re.search(r"NEXT_PUBLIC_\w*(?:SECRET|PASSWORD|DATABASE_URL)", line):
                title, rid = "Secret-named public env variable used in client code", "cfg-public-secret-client"
            else:
                continue
            f = Finding(
                scanner=NAME, category="secret-exposure", severity=Severity.HIGH, confidence=conf, title=title,
                description="Browser code references a credential that bypasses authorization (or should be server-only).",
                file=entry.rel, line=lineno, evidence=sanitize_evidence(line.strip(), 160),
                impact="If the value reaches the bundle, anyone can use it; a service-role key bypasses Row Level Security entirely.",
                recommendation="Use service-role keys only in server code (route handlers, server actions, edge functions); use the anon key with RLS in the browser.",
                validation="Build the app and grep client bundles for the key; verify the file is not shipped to the browser.",
                cwe="CWE-200", owasp="A01:2021-Broken Access Control", source=[f"internal:{rid}"],
                classification=Classification.POTENTIAL, rule_id=rid, dedup_key=rid,
                context=sanitize_evidence(line.strip(), 160),
                notes=["File marked 'use client'." if conf == Confidence.HIGH else "File location/extension suggests client-side code; verify."],
            )
            if test_ctx:
                f.confidence = Confidence.LOW
                f.tags.append("test-context")
            run.findings.append(f)


# ------------------------------------------------------------------ compose ports / Dockerfile USER


def check_compose_ports(entry: FileEntry, text: str, run: ScannerRun) -> None:
    in_ports = False
    for lineno, line in iter_lines(text):
        if re.match(r"^\s*ports\s*:", line):
            in_ports = True
            continue
        if in_ports:
            m = re.match(r"""^\s*-\s*['"]?(?:(\d{1,3}(?:\.\d{1,3}){3}|\[[^\]]+\]):)?(\d+)(?::(\d+))?(?:/\w+)?['"]?\s*$""", line)
            if not m:
                if line.strip() and not line.strip().startswith("#"):
                    in_ports = False
                continue
            bind, host_port, container_port = m.group(1), m.group(2), m.group(3) or m.group(2)
            if bind in ("127.0.0.1", "[::1]"):
                continue
            label = DANGEROUS_PORTS.get(container_port)
            if label:
                sev = Severity.HIGH if container_port == "2375" else Severity.MEDIUM
                run.findings.append(
                    Finding(
                        scanner=NAME, category="network-exposure", severity=sev, confidence=Confidence.MEDIUM,
                        title=f"{label} port published on all interfaces",
                        description=f"Port {container_port} ({label}) is published as host port {host_port} without a loopback bind address.",
                        file=entry.rel, line=lineno, evidence=sanitize_evidence(line.strip()),
                        impact="The service is reachable from any network the host is on (and the internet on cloud VMs).",
                        recommendation="Bind to 127.0.0.1 (\"127.0.0.1:PORT:PORT\") or remove the port mapping and use the internal network.",
                        validation="From another machine, attempt to connect to the host port and confirm it is refused.",
                        cwe="CWE-668", owasp="A05:2021-Security Misconfiguration", source=["internal:cfg-exposed-port"],
                        rule_id="cfg-exposed-port", dedup_key=f"cfg-exposed-port-{container_port}",
                        context=line.strip(), notes=["Acceptable for local-only development compose files; verify usage."],
                    )
                )


def check_dockerfile_user(entry: FileEntry, text: str, run: ScannerRun) -> None:
    users = re.findall(r"^\s*USER\s+(\S+)", text, re.M | re.I)
    if not re.search(r"^\s*FROM\s", text, re.M | re.I):
        return
    if not users or users[-1].lower() in ("root", "0", "0:0"):
        run.findings.append(
            Finding(
                scanner=NAME, category="container", severity=Severity.LOW, confidence=Confidence.MEDIUM,
                title="Container runs as root", description="The final image stage has no non-root USER instruction.",
                file=entry.rel, evidence="USER " + (users[-1] if users else "(not set)"),
                impact="A compromised application process runs as root inside the container, easing escapes.",
                recommendation="Add a non-root user and `USER app` in the final stage.",
                validation="`docker run --rm IMAGE id` prints a non-zero uid.", cwe="CWE-250",
                owasp="A05:2021-Security Misconfiguration", source=["internal:cfg-docker-root"],
                status=Status.REQUIRES_REVIEW, rule_id="cfg-docker-root", dedup_key="cfg-docker-root",
                notes=["Base images may already set a non-root user; verify."],
            )
        )


def check_github_actions(entry: FileEntry, text: str, run: ScannerRun) -> None:
    in_run = False
    run_indent = 0
    for lineno, line in iter_lines(text):
        m = re.match(r"^(\s*)-?\s*run\s*:(.*)$", line)
        if m:
            # Only block scalars (run: | / run: >) continue on following lines.
            in_run, run_indent = m.group(2).strip() in ("", "|", ">", "|-", ">-", "|+", ">+"), len(m.group(1))
        elif in_run and line.strip() and (len(line) - len(line.lstrip())) <= run_indent:
            in_run = False
        if (in_run or m) and GHA_INJECTION.search(line):
            run.findings.append(
                Finding(
                    scanner=NAME, category="ci-cd", severity=Severity.HIGH, confidence=Confidence.HIGH,
                    title="GitHub Actions script injection via untrusted event data",
                    description="Attacker-controlled event fields are interpolated directly into a shell `run:` step.",
                    file=entry.rel, line=lineno, evidence=sanitize_evidence(line.strip()),
                    impact="A crafted issue/PR title or branch name executes commands in the workflow with its token and secrets.",
                    recommendation="Pass the value through an environment variable (env: TITLE: ${{ ... }}) and reference \"$TITLE\" in the script.",
                    validation="Open a test PR titled `\"; echo INJECTED; #` in a fork and confirm nothing executes.",
                    cwe="CWE-78", owasp="A03:2021-Injection", source=["internal:cfg-gha-injection"],
                    classification=Classification.POTENTIAL, rule_id="cfg-gha-injection", dedup_key="cfg-gha-injection",
                    context=line.strip(),
                )
            )
        if re.match(r"^\s*on\s*:.*pull_request_target|^\s*pull_request_target\s*:", line):
            if re.search(r"ref\s*:\s*\$\{\{\s*github\.event\.pull_request\.head\.(?:sha|ref)", text):
                run.findings.append(
                    Finding(
                        scanner=NAME, category="ci-cd", severity=Severity.HIGH, confidence=Confidence.MEDIUM,
                        title="pull_request_target workflow checks out untrusted PR code",
                        description="The workflow runs with repository secrets and checks out the PR head.",
                        file=entry.rel, line=lineno, evidence="pull_request_target + checkout of pull_request.head",
                        impact="Fork PRs can run arbitrary code with write token/secrets (\"pwn request\").",
                        recommendation="Use pull_request for untrusted code, or never execute checked-out PR code in pull_request_target.",
                        validation="Review the workflow for build/test steps after checkout.", cwe="CWE-829",
                        owasp="A08:2021-Software and Data Integrity Failures", source=["internal:cfg-gha-prt"],
                        rule_id="cfg-gha-prt", dedup_key="cfg-gha-prt",
                    )
                )


# ------------------------------------------------------------------ entry point


def scan(ctx: ScanContext) -> ScannerRun:
    run = ScannerRun(NAME)
    for entry in ctx.files:
        if entry.build_output:
            continue
        name = entry.name.lower()
        text = None

        def t() -> str:
            nonlocal text
            if text is None:
                text = ctx.text(entry) or ""
            return text

        if entry.suffix == ".py":
            _apply_rules(PY_RULES, entry, t(), run, "#", code=True)
        elif entry.suffix in (".js", ".jsx", ".ts", ".tsx", ".mjs", ".cjs"):
            _apply_rules(JS_RULES, entry, t(), run, "//", code=True)
        if name == "dockerfile" or name.startswith("dockerfile.") or name.endswith(".dockerfile"):
            _apply_rules(DOCKERFILE_RULES, entry, t(), run, "#")
            check_dockerfile_user(entry, t(), run)
        if entry.suffix in (".yml", ".yaml"):
            if re.fullmatch(r"(docker-)?compose(\.[\w-]+)?\.ya?ml", name) or re.search(r"(^|/)(k8s|kubernetes|manifests|helm|charts|deploy)/", entry.rel) or re.search(r"^\s*kind\s*:\s*(Pod|Deployment|StatefulSet|DaemonSet|Job|CronJob)\b", t(), re.M):
                _apply_rules(COMPOSE_K8S_RULES, entry, t(), run, "#")
                check_compose_ports(entry, t(), run)
            if entry.rel.startswith(".github/workflows/") or "/.github/workflows/" in entry.rel:
                check_github_actions(entry, t(), run)
        if entry.suffix in (".tf", ".tfvars"):
            _apply_rules(TF_RULES, entry, t(), run, "#")
        if name in ("firestore.rules", "storage.rules", "database.rules.json") or entry.suffix == ".rules":
            _apply_rules(FIREBASE_RULES, entry, t(), run, "//")
        if entry.suffix == ".sql":
            _apply_rules(SQL_RULES, entry, t(), run, "--")
    check_env_files(ctx, run)
    check_client_code(ctx, run)
    run.limitations.append(
        "Configuration checks read files only. Effective runtime configuration (environment variables injected by the "
        "platform, reverse-proxy headers, cloud console settings) requires runtime verification in staging."
    )
    return run
