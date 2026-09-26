# Authentication, Session and Authorization runtime verification - design (v1.2)

**Status:**

- **Released versions (up to and including `v1.1.0`):** Authentication, Session, Authorization, IDOR/BOLA and tenant
  isolation are all **NOT VERIFIED** at runtime.
- **Implemented on `v1.2-dev`:**
  - the status rules;
  - the imported-results schema;
  - validation and redaction of imported results;
  - report, reader and SARIF integration (section 17).
- **v1.3 Native Verification:** Implemented on `v1.3-dev`. All five native verification areas (Authentication A1–A6,
  Session S1–S6, Authorization Z1–Z2, IDOR/BOLA I1–I4, and Tenant Isolation T1–T4) are implemented natively under
  `runtime_verification` for authorized local targets (see [docs/V1.3-AUTH-SESSION-AUTHORIZATION-DESIGN.md](V1.3-AUTH-SESSION-AUTHORIZATION-DESIGN.md)).
  The v1.2 imported-results path remains supported for external test suites. Native and imported sources remain distinct.

**Evidence limitation.** Imported results prove only the evidence the external test suite supplies. Vibe-Code checks
that the evidence has the right shape, is safe (no credentials, redacted values, within the request budget) and is
consistent (a status matches its findings and evidence). It does not independently prove that the external requests
happened or that the reported responses were observed.

## 1. Historical v1.2 baseline state

What existed on `v1.2-dev` (baseline `v1.1.0`, prior to v1.3 native verification):

*(Note: In v1.3, native runtime verification for Authentication, Session, Authorization, IDOR/BOLA, and Tenant Isolation is fully implemented for authorized local targets; see [docs/V1.3-AUTH-SESSION-AUTHORIZATION-DESIGN.md](V1.3-AUTH-SESSION-AUTHORIZATION-DESIGN.md). The table below documents the historical v1.2 baseline.)*

| Area | What existed in v1.2 | What did not exist in v1.2 (historical baseline) |
|---|---|---|
| Authentication (3B) | Config schema `authentication:` (`login` POST + content type + field names, `logout`, `protected_endpoint` GET/HEAD) and `credentials:` holding environment-variable **names** only (`auth/...`, `config.py`). Validated, never executed. Report area `auth_areas.authentication`, filled from imported results when configured (section 17). | Any login, logout or authenticated request. Credential values are never read. (Implemented natively in v1.3 under `runtime_verification`; v1.2 imported path remains available.) |
| Session (3B) | In-memory `SessionState` / `SessionRegistry` (`auth/models.py`): records presence flags only (`has_cookie`, `cookie_count`, `has_bearer_token`), refuses pickling, one state per actor. Report area `auth_areas.session`, filled from imported results when configured. | Any session establishment, continuity, fixation or invalidation check. The model was not used by any check in v1.2. (Implemented natively in v1.3.) |
| Authorization (3C) | `authz/status.py`: report block `authorization`. Fields: scope, `runtime_checks_executed`, `credentials_read: false`. Sub-areas `authorization`, `idor_bola` and `tenant_isolation` hold imported results when configured; otherwise all are NOT VERIFIED. | Any authorization, IDOR/BOLA or tenant-isolation request in v1.2. (Implemented natively in v1.3.) |
| Status rules | `verification/status.py` (pure). Statuses: NOT CONFIGURED, READY, EXECUTED, PASS, FAIL, INCOMPLETE, NOT VERIFIED. A PASS needs executed checks, evidence and no findings; ambiguous evidence becomes INCOMPLETE; NOT VERIFIED never becomes PASS. Without an import, the existing 3B/3C status logic is unchanged. | A PASS produced by this tool's own checks in v1.2. (Produced natively in v1.3.) |
| Imported results | Schema 1.0 (`schemas/verification-results.schema.json`); importer (`verification/importer.py`) loads one local JSON file named by `verification_results.path`. Validation is all-or-nothing and covers: target origin match, `requests_count` 0-20 per area and 20 in total, and each area's own namespace. Credential-shaped field names are rejected and values redacted (`verification/redaction.py`). | Any credential input (no environment variable, CLI option or config key). Any check that the external requests actually happened. |
| Finding IDs | `RT-<PREFIX>-NNN`. The 3A checks number findings per category in check order (`runner.py`). Imported findings keep their IDs, restricted to `RT-AUTH`, `RT-SESSION`, `RT-AUTHZ`, `RT-IDOR`, `RT-TENANT`. `FINDING_ID_RE` accepts all of these. | Any `RT-AUTH/SESSION/AUTHZ/IDOR/TENANT-*` finding generated natively in v1.2. (Generated natively in v1.3.) |
| Readers / SARIF | `read_phase3_report.py` (skill 17) exposes `authentication`, `session`, `authorization`, `authorization_subareas`, `idor_bola`, `tenant_isolation` and `requests_count`. security-ci adds `verificationSubareas` and `importedVerification` to the SARIF run properties and treats an INCOMPLETE import as an incomplete input. Engineering CI copies the three area statuses into `engineering-summary.json`. Old reports still parse. | - |
| Safety controls | Safety gate (production refused, environment allow-list, remote hosts need `authorized` + `authorized_by`), `limits.max_requests` (default 60, 1-200), `limits.timeout` (0.5-60 s), `limits.delay_seconds` (0-10), redaction of cookies/tokens/URL credentials, no redirects followed by the probes. Imported results are not applied when the gate refuses the target. | Identity-aware request budgets for runtime probing in v1.2. (Implemented in v1.3.) |
| Tests | `tests/test_auth_plumbing.py`, `tests/test_authz_status.py`, `tests/test_authz_subareas.py`, `tests/test_verification_status.py`, `tests/test_verification_import.py` (302 Phase 3 tests in total); security-ci `tests/test_imported_verification.py`. All use hand-written JSON; no request is sent for these areas. | Any test of an executed auth/session/authz runtime check in v1.2. (Tested natively in v1.3.) |
| Skills | `skills/06-security/17-security-audit` documents 3B as plumbing only, 3C as status only, and the imported-results exception. `01-authentication`, `02-authorization` and `07-session-cookie-security` cover source review (Layer 2). | Runtime procedures for these areas in v1.2. |

## 2. Verification goals

A future implementation should be able to state, with recorded evidence, for an explicitly authorized non-production
target:

1. a declared protected resource rejects unauthenticated access;
2. a declared synthetic identity can authenticate, and a deliberately wrong synthetic secret cannot;
3. authentication establishes a session that persists across requests and is invalidated by logout;
4. the session identifier changes across authentication (fixation resistance) and its cookie has safe attributes;
5. a low-privilege identity cannot read a declared privileged route;
6. an identity cannot read a declared object owned by another identity (IDOR/BOLA, read path);
7. an identity of tenant A cannot read a declared resource of tenant B, and vice versa.

It must never turn NOT VERIFIED into PASS, and never report PASS without positive controls (section 3.3).

## 3. Verification model and threat/test model

### 3.1 Area states

| State | Meaning | Final? |
|---|---|---|
| NOT CONFIGURED | No `runtime_verification` block (or the area is not declared in it). | yes |
| NOT VERIFIED | Configured, but the target is not eligible (e.g. refused by the safety gate, a mode not released yet, an unsupported authentication flow such as MFA), or the area is out of scope. Nothing was sent for this area. | yes |
| READY | Configuration valid, safety gate passed, identities/resources declared, execution plan computed; nothing sent yet. Appears only in a plan (`--plan`) output. | no |
| EXECUTED | The area's planned requests were sent and every response was classified. A lifecycle state recorded as `execution: EXECUTED`; never a verdict on its own. | no |
| PASS | EXECUTED, every positive control succeeded, every expected denial was a clear denial, no finding. | yes |
| FAIL | EXECUTED and at least one finding with sufficient evidence (section 12). | yes |
| INCOMPLETE | Started but not every check produced a classifiable result: a positive control failed, an ambiguous response, timeout, request budget exhausted, MFA challenge, unexpected redirect, 5xx. | yes |

Reports carry `status` (one of the final states) and `execution` (`NOT EXECUTED` / `EXECUTED`). NOT VERIFIED and
NOT CONFIGURED always mean nothing was verified. INCOMPLETE fails the security gate, as today.

### 3.2 Evidence required for EXECUTED

An area becomes EXECUTED only when all of the following exist in memory at the end of the run:

- the safety decision (`allowed: true`) and the resolved mode;
- one record per planned check: check id, identity label(s), method, declared path template, response status class,
  classification (section 8.3), whether the declared marker was present (boolean), elapsed time;
- the request count equals the planned count for that area (no extra, no missing requests);
- for Authentication/Session: the session-establishment facts (`SessionState` flags and redacted fingerprints).

If any of these is missing the area is INCOMPLETE, not EXECUTED.

### 3.3 Positive controls

A denial only counts when the same identity was shown to be authenticated and allowed on a resource it owns in the same
run. Without that, a 401/403 could simply mean the login did not work. Missing or failed positive control: INCOMPLETE.

### 3.4 Threat/test model

Tested: broken access control on declared read paths (vertical and horizontal), cross-tenant read, session
establishment/continuity/invalidation, session fixation on login, session cookie attributes, acceptance of an invalid
synthetic secret. Attacker model: an authenticated user of the same application who changes a declared object
reference or route, or an unauthenticated client. Out of scope: credential guessing, token forgery, cryptographic
weaknesses, write-path authorization, business logic, any real account.

## 4. Safety boundaries

The implementation must:

- run only against explicitly authorized targets: mode `fixture` (tool-started reference application on loopback) or,
  in a later increment, mode `local-app` (the adopter's own application started inside the CI job on loopback/private
  address, `environment` local/test, `authorized_by` set). Remote staging hosts: **NOT VERIFIED** (refused for this
  feature) until a separately designed and reviewed mechanism exists. Production: always refused, no override;
- never accept real passwords, access tokens, session cookies, refresh tokens or API keys - not in config, CLI flags,
  environment variables or files; the existing `credentials:` env-var-name section is never used by this feature;
- generate synthetic secrets for declared synthetic identities in memory per run (`secrets.token_urlsafe(32)`), hand
  them to the fixture only through an in-process seed (mode `fixture`) or a one-run seed file under the job's temp
  directory with owner-only permissions deleted after the run (mode `local-app`), and discard them at the end;
- send exactly one authentication attempt per declared step: one invalid-secret attempt and one valid login per
  identity, no retries, no guessing, no user or credential enumeration;
- use only GET/HEAD, except POST to the declared login and logout paths; never PUT, PATCH, DELETE or any other POST;
- never follow redirects automatically; never interact with MFA (an MFA challenge makes the area NOT VERIFIED /
  INCOMPLETE, it is never bypassed);
- request only declared routes and declared object/resource paths - no enumeration, no ID incrementing, no discovery;
- use only the declared fixture identities and roles; never attempt to obtain a role an identity was not declared with;
- keep the existing limits (`max_requests` 1-200, `timeout` 0.5-60 s, `delay_seconds`); the planned request count must
  fit in `max_requests` or the run is refused before sending anything;
- keep secrets and session values in memory only; reports contain no raw values (section 13).

## 5. Fixture architecture

A reference fixture application (stdlib `http.server`, loopback only) shipped with the tests, started and stopped by
the tool in mode `fixture`. It exists to prove the verification machinery and to give adopters a runnable reference;
findings against it say nothing about an adopter's application.

| Identity label | Role | Tenant | Purpose |
|---|---|---|---|
| `anonymous` | - | - | unauthenticated requests |
| `user_a` | `user` | `tenant-a` | low-privilege user A |
| `user_b` | `user` | `tenant-a` | second low-privilege user (horizontal checks) |
| `admin_a` | `admin` | `tenant-a` | privileged user (positive control for privileged route) |
| `user_c` | `user` | `tenant-b` | user of the second tenant |

Declared routes and resources (all read-only):

| Path | Access rule | Marker returned |
|---|---|---|
| `GET /account` | any authenticated identity | `fixture-account:<label>` |
| `GET /objects/object-a` | owner `user_a` | `fixture-owner:user_a` |
| `GET /objects/object-b` | owner `user_b` | `fixture-owner:user_b` |
| `GET /admin/report` | role `admin` | `fixture-privileged` |
| `GET /tenants/tenant-a/resource-a` | tenant `tenant-a` | `fixture-tenant:tenant-a` |
| `GET /tenants/tenant-b/resource-b` | tenant `tenant-b` | `fixture-tenant:tenant-b` |
| `POST /login` | JSON `{identity, secret}`; sets `session` cookie (HttpOnly, SameSite=Lax) | - |
| `POST /logout` | invalidates the session server-side | - |

Identity representation: config declares labels, roles and tenants only. The tool generates one synthetic secret per
identity per run and seeds the fixture in-process; nothing about an identity's secret appears in config, logs or reports.
Denials use 403 (authenticated, not allowed), 401 (unauthenticated) or 404 (object hidden) as declared.

Deliberately broken fixture variants (for tests only, like the Quality CI BAD fixtures): object read without owner check,
tenant check missing, privileged route without role check, session not invalidated on logout, session id not rotated on
login, invalid secret accepted, cookie without HttpOnly.

## 6. Authentication design

| Step | Identity | Method, path | Expected status class | Evidence |
|---|---|---|---|---|
| A1 unauthenticated access | `anonymous` | `GET` protected | 401 or 403 (or a declared login redirect 3xx) | status class, marker absent |
| A2 invalid synthetic secret | `user_a` label, wrong per-run secret | `POST` login | 4xx, no session issued | status class, `session_issued: false` |
| A3 valid login | `user_a` | `POST` login | 2xx or declared 3xx, session issued | status class, cookie/token presence, fingerprint |
| A4 authenticated access | `user_a` | `GET` protected | 2xx with marker `fixture-account:user_a` | status class, marker present |
| A5 logout | `user_a` | `POST` logout | 2xx or declared 3xx | status class |
| A6 access after logout | `user_a` (previous session) | `GET` protected | 401 or 403 | status class, marker absent |

State transitions (`SessionState`): `not_attempted` to `succeeded` (A3) to logout `succeeded` (A5); A2 records a failed
attempt on a separate throwaway state. Requests: 6 (A5/A6 run last, after the authorization checks that reuse the
`user_a` session). PASS needs A1 denied, A2 rejected, A3/A4 successful, A6 denied. A3 or A4 failing: INCOMPLETE.

## 7. Session design

| Check | Requests | Pass condition | Evidence (no raw values) |
|---|---|---|---|
| S1 establishment | reuses A3 | a session cookie or bearer token issued | `session_type`, `cookie_count`, fingerprint |
| S2 continuity | 1 (`GET` protected with the same session) | 2xx with marker | status class, fingerprint unchanged |
| S3 invalidation | reuses A5/A6 | A6 denied | status classes |
| S4 fixation resistance | reuses A1/A3 | if A1 issued a pre-authentication session cookie and it is sent with A3, the post-login identifier fingerprint differs; if no pre-auth cookie exists: NOT APPLICABLE | fingerprints before/after, boolean `rotated` |
| S5 cookie attributes | reuses A3 | session cookie has `HttpOnly` and `SameSite`; `Secure` required on https (NOT APPLICABLE on http loopback) | attribute booleans |
| S6 value handling | - | raw values held only in `SessionState` memory | `credentials_read: false`, no raw value in report |

Secure attribute applicability (S5):

- HTTPS fixture => Secure cookie attribute is required.
- HTTP fixture => Secure is NOT APPLICABLE and must not produce a finding.
- The tool must not switch protocols solely to manufacture a finding.

Fingerprints: `HMAC-SHA256(per-run random key, value)`, first 12 hex characters. The key is generated per run and
discarded, so fingerprints only compare values within one run and cannot be reversed or linked across runs.

## 8. Authorization design (vertical)

| Step | Identity | Request | Expected |
|---|---|---|---|
| Z1 positive control | `admin_a` | `GET /admin/report` | 2xx with `fixture-privileged` |
| Z2 low-privilege access | `user_a` | `GET /admin/report` | denied (401/403/declared 404) |

Requests: 2 (plus the `admin_a` login, counted in section 11).

### 8.3 Response classification (all authorization, IDOR and tenant checks)

| Classification | Condition |
|---|---|
| allowed | 2xx and the resource's declared marker present |
| denied | status in the declared `deny_statuses` (default 401, 403, 404), marker absent |
| ambiguous | 2xx without the marker, any 3xx (redirects are not followed), 400/405/409/422, or a marker belonging to a different resource |
| incomplete | 5xx, timeout, connection error, budget exhausted |

A check expecting denial PASSES only on `denied`; FAILS only on `allowed` (marker proves the protected content was
served); `ambiguous` and `incomplete` make the area INCOMPLETE. Bodies are inspected in memory for the marker only and
never stored.

## 9. IDOR/BOLA design (horizontal, read path)

| Step | Identity | Request | Expected |
|---|---|---|---|
| I1 own object | `user_a` | `GET /objects/object-a` | allowed |
| I2 other user's object | `user_a` | `GET /objects/object-b` | denied |
| I3 own object | `user_b` | `GET /objects/object-b` | allowed |
| I4 other user's object | `user_b` | `GET /objects/object-a` | denied |

Requests: 4. Object paths come only from the declared `resources` list; no identifier is guessed, incremented or
discovered.

## 10. Tenant-isolation design

| Step | Identity | Request | Expected |
|---|---|---|---|
| T1 own tenant | `user_a` (tenant-a) | `GET /tenants/tenant-a/resource-a` | allowed |
| T2 cross-tenant | `user_a` (tenant-a) | `GET /tenants/tenant-b/resource-b` | denied |
| T3 own tenant | `user_c` (tenant-b) | `GET /tenants/tenant-b/resource-b` | allowed |
| T4 cross-tenant | `user_c` (tenant-b) | `GET /tenants/tenant-a/resource-a` | denied |

Requests: 4. Only the two declared tenant resources are requested.

## 11. Configuration contract

```yaml
target:
  base_url: http://127.0.0.1:8081       # mode fixture: loopback address chosen by the tool
  environment: local                     # local | test for mode local-app; production always refused
  production: false
  authorized: true
  authorized_by: "QA lead"               # who approved runtime verification of this target

runtime_verification:
  mode: fixture                          # fixture | local-app (later increment); anything else: config error
  identities:                            # labels, roles and tenants only - never secrets
    user_a:  {role: user,  tenant: tenant-a}
    user_b:  {role: user,  tenant: tenant-a}
    admin_a: {role: admin, tenant: tenant-a}
    user_c:  {role: user,  tenant: tenant-b}
  authentication:
    login:     {method: POST, path: /login, content_type: application/json, identity_field: identity, secret_field: secret}
    logout:    {method: POST, path: /logout}
    protected: {method: GET, path: /account, marker: "fixture-account:{label}"}
  resources:
    - {id: object-a, path: /objects/object-a, owner: user_a, marker: "fixture-owner:user_a"}
    - {id: object-b, path: /objects/object-b, owner: user_b, marker: "fixture-owner:user_b"}
    - {id: resource-a, path: /tenants/tenant-a/resource-a, tenant: tenant-a, marker: "fixture-tenant:tenant-a"}
    - {id: resource-b, path: /tenants/tenant-b/resource-b, tenant: tenant-b, marker: "fixture-tenant:tenant-b"}
  privileged_routes:
    - {path: /admin/report, roles: [admin], marker: "fixture-privileged"}
  deny_statuses: [401, 403, 404]

limits:
  max_requests: 60                       # the plan (20 requests for the fixture) must fit, else refused before sending
  timeout: 10
  delay_seconds: 0
```

Rules:
- rejected keys anywhere under `runtime_verification`: `password`, `secret` (as a value key), `token`, `cookie`,
  `api_key`, `authorization`, `bearer`, `session`, `credentials`, `*_env` (no environment-variable indirection either);
- `runtime_verification` together with the legacy `credentials:` section: configuration error;
- every path must be a declared absolute path on the target origin; no wildcards, ranges or templates other than
  `{label}` in markers;
- roles/tenants must be declared on identities; checks are derived only from the declaration;
- the plan must be <= `limits.max_requests`, computed and printed by `--plan` before anything is sent. For the fixture
  it is exactly 20 requests: A1 1, A2 1, logins of `user_a`/`user_b`/`admin_a`/`user_c` 4, A4 1, S2 1, Z1-Z2 2,
  I1-I4 4, T1-T4 4, A5 1, A6 1;
- no CLI flag or environment variable carries identity data.

## 12. Finding namespaces and severity

| Namespace | Area | Examples of findings (future) |
|---|---|---|
| `RT-AUTH-*` | Authentication | protected resource served to `anonymous` (A1 allowed); invalid synthetic secret accepted (A2 session issued) |
| `RT-SESSION-*` | Session | session still valid after logout (A6 allowed); identifier not rotated on login (S4); session cookie without HttpOnly / SameSite / Secure on https (S5) |
| `RT-AUTHZ-*` | Authorization (vertical) | low-privilege identity served the privileged route (Z2 allowed) |
| `RT-IDOR-*` | IDOR/BOLA | identity served another identity's declared object (I2/I4 allowed) |
| `RT-TENANT-*` | Tenant isolation | identity served another tenant's declared resource (T2/T4 allowed) |

IDs stay `RT-<PREFIX>-NNN`, numbered per namespace in the fixed plan order, so the same result gives the same ID.
Readers (`FINDING_ID_RE` in `models.py`, `read_phase3_report.py`, `security-ci` inputs) must add `IDOR` and `TENANT`.

Severity (no CRITICAL: a fixture or in-job run cannot establish real-world impact; people may escalate manually):

| Severity | Sufficient evidence |
|---|---|
| HIGH (confidence HIGH, blocking under `release`) | an expected denial classified **allowed** - the declared marker of the protected/other/privileged/other-tenant resource was returned - with the relevant positive controls passed: A1, A2 (session issued and A4-style access works), A6, Z2, I2/I4, T2/T4 |
| MEDIUM (confidence HIGH) | S4 identifier not rotated; S5 missing `HttpOnly`; missing `Secure` on an https session cookie |
| LOW (confidence HIGH) | S5 missing `SameSite` |
| none (area INCOMPLETE) | ambiguous or incomplete responses; failed positive controls - never a finding, never PASS |

## 13. Report model

The existing blocks stay backward compatible: `auth_areas.authentication`, `auth_areas.session`, `authorization`.
`authorization` gains `subareas` for the three authorization areas; its own `status` is the worst of them.

Per area (`authentication`, `session`, `authorization.subareas.{authorization, idor, tenant_isolation}`):

| Field | Meaning |
|---|---|
| `status` | PASS / FAIL / INCOMPLETE / NOT CONFIGURED / NOT VERIFIED |
| `execution` | `NOT EXECUTED` or `EXECUTED` |
| `reason` | one sentence; for NOT VERIFIED/INCOMPLETE the cause |
| `scope` | the checks planned for the area, by check id |
| `runtime_checks_executed` | boolean |
| `credentials_read` | always `false`: no external credential is ever read |
| `synthetic_identities` | identity labels used (labels only) |
| `requests_count` | requests sent for the area |
| `checks` | per check: id, identity labels, method, path template, status class, classification, marker present, timing |
| `findings` | finding ids |
| `evidence_limitations` | fixed list (e.g. "read paths only", "declared resources only", "fixture/in-job target only") |

Redaction guarantees (unchanged and extended): no cookie, `Set-Cookie`, `Authorization` header, token, secret or body
content in reports, SARIF, logs or console; fingerprints as in section 7 only; identity labels, declared paths,
status classes and booleans only. SARIF and Engineering CI copy the area statuses as today and never turn NOT VERIFIED
or INCOMPLETE into a finding or a pass.

## 14. Test matrix (for the future implementation)

| # | Case | Expected |
|---|---|---|
| 1 | no `runtime_verification` block | all five areas NOT CONFIGURED; 0 requests for them; Phase 3A unchanged |
| 2 | mode not released / remote staging host | NOT VERIFIED with reason; 0 requests |
| 3 | production flag, prod environment or prod host | refused before any request; NOT VERIFIED |
| 4 | credential keys, `*_env`, or legacy `credentials:` with `runtime_verification` | configuration error; 0 requests |
| 5 | plan exceeds `max_requests` | refused before sending; INCOMPLETE |
| 6 | fixture GOOD | Authentication, Session, Authorization, IDOR, Tenant PASS; exact request count 20 |
| 7 | unauthenticated rejection (A1) broken variant | `RT-AUTH-*` HIGH |
| 8 | valid fixture authentication | A3/A4 succeed; session facts recorded without raw values |
| 9 | invalid synthetic secret accepted variant | `RT-AUTH-*` HIGH; exactly one invalid attempt sent |
| 10 | session establishment / continuity | S1/S2 PASS |
| 11 | logout does not invalidate variant | `RT-SESSION-*` HIGH |
| 12 | no rotation on login variant | `RT-SESSION-*` MEDIUM |
| 13 | cookie without HttpOnly variant | `RT-SESSION-*` MEDIUM; SameSite missing: LOW |
| 14 | cross-user object access denied / broken variant | PASS / `RT-IDOR-*` HIGH |
| 15 | cross-tenant access denied / broken variant | PASS / `RT-TENANT-*` HIGH |
| 16 | privileged route denied / broken variant | PASS / `RT-AUTHZ-*` HIGH |
| 17 | positive control fails (login broken) | INCOMPLETE, no finding |
| 18 | ambiguous responses (2xx without marker, 3xx, 5xx, timeout) | INCOMPLETE, no finding |
| 19 | MFA challenge on login | NOT VERIFIED / INCOMPLETE; no further request |
| 20 | report redaction | no cookie, token, secret or body text in JSON, Markdown, SARIF, console |
| 21 | no raw credential persistence | per-run secrets never on disk (fixture) / seed file removed (local-app); `SessionState` not serializable |
| 22 | only allowed methods and declared paths | recorded request log contains only GET/HEAD + POST login/logout on declared paths |
| 23 | deterministic finding IDs | same variant twice gives identical IDs; `IDOR`/`TENANT` accepted by all readers |
| 24 | existing behaviour unchanged | the 163 existing Phase 3 tests, 3A checks, 3B plumbing, 3C status and ZAP baseline unchanged; security-ci / Engineering CI suites unchanged |

## 15. Explicit non-goals

- remote staging or production targets (NOT VERIFIED until a separate, reviewed mechanism exists);
- real accounts, real credentials, credential stores, password managers, SSO/OAuth/OIDC/SAML flows, MFA;
- brute force, credential stuffing, user or credential enumeration, token forgery or tampering;
- write-path authorization (create/update/delete), state-changing requests other than login/logout;
- object or route discovery, ID enumeration, fuzzing, crawling authenticated areas;
- privilege escalation beyond the declared synthetic roles;
- business-logic authorization, rate limiting, CSRF on authenticated flows, account recovery flows;
- replacing the Layer 2 source-code review of these areas.

## 16. Verification gaps (even after implementation)

- Fixture mode proves the verification machinery, not the adopter's application.
- `local-app` mode covers only what the adopter declares, on read paths, for synthetic identities, in the CI job.
- Write paths, bulk/list endpoints, GraphQL/WebSocket, file downloads and indirect object references not declared in
  config remain NOT VERIFIED.
- Authentication flows other than a single form/JSON POST login (SSO, OAuth/OIDC, SAML, MFA, API keys) remain NOT
  VERIFIED.
- Remote staging and production remain NOT VERIFIED.
- A PASS covers only the declared checks; it is not proof that authentication, sessions or authorization are secure.

## 17. Imported Results (implemented in v1.2)

This is the part of the design that is implemented. Vibe-Code does **not** run authentication, session or
authorization checks. Another test suite, run by someone authorized to test the target, runs them and writes a
results file. Vibe-Code validates that file and reports what it contains.

- **Who does what.** The external suite sends the requests and holds any test identities. Phase 3
  (`runtime_security.verification`) reads one local JSON file named in the configuration:

  ```yaml
  verification_results:
    path: auth-results.json   # relative to the config file
  ```

  Loading the file sends no request.
- **No credentials.** Vibe-Code never receives credentials. There is no environment variable, CLI option or config
  key for credentials; `credentials_read` is always `false`. Credential-shaped field names are rejected anywhere in
  the file, and credential-shaped values are redacted (see "Redaction" below).
- **Request budget.** Each area's `requests_count` must be an integer from 0 to 20. The total over all areas must also
  be 20 or less. Negative numbers, non-integers, booleans and values over 20 are rejected. This checks the imported
  evidence only; Vibe-Code sends nothing.
- **Limits.** Imported results cover only the checks the external suite declares, against the target it ran on. They
  do not prove that a remote application's authentication, sessions or authorization are secure. The gaps in
  section 16 still apply.
- **Evidence limitation.** Imported results prove only the evidence the external suite supplies. Vibe-Code validates
  its shape (schema), safety (no credentials, redacted values, request budget) and consistency (status against
  findings, evidence and `runtime_checks_executed`). It does not independently prove that the external requests
  happened or that the reported responses were observed. `requests_count` and evidence items are checked for form
  and limits, not replayed.

### 17.1 Schema

The schema version is `1.0`. The file is `tools/phase3-runtime-security/schemas/verification-results.schema.json`.
The importer (`runtime_security/verification/importer.py`) is the authoritative validator.

Required top-level fields:

- `schema_version` must be `"1.0"`.
- `kind` must be `"vibe-code-engineering/verification-results"`.
- `producer` is `{name, version}`.
- `target` is `{base_url}`. It must match the origin (scheme, host, port) of the Phase 3 target and contain no
  credentials.
- `areas` holds one or more of `authentication`, `session`, `authorization`, `idor_bola` and `tenant_isolation`.

Fields of each area:

| Field | Required | Rule |
|---|---|---|
| `status` | yes | one of the statuses in 17.3 |
| `runtime_checks_executed` | yes | boolean |
| `requests_count` | yes | integer 0-20 |
| `findings` | no | up to 50 findings: `id`, `severity`, `confidence`, `title`, `endpoint`, `expected`, `actual`, `evidence`, `impact`, `recommendation`, `validation`, `status` (`OPEN`/`REQUIRES_REVIEW`); optional `cwe`, `owasp`, `notes` |
| `evidence` | no | up to 50 items: `check`, `expected` and `observed` (`allowed`/`denied`/`not_applicable`/`error`); optional `endpoint`; optional `fingerprint` (12 lower-case hex characters) |
| `limitations` | no | up to 20 strings |

Unknown fields are rejected. Validation is all-or-nothing. If any rule is broken, the whole import is rejected: every
configured area becomes INCOMPLETE, no imported finding is reported, and the Phase 3 exit code is 3.

### 17.2 Namespaces

Each area accepts findings only in its own namespace:

| Area | Namespace |
|---|---|
| `authentication` | `RT-AUTH-NNN` |
| `session` | `RT-SESSION-NNN` |
| `authorization` | `RT-AUTHZ-NNN` |
| `idor_bola` | `RT-IDOR-NNN` |
| `tenant_isolation` | `RT-TENANT-NNN` |

The following are rejected: invalid IDs, IDs from another namespace, and duplicate IDs. IDs are kept exactly as
imported and are listed in sorted order, so the same file always gives the same report.

No finding is ever created because an area is NOT VERIFIED or INCOMPLETE.

Severity keeps the existing semantics: blocking means CRITICAL, or HIGH with MEDIUM/HIGH confidence. In SARIF,
imported findings are ordinary Phase 3 runtime results.

### 17.3 Status semantics

Statuses: `NOT CONFIGURED`, `READY`, `EXECUTED`, `PASS`, `FAIL`, `INCOMPLETE`, `NOT VERIFIED`. The rules live in
`runtime_security/verification/status.py`.

When the import is missing, unused or unusable:

| Situation | Status |
|---|---|
| No `verification_results` configured | `verification_import` is NOT CONFIGURED; all areas keep their existing NOT VERIFIED status |
| Configured, but the safety gate refused the target | `verification_import` is READY; results are not applied |
| File missing, malformed or rejected | every area INCOMPLETE |
| An area is absent from a valid file | that area is NOT VERIFIED |

When an area is present, its `runtime_checks_executed` flag decides the result:

- **Checks not executed.** A claimed READY, NOT VERIFIED, NOT CONFIGURED or INCOMPLETE is kept. A claimed PASS, FAIL or
  EXECUTED is ambiguous and becomes INCOMPLETE.
- **Checks executed.**
  - PASS needs at least one request, at least one evidence item and no findings.
  - FAIL needs at least one request and at least one finding; the finding is the proven unauthorized access.
  - EXECUTED needs at least one request. It becomes FAIL if findings are present.
  - Every other combination is ambiguous and becomes INCOMPLETE.

NOT VERIFIED never becomes PASS on its own.

The overall Authorization status combines its three sub-areas:

1. FAIL if any sub-area is FAIL.
2. Otherwise INCOMPLETE if any sub-area is INCOMPLETE.
3. Otherwise PASS only if all three are PASS.
4. Otherwise EXECUTED if any sub-area is PASS or EXECUTED (partial coverage).
5. Otherwise READY if any sub-area is READY.
6. Otherwise NOT VERIFIED.

The reader and security-ci re-check the report:

- A PASS or EXECUTED claim without `runtime_checks_executed: true` is treated as NOT VERIFIED. For sub-areas, the same
  applies to FAIL.
- An imported block with an invalid `requests_count` becomes INCOMPLETE.
- In security-ci, an INCOMPLETE import is listed as an incomplete input. Unless `--allow-incomplete` is set, this fails
  the gate.

### 17.4 Redaction

Credential-shaped field names are rejected anywhere in the file (areas under `areas` are exempt): names containing
password, secret, token, cookie, bearer, authorization, API key, session ID or credential, and `sid`, `pwd`, `auth`,
`session`. Error messages name fields only, never values.

Every string value is redacted as it is imported. The following become `<redacted>`:

- header lines for `Cookie`, `Set-Cookie`, `Authorization`, `X-API-Key` and `X-Auth-Token`;
- Bearer, Basic, Digest and Token values;
- every query-string value;
- the runtime redaction patterns: `key=value` secrets, JWTs, keys, URL credentials and long tokens.

Reports contain only safe metadata: statuses, counts, check names, allowed/denied observations, fingerprints and
redacted text. security-ci redacts everything again before writing SARIF.
