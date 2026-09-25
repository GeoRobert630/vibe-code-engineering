"""Local identity-setup adapter for v1.3 native verification (Design §7.1).

Contract:
- Local only: one POST to identity_setup.path on the approved local target origin.
- Adapter: http-local only. No shell, script, or command adapters.
- Never for fixture mode (in-process instead).
- Never for remote or production targets (refused before setup).
- Exactly one setup request.
- Payload schema: 'vibe-identity-setup/1'.
- Payload fields: run_id, expires_in_seconds=180, synthetic identities with
  label, role, tenant, secret.
- Success: HTTP status 200 or 201 and response body:
  {"schema": "vibe-identity-setup/1", "run_id": <same>, "accepted": [<labels>]}.
- Failure: any other status, timeout, network error, malformed or extra-field
  body, run_id mismatch, or label mismatch marks setup and all native areas
  INCOMPLETE with no further requests sent.
- Discard: only status, schema, run_id, and accepted are retained; the rest of
  the body is discarded unread. Secrets must never be echoed.
- No persistence: payload is memory-only, never logged or written to disk.
"""

from __future__ import annotations

import json
from dataclasses import dataclass, field
from typing import Any, List, Set
from urllib.parse import urlsplit

from ..config import ActorConfig, Config
from ..utils.http import Response
from .identity import IdentityVault
from .plan import PlannedRequest

SETUP_SCHEMA = "vibe-identity-setup/1"
SETUP_EXPIRES_IN_SECONDS = 180
ALLOWED_RESPONSE_KEYS = frozenset({"schema", "run_id", "accepted"})


@dataclass(frozen=True)
class IdentitySetupResult:
    """Retained summary of identity setup delivery outcome (Design §7.1).

    Reports record only the adapter name, path, outcome (succeeded/failed),
    and accepted labels. Never the payload or secrets.
    """

    succeeded: bool
    adapter: str
    path: str
    run_id: str
    accepted: list[str] = field(default_factory=list)
    error: str | None = None

    def __repr__(self) -> str:
        return (
            f"IdentitySetupResult(succeeded={self.succeeded!r}, "
            f"adapter={self.adapter!r}, path={self.path!r}, "
            f"run_id={self.run_id!r}, accepted={self.accepted!r}, "
            f"error={self.error!r})"
        )


def build_setup_payload(
    vault: IdentityVault,
    actors: dict[str, ActorConfig],
) -> dict[str, Any]:
    """Build the synthetic identity setup payload for local-app mode (Design §7.1).

    Emits schema 'vibe-identity-setup/1', run_id, expires_in_seconds=180,
    and synthetic identities with label, role, tenant, secret.
    """
    identities: list[dict[str, Any]] = []
    # Deterministic sorted order by actor label
    for label in sorted(actors.keys()):
        actor = actors[label]
        secret_val = vault.get_actor_secret(label).reveal_for_request()
        identities.append(
            {
                "label": label,
                "role": actor.role,
                "tenant": actor.tenant,
                "secret": secret_val,
            }
        )
    return {
        "schema": SETUP_SCHEMA,
        "run_id": vault.run_id,
        "expires_in_seconds": SETUP_EXPIRES_IN_SECONDS,
        "identities": identities,
    }


def build_setup_request(cfg: Config, vault: IdentityVault) -> PlannedRequest:
    """Construct the single setup PlannedRequest for local-app mode."""
    rv = cfg.runtime_verification
    if not rv:
        raise ValueError("runtime_verification is not configured")
    if rv.mode != "local-app":
        raise ValueError(
            f"identity_setup is only available in local-app mode, got '{rv.mode}'"
        )
    if not rv.identity_setup:
        raise ValueError("runtime_verification.identity_setup is not configured")
    if rv.identity_setup.adapter != "http-local":
        raise ValueError(
            f"unsupported adapter '{rv.identity_setup.adapter}', only 'http-local' is supported"
        )

    payload = build_setup_payload(vault, rv.actors)
    body_bytes = json.dumps(payload, sort_keys=True).encode("utf-8")

    return PlannedRequest(
        area="identity_setup",
        check_id="setup",
        method="POST",
        path=rv.identity_setup.path,
        headers={"Content-Type": "application/json"},
        body=body_bytes,
    )


def validate_setup_response(
    resp: Response | None,
    expected_run_id: str,
    expected_labels: set[str] | list[str],
    vault: IdentityVault | None = None,
    path: str = "",
) -> IdentitySetupResult:
    """Validate target application's response to identity setup hook (Design §7.1).

    Enforces:
    - Status 200 or 201.
    - Valid JSON object.
    - Exact allowed keys only ('schema', 'run_id', 'accepted'); no extra fields.
    - Schema equals 'vibe-identity-setup/1'.
    - run_id exactly matches the request's run_id.
    - accepted exactly matches declared labels (sorted comparison).
    - Response body does not echo any synthetic secrets.
    - Retains only allowed metadata; rest of response body is discarded.
    """
    if resp is None:
        return IdentitySetupResult(
            succeeded=False,
            adapter="http-local",
            path=path,
            run_id=expected_run_id,
            accepted=[],
            error="no response received from target",
        )

    # 1. HTTP status: 200 or 201 only
    if resp.status not in (200, 201):
        return IdentitySetupResult(
            succeeded=False,
            adapter="http-local",
            path=path,
            run_id=expected_run_id,
            accepted=[],
            error=f"identity setup failed with HTTP status {resp.status} (expected 200 or 201)",
        )

    # 2. Secret echo check (Design §7.1: 'The application must never return secrets')
    if vault is not None:
        for lbl in expected_labels:
            try:
                secret_str = vault.get_actor_secret(lbl).reveal_for_request()
                if secret_str and secret_str in resp.body:
                    return IdentitySetupResult(
                        succeeded=False,
                        adapter="http-local",
                        path=path,
                        run_id=expected_run_id,
                        accepted=[],
                        error="security violation: setup response body echoes synthetic secret",
                    )
            except Exception:
                pass

    # 3. JSON parsing
    try:
        data = json.loads(resp.body)
    except Exception:
        return IdentitySetupResult(
            succeeded=False,
            adapter="http-local",
            path=path,
            run_id=expected_run_id,
            accepted=[],
            error="identity setup response body is not valid JSON",
        )

    if not isinstance(data, dict):
        return IdentitySetupResult(
            succeeded=False,
            adapter="http-local",
            path=path,
            run_id=expected_run_id,
            accepted=[],
            error="identity setup response JSON must be an object",
        )

    # 3. No extra fields allowed (Design §7.1: 'malformed or extra-field body')
    keys = set(data.keys())
    if keys != ALLOWED_RESPONSE_KEYS:
        extra = keys - ALLOWED_RESPONSE_KEYS
        missing = ALLOWED_RESPONSE_KEYS - keys
        details: list[str] = []
        if extra:
            details.append(f"unexpected extra keys {sorted(extra)}")
        if missing:
            details.append(f"missing keys {sorted(missing)}")
        return IdentitySetupResult(
            succeeded=False,
            adapter="http-local",
            path=path,
            run_id=expected_run_id,
            accepted=[],
            error=f"identity setup response schema violation: {', '.join(details)}",
        )

    # 4. Schema check
    schema_val = data.get("schema")
    if schema_val != SETUP_SCHEMA:
        return IdentitySetupResult(
            succeeded=False,
            adapter="http-local",
            path=path,
            run_id=expected_run_id,
            accepted=[],
            error=f"schema mismatch: expected '{SETUP_SCHEMA}', got '{schema_val}'",
        )

    # 5. run_id check: exact match required
    run_id_val = str(data.get("run_id", ""))
    if run_id_val != expected_run_id:
        return IdentitySetupResult(
            succeeded=False,
            adapter="http-local",
            path=path,
            run_id=expected_run_id,
            accepted=[],
            error=f"run_id mismatch: expected '{expected_run_id}', got '{run_id_val}'",
        )

    # 6. accepted labels check: exact match required (sorted comparison)
    accepted_val = data.get("accepted")
    if not isinstance(accepted_val, list) or not all(
        isinstance(lbl, str) for lbl in accepted_val
    ):
        return IdentitySetupResult(
            succeeded=False,
            adapter="http-local",
            path=path,
            run_id=expected_run_id,
            accepted=[],
            error="accepted field must be a list of string actor labels",
        )

    sorted_expected = sorted(set(expected_labels))
    sorted_accepted = sorted(set(accepted_val))
    if sorted_accepted != sorted_expected or len(accepted_val) != len(sorted_expected):
        return IdentitySetupResult(
            succeeded=False,
            adapter="http-local",
            path=path,
            run_id=expected_run_id,
            accepted=[],
            error=f"accepted labels mismatch: expected {sorted_expected}, got {sorted(accepted_val)}",
        )

    # 7. Success: retain only allowed fields
    return IdentitySetupResult(
        succeeded=True,
        adapter="http-local",
        path=path,
        run_id=expected_run_id,
        accepted=sorted_accepted,
        error=None,
    )
