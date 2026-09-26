"""v1.4 acceptance: CSRF declarative configuration contract (Design §11).

Locks down:
- csrf absent -> NOT CONFIGURED
- token / origin_only / both strategies
- valid methods POST, PUT, PATCH
- forbidden methods GET, HEAD, OPTIONS, DELETE rejected
- credential-shaped keys and unknown keys rejected
- absolute URLs rejected (path must be relative)
- login configuration resolution (cfg.authentication.login with csrf.session_setup fallback)
- token_source vs token_location separation
- mutual exclusivity of native and imported CSRF configurations
"""

from __future__ import annotations

import sys
from pathlib import Path

_SRC = str(Path(__file__).resolve().parents[1] / "src")
_TESTS = str(Path(__file__).resolve().parent)
if _SRC not in sys.path:
    sys.path.insert(0, _SRC)
if _TESTS not in sys.path:
    sys.path.insert(0, _TESTS)

import pytest
from runtime_security.config import ConfigError, parse

pending_config = pytest.mark.xfail(
    strict=True,
    reason="v1.4 design contract: CSRF configuration parsing pending in config.py",
)

BASE_TARGET = {
    "base_url": "http://127.0.0.1:3000",
    "environment": "local",
    "production": False,
}


# -----------------------------------------------------------------------------
# 1. CSRF Absent -> NOT CONFIGURED (Passes today)
# -----------------------------------------------------------------------------

def test_csrf_absent_from_config_defaults_to_none():
    """When runtime_verification does not declare csrf, it defaults to None (NOT CONFIGURED)."""
    data = {
        "target": BASE_TARGET,
        "runtime_verification": {
            "mode": "fixture",
            "allowed_targets": ["http://127.0.0.1:3000"],
            "actors": {"user_a": {"role": "user"}},
        },
    }
    cfg = parse(data)
    assert cfg.runtime_verification is not None
    # csrf attribute absent or None on v1.3 Config
    csrf_cfg = getattr(cfg.runtime_verification, "csrf", None)
    assert csrf_cfg is None


# -----------------------------------------------------------------------------
# 2. Token Strategies: token, origin_only, both
# -----------------------------------------------------------------------------

@pending_config
@pytest.mark.parametrize("strategy", ["token", "origin_only", "both"])
def test_valid_token_strategies_accepted(strategy: str):
    """CSRF configuration accepts token, origin_only, and both strategies."""
    data = {
        "target": BASE_TARGET,
        "runtime_verification": {
            "mode": "fixture",
            "csrf": {
                "path": "/api/settings",
                "token_strategy": strategy,
                "marker": "settings_updated",
            },
        },
    }
    cfg = parse(data)
    assert cfg.runtime_verification.csrf.token_strategy == strategy


@pending_config
def test_invalid_token_strategy_rejected():
    """Unrecognized token strategies must be rejected with ConfigError."""
    data = {
        "target": BASE_TARGET,
        "runtime_verification": {
            "mode": "fixture",
            "csrf": {
                "path": "/api/settings",
                "token_strategy": "magic_cookie",
            },
        },
    }
    with pytest.raises(ConfigError, match="token_strategy"):
        parse(data)


# -----------------------------------------------------------------------------
# 3. HTTP Method Constraints: POST, PUT, PATCH vs GET, HEAD, OPTIONS, DELETE
# -----------------------------------------------------------------------------

@pending_config
@pytest.mark.parametrize("method", ["POST", "PUT", "PATCH"])
def test_valid_mutation_methods_accepted(method: str):
    """CSRF verification supports POST, PUT, and PATCH methods."""
    data = {
        "target": BASE_TARGET,
        "runtime_verification": {
            "mode": "fixture",
            "csrf": {
                "path": "/api/update",
                "method": method,
                "marker": "updated",
            },
        },
    }
    cfg = parse(data)
    assert cfg.runtime_verification.csrf.method == method


@pending_config
@pytest.mark.parametrize("forbidden_method", ["GET", "HEAD", "OPTIONS", "DELETE"])
def test_forbidden_methods_rejected(forbidden_method: str):
    """Non-state-changing (GET/HEAD/OPTIONS) and destructive (DELETE) methods are rejected."""
    data = {
        "target": BASE_TARGET,
        "runtime_verification": {
            "mode": "fixture",
            "csrf": {
                "path": "/api/action",
                "method": forbidden_method,
            },
        },
    }
    with pytest.raises(ConfigError, match="method"):
        parse(data)


# -----------------------------------------------------------------------------
# 4. Rejection of Invalid Configurations & Credential Leaks
# -----------------------------------------------------------------------------

@pending_config
def test_absolute_url_rejected_for_csrf_path():
    """CSRF path must be target-relative; absolute URLs are rejected."""
    data = {
        "target": BASE_TARGET,
        "runtime_verification": {
            "mode": "fixture",
            "csrf": {
                "path": "http://evil.com/api/settings",
            },
        },
    }
    with pytest.raises(ConfigError, match="path must be relative"):
        parse(data)


@pending_config
@pytest.mark.parametrize("cred_key", ["password", "secret", "bearer", "api_key", "raw_token"])
def test_credential_shaped_keys_rejected_in_csrf_config(cred_key: str):
    """Literal credentials in csrf configuration must be rejected by parser."""
    data = {
        "target": BASE_TARGET,
        "runtime_verification": {
            "mode": "fixture",
            "csrf": {
                "path": "/api/settings",
                cred_key: "super_secret_value",
            },
        },
    }
    with pytest.raises(ConfigError, match="unknown keys in csrf|credential-shaped key"):
        parse(data)


# -----------------------------------------------------------------------------
# 5. Login Configuration Resolution & Session Setup Fallback
# -----------------------------------------------------------------------------

@pending_config
def test_login_config_resolution_from_canonical_auth():
    """CSRF uses canonical cfg.authentication.login when session_setup is not defined."""
    data = {
        "target": BASE_TARGET,
        "authentication": {
            "enabled": True,
            "login": {"method": "POST", "path": "/auth/login"},
        },
        "runtime_verification": {
            "mode": "fixture",
            "csrf": {
                "path": "/api/settings",
                "marker": "ok",
            },
        },
    }
    cfg = parse(data)
    assert cfg.authentication.login.path == "/auth/login"
    # csrf config cleanly resolves login configuration
    assert cfg.runtime_verification.csrf.session_setup is None


@pending_config
def test_explicit_csrf_session_setup_fallback():
    """Explicit csrf.session_setup is used when authentication.login is absent."""
    data = {
        "target": BASE_TARGET,
        "runtime_verification": {
            "mode": "fixture",
            "csrf": {
                "path": "/api/settings",
                "session_setup": {
                    "path": "/custom/csrf/login",
                    "method": "POST",
                },
            },
        },
    }
    cfg = parse(data)
    assert cfg.runtime_verification.csrf.session_setup.path == "/custom/csrf/login"
    assert cfg.runtime_verification.csrf.session_setup.method == "POST"


# -----------------------------------------------------------------------------
# 6. Token Model Configuration: Source vs Location Separation
# -----------------------------------------------------------------------------

@pending_config
@pytest.mark.parametrize("source", ["none", "session_cookie", "prefetch", "page_body"])
def test_valid_token_sources_accepted(source: str):
    """Valid token sources: none, session_cookie, prefetch, page_body."""
    data = {
        "target": BASE_TARGET,
        "runtime_verification": {
            "mode": "fixture",
            "csrf": {
                "path": "/api/profile",
                "token_source": source,
                "token_source_marker": "csrf_token" if source in ("prefetch", "page_body") else None,
            },
        },
    }
    cfg = parse(data)
    assert cfg.runtime_verification.csrf.token_source == source


@pending_config
@pytest.mark.parametrize("location", ["header", "form", "json", "double_submit_cookie"])
def test_valid_token_locations_accepted(location: str):
    """Valid token transport locations: header, form, json, double_submit_cookie."""
    data = {
        "target": BASE_TARGET,
        "runtime_verification": {
            "mode": "fixture",
            "csrf": {
                "path": "/api/profile",
                "token_location": location,
                "token_name": "X-CSRF-Token" if location == "header" else "csrf_token",
            },
        },
    }
    cfg = parse(data)
    assert cfg.runtime_verification.csrf.token_location == location


# -----------------------------------------------------------------------------
# 7. Native vs Imported Conflict Refusal
# -----------------------------------------------------------------------------

@pending_config
def test_native_csrf_and_imported_csrf_conflict_refused(tmp_path):
    """Configuring native csrf verification AND imported csrf results is refused as ConfigError."""
    import_file = tmp_path / "imported.json"
    import_file.write_text('{"schema_version": "1.1", "areas": {"csrf": {}}}', encoding="utf-8")

    data = {
        "target": BASE_TARGET,
        "verification_results": {"path": str(import_file)},
        "runtime_verification": {
            "mode": "fixture",
            "csrf": {"path": "/api/action"},
        },
    }
    with pytest.raises(ConfigError, match="conflict|mutually exclusive"):
        parse(data)
