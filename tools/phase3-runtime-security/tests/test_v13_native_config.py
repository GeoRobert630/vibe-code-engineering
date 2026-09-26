import pytest
from runtime_security.config import parse, ConfigError

def test_credential_keys_rejected():
    for bad_key in ("password", "secret", "token", "cookie", "bearer", "authorization", "api_key", "session_id", "credentials", "token_env"):
        data = {
            "target": {"base_url": "http://127.0.0.1:3000", "environment": "local", "production": False},
            "runtime_verification": {
                "mode": "fixture",
                bad_key: "value"
            }
        }
        with pytest.raises(ConfigError, match="unknown keys in runtime_verification|credential-shaped"):
            parse(data)

def test_legacy_credentials_and_runtime_verification_mutually_exclusive():
    data = {
        "target": {"base_url": "http://127.0.0.1:3000", "environment": "local", "production": False},
        "credentials": {"username_env": "U", "password_env": "P"},
        "runtime_verification": {"mode": "fixture"}
    }
    with pytest.raises(ConfigError, match="runtime_verification together with the legacy credentials section is a configuration error|cannot be used together"):
        parse(data)

def test_valid_runtime_verification():
    data = {
        "target": {"base_url": "http://127.0.0.1:3000", "environment": "local", "production": False},
        "runtime_verification": {
            "mode": "local-app",
            "allowed_targets": ["http://127.0.0.1:3000"],
            "identity_setup": {
                "adapter": "http-local",
                "path": "/__vibe_test__/identities"
            },
            "actors": {
                "user_a": {"role": "user", "tenant": "tenant-a"}
            },
            "routes": {
                "protected": {"path": "/account", "marker": "account:{label}"}
            },
            "resources": [
                {"id": "object-a", "path": "/objects/object-a", "owner": "user_a", "marker": "owner:user_a"}
            ],
            "deny_statuses": [401, 403, 404]
        }
    }
    cfg = parse(data)
    assert cfg.runtime_verification is not None
    assert cfg.runtime_verification.mode == "local-app"
    assert cfg.runtime_verification.allowed_targets == ["http://127.0.0.1:3000"]
    assert cfg.runtime_verification.actors["user_a"].role == "user"
    assert cfg.runtime_verification.routes["protected"].path == "/account"
    assert len(cfg.runtime_verification.resources) == 1
    assert cfg.runtime_verification.deny_statuses == frozenset({401, 403, 404})
