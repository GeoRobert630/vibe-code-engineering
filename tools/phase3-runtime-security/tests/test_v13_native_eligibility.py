import pytest
import socket
from unittest.mock import patch
from runtime_security.config import parse, ConfigError
from runtime_security.native.eligibility import evaluate_native


def _make_config(mode="fixture", env="local", host="http://127.0.0.1:3000",
                 authorized=False, authorized_by="", production=False):
    data = {
        "target": {
            "base_url": host,
            "environment": env,
            "production": production,
            "authorized": authorized,
            "authorized_by": authorized_by
        },
        "runtime_verification": {
            "mode": mode,
            "allowed_targets": [host],
            "actors": {},
            "routes": {},
            "resources": [],
            "deny_statuses": []
        }
    }
    if mode == "local-app":
        data["runtime_verification"]["identity_setup"] = {
            "adapter": "http-local",
            "path": "/__vibe_test__/identities"
        }
    return parse(data)


# ─── EXISTING TESTS (preserved) ───────────────────────────────────────────

@patch("socket.getaddrinfo")
def test_native_eligibility_loopback(mock_getaddrinfo):
    mock_getaddrinfo.return_value = [(socket.AF_INET, socket.SOCK_STREAM, 6, '', ('127.0.0.1', 3000))]
    cfg = _make_config(mode="fixture")
    dec = evaluate_native(cfg)
    assert dec.allowed is True
    assert dec.resolved_ips == ["127.0.0.1"]

@patch("socket.getaddrinfo")
def test_native_eligibility_private_allowed(mock_getaddrinfo):
    mock_getaddrinfo.return_value = [(socket.AF_INET, socket.SOCK_STREAM, 6, '', ('10.0.0.5', 3000))]
    cfg = _make_config(mode="local-app", env="test", host="http://10.0.0.5:3000", authorized=True, authorized_by="tester")
    dec = evaluate_native(cfg)
    assert dec.allowed is True

@patch("socket.getaddrinfo")
def test_native_eligibility_private_denied_fixture(mock_getaddrinfo):
    mock_getaddrinfo.return_value = [(socket.AF_INET, socket.SOCK_STREAM, 6, '', ('10.0.0.5', 3000))]
    cfg = _make_config(mode="fixture", env="test", host="http://10.0.0.5:3000")
    dec = evaluate_native(cfg)
    assert dec.allowed is False
    assert "private IP" in dec.reason

@patch("socket.getaddrinfo")
def test_native_eligibility_public_ip_denied(mock_getaddrinfo):
    mock_getaddrinfo.return_value = [(socket.AF_INET, socket.SOCK_STREAM, 6, '', ('8.8.8.8', 3000))]
    cfg = _make_config(mode="local-app", env="test", host="http://8.8.8.8:3000", authorized=True, authorized_by="tester")
    dec = evaluate_native(cfg)
    assert dec.allowed is False
    assert "not allowed" in dec.reason


# ─── BLOCKER 1: PRODUCTION REFUSAL ────────────────────────────────────────

def test_production_flag_refused():
    """Design §5: production — always refused, absolutely."""
    cfg = _make_config(mode="fixture", env="local", production=True)
    dec = evaluate_native(cfg)
    assert dec.allowed is False
    assert "production" in dec.reason.lower()
    assert dec.safety_gate_passed is False

@patch("socket.getaddrinfo")
def test_production_loopback_still_refused(mock_getaddrinfo):
    """Production refusal cannot be bypassed by using a loopback address."""
    mock_getaddrinfo.return_value = [(socket.AF_INET, socket.SOCK_STREAM, 6, '', ('127.0.0.1', 3000))]
    cfg = _make_config(mode="fixture", env="local", production=True)
    dec = evaluate_native(cfg)
    assert dec.allowed is False
    assert "production" in dec.reason.lower()

@patch("socket.getaddrinfo")
def test_production_private_ip_still_refused(mock_getaddrinfo):
    """Production refusal cannot be bypassed by using a private IP."""
    mock_getaddrinfo.return_value = [(socket.AF_INET, socket.SOCK_STREAM, 6, '', ('10.0.0.5', 3000))]
    cfg = _make_config(mode="local-app", env="local", host="http://10.0.0.5:3000",
                       authorized=True, authorized_by="tester", production=True)
    dec = evaluate_native(cfg)
    assert dec.allowed is False
    assert "production" in dec.reason.lower()

def test_production_environment_name_refused():
    """Design §5: forbidden environment names are refused by the existing gate."""
    # 'prod' is a forbidden environment in the existing safety gate.
    cfg = _make_config(mode="fixture", env="prod", production=False)
    dec = evaluate_native(cfg)
    assert dec.allowed is False
    assert "production" in dec.reason.lower()


# ─── BLOCKER 2: UNSPECIFIED / MULTICAST / LINK-LOCAL REFUSAL ──────────────

@patch("socket.getaddrinfo")
def test_unspecified_ipv4_refused(mock_getaddrinfo):
    """0.0.0.0 must be refused — it must NOT pass as a private address."""
    mock_getaddrinfo.return_value = [(socket.AF_INET, socket.SOCK_STREAM, 6, '', ('0.0.0.0', 3000))]
    cfg = _make_config(mode="fixture")
    dec = evaluate_native(cfg)
    assert dec.allowed is False
    assert "unspecified" in dec.reason.lower()

@patch("socket.getaddrinfo")
def test_unspecified_ipv6_refused(mock_getaddrinfo):
    """:: (IPv6 unspecified) must be refused."""
    mock_getaddrinfo.return_value = [(socket.AF_INET6, socket.SOCK_STREAM, 6, '', ('::', 3000, 0, 0))]
    cfg = _make_config(mode="fixture")
    dec = evaluate_native(cfg)
    assert dec.allowed is False
    assert "unspecified" in dec.reason.lower()

@patch("socket.getaddrinfo")
def test_link_local_ipv4_refused(mock_getaddrinfo):
    """169.254.x.x (link-local) must be refused."""
    mock_getaddrinfo.return_value = [(socket.AF_INET, socket.SOCK_STREAM, 6, '', ('169.254.1.1', 3000))]
    cfg = _make_config(mode="local-app", env="test", host="http://169.254.1.1:3000",
                       authorized=True, authorized_by="tester")
    dec = evaluate_native(cfg)
    assert dec.allowed is False
    assert "link-local" in dec.reason.lower()

@patch("socket.getaddrinfo")
def test_link_local_ipv6_refused(mock_getaddrinfo):
    """fe80:: (IPv6 link-local) must be refused."""
    mock_getaddrinfo.return_value = [(socket.AF_INET6, socket.SOCK_STREAM, 6, '', ('fe80::1', 3000, 0, 0))]
    cfg = _make_config(mode="local-app", env="test", host="http://[fe80::1]:3000",
                       authorized=True, authorized_by="tester")
    dec = evaluate_native(cfg)
    assert dec.allowed is False
    assert "link-local" in dec.reason.lower()

@patch("socket.getaddrinfo")
def test_multicast_ipv4_refused(mock_getaddrinfo):
    """224.0.0.1 (multicast) must be refused."""
    mock_getaddrinfo.return_value = [(socket.AF_INET, socket.SOCK_STREAM, 6, '', ('224.0.0.1', 3000))]
    cfg = _make_config(mode="fixture")
    dec = evaluate_native(cfg)
    assert dec.allowed is False
    assert "multicast" in dec.reason.lower()

@patch("socket.getaddrinfo")
def test_multicast_ipv6_refused(mock_getaddrinfo):
    """ff02::1 (IPv6 multicast) must be refused."""
    mock_getaddrinfo.return_value = [(socket.AF_INET6, socket.SOCK_STREAM, 6, '', ('ff02::1', 3000, 0, 0))]
    cfg = _make_config(mode="fixture")
    dec = evaluate_native(cfg)
    assert dec.allowed is False
    assert "multicast" in dec.reason.lower()

@patch("socket.getaddrinfo")
def test_ipv6_loopback_allowed(mock_getaddrinfo):
    """::1 (IPv6 loopback) must be allowed."""
    mock_getaddrinfo.return_value = [(socket.AF_INET6, socket.SOCK_STREAM, 6, '', ('::1', 3000, 0, 0))]
    cfg = _make_config(mode="fixture", host="http://[::1]:3000")
    dec = evaluate_native(cfg)
    assert dec.allowed is True

@patch("socket.getaddrinfo")
def test_rfc1918_ranges_allowed_in_local_app(mock_getaddrinfo):
    """RFC1918 private ranges (10.x, 172.16.x, 192.168.x) allowed in local-app."""
    for ip in ("10.0.0.1", "172.16.0.1", "192.168.1.1"):
        mock_getaddrinfo.return_value = [(socket.AF_INET, socket.SOCK_STREAM, 6, '', (ip, 3000))]
        cfg = _make_config(mode="local-app", env="test", host=f"http://{ip}:3000",
                           authorized=True, authorized_by="tester")
        dec = evaluate_native(cfg)
        assert dec.allowed is True, f"{ip} should be allowed in local-app mode"

@patch("socket.getaddrinfo")
def test_fc00_ipv6_allowed_in_local_app(mock_getaddrinfo):
    """fc00::/7 (IPv6 ULA) allowed in local-app mode."""
    mock_getaddrinfo.return_value = [(socket.AF_INET6, socket.SOCK_STREAM, 6, '', ('fd12::1', 3000, 0, 0))]
    cfg = _make_config(mode="local-app", env="test", host="http://[fd12::1]:3000",
                       authorized=True, authorized_by="tester")
    dec = evaluate_native(cfg)
    assert dec.allowed is True


# ─── BLOCKER 3: EXISTING SAFETY GATE INTEGRATION ──────────────────────────

def test_safety_gate_runs_before_native_checks():
    """The existing Phase 3 safety gate must run and its refusal prevents
    native eligibility from proceeding to address resolution."""
    # A forbidden environment ('prod') should be caught by the safety gate,
    # not by native eligibility's own checks.
    cfg = _make_config(mode="fixture", env="prod")
    dec = evaluate_native(cfg)
    assert dec.allowed is False
    assert dec.safety_gate_passed is False
    assert "safety gate" in dec.reason.lower() or "production" in dec.reason.lower()

@patch("runtime_security.native.eligibility.safety_gate_evaluate")
def test_safety_gate_is_actually_invoked(mock_gate):
    """Prove the existing safety gate function is called by evaluate_native."""
    from runtime_security.utils.safety import SafetyDecision
    mock_gate.return_value = SafetyDecision(True, "local target", True)
    with patch("socket.getaddrinfo") as mock_dns:
        mock_dns.return_value = [(socket.AF_INET, socket.SOCK_STREAM, 6, '', ('127.0.0.1', 3000))]
        cfg = _make_config(mode="fixture")
        dec = evaluate_native(cfg)
    mock_gate.assert_called_once_with(cfg)
    assert dec.allowed is True
    assert dec.safety_gate_passed is True

@patch("runtime_security.native.eligibility.safety_gate_evaluate")
def test_safety_gate_refusal_blocks_native(mock_gate):
    """If the existing safety gate refuses, native eligibility refuses without
    performing any address resolution."""
    from runtime_security.utils.safety import SafetyDecision
    mock_gate.return_value = SafetyDecision(False, "test refusal from gate", False)
    with patch("socket.getaddrinfo") as mock_dns:
        cfg = _make_config(mode="fixture")
        dec = evaluate_native(cfg)
    assert dec.allowed is False
    assert dec.safety_gate_passed is False
    assert "safety gate" in dec.reason.lower()
    # DNS resolution must NOT have been called — the gate stopped everything.
    mock_dns.assert_not_called()

@patch("socket.getaddrinfo")
def test_hostname_resolving_to_unspecified_refused(mock_getaddrinfo):
    """A hostname that resolves to 0.0.0.0 cannot bypass refusal even when
    the hostname itself looks legitimate."""
    mock_getaddrinfo.return_value = [(socket.AF_INET, socket.SOCK_STREAM, 6, '', ('0.0.0.0', 3000))]
    cfg = _make_config(mode="local-app", env="test", host="http://my-service:3000",
                       authorized=True, authorized_by="tester")
    dec = evaluate_native(cfg)
    assert dec.allowed is False
    assert "unspecified" in dec.reason.lower()
