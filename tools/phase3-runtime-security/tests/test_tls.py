from conftest import client_for, make_cert, make_cfg
from mock_app import MockServer

from runtime_security.checks import tls
from runtime_security.models import Outcome, Severity


def test_valid_certificate_with_trusted_ca(tmp_path):
    cert, key = make_cert(tmp_path, "ok", "IP:127.0.0.1")
    with MockServer("safe", certfile=cert, keyfile=key) as s:
        cfg = make_cfg(s.url, target__ca_file=cert)
        run = tls.run(client_for(cfg), cfg)
    assert run.findings == []
    outcomes = {r.name: r for r in run.results}
    assert outcomes["certificate"].outcome == Outcome.PASSED
    assert outcomes["protocol"].outcome == Outcome.PASSED and ("TLSv1.2" in outcomes["protocol"].detail or "TLSv1.3" in outcomes["protocol"].detail)


def test_untrusted_self_signed_certificate_detected(tmp_path):
    cert, key = make_cert(tmp_path, "selfsigned", "IP:127.0.0.1")
    with MockServer("safe", certfile=cert, keyfile=key) as s:
        cfg = make_cfg(s.url)  # no ca_file: system trust store only
        run = tls.run(client_for(cfg), cfg)
    f = run.findings[0]
    assert f.title == "TLS certificate does not validate" and f.severity == Severity.HIGH
    assert "self" in f.actual.lower() or "certificate" in f.actual.lower()


def test_hostname_mismatch_detected(tmp_path):
    cert, key = make_cert(tmp_path, "wronghost", "DNS:other.example.test")
    with MockServer("safe", certfile=cert, keyfile=key) as s:
        cfg = make_cfg(s.url, target__ca_file=cert)
        run = tls.run(client_for(cfg), cfg)
    assert run.findings[0].title == "TLS certificate hostname mismatch"


def test_http_target_tls_not_verified(safe_app):
    cfg = make_cfg(safe_app.url)
    run = tls.run(client_for(cfg), cfg)
    assert run.results[0].outcome == Outcome.NOT_VERIFIED and run.findings == []


def test_https_headers_check_requires_hsts(tmp_path):
    from runtime_security.checks import headers

    cert, key = make_cert(tmp_path, "ok2", "IP:127.0.0.1")
    with MockServer("unsafe", certfile=cert, keyfile=key) as s:
        cfg = make_cfg(s.url, target__ca_file=cert)
        run = headers.run(client_for(cfg), cfg)
    assert any(f.title == "Missing Strict-Transport-Security header" for f in run.findings)
