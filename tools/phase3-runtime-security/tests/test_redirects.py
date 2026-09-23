from conftest import client_for, make_cfg
from mock_app import MockServer

from runtime_security.checks import redirects
from runtime_security.models import Outcome, Severity


def test_http_redirects_to_https_passes(safe_app):
    with MockServer("safe", role="redirect", https_port=8443) as listener:
        cfg = make_cfg(safe_app.url, target__http_url=listener.url + "/")
        run = redirects.run(client_for(cfg), cfg)
    assert run.findings == []
    assert run.results[0].outcome == Outcome.PASSED and "301" in run.results[0].detail


def test_http_without_redirect_detected(unsafe_app):
    with MockServer("unsafe", role="redirect") as listener:
        cfg = make_cfg(unsafe_app.url, target__http_url=listener.url + "/")
        run = redirects.run(client_for(cfg), cfg)
    f = run.findings[0]
    assert f.title == "Content served over plain HTTP without redirect" and f.severity == Severity.MEDIUM


def test_plain_http_target_without_http_url_not_verified(safe_app):
    cfg = make_cfg(safe_app.url)
    run = redirects.run(client_for(cfg), cfg)
    assert run.results[0].outcome == Outcome.NOT_VERIFIED


def test_redirect_is_not_followed(safe_app):
    with MockServer("safe", role="redirect", https_port=8443) as listener:
        cfg = make_cfg(safe_app.url, target__http_url=listener.url + "/")
        client = client_for(cfg)
        redirects.run(client, cfg)
    # exactly one request to the listener; the https Location (port 8443) was never requested
    assert client.sent == 1 and all("8443" not in line for line in client.log)
