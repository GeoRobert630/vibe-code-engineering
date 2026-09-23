from conftest import client_for, failed, make_cfg

from runtime_security.checks import cors
from runtime_security.models import Outcome, Severity


def test_restrictive_cors_passes(safe_app):
    cfg = make_cfg(safe_app.url)
    run = cors.run(client_for(cfg), cfg)
    assert run.findings == []
    trusted = next(r for r in run.results if r.name == "trusted origin")
    assert trusted.outcome == Outcome.PASSED


def test_reflected_credentialed_cors_detected(unsafe_app):
    cfg = make_cfg(unsafe_app.url)
    run = cors.run(client_for(cfg), cfg)
    assert {"untrusted origin", "null origin", "preflight"} <= failed(run)
    reflect = next(f for f in run.findings if f.title.startswith("CORS reflects"))
    assert reflect.severity == Severity.HIGH and "credentials" in reflect.title
    assert all("not authorization" in " ".join(f.notes) for f in run.findings)


def test_wildcard_without_credentials_is_low():
    class R:
        def __init__(self, h):
            self.h = {k.lower(): v for k, v in h.items()}
            self.status = 200

        def header(self, name):
            return self.h.get(name.lower())

    class FakeClient:
        def request(self, method, path, headers=None, body=None, base=None):
            if method == "OPTIONS":
                return R({})
            return R({"Access-Control-Allow-Origin": "*"})

    cfg = make_cfg("http://127.0.0.1:9")
    run = cors.run(FakeClient(), cfg)
    wc = next(f for f in run.findings if "wildcard" in f.title)
    assert wc.severity == Severity.LOW


def test_untrusted_origin_is_never_contacted(safe_app):
    cfg = make_cfg(safe_app.url)
    client = client_for(cfg)
    cors.run(client, cfg)
    assert all("127.0.0.1" in line for line in client.log)
