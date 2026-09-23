"""Local deterministic HTTP server for tests (127.0.0.1, random port). Records every request method/path.

Routes: the three fixtures (/good.html, /bad.html, /fixed.html) plus test-only pages:
  /slow.html        responds after a delay (timeout)
  /big.html         larger than the configured byte limit
  /autopost.html    accessible page whose script tries a POST fetch and a form submit on load
  /redirect.html    302 to /good.html (redirects are not followed)
  /offsite.html     loads a script from another origin (blocked)
  /secret.html?...  page with a token-like id/attribute used for redaction tests
"""

from __future__ import annotations

import threading
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

FIXTURES = Path(__file__).resolve().parents[1] / "fixtures"

AUTOPOST = """<!DOCTYPE html><html lang="en"><head><title>Autopost</title></head><body><main><h1>Autopost</h1>
<form id="f" action="/submit" method="post"><label for="q">Q</label><input id="q" name="q"></form>
<script>
fetch('/api/delete', {method: 'POST', body: 'x'}).catch(() => {});
fetch('/api/item', {method: 'DELETE'}).catch(() => {});
document.getElementById('f').submit();
</script></main></body></html>"""

OFFSITE = """<!DOCTYPE html><html lang="en"><head><title>Offsite</title>
<script src="http://203.0.113.10/tracker.js"></script></head><body><main><h1>Offsite</h1></main></body></html>"""

SECRET = """<!DOCTYPE html><html lang="en"><head><title>Secret selectors</title></head><body><main><h1>Secret</h1>
<input id="tok_ghp_abcdefghijklmnopqrstuvwxyz0123456789AB" value="sk_live_abcdefghijklmnop" type="text">
<a href="/secret.html?session=abcdef123456"></a>
</main></body></html>"""


class Recorder:
    def __init__(self) -> None:
        self.requests: list[tuple[str, str]] = []
        self.lock = threading.Lock()

    def add(self, method: str, path: str) -> None:
        with self.lock:
            self.requests.append((method, path))

    def methods(self) -> set[str]:
        return {m for m, _ in self.requests}


def _handler(rec: Recorder, slow_seconds: float, big_bytes: int):
    class H(BaseHTTPRequestHandler):
        def log_message(self, *a):  # quiet
            pass

        def _send(self, code: int, body: bytes, ctype: str = "text/html; charset=utf-8", extra=None) -> None:
            self.send_response(code)
            self.send_header("Content-Type", ctype)
            self.send_header("Content-Length", str(len(body)))
            for k, v in (extra or {}).items():
                self.send_header(k, v)
            self.end_headers()
            if self.command != "HEAD":
                try:
                    self.wfile.write(body)
                except (BrokenPipeError, ConnectionResetError):
                    pass

        def do_GET(self):
            rec.add("GET", self.path)
            path = self.path.split("?", 1)[0]
            if path in ("/good.html", "/bad.html", "/fixed.html"):
                return self._send(200, (FIXTURES / path[1:]).read_bytes())
            if path == "/slow.html":
                time.sleep(slow_seconds)
                return self._send(200, (FIXTURES / "good.html").read_bytes())
            if path == "/big.html":
                return self._send(200, b"<!DOCTYPE html><html lang='en'><title>Big</title><p>" + b"a" * big_bytes + b"</p></html>")
            if path == "/autopost.html":
                return self._send(200, AUTOPOST.encode())
            if path == "/offsite.html":
                return self._send(200, OFFSITE.encode())
            if path == "/secret.html":
                return self._send(200, SECRET.encode())
            if path == "/redirect.html":
                return self._send(302, b"", extra={"Location": "/good.html"})
            return self._send(404, b"not found", "text/plain")

        def do_HEAD(self):
            return self.do_GET()

        def _unsafe(self):
            rec.add(self.command, self.path)
            return self._send(405, b"", "text/plain")

        do_POST = do_PUT = do_DELETE = do_PATCH = _unsafe

    return H


class FixtureServer:
    def __init__(self, slow_seconds: float = 5.0, big_bytes: int = 300_000):
        self.rec = Recorder()
        self.httpd = ThreadingHTTPServer(("127.0.0.1", 0), _handler(self.rec, slow_seconds, big_bytes))
        self.httpd.daemon_threads = True
        self.thread = threading.Thread(target=self.httpd.serve_forever, daemon=True)

    @property
    def url(self) -> str:
        return f"http://127.0.0.1:{self.httpd.server_address[1]}"

    def __enter__(self) -> FixtureServer:
        self.thread.start()
        return self

    def __exit__(self, *exc) -> None:
        self.httpd.shutdown()
        self.httpd.server_close()
